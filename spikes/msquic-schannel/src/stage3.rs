//! Stage 3: a WebTransport bidirectional stream carrying holdfast's own
//! protocol, over our own `h3::quic` adapter.
//!
//! Stage 2 proved the session *opens*. What the real client does per channel is
//! `connection.open_bi()` (`Chan::open`) and then 4-byte big-endian
//! length-prefixed protobuf. This proves that end to end:
//!
//! 1. channel binding via Schannel `GetParam` (as stage 2, but through our
//!    adapter rather than msquic-h3),
//! 2. extended CONNECT accepted,
//! 3. a WebTransport bidi stream opened, framed with
//!    `WEBTRANSPORT_BI_STREAM` + session id, and
//! 4. a real `ClientHello` sent with holdfast's own encoder, and a real
//!    `ServerHello` decoded back.
//!
//! Step 4 is the one that matters: it is wire compatibility with the live
//! daemon, not an approximation of it.
//!
//! ```powershell
//! stage3.exe https://host:4444 --expect <base64-sha256>
//! ```

use std::ffi::c_void;
use std::future::poll_fn;
use std::ptr;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use bytes::{Buf, Bytes};
use h3::quic::{BidiStream as _, Connection as _, OpenStreams as _, RecvStream as _, SendStream as _, SendStreamUnframed as _};
use h3::stream::BidiStreamHeader;
use hf_protocol::framing::{encode_frame, FrameDecoder};
use hf_protocol::pb::{self, envelope::Message as Msg, Envelope};
use hf_protocol::{FRAME_BYTES_DEFAULT, PROTOCOL_MAJOR, PROTOCOL_MINOR};
use msquic::{BufferRef, CredentialConfig, CredentialFlags, RegistrationConfig, Settings};
use msquic_async as ma;
use sha2::{Digest, Sha256};
use spike_msquic_schannel::adapter;

const ALPN: &str = "h3";
const SECPKG_ATTR_REMOTE_CERT_CONTEXT: u32 = 0x53;

#[repr(C)]
struct CertContext {
    encoding_type: u32,
    encoded: *mut u8,
    encoded_len: u32,
    cert_info: *mut c_void,
    cert_store: *mut c_void,
}

#[tokio::main]
async fn main() -> Result<()> {
    let (host, port, expected) = parse_args()?;
    println!("target      {host}:{port}");

    let registration = msquic::Registration::new(&RegistrationConfig::default())
        .map_err(|s| anyhow!("open registration failed: {s:?}"))?;
    let alpn = [BufferRef::from(ALPN)];
    let settings = Settings::new()
        .set_IdleTimeoutMs(15_000)
        .set_PeerBidiStreamCount(16)
        .set_PeerUnidiStreamCount(16)
        .set_DatagramReceiveEnabled();
    let configuration = msquic::Configuration::open(&registration, &alpn, Some(&settings))
        .map_err(|s| anyhow!("open configuration failed: {s:?}"))?;
    let credential = CredentialConfig::new_client()
        .set_credential_flags(CredentialFlags::NO_CERTIFICATE_VALIDATION);
    configuration
        .load_credential(&credential)
        .map_err(|s| anyhow!("load client credential failed: {s:?}"))?;

    let conn = Arc::new(ma::Connection::new(&registration).map_err(|e| anyhow!("open: {e}"))?);
    conn.start(&configuration, &host, port)
        .await
        .map_err(|e| anyhow!("quic connect failed: {e}"))?;
    println!("connected   QUIC handshake complete (Schannel)");

    // --- 1. channel binding ------------------------------------------------
    let der = schannel_peer_leaf(&conn)?;
    let observed: [u8; 32] = Sha256::digest(&der).into();
    println!("leaf DER    {} bytes", der.len());
    println!("observed    {}", hex(&observed));
    if observed != expected {
        bail!("FAIL - channel binding mismatch");
    }
    println!("            channel binding matches");

    // The opener is taken before the connection is handed to h3; both hold an
    // Arc to the same msquic connection.
    let adapted = adapter::Connection::new(conn.clone());
    let mut opener = <adapter::Connection as h3::quic::Connection<Bytes>>::opener(&adapted);

    let mut builder = h3::client::builder();
    builder.enable_extended_connect(true);
    builder.enable_webtransport(true);
    builder.enable_datagram(true);
    let (mut driver, mut send_request) = builder
        .build::<_, _, Bytes>(adapted)
        .await
        .map_err(|e| anyhow!("h3 handshake failed: {e}"))?;
    tokio::spawn(async move {
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
    });
    println!("h3          SETTINGS exchanged");

    // --- 2. WebTransport session -------------------------------------------
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!("https://{host}:{port}/"))
        .extension(h3::ext::Protocol::WEB_TRANSPORT)
        .body(())
        .context("build extended CONNECT")?;
    let mut connect = send_request
        .send_request(request)
        .await
        .map_err(|e| anyhow!("send extended CONNECT failed: {e}"))?;
    let response = connect
        .recv_response()
        .await
        .map_err(|e| anyhow!("no response to extended CONNECT: {e}"))?;
    println!("CONNECT     status {}", response.status());
    if !response.status().is_success() {
        bail!("FAIL - daemon refused the session ({})", response.status());
    }
    // The session id is the CONNECT stream's id, exactly as the server derives
    // it (h3-webtransport server.rs: `stream.send_id().into()`).
    let session_id: h3::webtransport::SessionId = connect.id().into();

    // --- 3. a WebTransport bidi stream -------------------------------------
    let mut stream = poll_fn(|cx| opener.poll_open_bidi(cx))
        .await
        .map_err(|e| anyhow!("open webtransport bidi failed: {e}"))?;
    h3::quic::SendStream::<Bytes>::send_data(
        &mut stream,
        BidiStreamHeader::WebTransportBidi(session_id),
    )
    .map_err(|e| anyhow!("queue stream header failed: {e}"))?;
    poll_fn(|cx| h3::quic::SendStream::<Bytes>::poll_ready(&mut stream, cx))
        .await
        .map_err(|e| anyhow!("write stream header failed: {e}"))?;
    println!("wt stream   opened, header written (session {session_id:?})");

    // --- 4. holdfast's own protocol over it --------------------------------
    let hello = Envelope {
        message: Some(Msg::ClientHello(pb::ClientHello {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            client_kind: pb::ClientKind::NativeQuic as i32,
            client_build: "stage3-spike".to_string(),
            capabilities: vec![],
            max_frame_bytes: FRAME_BYTES_DEFAULT,
            max_datagram_bytes: 1200,
            encodings: vec![pb::Encoding::Utf8 as i32],
        })),
        ..Default::default()
    };
    let framed = encode_frame(&hello, FRAME_BYTES_DEFAULT)?;
    let framed_len = framed.len();
    let mut payload = Bytes::from(framed);
    while payload.has_remaining() {
        poll_fn(|cx| {
            h3::quic::SendStreamUnframed::<Bytes>::poll_send(&mut stream, cx, &mut payload)
        })
        .await
        .map_err(|e| anyhow!("write ClientHello failed: {e}"))?;
    }
    println!("sent        ClientHello ({framed_len} bytes framed)");

    let mut decoder = FrameDecoder::new(FRAME_BYTES_DEFAULT);
    loop {
        if let Some(envelope) = decoder.next_frame()? {
            match envelope.message {
                Some(Msg::ServerHello(hello)) => {
                    println!(
                        "recv        ServerHello: protocol {}.{}, max_frame_bytes {}",
                        hello.protocol_major, hello.protocol_minor, hello.max_frame_bytes
                    );
                    println!("\nPASS - a WebTransport bidi stream over our own h3::quic adapter");
                    println!("carried holdfast's protocol end to end. Wire compatible.");
                    return Ok(());
                }
                other => bail!("expected ServerHello, got {other:?}"),
            }
        }
        let chunk = poll_fn(|cx| h3::quic::RecvStream::poll_data(&mut stream, cx))
            .await
            .map_err(|e| anyhow!("read failed: {e}"))?;
        match chunk {
            Some(mut buf) => {
                let bytes = buf.copy_to_bytes(buf.remaining());
                decoder.extend(&bytes)?;
            }
            None => bail!("stream closed before ServerHello arrived"),
        }
    }
}

fn schannel_peer_leaf(conn: &ma::Connection) -> Result<Vec<u8>> {
    #[repr(C)]
    struct SchannelContextAttribute {
        attribute: u32,
        buffer: *mut c_void,
    }

    let mut cert: *mut CertContext = ptr::null_mut();
    let mut attribute = SchannelContextAttribute {
        attribute: SECPKG_ATTR_REMOTE_CERT_CONTEXT,
        buffer: &mut cert as *mut _ as *mut c_void,
    };
    let len = std::mem::size_of::<SchannelContextAttribute>() as u32;

    // SAFETY: handle is live for the call; buffer matches
    // QUIC_SCHANNEL_CONTEXT_ATTRIBUTE_W.
    unsafe {
        msquic::Api::get_param(
            conn.msquic_handle(),
            msquic::PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_W,
            &len,
            &mut attribute as *mut _ as *mut c_void,
        )
        .map_err(|s| anyhow!("GetParam(SCHANNEL_CONTEXT_ATTRIBUTE_W) failed: {s:?}"))?;
    }
    if cert.is_null() {
        bail!("Schannel returned a null certificate context");
    }
    // SAFETY: non-null CERT_CONTEXT from Schannel; intentionally leaked (probe).
    let der = unsafe {
        let cert = &*cert;
        if cert.encoded.is_null() || cert.encoded_len == 0 {
            bail!("certificate context carries no encoded bytes");
        }
        std::slice::from_raw_parts(cert.encoded, cert.encoded_len as usize).to_vec()
    };
    Ok(der)
}

fn parse_args() -> Result<(String, u16, [u8; 32])> {
    let mut args = std::env::args().skip(1);
    let url = args
        .next()
        .ok_or_else(|| anyhow!("usage: stage3 <https://host[:port]> --expect <base64-sha256>"))?;
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| anyhow!("URL must start with https:// (got {url})"))?
        .trim_end_matches('/');
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h.to_string(), p.parse().unwrap_or(443))
        }
        _ => (rest.to_string(), 443u16),
    };

    let mut expected = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--expect" => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow!("--expect needs a base64 SHA-256"))?;
                let raw = base64::engine::general_purpose::STANDARD
                    .decode(&value)
                    .context("decode base64 hash")?;
                expected = Some(
                    <[u8; 32]>::try_from(raw.as_slice())
                        .map_err(|_| anyhow!("certificate hash must be 32 bytes"))?,
                );
            }
            other => bail!("unexpected argument: {other}"),
        }
    }
    Ok((
        host,
        port,
        expected.ok_or_else(|| anyhow!("--expect is required"))?,
    ))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
