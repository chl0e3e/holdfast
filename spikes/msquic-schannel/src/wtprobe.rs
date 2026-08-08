//! Stage 2 of the MsQuic/Schannel port spike: does the channel binding survive
//! the HTTP/3 layer, and will the daemon accept a WebTransport session from a
//! non-wtransport client?
//!
//! Stage 1 (`certprobe`) proved Schannel hands back the peer leaf DER through
//! the raw msquic connection callback. But the real client cannot use that
//! callback: `msquic-h3` owns the connection and its callback has no
//! `PeerCertificateReceived` arm. So this probe takes the other route —
//! `GetParam(PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_W)` with
//! `SECPKG_ATTR_REMOTE_CERT_CONTEXT`, which asks Schannel for the remote
//! certificate context on an already-established connection. That needs a
//! handle to the msquic connection, which upstream `msquic-h3` does not expose;
//! see the three-line patch in `vendor/msquic-h3`.
//!
//! Two assertions, in order:
//!
//! 1. the leaf Schannel reports equals the hash holdfast pins (ADR 0008), and
//! 2. an extended CONNECT with `:protocol: webtransport` is accepted by the
//!    live daemon, which is the WebTransport session handshake itself.
//!
//! ```powershell
//! wtprobe.exe https://host:4444 --expect <base64-sha256>
//! ```

use std::ffi::c_void;
use std::ptr;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use bytes::Bytes;
use msquic::{BufferRef, CredentialConfig, CredentialFlags, RegistrationConfig, Settings};
use msquic_h3::{Connection, Registration};
use sha2::{Digest, Sha256};

/// The daemon's HTTP/3 endpoint negotiates `h3` and nothing else.
const ALPN: &str = "h3";

/// `SECPKG_ATTR_REMOTE_CERT_CONTEXT` from sspi.h. Asks Schannel for the peer's
/// certificate context on an established security context.
const SECPKG_ATTR_REMOTE_CERT_CONTEXT: u32 = 0x53;

/// wincrypt.h `CERT_CONTEXT`. Only the first three fields are read; the rest
/// are present so the layout matches.
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
    println!("expecting   {}", hex(&expected));

    let registration = Registration::new(&RegistrationConfig::default())
        .map_err(|s| anyhow!("open registration failed: {s:?}"))?;
    let alpn = [BufferRef::from(ALPN)];
    // The server opens its own control and QPACK streams, so the peer stream
    // allowances have to be non-zero or the h3 handshake stalls.
    // WebTransport over HTTP/3 requires H3_DATAGRAM, so the QUIC layer has to
    // actually support datagrams before we advertise it.
    let settings = Settings::new()
        .set_IdleTimeoutMs(15_000)
        .set_PeerBidiStreamCount(16)
        .set_PeerUnidiStreamCount(16)
        .set_DatagramReceiveEnabled();
    let configuration = registration
        .open_configuration(&alpn, Some(&settings))
        .map_err(|s| anyhow!("open configuration failed: {s:?}"))?;

    // Validation off, as in certprobe: the pin is the hash check we do
    // ourselves. Note we deliberately do NOT set INDICATE_CERTIFICATE_RECEIVED
    // here - msquic-h3 owns the callback and would swallow the event, so the
    // certificate comes from GetParam instead.
    let credential =
        CredentialConfig::new_client().set_credential_flags(CredentialFlags::NO_CERTIFICATE_VALIDATION);
    configuration
        .load_credential(&credential)
        .map_err(|s| anyhow!("load client credential failed: {s:?}"))?;

    let connection = Connection::connect(&registration, &configuration, &host, port)
        .await
        .map_err(|s| anyhow!("quic connect failed: {s:?}"))?;
    println!("connected   QUIC handshake complete (Schannel)");

    // --- assertion 1: the ADR 0008 channel binding -------------------------
    let der = schannel_peer_leaf(&connection).context("read peer certificate via GetParam")?;
    let observed: [u8; 32] = Sha256::digest(&der).into();
    println!("leaf DER    {} bytes", der.len());
    println!("observed    {}", hex(&observed));
    if observed != expected {
        bail!(
            "FAIL - the certificate Schannel reported via GetParam is not the leaf holdfast \
             pins, so the signed challenge would differ"
        );
    }
    println!("            channel binding matches");

    // --- assertion 2: the WebTransport session handshake -------------------
    // enable_webtransport comes from the vendored h3 patch: upstream has it on
    // the server builder only, and h3-webtransport's server rejects a client
    // that does not advertise it (H3_SETTINGS_ERROR, "webtransport is not
    // supported by client"). Round 33 failed exactly there.
    let mut builder = h3::client::builder();
    builder.enable_extended_connect(true);
    builder.enable_webtransport(true);
    builder.enable_datagram(true);
    let (mut driver, mut send_request) = builder
        .build::<_, _, Bytes>(connection)
        .await
        .map_err(|e| anyhow!("h3 handshake failed: {e}"))?;
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });
    println!("h3          SETTINGS exchanged, extended CONNECT enabled");

    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .uri(format!("https://{host}:{port}/"))
        .extension(h3::ext::Protocol::WEB_TRANSPORT)
        .body(())
        .context("build extended CONNECT")?;

    // Deliberately not finished: for WebTransport the CONNECT stream *is* the
    // session stream and must stay open.
    let mut stream = send_request
        .send_request(request)
        .await
        .map_err(|e| anyhow!("send extended CONNECT failed: {e}"))?;
    let response = stream
        .recv_response()
        .await
        .map_err(|e| anyhow!("no response to extended CONNECT: {e}"))?;
    println!("CONNECT     status {}", response.status());

    if !response.status().is_success() {
        bail!(
            "FAIL - the daemon refused the WebTransport session (status {})",
            response.status()
        );
    }

    println!("\nPASS - channel binding preserved and the daemon accepted a WebTransport");
    println!("session from a msquic/Schannel client. Stage 2 mechanism is sound.");
    Ok(())
}

/// Ask Schannel for the peer's leaf certificate on an established connection.
///
/// MsQuic forwards this to `QueryContextAttributesW` on the security context it
/// owns, writing the resulting `PCCERT_CONTEXT` into the `Buffer` field.
fn schannel_peer_leaf(connection: &Connection) -> Result<Vec<u8>> {
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

    // SAFETY: the handle is live for the duration of the call (we hold
    // `connection`), and the buffer matches QUIC_SCHANNEL_CONTEXT_ATTRIBUTE_W.
    unsafe {
        let handle = connection.msquic_connection().as_raw();
        msquic::Api::get_param(
            handle,
            msquic::PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_W,
            &len,
            &mut attribute as *mut _ as *mut c_void,
        )
        .map_err(|s| anyhow!("GetParam(SCHANNEL_CONTEXT_ATTRIBUTE_W) failed: {s:?}"))?;
    }

    if cert.is_null() {
        bail!("Schannel returned a null certificate context");
    }
    // SAFETY: non-null CERT_CONTEXT from Schannel. The context is intentionally
    // leaked - this is a probe, and CertFreeCertificateContext would pull in
    // crypt32 for no benefit.
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
        .ok_or_else(|| anyhow!("usage: wtprobe <https://host[:port]> --expect <base64-sha256>"))?;
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

    let expected = expected.ok_or_else(|| anyhow!("--expect is required; nothing to verify against"))?;
    Ok((host, port, expected))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
