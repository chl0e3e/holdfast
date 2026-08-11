//! HTTP/3 endpoint (ADR 0014): one QUIC endpoint serves both the browser
//! client page (plain HTTP/3 GET, bounded static files) and WebTransport
//! terminal sessions. Per connection the first request decides the mode:
//! an extended CONNECT (`:protocol = webtransport`) upgrades the connection
//! to a session whose bidirectional streams are protocol channels (spec §2:
//! first client-opened stream is the control channel 0; each further stream
//! is an attachment channel); anything else is served as a static-file
//! request. Browsers give every WebTransport session its own QUIC
//! connection, so page traffic and terminal traffic never contend.
//!
//! Frames are the plain §3 length-prefixed encoding — no varint prefix
//! (streams delimit channels).
//!
//! Development uses a fresh self-signed identity per daemon start (≤14 days,
//! the `serverCertificateHashes` ceiling). Production loads an explicitly
//! bounded PEM chain/key and relies on browser WebPKI (ADR 0005).

use std::collections::HashMap;
use std::io::Read;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use h3::ext::Protocol;
use h3::quic::BidiStream as _;
use h3_webtransport::server::AcceptedBi;
use hf_protocol::framing::FrameDecoder;
use hf_protocol::pb::Envelope;
use http::{Method, Response, StatusCode};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroize;

use crate::conn::{Conn, OUTGOING_QUEUE};
use crate::{AppState, WebTransportCertificateMode};

/// Explicit ceiling on concurrent bidirectional streams per connection.
/// On a WebTransport connection these are protocol channels; on a page-load
/// connection they are in-flight HTTP/3 requests. Each accepted stream spawns
/// a task holding a buffer, and quinn's own docs note worst-case memory is
/// proportional to this value — so we set it deliberately rather than
/// inheriting the library default (the project rule: every buffer is bounded
/// by a value we chose). A legitimate client needs one control stream plus a
/// handful of attachment streams — or a page load's worth of asset fetches —
/// well under this.
const MAX_CONCURRENT_BIDI_STREAMS: u32 = 64;
/// HTTP/3 itself needs unidirectional streams (control + QPACK, both
/// directions). The protocol never uses them for terminal data; a small
/// explicit bound replaces the library default. Never set this to zero —
/// HTTP/3 cannot function without its unidirectional streams.
const MAX_CONCURRENT_UNI_STREAMS: u32 = 32;
/// How long a connection may go completely silent before QUIC tears it down.
/// quinn's default is 30s, which is shorter than the gaps a terminal session
/// legitimately has (an idle shell emits nothing for hours), so an untouched
/// browser tab lost its session and came back to a blank screen.
const MAX_IDLE_TIMEOUT_MS: u32 = 60_000;
/// Server-driven QUIC PING interval. This is what actually keeps an idle
/// session alive: the daemon has never implemented spec §14's application-level
/// ping ticker, and of the clients only the desktop core sends pings (ADR
/// 0020) — the browser client answers them but never sends. Keeping this at
/// the transport layer fixes every client at once.
///
/// 10s, for exactly the reason [`hf_protocol::AGENT_KEEP_ALIVE_INTERVAL_MS`]
/// is: the effective idle limit is the *lower* of the two peers', so raising
/// [`MAX_IDLE_TIMEOUT_MS`] on our side buys nothing against a peer still
/// enforcing quinn's un-raised 30s — and a browser is precisely such a peer,
/// since its idle limit is the engine's, not ours. The interval must fit
/// inside that 30s, and fit *twice over*, or one dropped ping ends the
/// connection at exactly the deadline. This was 15s, which fails that test by
/// landing precisely on it (2 × 15s = 30s), leaving no margin for a retry.
const KEEP_ALIVE_INTERVAL_MS: u64 = 10_000;
const MAX_CERTIFICATE_CHAIN_BYTES: u64 = 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES: u64 = 64 * 1024;
const MAX_CERTIFICATES: usize = 8;
/// Largest static asset the h3 side will serve (the built client is ~1 MiB).
const MAX_STATIC_FILE_BYTES: u64 = 16 * 1024 * 1024;
/// Longest accepted request path for static serving.
const MAX_REQUEST_PATH_BYTES: usize = 1024;

type H3Conn = h3::server::Connection<h3_quinn::Connection, Bytes>;
type H3RequestStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type WtSession = h3_webtransport::server::WebTransportSession<h3_quinn::Connection, Bytes>;
type WtSendStream = h3_webtransport::stream::SendStream<h3_quinn::SendStream<Bytes>, Bytes>;

pub struct WtListener {
    pub local_addr: SocketAddr,
    /// SHA-256 of the certificate, base64 (for serverCertificateHashes).
    pub cert_hash_base64: String,
    /// Raw SHA-256 of the certificate — the channel-binding value for SSH auth
    /// over this transport (ADR 0008).
    pub cert_hash: [u8; 32],
    pub certificate_mode: WebTransportCertificateMode,
    endpoint: quinn::Endpoint,
    web_root: Option<PathBuf>,
}

impl WtListener {
    pub fn bind(
        bind: SocketAddr,
        certificate_path: Option<&Path>,
        private_key_path: Option<&Path>,
        web_root: Option<PathBuf>,
    ) -> anyhow::Result<WtListener> {
        let (tls, hash, certificate_mode) = match (certificate_path, private_key_path) {
            (None, None) => {
                let (tls, hash) = self_signed_tls()?;
                (tls, hash, WebTransportCertificateMode::DevelopmentHashPin)
            }
            (Some(certificate), Some(private_key)) => {
                let (tls, hash) = load_configured_tls(certificate, private_key)?;
                (tls, hash, WebTransportCertificateMode::WebPki)
            }
            _ => anyhow::bail!("WebTransport TLS requires both certificate and private key"),
        };

        let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(MAX_CONCURRENT_BIDI_STREAMS.into());
        transport.max_concurrent_uni_streams(MAX_CONCURRENT_UNI_STREAMS.into());
        transport.max_idle_timeout(Some(quinn::VarInt::from_u32(MAX_IDLE_TIMEOUT_MS).into()));
        transport.keep_alive_interval(Some(std::time::Duration::from_millis(
            KEEP_ALIVE_INTERVAL_MS,
        )));
        server_config.transport_config(Arc::new(transport));
        let endpoint = quinn::Endpoint::server(server_config, bind)?;
        let local_addr = endpoint.local_addr()?;
        Ok(WtListener {
            local_addr,
            cert_hash_base64: base64_encode(&hash),
            cert_hash: hash,
            certificate_mode,
            endpoint,
            web_root,
        })
    }

    pub fn spawn_accept_loop(&self, state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
        let endpoint = self.endpoint.clone();
        let web_root = self.web_root.clone();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let state = Arc::clone(&state);
                let web_root = web_root.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(incoming, state, web_root).await {
                        tracing::debug!("http3 connection ended: {e:#}");
                    }
                });
            }
        })
    }
}

fn tls_server_config(
    certificates: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> anyhow::Result<rustls::ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    Ok(tls)
}

/// Fresh self-signed development identity, valid under the 14-day
/// `serverCertificateHashes` ceiling.
fn self_signed_tls() -> anyhow::Result<(rustls::ServerConfig, [u8; 32])> {
    let mut params = rcgen::CertificateParams::new(vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ])?;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(13);
    let key = rcgen::KeyPair::generate()?;
    let certificate = params.self_signed(&key)?;
    let certificate_der = CertificateDer::from(certificate.der().to_vec());
    let hash: [u8; 32] = Sha256::digest(certificate_der.as_ref()).into();
    let private_key = PrivateKeyDer::Pkcs8(key.serialize_der().into());
    Ok((tls_server_config(vec![certificate_der], private_key)?, hash))
}

fn load_configured_tls(
    certificate_path: &Path,
    private_key_path: &Path,
) -> anyhow::Result<(rustls::ServerConfig, [u8; 32])> {
    let certificate_pem = read_bounded_file(
        certificate_path,
        MAX_CERTIFICATE_CHAIN_BYTES,
        "WebTransport certificate chain",
        false,
    )?;
    let certificates: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(&certificate_pem).collect::<Result<_, _>>()?;
    if certificates.is_empty() {
        anyhow::bail!("WebTransport certificate chain contains no certificates");
    }
    if certificates.len() > MAX_CERTIFICATES {
        anyhow::bail!("WebTransport certificate chain exceeds {MAX_CERTIFICATES} certificates");
    }
    let hash: [u8; 32] = Sha256::digest(certificates[0].as_ref()).into();

    let mut private_key_pem = read_bounded_file(
        private_key_path,
        MAX_PRIVATE_KEY_BYTES,
        "WebTransport private key",
        true,
    )?;
    let private_key = PrivateKeyDer::from_pem_slice(&private_key_pem)
        .map_err(|error| anyhow::anyhow!("parse WebTransport private key: {error}"))?;
    private_key_pem.zeroize();

    Ok((tls_server_config(certificates, private_key)?, hash))
}

fn read_bounded_file(
    path: &Path,
    maximum: u64,
    kind: &str,
    private: bool,
) -> anyhow::Result<Vec<u8>> {
    let file = std::fs::File::open(path)
        .map_err(|error| anyhow::anyhow!("open {kind} {}: {error}", path.display()))?;
    let metadata = file.metadata()?;
    if metadata.len() > maximum {
        anyhow::bail!("{kind} exceeds {maximum} bytes");
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            anyhow::bail!("{kind} {} must be mode 0600 or stricter", path.display());
        }
    }
    let mut bytes = Vec::with_capacity(metadata.len().min(maximum) as usize);
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        bytes.zeroize();
        anyhow::bail!("{kind} exceeds {maximum} bytes");
    }
    Ok(bytes)
}

async fn handle_connection(
    incoming: quinn::Incoming,
    state: Arc<AppState>,
    web_root: Option<PathBuf>,
) -> anyhow::Result<()> {
    let quic = incoming.await?;
    // Cheap handle kept for closing the connection from stream tasks; the
    // connection itself moves into the h3 layer.
    let quic_handle = quic.clone();
    let mut h3_conn: H3Conn = h3::server::builder()
        .enable_webtransport(true)
        .enable_extended_connect(true)
        .enable_datagram(true)
        .max_webtransport_sessions(1)
        .send_grease(true)
        .build(h3_quinn::Connection::new(quic))
        .await
        .map_err(|e| anyhow::anyhow!("h3 handshake: {e}"))?;

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let (request, stream) = match resolver.resolve_request().await {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::debug!("h3 request resolution failed: {e}");
                        continue;
                    }
                };
                if request.method() == Method::CONNECT
                    && request.extensions().get::<Protocol>() == Some(&Protocol::WEB_TRANSPORT)
                {
                    // Origin allowlist (threat model T7), enforced on the
                    // browser's session request; native clients send none.
                    let origin = request
                        .headers()
                        .get(http::header::ORIGIN)
                        .and_then(|v| v.to_str().ok());
                    if !state.origin_allowed(origin) {
                        tracing::warn!(
                            ?origin,
                            "rejected WebTransport session: origin not allowed"
                        );
                        let mut stream = stream;
                        let response = Response::builder().status(StatusCode::FORBIDDEN).body(())?;
                        let _ = stream.send_response(response).await;
                        let _ = stream.finish().await;
                        continue;
                    }
                    let session = WtSession::accept(request, stream, h3_conn)
                        .await
                        .map_err(|e| anyhow::anyhow!("webtransport accept: {e}"))?;
                    return handle_wt_session(session, quic_handle, state, web_root).await;
                }
                let state = Arc::clone(&state);
                let web_root = web_root.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        serve_h3_request(&state, web_root.as_deref(), request, stream).await
                    {
                        tracing::debug!("h3 request failed: {e:#}");
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                tracing::debug!("h3 connection ended: {e}");
                break;
            }
        }
    }
    Ok(())
}

/// Static serving over HTTP/3 (plus `/webtransport-info` for parity with the
/// TCP bootstrap). GET/HEAD only; paths are matched literally against the web
/// root (no percent-decoding — built asset names are plain), every read is
/// bounded, and any traversal-shaped path is rejected before touching the
/// filesystem.
async fn serve_h3_request(
    state: &AppState,
    web_root: Option<&Path>,
    request: http::Request<()>,
    mut stream: H3RequestStream,
) -> anyhow::Result<()> {
    let method = request.method().clone();
    if method != Method::GET && method != Method::HEAD {
        return send_simple(
            &mut stream,
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"method not allowed"),
            &method,
        )
        .await;
    }
    let path = request.uri().path();

    if path == "/webtransport-info" {
        let body = match &state.webtransport_info {
            Some((port, hash, mode)) => format!(
                r#"{{"port":{port},"certHashBase64":"{hash}","certificateMode":"{}","passwordAuth":{}}}"#,
                mode.as_wire_name(),
                state.auth.password.is_some()
            ),
            None => String::new(),
        };
        if body.is_empty() {
            return send_simple(
                &mut stream,
                StatusCode::NOT_FOUND,
                "text/plain; charset=utf-8",
                Bytes::from_static(b"webtransport disabled"),
                &method,
            )
            .await;
        }
        return send_simple(
            &mut stream,
            StatusCode::OK,
            "application/json",
            Bytes::from(body),
            &method,
        )
        .await;
    }

    let Some(root) = web_root else {
        return send_simple(
            &mut stream,
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"not found"),
            &method,
        )
        .await;
    };
    let Some(file_path) = resolve_static_path(root, path) else {
        return send_simple(
            &mut stream,
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"not found"),
            &method,
        )
        .await;
    };
    let Ok(metadata) = tokio::fs::metadata(&file_path).await else {
        return send_simple(
            &mut stream,
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"not found"),
            &method,
        )
        .await;
    };
    if !metadata.is_file() || metadata.len() > MAX_STATIC_FILE_BYTES {
        return send_simple(
            &mut stream,
            StatusCode::NOT_FOUND,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"not found"),
            &method,
        )
        .await;
    }
    let bytes = tokio::fs::read(&file_path).await?;
    send_simple(
        &mut stream,
        StatusCode::OK,
        content_type_for(&file_path),
        Bytes::from(bytes),
        &method,
    )
    .await
}

async fn send_simple(
    stream: &mut H3RequestStream,
    status: StatusCode,
    content_type: &str,
    body: Bytes,
    method: &Method,
) -> anyhow::Result<()> {
    let response = Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, content_type)
        .header(http::header::CONTENT_LENGTH, body.len())
        .header(http::header::CACHE_CONTROL, "no-cache")
        .body(())?;
    stream
        .send_response(response)
        .await
        .map_err(|e| anyhow::anyhow!("send response: {e}"))?;
    if method == Method::GET && !body.is_empty() {
        stream
            .send_data(body)
            .await
            .map_err(|e| anyhow::anyhow!("send body: {e}"))?;
    }
    stream
        .finish()
        .await
        .map_err(|e| anyhow::anyhow!("finish stream: {e}"))?;
    Ok(())
}

/// Map a request path to a file strictly inside the web root, or `None`.
fn resolve_static_path(root: &Path, path: &str) -> Option<PathBuf> {
    if path.len() > MAX_REQUEST_PATH_BYTES || path.contains('%') || path.contains('\\') {
        return None;
    }
    let relative = path.strip_prefix('/')?;
    let relative = if relative.is_empty() {
        "index.html"
    } else {
        relative
    };
    let candidate = Path::new(relative);
    if !candidate
        .components()
        .all(|c| matches!(c, Component::Normal(_)))
    {
        return None;
    }
    Some(root.join(candidate))
}

fn content_type_for(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript",
        Some("css") => "text/css",
        Some("json") | Some("map") => "application/json",
        Some("wasm") => "application/wasm",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

enum WriterMsg {
    Register(u64, WtSendStream),
    Frame(u64, Envelope),
}

async fn handle_wt_session(
    session: WtSession,
    quic: quinn::Connection,
    state: Arc<AppState>,
    web_root: Option<PathBuf>,
) -> anyhow::Result<()> {
    // Writer: owns all send-halves, serializes frames per channel.
    let (writer_tx, mut writer_rx) = tokio::sync::mpsc::channel::<WriterMsg>(OUTGOING_QUEUE);
    let writer = tokio::spawn(async move {
        let mut streams: HashMap<u64, WtSendStream> = HashMap::new();
        while let Some(msg) = writer_rx.recv().await {
            match msg {
                WriterMsg::Register(channel, stream) => {
                    streams.insert(channel, stream);
                }
                WriterMsg::Frame(channel, envelope) => {
                    let Some(stream) = streams.get_mut(&channel) else {
                        continue;
                    };
                    match hf_protocol::framing::encode_frame(
                        &envelope,
                        hf_protocol::FRAME_BYTES_DEFAULT,
                    ) {
                        Ok(bytes) => {
                            if stream.write_all(&bytes).await.is_err() {
                                streams.remove(&channel);
                            }
                        }
                        Err(e) => tracing::warn!("dropping unencodable frame: {e}"),
                    }
                }
            }
        }
    });

    // Adapter: Conn's transport-neutral (channel, envelope) → WriterMsg.
    // Registration always precedes the channel's first outgoing frame because
    // Register is enqueued before the reader dispatches anything.
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<(u64, Envelope)>(OUTGOING_QUEUE);
    let adapter_writer_tx = writer_tx.clone();
    tokio::spawn(async move {
        while let Some((channel, envelope)) = out_rx.recv().await {
            if adapter_writer_tx
                .send(WriterMsg::Frame(channel, envelope))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    let peer_ip = quic.remote_address().ip();
    // SSH-auth channel binding for this transport: our certificate hash, which
    // the client independently pinned (ADR 0008).
    let channel_binding = state
        .webtransport_cert_hash
        .map(|h| h.to_vec())
        .unwrap_or_default();
    let conn = Arc::new(tokio::sync::Mutex::new(Conn::new(
        Arc::clone(&state),
        peer_ip,
        out_tx,
        true,
        channel_binding,
    )));
    let mut next_channel: u64 = 0;

    loop {
        match session.accept_bi().await {
            Ok(Some(AcceptedBi::BidiStream(_session_id, stream))) => {
                let (send, mut recv) = stream.split();
                let channel = next_channel;
                next_channel += 1;
                if writer_tx
                    .send(WriterMsg::Register(channel, send))
                    .await
                    .is_err()
                {
                    break;
                }

                let conn = Arc::clone(&conn);
                let quic = quic.clone();
                tokio::spawn(async move {
                    let mut decoder = FrameDecoder::new(hf_protocol::FRAME_BYTES_DEFAULT);
                    let mut buf = vec![0u8; 16 * 1024];
                    'read: loop {
                        let n = match recv.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        if decoder.extend(&buf[..n]).is_err() {
                            quic.close(0u32.into(), b"frame too large");
                            break;
                        }
                        loop {
                            match decoder.next_frame() {
                                Ok(Some(envelope)) => {
                                    if !conn.lock().await.dispatch(channel, envelope).await {
                                        quic.close(0u32.into(), b"closed");
                                        break 'read;
                                    }
                                }
                                Ok(None) => break,
                                Err(e) => {
                                    tracing::warn!("protocol error on stream: {e}");
                                    quic.close(0u32.into(), b"protocol error");
                                    break 'read;
                                }
                            }
                        }
                    }
                    // Stream finished: control stream ends the session; an
                    // attachment stream just detaches (spec §11).
                    if channel == 0 {
                        quic.close(0u32.into(), b"control stream closed");
                    } else {
                        conn.lock().await.channel_closed(channel);
                    }
                });
            }
            // A further HTTP/3 request multiplexed onto this session's
            // connection (allowed by the spec, unusual from browsers): serve
            // it like any page request.
            Ok(Some(AcceptedBi::Request(request, stream))) => {
                let state = Arc::clone(&state);
                let web_root = web_root.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        serve_h3_request(&state, web_root.as_deref(), request, stream).await
                    {
                        tracing::debug!("h3 request on session connection failed: {e:#}");
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                tracing::debug!("webtransport session ended: {e}");
                break;
            }
        }
    }

    conn.lock().await.detach_all();
    writer.abort();
    Ok(())
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    #[test]
    fn base64_matches_reference() {
        assert_eq!(super::base64_encode(b""), "");
        assert_eq!(super::base64_encode(b"f"), "Zg==");
        assert_eq!(super::base64_encode(b"fo"), "Zm8=");
        assert_eq!(super::base64_encode(b"foo"), "Zm9v");
        assert_eq!(super::base64_encode(&[0xfb, 0xff, 0x00]), "+/8A");
    }

    /// The web link's counterpart to `hf_protocol`'s `agent_liveness_tests`.
    /// Both links obey one rule; this pins it on the side quinn cannot check
    /// for us, because the other peer is a browser we do not build.
    #[test]
    fn keepalive_survives_a_dropped_ping_against_an_un_raised_peer() {
        /// quinn's own default — what a browser, or any peer built before the
        /// idle-timeout change, is still enforcing.
        const QUINN_DEFAULT_IDLE_TIMEOUT_MS: u64 = 30_000;

        let keepalive = super::KEEP_ALIVE_INTERVAL_MS;

        // The negotiated idle limit is the LOWER of the two peers', so our own
        // raised MAX_IDLE_TIMEOUT_MS does not protect this link on its own.
        assert!(
            keepalive < QUINN_DEFAULT_IDLE_TIMEOUT_MS,
            "keepalive {keepalive}ms must fit inside an un-raised peer's \
             {QUINN_DEFAULT_IDLE_TIMEOUT_MS}ms idle limit",
        );

        // Twice over, or a single dropped ping ends the connection exactly at
        // the deadline. This is the assertion 15s failed.
        assert!(
            keepalive * 2 < QUINN_DEFAULT_IDLE_TIMEOUT_MS,
            "keepalive {keepalive}ms must leave room to retry a dropped ping \
             inside an un-raised peer's {QUINN_DEFAULT_IDLE_TIMEOUT_MS}ms limit",
        );
        assert!(
            keepalive * 2 < u64::from(super::MAX_IDLE_TIMEOUT_MS),
            "keepalive {keepalive}ms must leave the same retry room against \
             our own {}ms limit",
            super::MAX_IDLE_TIMEOUT_MS,
        );
    }

    #[test]
    fn static_paths_stay_inside_the_root() {
        let root = Path::new("/srv/web");
        let ok = |p: &str| super::resolve_static_path(root, p);
        assert_eq!(ok("/"), Some(root.join("index.html")));
        assert_eq!(ok("/assets/app.js"), Some(root.join("assets/app.js")));
        assert_eq!(ok("/../etc/passwd"), None);
        assert_eq!(ok("/a/../../etc/passwd"), None);
        assert_eq!(ok("/%2e%2e/etc/passwd"), None);
        assert_eq!(ok("/a\\..\\b"), None);
        assert_eq!(ok(&format!("/{}", "x".repeat(2000))), None);
        assert_eq!(ok("//etc/passwd"), None);
    }
}
