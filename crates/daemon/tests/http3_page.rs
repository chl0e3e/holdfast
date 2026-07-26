//! ADR 0014: the QUIC endpoint serves the browser client over plain HTTP/3
//! GET, and the TCP side becomes a QUIC-first bootstrap (Alt-Svc plus a
//! "QUIC required" interstitial) when an operator certificate is configured.
//!
//! Reproduce with: `cargo test -p hf-daemon --test http3_page`

use std::path::PathBuf;
use std::sync::Arc;

use hf_daemon::{AuthConfig, Daemon, DaemonConfig};
use http::StatusCode;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct WebRoot {
    dir: PathBuf,
}

impl Drop for WebRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn web_root() -> WebRoot {
    let dir = std::env::temp_dir().join(format!(
        "holdfast-http3-page-{}-{}",
        std::process::id(),
        rand_suffix()
    ));
    std::fs::create_dir_all(dir.join("assets")).unwrap();
    std::fs::write(
        dir.join("index.html"),
        "<!doctype html><title>Holdfast app</title>",
    )
    .unwrap();
    std::fs::write(dir.join("assets/app.js"), "console.log('holdfast');").unwrap();
    WebRoot { dir }
}

fn rand_suffix() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish()
}

/// Accepts exactly the certificate whose SHA-256 matches — the client-side
/// twin of the daemon's development hash-pinning.
#[derive(Debug)]
struct PinnedCert {
    expected: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let hash: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if hash == self.expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("certificate hash mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

async fn h3_get(daemon: &Daemon, path: &str) -> (StatusCode, Option<String>, Vec<u8>) {
    use base64::Engine;
    let expected: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(daemon.webtransport_cert_hash_base64.as_ref().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCert { expected, provider }))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let client_config = quinn::ClientConfig::new(Arc::new(quic_tls));
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config);

    let connection = endpoint
        .connect(daemon.webtransport_addr.unwrap(), "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(connection))
        .await
        .unwrap();
    let drive = tokio::spawn(async move { driver.wait_idle().await });

    let request = http::Request::get(format!("https://localhost{path}"))
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(request).await.unwrap();
    stream.finish().await.unwrap();
    let response = stream.recv_response().await.unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_string());
    let mut body = Vec::new();
    while let Some(chunk) = stream.recv_data().await.unwrap() {
        use bytes::Buf;
        body.extend_from_slice(chunk.chunk());
    }
    drop(send_request);
    drive.abort();
    (status, content_type, body)
}

#[tokio::test]
async fn quic_endpoint_serves_the_client_page_over_http3() {
    let root = web_root();
    let daemon = Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        web_root: Some(root.dir.clone()),
        auth: AuthConfig::DevInsecure,
        ..DaemonConfig::default()
    })
    .await
    .unwrap();

    let (status, content_type, body) = h3_get(&daemon, "/").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type.as_deref(), Some("text/html; charset=utf-8"));
    assert_eq!(body, b"<!doctype html><title>Holdfast app</title>");

    let (status, content_type, body) = h3_get(&daemon, "/assets/app.js").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type.as_deref(), Some("text/javascript"));
    assert_eq!(body, b"console.log('holdfast');");

    let (status, _, _) = h3_get(&daemon, "/no-such-file.js").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The info endpoint answers over HTTP/3 too, so a page served over QUIC
    // never needs the TCP side again.
    let (status, content_type, body) = h3_get(&daemon, "/webtransport-info").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type.as_deref(), Some("application/json"));
    assert!(String::from_utf8(body).unwrap().contains("certHashBase64"));

    daemon.abort();
}

/// Minimal HTTP/1.1 GET against the daemon's TCP listener.
async fn tcp_get(addr: std::net::SocketAddr, path: &str) -> (u16, String, String) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status: u16 = head
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (status, head.to_lowercase(), body.to_string())
}

#[tokio::test]
async fn production_tcp_bootstrap_advertises_alt_svc_and_requires_quic() {
    let root = web_root();

    // Operator-configured PEM identity → WebPki mode → QUIC-first bootstrap.
    let dir = std::env::temp_dir().join(format!(
        "holdfast-http3-tls-{}-{}",
        std::process::id(),
        rand_suffix()
    ));
    std::fs::create_dir(&dir).unwrap();
    let certificate = dir.join("fullchain.pem");
    let private_key = dir.join("privkey.pem");
    let identity = wtransport::Identity::self_signed(["localhost", "127.0.0.1"]).unwrap();
    identity
        .certificate_chain()
        .store_pemfile(&certificate)
        .await
        .unwrap();
    identity
        .private_key()
        .store_secret_pemfile(&private_key)
        .await
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&private_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let daemon = Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        web_root: Some(root.dir.clone()),
        webtransport_certificate: Some(certificate),
        webtransport_private_key: Some(private_key),
        auth: AuthConfig::DevInsecure,
        ..DaemonConfig::default()
    })
    .await
    .unwrap();
    let wt_port = daemon.webtransport_addr.unwrap().port();

    // `/` over TCP: the interstitial, telling the visitor QUIC is loading /
    // required, with the Alt-Svc upgrade advertised.
    let (status, head, body) = tcp_get(daemon.local_addr, "/").await;
    assert_eq!(status, 200);
    assert!(head.contains(&format!("alt-svc: h3=\":{wt_port}\"; ma=86400")));
    assert!(body.contains("QUIC"));
    assert!(!body.contains("Holdfast app"));

    // No TCP fallback: every TCP path gets the interstitial, never the app.
    let (status, head, body) = tcp_get(daemon.local_addr, "/index.html").await;
    assert_eq!(status, 200);
    assert!(head.contains("alt-svc"));
    assert!(body.contains("QUIC"));
    assert!(!body.contains("Holdfast app"));

    // The app is served over HTTP/3 on the QUIC endpoint. (The test client
    // pins the certificate hash; browsers use WebPKI in this mode.)
    let (status, _, h3_body) = h3_get(&daemon, "/index.html").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h3_body, b"<!doctype html><title>Holdfast app</title>");

    let _ = std::fs::remove_dir_all(&dir);
    daemon.abort();
}

#[tokio::test]
async fn development_tcp_serving_is_unchanged() {
    let root = web_root();
    let daemon = Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        web_root: Some(root.dir.clone()),
        auth: AuthConfig::DevInsecure,
        ..DaemonConfig::default()
    })
    .await
    .unwrap();

    // Dev (hash-pin) mode: browsers never Alt-Svc-upgrade a plain-HTTP
    // origin, so the app is served over TCP directly and no upgrade is
    // advertised.
    let (status, head, body) = tcp_get(daemon.local_addr, "/").await;
    assert_eq!(status, 200);
    assert!(!head.contains("alt-svc"));
    assert!(body.contains("Holdfast app"));

    daemon.abort();
}
