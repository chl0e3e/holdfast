//! Origin allowlist on the browser endpoints (threat model T7): enforced on
//! the WebTransport CONNECT request (the product transport, ADR 0014) and on
//! the config-gated test-only WebSocket endpoint.
//! Reproduce with: `cargo test -p hf-daemon --test origin`

use hf_daemon::{Daemon, DaemonConfig};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::ORIGIN;

async fn daemon_with_allowlist(origins: Vec<String>) -> Daemon {
    Daemon::start(DaemonConfig {
        enable_websocket: true,
        bind: "127.0.0.1:0".parse().unwrap(),
        webtransport_bind: None,
        allowed_origins: Some(origins),
        ..Default::default()
    })
    .await
    .unwrap()
}

fn ws_request(
    addr: std::net::SocketAddr,
    origin: Option<&str>,
) -> tokio_tungstenite::tungstenite::handshake::client::Request {
    let mut req = format!("ws://{addr}/terminal/ws")
        .into_client_request()
        .unwrap();
    if let Some(o) = origin {
        req.headers_mut().insert(ORIGIN, o.parse().unwrap());
    }
    req
}

#[tokio::test]
async fn allowed_origin_connects() {
    let daemon = daemon_with_allowlist(vec!["https://terminal.example".into()]).await;
    let result = tokio_tungstenite::connect_async(ws_request(
        daemon.local_addr,
        Some("https://terminal.example"),
    ))
    .await;
    assert!(result.is_ok(), "allowed origin must connect");
    daemon.abort();
}

#[tokio::test]
async fn disallowed_origin_is_rejected() {
    let daemon = daemon_with_allowlist(vec!["https://terminal.example".into()]).await;
    let result = tokio_tungstenite::connect_async(ws_request(
        daemon.local_addr,
        Some("https://evil.example"),
    ))
    .await;
    assert!(
        result.is_err(),
        "cross-origin request must be rejected (403)"
    );
    daemon.abort();
}

#[tokio::test]
async fn missing_origin_is_allowed_for_native_clients() {
    let daemon = daemon_with_allowlist(vec!["https://terminal.example".into()]).await;
    let result = tokio_tungstenite::connect_async(ws_request(daemon.local_addr, None)).await;
    assert!(
        result.is_ok(),
        "no Origin header (native client) must be allowed"
    );
    daemon.abort();
}

// ------------------------------------------------- WebTransport (ADR 0014)

async fn wt_daemon_with_allowlist(origins: Vec<String>) -> Daemon {
    Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        allowed_origins: Some(origins),
        ..Default::default()
    })
    .await
    .unwrap()
}

async fn wt_try_connect(
    daemon: &Daemon,
    origin: Option<&str>,
) -> Result<wtransport::Connection, wtransport::error::ConnectingError> {
    use base64::Engine;
    let hash: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(daemon.webtransport_cert_hash_base64.as_ref().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let endpoint = wtransport::Endpoint::client(
        wtransport::ClientConfig::builder()
            .with_bind_default()
            .with_server_certificate_hashes([wtransport::tls::Sha256Digest::new(hash)])
            .build(),
    )
    .unwrap();
    let url = format!(
        "https://127.0.0.1:{}/",
        daemon.webtransport_addr.unwrap().port()
    );
    let mut options = wtransport::endpoint::ConnectOptions::builder(&url);
    if let Some(origin) = origin {
        options = options.add_header("origin", origin);
    }
    endpoint.connect(options.build()).await
}

#[tokio::test]
async fn webtransport_allowed_origin_connects() {
    let daemon = wt_daemon_with_allowlist(vec!["https://terminal.example".into()]).await;
    let result = wt_try_connect(&daemon, Some("https://terminal.example")).await;
    assert!(result.is_ok(), "allowed origin must establish a session");
    daemon.abort();
}

#[tokio::test]
async fn webtransport_disallowed_origin_is_rejected() {
    let daemon = wt_daemon_with_allowlist(vec!["https://terminal.example".into()]).await;
    let result = wt_try_connect(&daemon, Some("https://evil.example")).await;
    assert!(
        result.is_err(),
        "cross-origin session request must be rejected"
    );
    daemon.abort();
}

#[tokio::test]
async fn webtransport_missing_origin_is_allowed_for_native_clients() {
    let daemon = wt_daemon_with_allowlist(vec!["https://terminal.example".into()]).await;
    let result = wt_try_connect(&daemon, None).await;
    assert!(
        result.is_ok(),
        "no Origin header (native client) must be allowed"
    );
    daemon.abort();
}
