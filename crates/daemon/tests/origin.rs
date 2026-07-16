//! Phase 7: Origin allowlist on the WebSocket endpoint (threat model T7).
//! Reproduce with: `cargo test -p hf-daemon --test origin`

use hf_daemon::{Daemon, DaemonConfig};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::ORIGIN;

async fn daemon_with_allowlist(origins: Vec<String>) -> Daemon {
    Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        webtransport_bind: None,
        allowed_origins: Some(origins),
        ..Default::default()
    })
    .await
    .unwrap()
}

fn ws_request(addr: std::net::SocketAddr, origin: Option<&str>) -> tokio_tungstenite::tungstenite::handshake::client::Request {
    let mut req = format!("ws://{addr}/terminal/ws").into_client_request().unwrap();
    if let Some(o) = origin {
        req.headers_mut().insert(ORIGIN, o.parse().unwrap());
    }
    req
}

#[tokio::test]
async fn allowed_origin_connects() {
    let daemon = daemon_with_allowlist(vec!["https://terminal.example".into()]).await;
    let result =
        tokio_tungstenite::connect_async(ws_request(daemon.local_addr, Some("https://terminal.example"))).await;
    assert!(result.is_ok(), "allowed origin must connect");
    daemon.abort();
}

#[tokio::test]
async fn disallowed_origin_is_rejected() {
    let daemon = daemon_with_allowlist(vec!["https://terminal.example".into()]).await;
    let result =
        tokio_tungstenite::connect_async(ws_request(daemon.local_addr, Some("https://evil.example"))).await;
    assert!(result.is_err(), "cross-origin request must be rejected (403)");
    daemon.abort();
}

#[tokio::test]
async fn missing_origin_is_allowed_for_native_clients() {
    let daemon = daemon_with_allowlist(vec!["https://terminal.example".into()]).await;
    let result = tokio_tungstenite::connect_async(ws_request(daemon.local_addr, None)).await;
    assert!(result.is_ok(), "no Origin header (native client) must be allowed");
    daemon.abort();
}
