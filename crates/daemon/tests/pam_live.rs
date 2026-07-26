//! Real-PAM end-to-end check for ADR 0016, mirroring production: the actual
//! daemon password arm → hf_auth::pam::PamVerifier → /etc/pam.d/holdfast-ssh.
//! #[ignore]d — needs root + a throwaway account; run via a wrapper.
#![cfg(unix)]

use std::collections::BTreeSet;
use futures_util::{SinkExt, StreamExt};
use hf_daemon::{wire, AuthConfig, Daemon, DaemonConfig, PasswordAuthConfig};
use hf_protocol::pb::{self, envelope::Message as Msg, Envelope};
use hf_protocol::{FRAME_BYTES_DEFAULT, PROTOCOL_MAJOR, PROTOCOL_MINOR};
use tokio_tungstenite::tungstenite::Message as WsMessage;

type Ws = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn send(ws: &mut Ws, env: Envelope) {
    let bytes = wire::encode_message(0, &env, FRAME_BYTES_DEFAULT).unwrap();
    ws.send(WsMessage::Binary(bytes.into())).await.unwrap();
}
async fn recv(ws: &mut Ws) -> Envelope {
    loop {
        if let WsMessage::Binary(d) = ws.next().await.unwrap().unwrap() {
            return wire::decode_message(&d, FRAME_BYTES_DEFAULT).unwrap().1;
        }
    }
}
fn plain(m: Msg) -> Envelope {
    Envelope { request_id: 1, server_id: vec![], shell_id: vec![], message: Some(m) }
}

#[tokio::test]
#[ignore = "needs root + throwaway account + /etc/pam.d/holdfast-ssh"]
async fn real_pam_password_login_over_the_protocol() {
    let user = std::env::var("HF_USER").unwrap();
    let password = std::env::var("HF_PASS").unwrap();
    let service = std::env::var("HF_SERVICE").unwrap_or_else(|_| "holdfast-ssh".into());

    let mut users = BTreeSet::new();
    users.insert(user.clone());
    let daemon = Daemon::start(DaemonConfig {
        enable_websocket: true,
        bind: "127.0.0.1:0".parse().unwrap(),
        webtransport_bind: None,
        auth: AuthConfig::SshKeys { users: Default::default() },
        password_auth: Some(PasswordAuthConfig {
            users,
            verifier: std::sync::Arc::new(hf_auth::pam::PamVerifier::new(service).unwrap()),
        }),
        ..Default::default()
    }).await.unwrap();

    let (mut ws, _) = tokio_tungstenite::connect_async(
        format!("ws://{}/terminal/ws", daemon.local_addr)).await.unwrap();
    send(&mut ws, plain(Msg::ClientHello(pb::ClientHello {
        protocol_major: PROTOCOL_MAJOR, protocol_minor: PROTOCOL_MINOR,
        client_kind: pb::ClientKind::BrowserWebsocket as i32, client_build: "pam-live".into(),
        capabilities: vec![], max_frame_bytes: FRAME_BYTES_DEFAULT, max_datagram_bytes: 0,
        encodings: vec![pb::Encoding::Utf8 as i32],
    }))).await;
    loop { if matches!(recv(&mut ws).await.message, Some(Msg::ServerHello(_))) { break; } }

    // Correct password authenticates and yields a grant.
    send(&mut ws, plain(Msg::Authenticate(pb::Authenticate {
        method: Some(pb::authenticate::Method::PasswordRequest(pb::PasswordRequest {
            username: user.clone(), password: password.clone(),
        })),
    }))).await;
    let ok = loop { if let Some(Msg::AuthenticationResult(r)) = recv(&mut ws).await.message { break r; } };
    assert!(ok.ok, "correct password must authenticate via real PAM");
    assert!(!ok.challenge.is_empty(), "a grant is issued");
    eprintln!("PASS: real PAM login for {user} ok, grant issued");

    // Wrong password is rejected.
    let (mut ws2, _) = tokio_tungstenite::connect_async(
        format!("ws://{}/terminal/ws", daemon.local_addr)).await.unwrap();
    send(&mut ws2, plain(Msg::ClientHello(pb::ClientHello {
        protocol_major: PROTOCOL_MAJOR, protocol_minor: PROTOCOL_MINOR,
        client_kind: pb::ClientKind::BrowserWebsocket as i32, client_build: "pam-live".into(),
        capabilities: vec![], max_frame_bytes: FRAME_BYTES_DEFAULT, max_datagram_bytes: 0,
        encodings: vec![pb::Encoding::Utf8 as i32],
    }))).await;
    loop { if matches!(recv(&mut ws2).await.message, Some(Msg::ServerHello(_))) { break; } }
    send(&mut ws2, plain(Msg::Authenticate(pb::Authenticate {
        method: Some(pb::authenticate::Method::PasswordRequest(pb::PasswordRequest {
            username: user, password: format!("{password}-wrong"),
        })),
    }))).await;
    let bad = loop { if let Some(Msg::AuthenticationResult(r)) = recv(&mut ws2).await.message { break r; } };
    assert!(!bad.ok, "wrong password must be rejected");
    eprintln!("PASS: wrong password rejected");
    daemon.abort();
}
