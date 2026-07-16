//! Phase 7 tests: the real SSH-key local issuer and source-address rate
//! limiting, end to end over WebSocket. Reproduce with:
//! `cargo test -p hf-daemon --test auth`

use std::collections::BTreeMap;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hf_daemon::{wire, AuthConfig, Daemon, DaemonConfig};
use hf_protocol::pb::{self, envelope::Message as Msg, Envelope};
use hf_protocol::{FRAME_BYTES_DEFAULT, PROTOCOL_MAJOR, PROTOCOL_MINOR};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use tokio_tungstenite::tungstenite::Message as WsMessage;

const NS: &str = "holdfast-auth@v0";
const T: Duration = Duration::from_secs(10);

type Ws = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

fn plain(message: Msg) -> Envelope {
    Envelope { request_id: 1, server_id: vec![], shell_id: vec![], message: Some(message) }
}

async fn send(ws: &mut Ws, env: Envelope) {
    let bytes = wire::encode_message(0, &env, FRAME_BYTES_DEFAULT).unwrap();
    ws.send(WsMessage::Binary(bytes.into())).await.unwrap();
}

async fn recv(ws: &mut Ws) -> Envelope {
    loop {
        let msg = tokio::time::timeout(T, ws.next()).await.unwrap().unwrap().unwrap();
        if let WsMessage::Binary(data) = msg {
            return wire::decode_message(&data, FRAME_BYTES_DEFAULT).unwrap().1;
        }
    }
}

async fn connect(daemon: &Daemon) -> Ws {
    let (mut ws, _) =
        tokio_tungstenite::connect_async(format!("ws://{}/terminal/ws", daemon.local_addr))
            .await
            .unwrap();
    send(&mut ws, plain(Msg::ClientHello(pb::ClientHello {
        protocol_major: PROTOCOL_MAJOR,
        protocol_minor: PROTOCOL_MINOR,
        client_kind: pb::ClientKind::BrowserWebsocket as i32,
        client_build: "auth-test".into(),
        capabilities: vec![],
        max_frame_bytes: FRAME_BYTES_DEFAULT,
        max_datagram_bytes: 0,
        encodings: vec![pb::Encoding::Utf8 as i32],
    })))
    .await;
    loop {
        if matches!(recv(&mut ws).await.message, Some(Msg::ServerHello(_))) {
            break;
        }
    }
    ws
}

/// Full SSH challenge/response against authorized_keys.
async fn ssh_authenticate(ws: &mut Ws, username: &str, key: &PrivateKey) -> pb::AuthenticationResult {
    let public_line = key.public_key().to_openssh().unwrap();
    send(ws, plain(Msg::Authenticate(pb::Authenticate {
        method: Some(pb::authenticate::Method::SshChallengeRequest(pb::SshChallengeRequest {
            username: username.into(),
            public_key: public_line.into_bytes(),
        })),
    })))
    .await;
    let challenge = loop {
        if let Some(Msg::AuthenticationResult(r)) = recv(ws).await.message {
            break r.challenge;
        }
    };
    if challenge.is_empty() {
        // Rejected outright (unauthorized) — return a synthetic failure.
        return pb::AuthenticationResult {
            ok: false,
            challenge: vec![],
            ..Default::default()
        };
    }

    let sig = key.sign(NS, HashAlg::Sha512, &challenge).unwrap();
    let pem = sig.to_pem(LineEnding::LF).unwrap();
    send(ws, plain(Msg::Authenticate(pb::Authenticate {
        method: Some(pb::authenticate::Method::SshChallengeResponse(pb::SshChallengeResponse {
            challenge,
            signature: pem.into_bytes(),
        })),
    })))
    .await;
    loop {
        if let Some(Msg::AuthenticationResult(r)) = recv(ws).await.message {
            return r;
        }
    }
}

fn daemon_config_with_key(line: &str) -> DaemonConfig {
    let mut users = BTreeMap::new();
    users.insert("alice".to_string(), format!("{line}\n"));
    DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        // WebTransport off: keep the test purely on the TCP path.
        webtransport_bind: None,
        auth: AuthConfig::SshKeys { users },
        ..Default::default()
    }
}

#[tokio::test]
async fn authorized_key_authenticates_and_can_open_a_shell() {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let daemon = Daemon::start(daemon_config_with_key(&key.public_key().to_openssh().unwrap()))
        .await
        .unwrap();

    let mut ws = connect(&daemon).await;
    let result = ssh_authenticate(&mut ws, "alice", &key).await;
    assert!(result.ok, "authorized key must authenticate");
    assert_eq!(result.user_id, "alice");
    assert!(!result.challenge.is_empty(), "a connection grant is handed back");

    // Authenticated: a control request now succeeds.
    send(&mut ws, plain(Msg::ListShells(pb::ListShells {}))).await;
    assert!(matches!(recv(&mut ws).await.message, Some(Msg::ShellList(_))));

    daemon.abort();
}

#[tokio::test]
async fn account_authorization_is_enforced() {
    // alice may run only as "alice" or "deploy".
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let public_line = key.public_key().to_openssh().unwrap();
    let mut users = std::collections::BTreeMap::new();
    users.insert("alice".to_string(), format!("{public_line}\n"));
    let mut accounts = std::collections::BTreeMap::new();
    accounts.insert("alice".to_string(), vec!["alice".to_string(), "deploy".to_string()]);
    let daemon = Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        webtransport_bind: None,
        auth: AuthConfig::SshKeys { users },
        account_policy: Some(accounts),
        ..Default::default()
    })
    .await
    .unwrap();

    let mut ws = connect(&daemon).await;
    assert!(ssh_authenticate(&mut ws, "alice", &key).await.ok);

    // Allowed account: shell opens.
    send(&mut ws, open_shell_env("deploy")).await;
    assert!(
        matches!(recv(&mut ws).await.message, Some(Msg::ShellOpened(_))),
        "allowed account must open"
    );

    // Disallowed account: forbidden.
    send(&mut ws, open_shell_env("root")).await;
    let reply = recv(&mut ws).await;
    assert!(
        matches!(&reply.message, Some(Msg::Error(e)) if e.code == pb::ErrorCode::ErrForbidden as i32),
        "disallowed account must be ERR_FORBIDDEN, got {:?}",
        reply.message
    );

    daemon.abort();
}

fn open_shell_env(account: &str) -> Envelope {
    plain(Msg::OpenShell(pb::OpenShell {
        unix_account: account.into(),
        command: "bash".into(),
        initial_cols: 40,
        initial_rows: 6,
        idempotency_key: rand_key(account),
    }))
}

fn rand_key(seed: &str) -> Vec<u8> {
    // Distinct idempotency key per account so the two opens are independent.
    let mut k = vec![0u8; 16];
    for (i, b) in seed.bytes().enumerate().take(16) {
        k[i] = b;
    }
    k
}

#[tokio::test]
async fn unauthorized_key_is_rejected() {
    let authorized = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let daemon = Daemon::start(daemon_config_with_key(
        &authorized.public_key().to_openssh().unwrap(),
    ))
    .await
    .unwrap();

    let attacker = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let mut ws = connect(&daemon).await;
    let result = ssh_authenticate(&mut ws, "alice", &attacker).await;
    assert!(!result.ok, "unauthorized key must be rejected");

    // Still unauthenticated: control requests are refused.
    send(&mut ws, plain(Msg::ListShells(pb::ListShells {}))).await;
    let err = recv(&mut ws).await;
    assert!(
        matches!(&err.message, Some(Msg::Error(e)) if e.code == pb::ErrorCode::ErrUnauthenticated as i32)
    );

    daemon.abort();
}

#[tokio::test]
async fn wrong_signature_is_rejected() {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let daemon = Daemon::start(daemon_config_with_key(&key.public_key().to_openssh().unwrap()))
        .await
        .unwrap();

    let mut ws = connect(&daemon).await;
    // Request a challenge with the authorized key...
    let public_line = key.public_key().to_openssh().unwrap();
    send(&mut ws, plain(Msg::Authenticate(pb::Authenticate {
        method: Some(pb::authenticate::Method::SshChallengeRequest(pb::SshChallengeRequest {
            username: "alice".into(),
            public_key: public_line.into_bytes(),
        })),
    })))
    .await;
    let challenge = loop {
        if let Some(Msg::AuthenticationResult(r)) = recv(&mut ws).await.message {
            break r.challenge;
        }
    };
    // ...but sign a *different* nonce.
    let sig = key.sign(NS, HashAlg::Sha512, b"not-the-challenge").unwrap();
    let pem = sig.to_pem(LineEnding::LF).unwrap();
    send(&mut ws, plain(Msg::Authenticate(pb::Authenticate {
        method: Some(pb::authenticate::Method::SshChallengeResponse(pb::SshChallengeResponse {
            challenge,
            signature: pem.into_bytes(),
        })),
    })))
    .await;
    let result = loop {
        if let Some(Msg::AuthenticationResult(r)) = recv(&mut ws).await.message {
            break r;
        }
    };
    assert!(!result.ok, "wrong signature must be rejected");

    daemon.abort();
}

#[tokio::test]
async fn issued_grant_reauthenticates() {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let daemon = Daemon::start(daemon_config_with_key(&key.public_key().to_openssh().unwrap()))
        .await
        .unwrap();

    // Authenticate once and capture the grant.
    let mut ws = connect(&daemon).await;
    let grant = ssh_authenticate(&mut ws, "alice", &key).await.challenge;
    assert!(!grant.is_empty());
    drop(ws);

    // A fresh connection presents the grant directly — no challenge needed.
    let mut ws2 = connect(&daemon).await;
    send(&mut ws2, plain(Msg::Authenticate(pb::Authenticate {
        method: Some(pb::authenticate::Method::ConnectionGrant(grant)),
    })))
    .await;
    let result = loop {
        if let Some(Msg::AuthenticationResult(r)) = recv(&mut ws2).await.message {
            break r;
        }
    };
    assert!(result.ok, "a valid grant must authenticate");
    assert_eq!(result.user_id, "alice");

    daemon.abort();
}

#[tokio::test]
async fn repeated_failures_trigger_rate_limit_lockout() {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let attacker = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let daemon = Daemon::start(daemon_config_with_key(&key.public_key().to_openssh().unwrap()))
        .await
        .unwrap();

    // Default policy: 5 failures in the window → lockout. All connections come
    // from 127.0.0.1, so the source-address bucket is shared.
    for _ in 0..5 {
        let mut ws = connect(&daemon).await;
        let r = ssh_authenticate(&mut ws, "alice", &attacker).await;
        assert!(!r.ok);
    }

    // Now even the *correct* key is locked out by source address.
    let mut ws = connect(&daemon).await;
    send(&mut ws, plain(Msg::Authenticate(pb::Authenticate {
        method: Some(pb::authenticate::Method::SshChallengeRequest(pb::SshChallengeRequest {
            username: "alice".into(),
            public_key: key.public_key().to_openssh().unwrap().into_bytes(),
        })),
    })))
    .await;
    let result = loop {
        if let Some(Msg::AuthenticationResult(r)) = recv(&mut ws).await.message {
            break r;
        }
    };
    assert!(!result.ok, "source address must be locked out");
    assert_eq!(result.error_code, pb::ErrorCode::ErrLimitExceeded as i32);

    daemon.abort();
}
