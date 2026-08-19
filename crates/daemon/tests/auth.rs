//! Phase 7 tests: the real SSH-key local issuer and source-address rate
//! limiting, end to end over WebSocket. Reproduce with:
//! `cargo test -p hf-daemon --test auth`

use std::collections::BTreeMap;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hf_daemon::observability::AuditEvent;
use hf_daemon::{wire, AuthConfig, Daemon, DaemonConfig};
use hf_protocol::pb::{self, envelope::Message as Msg, Envelope};
use hf_protocol::{FRAME_BYTES_DEFAULT, PROTOCOL_MAJOR, PROTOCOL_MINOR};
use sha2::Digest;
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};
use tokio_tungstenite::tungstenite::Message as WsMessage;

const NS: &str = "holdfast-auth@v0";
const T: Duration = Duration::from_secs(10);

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

fn plain(message: Msg) -> Envelope {
    Envelope {
        request_id: 1,
        server_id: vec![],
        shell_id: vec![],
        message: Some(message),
    }
}

async fn send(ws: &mut Ws, env: Envelope) {
    send_on(ws, 0, env).await;
}

async fn send_on(ws: &mut Ws, channel: u64, env: Envelope) {
    let bytes = wire::encode_message(channel, &env, FRAME_BYTES_DEFAULT).unwrap();
    ws.send(WsMessage::Binary(bytes.into())).await.unwrap();
}

async fn recv(ws: &mut Ws) -> Envelope {
    loop {
        let msg = tokio::time::timeout(T, ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
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
    send(
        &mut ws,
        plain(Msg::ClientHello(pb::ClientHello {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            client_kind: pb::ClientKind::BrowserWebsocket as i32,
            client_build: "auth-test".into(),
            capabilities: vec![pb::Capability::FileTransfer as i32],
            max_frame_bytes: FRAME_BYTES_DEFAULT,
            max_datagram_bytes: 0,
            encodings: vec![pb::Encoding::Utf8 as i32],
        })),
    )
    .await;
    loop {
        if matches!(recv(&mut ws).await.message, Some(Msg::ServerHello(_))) {
            break;
        }
    }
    ws
}

/// Full SSH challenge/response against authorized_keys.
async fn ssh_authenticate(
    ws: &mut Ws,
    username: &str,
    key: &PrivateKey,
) -> pb::AuthenticationResult {
    let public_line = key.public_key().to_openssh().unwrap();
    send(
        ws,
        plain(Msg::Authenticate(pb::Authenticate {
            method: Some(pb::authenticate::Method::SshChallengeRequest(
                pb::SshChallengeRequest {
                    username: username.into(),
                    public_key: public_line.into_bytes(),
                },
            )),
        })),
    )
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
    send(
        ws,
        plain(Msg::Authenticate(pb::Authenticate {
            method: Some(pb::authenticate::Method::SshChallengeResponse(
                pb::SshChallengeResponse {
                    challenge,
                    signature: pem.into_bytes(),
                },
            )),
        })),
    )
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
        enable_websocket: true,
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
    let daemon = Daemon::start(daemon_config_with_key(
        &key.public_key().to_openssh().unwrap(),
    ))
    .await
    .unwrap();

    let mut ws = connect(&daemon).await;
    let result = ssh_authenticate(&mut ws, "alice", &key).await;
    assert!(result.ok, "authorized key must authenticate");
    assert_eq!(result.user_id, "alice");
    assert!(
        !result.challenge.is_empty(),
        "a connection grant is handed back"
    );

    // Authenticated: opening a shell succeeds and emits only safe lifecycle
    // metadata into the bounded audit ring.
    send(&mut ws, open_shell_env("")).await;
    assert!(matches!(
        recv(&mut ws).await.message,
        Some(Msg::ShellOpened(_))
    ));

    let metrics = daemon.metrics();
    assert_eq!(metrics.authentication_succeeded, 1);
    assert_eq!(metrics.shells_opened, 1);
    let audit = daemon.audit_events();
    assert!(audit.iter().any(|record| matches!(
        &record.event,
        AuditEvent::AuthenticationSucceeded { user, .. } if user == "alice"
    )));
    assert!(audit
        .iter()
        .any(|record| matches!(&record.event, AuditEvent::ShellOpened { .. })));
    let rendered = format!("{audit:?}");
    for forbidden in [
        "resume_token",
        "connection_grant",
        "terminal_output",
        "command",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "audit leaked forbidden field {forbidden}"
        );
    }

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
    accounts.insert(
        "alice".to_string(),
        vec!["alice".to_string(), "deploy".to_string()],
    );
    let daemon = Daemon::start(DaemonConfig {
        enable_websocket: true,
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
    let daemon = Daemon::start(daemon_config_with_key(
        &key.public_key().to_openssh().unwrap(),
    ))
    .await
    .unwrap();

    let mut ws = connect(&daemon).await;
    // Request a challenge with the authorized key...
    let public_line = key.public_key().to_openssh().unwrap();
    send(
        &mut ws,
        plain(Msg::Authenticate(pb::Authenticate {
            method: Some(pb::authenticate::Method::SshChallengeRequest(
                pb::SshChallengeRequest {
                    username: "alice".into(),
                    public_key: public_line.into_bytes(),
                },
            )),
        })),
    )
    .await;
    let challenge = loop {
        if let Some(Msg::AuthenticationResult(r)) = recv(&mut ws).await.message {
            break r.challenge;
        }
    };
    // ...but sign a *different* nonce.
    let sig = key.sign(NS, HashAlg::Sha512, b"not-the-challenge").unwrap();
    let pem = sig.to_pem(LineEnding::LF).unwrap();
    send(
        &mut ws,
        plain(Msg::Authenticate(pb::Authenticate {
            method: Some(pb::authenticate::Method::SshChallengeResponse(
                pb::SshChallengeResponse {
                    challenge,
                    signature: pem.into_bytes(),
                },
            )),
        })),
    )
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
    let daemon = Daemon::start(daemon_config_with_key(
        &key.public_key().to_openssh().unwrap(),
    ))
    .await
    .unwrap();

    // Authenticate once and capture the grant.
    let mut ws = connect(&daemon).await;
    let grant = ssh_authenticate(&mut ws, "alice", &key).await.challenge;
    assert!(!grant.is_empty());
    drop(ws);

    // A fresh connection presents the grant directly — no challenge needed.
    let mut ws2 = connect(&daemon).await;
    send(
        &mut ws2,
        plain(Msg::Authenticate(pb::Authenticate {
            method: Some(pb::authenticate::Method::ConnectionGrant(grant)),
        })),
    )
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
    let daemon = Daemon::start(daemon_config_with_key(
        &key.public_key().to_openssh().unwrap(),
    ))
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
    send(
        &mut ws,
        plain(Msg::Authenticate(pb::Authenticate {
            method: Some(pb::authenticate::Method::SshChallengeRequest(
                pb::SshChallengeRequest {
                    username: "alice".into(),
                    public_key: key.public_key().to_openssh().unwrap().into_bytes(),
                },
            )),
        })),
    )
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

/// Per-user isolation (threat model T12): one authenticated user must not be
/// able to enumerate or terminate another user's shells. Regression test for
/// the missing owner checks on ListShells / TerminateShell.
#[tokio::test]
async fn users_cannot_see_or_terminate_each_others_shells() {
    let alice_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let bob_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let mut users = BTreeMap::new();
    users.insert(
        "alice".to_string(),
        format!("{}\n", alice_key.public_key().to_openssh().unwrap()),
    );
    users.insert(
        "bob".to_string(),
        format!("{}\n", bob_key.public_key().to_openssh().unwrap()),
    );
    let temp = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(DaemonConfig {
        enable_websocket: true,
        bind: "127.0.0.1:0".parse().unwrap(),
        webtransport_bind: None,
        auth: AuthConfig::SshKeys { users },
        upload_root: Some(temp.path().join("uploads")),
        ..Default::default()
    })
    .await
    .unwrap();

    // Alice opens a shell and learns its id.
    let mut alice = connect(&daemon).await;
    assert!(ssh_authenticate(&mut alice, "alice", &alice_key).await.ok);
    send(&mut alice, open_shell_env("")).await;
    let (alice_shell, alice_token) = loop {
        let env = recv(&mut alice).await;
        if let Some(Msg::ShellOpened(opened)) = env.message {
            break (env.shell_id, opened.resume_token);
        }
    };
    assert!(!alice_shell.is_empty());

    // Bob authenticates on his own connection.
    let mut bob = connect(&daemon).await;
    assert!(ssh_authenticate(&mut bob, "bob", &bob_key).await.ok);

    // Upload authorization is shell-scoped too. A valid declaration must not
    // reveal whether the copied shell id belongs to another user.
    let mut upload = plain(Msg::BeginUpload(pb::BeginUpload {
        original_name: "probe.txt".into(),
        total_bytes: 0,
        sha256: sha2::Sha256::digest([]).to_vec(),
    }));
    upload.shell_id = alice_shell.clone();
    send_on(&mut bob, 3, upload).await;
    let upload_reply = recv(&mut bob).await;
    assert!(
        matches!(&upload_reply.message, Some(Msg::Error(e)) if e.code == pb::ErrorCode::ErrForbidden as i32),
        "bob uploading to alice's shell must be ErrForbidden, got {:?}",
        upload_reply.message
    );

    // Bob's ListShells must not reveal Alice's shell.
    send(&mut bob, plain(Msg::ListShells(pb::ListShells {}))).await;
    let list = loop {
        if let Some(Msg::ShellList(l)) = recv(&mut bob).await.message {
            break l;
        }
    };
    assert!(
        list.shells.is_empty(),
        "bob must not see alice's shells: {:?}",
        list.shells
    );

    // A copied, valid token remains scoped to Alice's authenticated identity.
    let mut attach = plain(Msg::AttachShell(pb::AttachShell {
        resume_token: alice_token,
        cols: 40,
        rows: 6,
        last_seen_revision: 0,
        last_history_line_id: 0,
    }));
    attach.shell_id = alice_shell.clone();
    send_on(&mut bob, 1, attach).await;
    let attach_reply = recv(&mut bob).await;
    assert!(
        matches!(&attach_reply.message, Some(Msg::Error(e)) if e.code == pb::ErrorCode::ErrNotFound as i32),
        "bob attaching alice's shell must be ErrNotFound, got {:?}",
        attach_reply.message
    );

    // Bob tries to terminate Alice's shell by id → not-found, not honored.
    let mut term = plain(Msg::TerminateShell(pb::TerminateShell {}));
    term.shell_id = alice_shell.clone();
    send(&mut bob, term).await;
    let reply = loop {
        let env = recv(&mut bob).await;
        if matches!(env.message, Some(Msg::Error(_)) | Some(Msg::ShellExited(_))) {
            break env;
        }
    };
    assert!(
        matches!(&reply.message, Some(Msg::Error(e)) if e.code == pb::ErrorCode::ErrNotFound as i32),
        "bob terminating alice's shell must be ErrNotFound, got {:?}",
        reply.message
    );

    // Alice's shell is still alive and visible to her.
    send(&mut alice, plain(Msg::ListShells(pb::ListShells {}))).await;
    let alice_list = loop {
        if let Some(Msg::ShellList(l)) = recv(&mut alice).await.message {
            break l;
        }
    };
    assert_eq!(
        alice_list.shells.len(),
        1,
        "alice still sees her own running shell"
    );

    daemon.abort();
}

/// A connection grant with a restricted `ops` scope must be honored, not
/// silently upgraded to full access (threat model T4). A list-only grant can
/// list but cannot open, attach, or terminate.
#[tokio::test]
async fn scoped_grant_ops_are_enforced() {
    use hf_auth::{GrantClaims, GrantSigner};

    // Pin the grant signing key so the test can mint a scoped grant the daemon
    // will accept. Empty SSH user set: we authenticate purely via the grant.
    let grant_key = [7u8; 32];
    let temp = tempfile::tempdir().unwrap();
    let daemon = Daemon::start(DaemonConfig {
        enable_websocket: true,
        bind: "127.0.0.1:0".parse().unwrap(),
        webtransport_bind: None,
        auth: AuthConfig::SshKeys {
            users: BTreeMap::new(),
        },
        grant_signing_key: Some(grant_key),
        upload_root: Some(temp.path().join("uploads")),
        ..Default::default()
    })
    .await
    .unwrap();

    // Mint a list-only grant bound to this daemon's audience (its server id).
    let signer = GrantSigner::from_bytes(&grant_key);
    let grant = signer.issue(&GrantClaims {
        sub: "alice".into(),
        aud: daemon.server_id.to_string(),
        servers: vec![],
        ops: vec!["list".into()],
        iat_ms: 0,
        exp_ms: 4_102_444_800_000, // year 2100
        jti: "test-jti".into(),
    });

    let mut ws = connect(&daemon).await;
    send(
        &mut ws,
        plain(Msg::Authenticate(pb::Authenticate {
            method: Some(pb::authenticate::Method::ConnectionGrant(
                grant.as_bytes().to_vec(),
            )),
        })),
    )
    .await;
    let ok = loop {
        if let Some(Msg::AuthenticationResult(r)) = recv(&mut ws).await.message {
            break r.ok;
        }
    };
    assert!(ok, "valid scoped grant must authenticate");

    // Permitted op: list works.
    send(&mut ws, plain(Msg::ListShells(pb::ListShells {}))).await;
    assert!(
        matches!(recv(&mut ws).await.message, Some(Msg::ShellList(_))),
        "list is permitted"
    );

    // Forbidden ops: open and terminate are rejected with ERR_FORBIDDEN.
    send(&mut ws, open_shell_env("")).await;
    let open_reply = recv(&mut ws).await;
    assert!(
        matches!(&open_reply.message, Some(Msg::Error(e)) if e.code == pb::ErrorCode::ErrForbidden as i32),
        "open must be forbidden for a list-only grant, got {:?}",
        open_reply.message
    );

    let mut term = plain(Msg::TerminateShell(pb::TerminateShell {}));
    term.shell_id = vec![9u8; 16];
    send(&mut ws, term).await;
    let term_reply = recv(&mut ws).await;
    assert!(
        matches!(&term_reply.message, Some(Msg::Error(e)) if e.code == pb::ErrorCode::ErrForbidden as i32),
        "terminate must be forbidden for a list-only grant, got {:?}",
        term_reply.message
    );

    let mut upload = plain(Msg::BeginUpload(pb::BeginUpload {
        original_name: "forbidden.txt".into(),
        total_bytes: 0,
        sha256: sha2::Sha256::digest([]).to_vec(),
    }));
    upload.shell_id = vec![8u8; 16];
    send_on(&mut ws, 3, upload).await;
    let upload_reply = recv(&mut ws).await;
    assert!(
        matches!(&upload_reply.message, Some(Msg::Error(e)) if e.code == pb::ErrorCode::ErrForbidden as i32),
        "upload must be forbidden for a list-only grant, got {:?}",
        upload_reply.message
    );

    daemon.abort();
}

/// Password login (ADR 0016): single round trip via the injected verifier.
async fn password_authenticate(
    ws: &mut Ws,
    username: &str,
    password: &str,
) -> pb::AuthenticationResult {
    send(
        ws,
        plain(Msg::Authenticate(pb::Authenticate {
            method: Some(pb::authenticate::Method::PasswordRequest(
                pb::PasswordRequest {
                    username: username.into(),
                    password: password.into(),
                },
            )),
        })),
    )
    .await;
    loop {
        if let Some(Msg::AuthenticationResult(r)) = recv(ws).await.message {
            return r;
        }
    }
}

fn counting_verifier(
    user: &'static str,
    password: &'static str,
) -> (
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    std::sync::Arc<dyn hf_auth::PasswordVerifier>,
) {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = calls.clone();
    let verifier = std::sync::Arc::new(move |u: &str, p: &str| {
        counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        u == user && p == password
    });
    (calls, verifier)
}

fn password_config(
    key_line: &str,
    verifier: std::sync::Arc<dyn hf_auth::PasswordVerifier>,
) -> DaemonConfig {
    let mut config = daemon_config_with_key(key_line);
    config.password_auth = Some(hf_daemon::PasswordAuthConfig {
        users: std::iter::once("alice".to_string()).collect(),
        verifier,
    });
    config
}

#[tokio::test]
async fn password_login_issues_a_grant_that_reconnects() {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let (_, verifier) = counting_verifier("alice", "correct horse battery staple");
    let daemon = Daemon::start(password_config(
        &key.public_key().to_openssh().unwrap(),
        verifier,
    ))
    .await
    .unwrap();

    let mut ws = connect(&daemon).await;
    let result = password_authenticate(&mut ws, "alice", "correct horse battery staple").await;
    assert!(result.ok, "correct password must authenticate");
    assert_eq!(result.user_id, "alice");
    let grant = result.challenge.clone();
    assert!(!grant.is_empty(), "a connection grant is handed back");

    // Authenticated: a shell opens, and the audit trail records the method
    // without ever containing the password itself.
    send(&mut ws, open_shell_env("")).await;
    assert!(matches!(
        recv(&mut ws).await.message,
        Some(Msg::ShellOpened(_))
    ));
    let audit = daemon.audit_events();
    assert!(audit.iter().any(|record| matches!(
        &record.event,
        AuditEvent::AuthenticationSucceeded {
            user,
            method: hf_daemon::observability::AuthMethod::Password,
            ..
        } if user == "alice"
    )));
    assert!(
        !format!("{audit:?}").contains("correct horse"),
        "audit must never contain password material"
    );

    // The issued grant works on a fresh connection, like the SSH-key path.
    let mut ws2 = connect(&daemon).await;
    send(
        &mut ws2,
        plain(Msg::Authenticate(pb::Authenticate {
            method: Some(pb::authenticate::Method::ConnectionGrant(grant)),
        })),
    )
    .await;
    let reconnected = loop {
        if let Some(Msg::AuthenticationResult(r)) = recv(&mut ws2).await.message {
            break r;
        }
    };
    assert!(reconnected.ok, "issued grant must authenticate a reconnect");
    assert_eq!(reconnected.user_id, "alice");

    daemon.abort();
}

#[tokio::test]
async fn wrong_password_foreign_user_and_oversized_input_fail_closed() {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let (calls, verifier) = counting_verifier("alice", "right");
    let daemon = Daemon::start(password_config(
        &key.public_key().to_openssh().unwrap(),
        verifier,
    ))
    .await
    .unwrap();

    let mut ws = connect(&daemon).await;
    assert!(!password_authenticate(&mut ws, "alice", "wrong").await.ok);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

    // Not allowlisted, empty, and oversized input never reach the verifier.
    assert!(!password_authenticate(&mut ws, "mallory", "right").await.ok);
    assert!(!password_authenticate(&mut ws, "alice", "").await.ok);
    let oversized = "x".repeat(hf_auth::MAX_PASSWORD_BYTES + 1);
    assert!(!password_authenticate(&mut ws, "alice", &oversized).await.ok);
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "only the well-formed allowlisted attempt may reach the verifier"
    );

    // Failed password attempts count toward the source-address rate limiter.
    let result = password_authenticate(&mut ws, "alice", "wrong").await;
    assert!(!result.ok);
    let result = ssh_authenticate(&mut ws, "alice", &key).await; // 6th failure context
    let _ = result;
    let metrics = daemon.metrics();
    assert!(
        metrics.authentication_failed >= 4,
        "password failures must be audited/rate-limited, got {}",
        metrics.authentication_failed
    );

    daemon.abort();
}

#[tokio::test]
async fn password_login_is_rejected_when_not_enabled() {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let daemon = Daemon::start(daemon_config_with_key(
        &key.public_key().to_openssh().unwrap(),
    ))
    .await
    .unwrap();

    let mut ws = connect(&daemon).await;
    let result = password_authenticate(&mut ws, "alice", "anything").await;
    assert!(!result.ok, "password must be refused on a key-only daemon");

    // The SSH-key path is unaffected.
    let result = ssh_authenticate(&mut ws, "alice", &key).await;
    assert!(result.ok);

    daemon.abort();
}

#[tokio::test]
async fn persisted_grant_key_gives_stable_server_id_and_grants_survive_restart() {
    // ADR 0017: the standalone server identity derives from the grant signing
    // key, so a grant issued before a daemon restart still passes the
    // audience check after it.
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let seed: [u8; 32] = rand::random();
    let mut config = daemon_config_with_key(&key.public_key().to_openssh().unwrap());
    config.grant_signing_key = Some(seed);

    let daemon_a = Daemon::start(config.clone()).await.unwrap();
    let id_a = daemon_a.server_id;
    let mut ws = connect(&daemon_a).await;
    let grant = ssh_authenticate(&mut ws, "alice", &key).await.challenge;
    assert!(!grant.is_empty());
    drop(ws);
    daemon_a.abort();

    // "Restart": a new daemon with the same signing key (fresh port).
    let daemon_b = Daemon::start(config.clone()).await.unwrap();
    assert_eq!(daemon_b.server_id, id_a, "same key must give the same id");

    let mut ws = connect(&daemon_b).await;
    send(
        &mut ws,
        plain(Msg::Authenticate(pb::Authenticate {
            method: Some(pb::authenticate::Method::ConnectionGrant(grant)),
        })),
    )
    .await;
    let result = loop {
        if let Some(Msg::AuthenticationResult(r)) = recv(&mut ws).await.message {
            break r;
        }
    };
    assert!(result.ok, "grant issued before restart must still verify");
    assert_eq!(result.user_id, "alice");
    daemon_b.abort();

    // A different signing key is a different identity.
    let mut other = daemon_config_with_key(&key.public_key().to_openssh().unwrap());
    other.grant_signing_key = Some(rand::random());
    let daemon_c = Daemon::start(other).await.unwrap();
    assert_ne!(daemon_c.server_id, id_a);
    daemon_c.abort();

    // An explicit --server-id overrides derivation.
    let explicit = hf_protocol::ids::ServerId([0x42; 16]);
    let mut pinned = daemon_config_with_key(&key.public_key().to_openssh().unwrap());
    pinned.grant_signing_key = Some(seed);
    pinned.server_id = Some(explicit);
    let daemon_d = Daemon::start(pinned).await.unwrap();
    assert_eq!(daemon_d.server_id, explicit);
    daemon_d.abort();
}
