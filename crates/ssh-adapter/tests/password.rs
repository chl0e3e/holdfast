//! Opt-in password authentication (ADR 0015), driven by a russh client.
//!
//! These tests inject a deterministic [`PasswordVerifier`] so they exercise
//! the adapter's negotiation, gating and bridging without depending on host
//! PAM state; the PAM verifier itself is covered by `src/pam.rs` unit tests.

#![cfg(unix)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hf_auth::ssh::SshVerifier;
use hf_daemon::{Daemon, DaemonConfig};
use hf_native_client::AuthMethod;
use hf_ssh_adapter::{
    serve_on, AdapterConfig, PasswordVerifier, AUTH_REJECTION_DELAY, MAX_PASSWORD_BYTES,
};
use russh::client::AuthResult;
use russh::ChannelMsg;
use tokio::net::TcpListener;

const LOCAL_USER: &str = "adapter";
const PASSWORD: &str = "correct horse battery staple";
const AUTHORIZED_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICyA4HLtsYpDxEz/pbI5Ey0RZQxQ5qDlYTV5s++MFVJv";

struct FixedPassword {
    calls: AtomicUsize,
}

impl PasswordVerifier for FixedPassword {
    fn verify(&self, user: &str, password: &str) -> bool {
        self.calls.fetch_add(1, Ordering::SeqCst);
        user == LOCAL_USER && password == PASSWORD
    }
}

struct AcceptHostKey;

impl russh::client::Handler for AcceptHostKey {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

async fn start_adapter(
    verifier: Option<Arc<FixedPassword>>,
) -> (Daemon, tokio::task::JoinHandle<()>, u16) {
    let daemon = Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    })
    .await
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = AdapterConfig {
        listen: listener.local_addr().unwrap(),
        remote_url: format!("http://{}", daemon.local_addr),
        remote_auth: AuthMethod::Dev,
        local_user: LOCAL_USER.into(),
        authorized_keys: Arc::new(SshVerifier::from_authorized_keys(AUTHORIZED_KEY).unwrap()),
        password_auth: verifier.map(|verifier| verifier as Arc<dyn PasswordVerifier>),
        host_key: russh::keys::PrivateKey::random(
            &mut rand_10::rng(),
            russh::keys::ssh_key::Algorithm::Ed25519,
        )
        .unwrap(),
        max_connections: 4,
    };
    let task = tokio::spawn(async move {
        serve_on(listener, config).await.unwrap();
    });
    (daemon, task, port)
}

async fn authenticate(port: u16, user: &str, password: &str) -> AuthResult {
    let config = Arc::new(russh::client::Config::default());
    let mut session = russh::client::connect(config, ("127.0.0.1", port), AcceptHostKey)
        .await
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(10),
        session.authenticate_password(user, password),
    )
    .await
    .expect("password authentication timed out")
    .unwrap()
}

#[tokio::test]
async fn correct_password_opens_an_interactive_shell() {
    let verifier = Arc::new(FixedPassword {
        calls: AtomicUsize::new(0),
    });
    let (daemon, adapter, port) = start_adapter(Some(verifier)).await;

    let config = Arc::new(russh::client::Config::default());
    let mut session = russh::client::connect(config, ("127.0.0.1", port), AcceptHostKey)
        .await
        .unwrap();
    let auth = session
        .authenticate_password(LOCAL_USER, PASSWORD)
        .await
        .unwrap();
    assert!(matches!(auth, AuthResult::Success), "auth failed: {auth:?}");

    let channel = session.channel_open_session().await.unwrap();
    channel
        .request_pty(false, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    channel.request_shell(true).await.unwrap();
    // Octal escapes keep the expected literal out of the terminal's input
    // echo, proving it came from the remote PTY output.
    channel
        .data(&b"printf '\\160\\141\\163\\163\\167\\144\\055\\157\\153\\012'\rexit\r"[..])
        .await
        .unwrap();

    let mut channel = channel;
    let mut output = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    while !String::from_utf8_lossy(&output).contains("passwd-ok") {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let message = tokio::time::timeout(remaining, channel.wait())
            .await
            .expect("shell output timed out");
        match message {
            Some(ChannelMsg::Data { data }) => output.extend_from_slice(&data),
            Some(_) => {}
            None => break,
        }
    }
    let output = String::from_utf8_lossy(&output);
    assert!(output.contains("passwd-ok"), "terminal output: {output:?}");

    adapter.abort();
    daemon.abort();
}

#[tokio::test]
async fn wrong_password_is_rejected_after_the_constant_delay() {
    let verifier = Arc::new(FixedPassword {
        calls: AtomicUsize::new(0),
    });
    let (daemon, adapter, port) = start_adapter(Some(verifier)).await;

    let started = Instant::now();
    let auth = authenticate(port, LOCAL_USER, "wrong password").await;
    assert!(matches!(auth, AuthResult::Failure { .. }));
    assert!(
        started.elapsed() >= AUTH_REJECTION_DELAY - Duration::from_millis(50),
        "rejection returned faster than the constant delay: {:?}",
        started.elapsed()
    );

    adapter.abort();
    daemon.abort();
}

#[tokio::test]
async fn foreign_username_and_oversized_password_never_reach_the_verifier() {
    let verifier = Arc::new(FixedPassword {
        calls: AtomicUsize::new(0),
    });
    let (daemon, adapter, port) = start_adapter(Some(verifier.clone())).await;

    let auth = authenticate(port, "someone-else", PASSWORD).await;
    assert!(matches!(auth, AuthResult::Failure { .. }));
    let auth = authenticate(port, LOCAL_USER, &"x".repeat(MAX_PASSWORD_BYTES + 1)).await;
    assert!(matches!(auth, AuthResult::Failure { .. }));
    let auth = authenticate(port, LOCAL_USER, "").await;
    assert!(matches!(auth, AuthResult::Failure { .. }));
    assert_eq!(verifier.calls.load(Ordering::SeqCst), 0);

    adapter.abort();
    daemon.abort();
}

#[tokio::test]
async fn password_authentication_is_refused_when_not_configured() {
    let (daemon, adapter, port) = start_adapter(None).await;

    let auth = authenticate(port, LOCAL_USER, PASSWORD).await;
    let AuthResult::Failure {
        remaining_methods, ..
    } = auth
    else {
        panic!("password unexpectedly accepted on a public-key-only adapter");
    };
    assert!(
        !remaining_methods.contains(&russh::MethodKind::Password),
        "password advertised while disabled: {remaining_methods:?}"
    );

    adapter.abort();
    daemon.abort();
}
