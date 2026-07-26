//! Phase 7: the native client authenticates against an SSH-auth daemon with
//! a real OpenSSH private key (challenge/response), and the issued grant is
//! reusable. Reproduce with: `cargo test -p hf-native-client --test ssh_auth`

#![cfg(unix)] // these tests spawn a real daemon (pty/pam are unix-only)

use std::collections::BTreeMap;

use hf_daemon::{AuthConfig, Daemon, DaemonConfig};
use hf_native_client::{connect_with, AuthMethod};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};

fn write_key(dir: &std::path::Path) -> (std::path::PathBuf, String) {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let path = dir.join("id_ed25519");
    let pem = key.to_openssh(LineEnding::LF).unwrap();
    std::fs::write(&path, pem.as_bytes()).unwrap();
    let public_line = key.public_key().to_openssh().unwrap();
    (path, public_line)
}

fn ssh_daemon_config(public_line: &str) -> DaemonConfig {
    let mut users = BTreeMap::new();
    users.insert("alice".to_string(), format!("{public_line}\n"));
    DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        // Native client is WebTransport-only; keep it enabled on an ephemeral port.
        webtransport_bind: Some("127.0.0.1:0".parse().unwrap()),
        auth: AuthConfig::SshKeys { users },
        ..Default::default()
    }
}

#[tokio::test]
async fn native_client_authenticates_with_ssh_key_and_reuses_grant() {
    let tmp = std::env::temp_dir().join(format!("hf-ssh-auth-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let (key_path, public_line) = write_key(&tmp);

    let daemon = Daemon::start(ssh_daemon_config(&public_line))
        .await
        .unwrap();
    let url = format!("http://{}", daemon.local_addr);

    // Authenticate by signing the challenge with the private key.
    let mut conn = connect_with(
        &url,
        AuthMethod::SshKey {
            username: "alice".into(),
            private_key_path: key_path.clone(),
        },
    )
    .await
    .expect("ssh-key auth should succeed");
    assert!(!conn.grant.is_empty(), "daemon issues a grant on ssh auth");
    let grant = conn.grant.clone();

    // The authenticated session works.
    assert!(conn.list_shells().await.unwrap().is_empty());

    // The issued grant re-authenticates without signing again.
    let conn2 = connect_with(&url, AuthMethod::Grant(grant))
        .await
        .expect("grant reuse");
    assert!(!conn2.grant.is_empty());

    // A wrong username is rejected even with a valid key file.
    let bad = connect_with(
        &url,
        AuthMethod::SshKey {
            username: "mallory".into(),
            private_key_path: key_path,
        },
    )
    .await;
    assert!(bad.is_err(), "unknown user must fail");

    daemon.abort();
    std::fs::remove_dir_all(&tmp).ok();
}
