//! Phase 8 exit evidence through the real OpenSSH client.
//!
//! Reproduce exactly with:
//! `cargo test -p hf-ssh-adapter --test openssh -- --nocapture`

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use hf_auth::ssh::SshVerifier;
use hf_daemon::{Daemon, DaemonConfig};
use hf_native_client::AuthMethod;
use hf_ssh_adapter::{serve_on, AdapterConfig};
use ssh_key::rand_core::OsRng;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::process::Command;

struct TestFiles {
    dir: PathBuf,
    client_key: PathBuf,
}

impl Drop for TestFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn write_private_key(path: &Path, key: &PrivateKey) {
    let pem = key.to_openssh(LineEnding::LF).unwrap();
    std::fs::write(path, pem.as_bytes()).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn test_files(client: &PrivateKey) -> TestFiles {
    let dir = std::env::temp_dir().join(format!(
        "holdfast-ssh-adapter-{}-{}",
        std::process::id(),
        rand_10::random::<u64>()
    ));
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let client_key = dir.join("id_ed25519");
    write_private_key(&client_key, client);
    TestFiles { dir, client_key }
}

async fn start_adapter(public_line: &str) -> (Daemon, tokio::task::JoinHandle<()>, u16) {
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
        local_user: "adapter".into(),
        authorized_keys: Arc::new(SshVerifier::from_authorized_keys(public_line).unwrap()),
        password_auth: None,
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

fn ssh_command(port: u16, private_key: &Path) -> Command {
    let mut command = Command::new("/usr/bin/ssh");
    command
        .arg("-p")
        .arg(port.to_string())
        .arg("-i")
        .arg(private_key)
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "ConnectTimeout=5",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

#[tokio::test]
async fn unmodified_openssh_runs_an_interactive_holdfast_shell() {
    assert!(
        Path::new("/usr/bin/ssh").exists(),
        "this test requires OpenSSH"
    );
    let client = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let public_line = client.public_key().to_openssh().unwrap();
    let files = test_files(&client);
    let (daemon, adapter, port) = start_adapter(&public_line).await;

    let mut command = ssh_command(port, &files.client_key);
    command.arg("-tt").arg("adapter@127.0.0.1");
    let mut child = command.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    // Octal escapes keep the expected literal out of the terminal's input
    // echo, proving it came from the remote PTY output.
    stdin
        .write_all(b"printf '\\160\\150\\141\\163\\145\\070\\055\\157\\153\\012'\rexit\r")
        .await
        .unwrap();
    drop(stdin);
    let output = tokio::time::timeout(Duration::from_secs(15), child.wait_with_output())
        .await
        .expect("OpenSSH timed out")
        .unwrap();
    assert!(
        output.status.success(),
        "ssh failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("phase8-ok"), "terminal output: {stdout:?}");

    adapter.abort();
    daemon.abort();
}

#[tokio::test]
async fn remote_exec_is_rejected_without_opening_a_shell() {
    let client = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let public_line = client.public_key().to_openssh().unwrap();
    let files = test_files(&client);
    let (daemon, adapter, port) = start_adapter(&public_line).await;

    let mut command = ssh_command(port, &files.client_key);
    command.arg("adapter@127.0.0.1").arg("echo must-not-run");
    let output = tokio::time::timeout(Duration::from_secs(10), command.output())
        .await
        .expect("OpenSSH exec rejection timed out")
        .unwrap();
    assert!(!output.status.success(), "exec unexpectedly succeeded");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("must-not-run"));

    adapter.abort();
    daemon.abort();
}

#[tokio::test]
async fn unauthorized_local_key_is_rejected() {
    let authorized = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let attacker = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let public_line = authorized.public_key().to_openssh().unwrap();
    let files = test_files(&attacker);
    let (daemon, adapter, port) = start_adapter(&public_line).await;

    let mut command = ssh_command(port, &files.client_key);
    command.arg("-tt").arg("adapter@127.0.0.1");
    let output = tokio::time::timeout(Duration::from_secs(10), command.output())
        .await
        .expect("OpenSSH auth rejection timed out")
        .unwrap();
    assert!(
        !output.status.success(),
        "unauthorized key unexpectedly succeeded"
    );

    adapter.abort();
    daemon.abort();
}
