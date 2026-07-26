//! The browser login flow (ADR 0014 deployment) has the user sign the
//! channel-bound challenge with the real OpenSSH binary:
//!
//!   echo <b64> | base64 -d | ssh-keygen -Y sign -f <key> -n holdfast-auth@v0
//!
//! This test locks in that compatibility: a signature produced by the actual
//! `ssh-keygen` CLI must verify through the same `SshVerifier` path the
//! daemon uses. Skips (passes) when ssh-keygen is not installed.
//!
//! Reproduce with: `cargo test -p hf-auth --test ssh_keygen_cli`

use std::path::PathBuf;
use std::process::{Command, Stdio};

use hf_auth::ssh::{channel_bound_message, new_challenge};
use hf_auth::SshVerifier;

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn signature_from_real_ssh_keygen_verifies() {
    if Command::new("ssh-keygen").arg("-?").output().is_err() {
        eprintln!("ssh-keygen not installed; skipping");
        return;
    }
    let dir = TempDir(std::env::temp_dir().join(format!(
        "holdfast-sshkeygen-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    std::fs::create_dir(&dir.0).unwrap();
    let key_path = dir.0.join("id_ed25519");

    let generated = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-q", "-f"])
        .arg(&key_path)
        .status()
        .unwrap();
    assert!(generated.success());
    let public_line = std::fs::read_to_string(key_path.with_extension("pub")).unwrap();

    let verifier = SshVerifier::from_authorized_keys(&public_line).unwrap();
    let challenge = new_challenge();
    let binding = [0x42u8; 32]; // stand-in for the server certificate hash
    let message = channel_bound_message(&binding, &challenge);

    // Sign over stdin/stdout exactly as the browser instructs the user to.
    let mut child = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-n", "holdfast-auth@v0", "-f"])
        .arg(&key_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    use std::io::Write;
    child.stdin.take().unwrap().write_all(&message).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "ssh-keygen -Y sign failed");
    let signature_pem = output.stdout;
    assert!(signature_pem.starts_with(b"-----BEGIN SSH SIGNATURE-----"));

    let identity = verifier
        .verify_response(&binding, &challenge, &signature_pem)
        .expect("CLI-produced SSHSIG must verify");
    assert!(!identity.fingerprint.is_empty());

    // Wrong binding (a different server's certificate) must fail.
    let err = verifier.verify_response(&[0x43u8; 32], &challenge, &signature_pem);
    assert!(
        err.is_err(),
        "signature must be bound to the certificate hash"
    );
}
