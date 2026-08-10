//! End-to-end check against a **real** FIDO security key (YubiKey), the one
//! part of the flow that unit tests can only simulate: the unit tests in
//! `ssh::tests` build the `sk-ssh-ed25519@openssh.com` signature themselves,
//! so they prove the verifier implements the format — not that a physical
//! authenticator produces what the verifier expects.
//!
//! Opt-in, because it needs hardware and two touches:
//!
//!   HOLDFAST_SECURITY_KEY_TEST=1 cargo test -p hf-auth --test security_key_cli -- --nocapture
//!
//! Without the variable it passes immediately, so CI and ordinary runs are
//! unaffected. Enrolment writes to a temporary directory that is removed on
//! the way out; the credential itself lives on the key and is discardable.

use std::path::PathBuf;
use std::process::{Command, Stdio};

use hf_auth::ssh::{channel_bound_message, new_challenge};
use hf_auth::{SshError, SshVerifier};

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn real_security_key_authenticates_and_is_channel_bound() {
    if std::env::var_os("HOLDFAST_SECURITY_KEY_TEST").is_none() {
        eprintln!("HOLDFAST_SECURITY_KEY_TEST unset; skipping (needs a plugged-in YubiKey)");
        return;
    }

    let dir = TempDir(std::env::temp_dir().join(format!(
        "holdfast-securitykey-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    std::fs::create_dir(&dir.0).unwrap();
    let key_path = dir.0.join("id_ed25519_sk");

    // Enrol a discardable credential. ed25519-sk needs YubiKey firmware
    // 5.2.3+; on older keys swap in `-t ecdsa-sk`, which the verifier accepts
    // through the same path (that is what the "p256" ssh-key feature buys).
    eprintln!("== touch your security key to enrol a test credential ==");
    let generated = Command::new("ssh-keygen")
        .args(["-t", "ed25519-sk", "-N", "", "-q", "-f"])
        .arg(&key_path)
        .status()
        .expect("run ssh-keygen");
    assert!(
        generated.success(),
        "could not enrol an ed25519-sk credential — is a security key plugged in, \
         and was this ssh-keygen built with FIDO support?"
    );

    let public_line = std::fs::read_to_string(key_path.with_extension("pub")).unwrap();
    assert!(
        public_line.starts_with("sk-ssh-ed25519@openssh.com"),
        "expected a security-key public key, got: {public_line}"
    );

    let verifier = SshVerifier::from_authorized_keys(&public_line).unwrap();
    verifier
        .is_authorized(&public_line)
        .expect("the enrolled key is its own authorized key");

    let challenge = new_challenge();
    let binding = [0x42u8; 32]; // stand-in for the server certificate hash
    let message = channel_bound_message(&binding, &challenge);

    eprintln!("== touch your security key again to sign the challenge ==");
    let mut child = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-n", "holdfast-auth@v0", "-f"])
        .arg(&key_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn ssh-keygen -Y sign");
    use std::io::Write;
    child.stdin.take().unwrap().write_all(&message).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "ssh-keygen -Y sign failed");
    let signature_pem = output.stdout;

    let identity = verifier
        .verify_response(&binding, &challenge, &signature_pem)
        .expect("a touched security key must authenticate");
    let attestation = identity
        .security_key
        .expect("must be recognised as hardware-backed");
    eprintln!(
        "authenticated {} (user_verified={})",
        identity.fingerprint, attestation.user_verified
    );

    // The hardware signature is channel-bound like any other (ADR 0008).
    assert!(
        matches!(
            verifier.verify_response(&[0x43u8; 32], &challenge, &signature_pem),
            Err(SshError::BadSignature)
        ),
        "signature must be bound to the certificate hash"
    );
}
