//! Local issuer: SSH public-key challenge/response (spec §5).
//!
//! Flow (rides in the `Authenticate` message, spec §5/§6):
//!   1. client → `SshChallengeRequest { username, public_key }`
//!   2. server: is `public_key` in this user's `authorized_keys`? If not,
//!      fail *without* revealing whether the user or the key was the problem.
//!   3. server → random 32-byte challenge nonce.
//!   4. client signs the nonce with the matching private key
//!      (`ssh-keygen -Y sign -n holdfast-auth@v0`) → `SshChallengeResponse`.
//!   5. server verifies the SshSig against the offered (authorized) key.
//!
//! The signature is an `SshSig` (PEM), so any OpenSSH key type ssh-key
//! supports (ed25519, RSA, ECDSA) works and clients can use standard tooling.

use ssh_key::{AuthorizedKeys, HashAlg, PublicKey, SshSig};

use crate::SSH_NAMESPACE;

#[derive(Debug, thiserror::Error)]
pub enum SshError {
    #[error("no authorized_keys available for user")]
    NoAuthorizedKeys,
    #[error("offered key is not authorized")]
    KeyNotAuthorized,
    #[error("malformed public key")]
    MalformedKey,
    #[error("malformed signature")]
    MalformedSignature,
    #[error("signature verification failed")]
    BadSignature,
    #[error("challenge mismatch")]
    ChallengeMismatch,
}

/// Resolves and verifies against a user's authorized public keys.
///
/// The set is captured up front (e.g. read from `~<user>/.ssh/authorized_keys`
/// by a caller that has already validated the account against policy). This
/// crate never maps usernames to home directories itself — that decision
/// belongs to the daemon/launcher with the right privileges.
pub struct SshVerifier {
    authorized: Vec<PublicKey>,
}

impl SshVerifier {
    /// Build from OpenSSH `authorized_keys` text.
    ///
    /// Comments are ignored. Any entry that carries **options**
    /// (`command="..."`, `restrict`, `from="..."`, `expiry-time="..."`,
    /// `no-pty`, …) is **skipped, not honored**: Holdfast does not implement
    /// OpenSSH's per-key restrictions, and silently treating a restricted key
    /// as full-access would be a privilege escalation. Skipping fails closed —
    /// a key an admin deliberately constrained cannot authenticate here at all,
    /// rather than authenticating with more access than intended. If every
    /// entry is skipped (or the file is empty), this returns
    /// [`SshError::NoAuthorizedKeys`].
    pub fn from_authorized_keys(text: &str) -> Result<SshVerifier, SshError> {
        let authorized: Vec<PublicKey> = AuthorizedKeys::new(text)
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.config_opts().is_empty())
            .map(|entry| entry.public_key().clone())
            .collect();
        if authorized.is_empty() {
            return Err(SshError::NoAuthorizedKeys);
        }
        Ok(SshVerifier { authorized })
    }

    pub fn from_keys(authorized: Vec<PublicKey>) -> Result<SshVerifier, SshError> {
        if authorized.is_empty() {
            return Err(SshError::NoAuthorizedKeys);
        }
        Ok(SshVerifier { authorized })
    }

    /// Step 2: is the offered key (OpenSSH one-line text, e.g.
    /// `ssh-ed25519 AAAA... comment`) authorized? Always scans the whole set.
    pub fn is_authorized(&self, offered_openssh: &str) -> Result<(), SshError> {
        let offered =
            PublicKey::from_openssh(offered_openssh).map_err(|_| SshError::MalformedKey)?;
        let mut found = false;
        for key in &self.authorized {
            // Compare key material, not comments.
            found |= key.key_data() == offered.key_data();
        }
        if found {
            Ok(())
        } else {
            Err(SshError::KeyNotAuthorized)
        }
    }

    /// Step 5: verify a signature over the channel-bound challenge. Confirms
    /// (a) the SshSig's embedded key is authorized, (b) the SshSig namespace is
    /// ours, and (c) the signature is valid over exactly
    /// [`channel_bound_message(channel_binding, challenge)`].
    ///
    /// `channel_binding` binds the signature to the TLS channel the client
    /// authenticated over (the server's WebTransport certificate hash), so a
    /// relayed signature — produced against the attacker's channel — fails here
    /// (ADR 0008). Pass an empty slice for transports without a usable binding
    /// (e.g. the nginx-terminated WebSocket path), which reproduces the
    /// unbound behavior.
    pub fn verify_response(
        &self,
        channel_binding: &[u8],
        challenge: &[u8],
        signature_pem: &[u8],
    ) -> Result<VerifiedIdentity, SshError> {
        let sig = SshSig::from_pem(signature_pem).map_err(|_| SshError::MalformedSignature)?;
        if sig.namespace() != SSH_NAMESPACE {
            return Err(SshError::BadSignature);
        }

        // The key that produced the signature must itself be authorized.
        let signer_key = sig.public_key();
        let authorized_match = self
            .authorized
            .iter()
            .find(|k| k.key_data() == signer_key)
            .ok_or(SshError::KeyNotAuthorized)?;

        let message = channel_bound_message(channel_binding, challenge);
        authorized_match
            .verify(SSH_NAMESPACE, &message, &sig)
            .map_err(|_| SshError::BadSignature)?;

        Ok(VerifiedIdentity {
            fingerprint: authorized_match.fingerprint(HashAlg::Sha256).to_string(),
        })
    }
}

/// The exact bytes a client signs and the server verifies: the TLS channel
/// binding followed by the server nonce (ADR 0008). Both sides compute this
/// identically; the client uses the certificate hash it pinned, the server its
/// own certificate hash. A relay sees the two diverge and the signature fails.
/// The binding is fixed-length per transport (a 32-byte cert hash, or empty),
/// so the plain concatenation is unambiguous.
pub fn channel_bound_message(channel_binding: &[u8], challenge: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(channel_binding.len() + challenge.len());
    message.extend_from_slice(channel_binding);
    message.extend_from_slice(challenge);
    message
}

/// Successful verification; the SHA-256 key fingerprint identifies which
/// authorized key was used (safe to log — threat model T10).
#[derive(Debug, Clone)]
pub struct VerifiedIdentity {
    pub fingerprint: String,
}

/// Generate a random 32-byte challenge nonce (spec §5).
pub fn new_challenge() -> [u8; 32] {
    rand::random()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, PrivateKey};

    fn keypair() -> (PrivateKey, String) {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let authorized_line = key.public_key().to_openssh().unwrap();
        (key, authorized_line)
    }

    #[test]
    fn authorized_key_challenge_response_succeeds() {
        let (private, authorized_line) = keypair();
        let verifier = SshVerifier::from_authorized_keys(&authorized_line).unwrap();

        let offered = private.public_key().to_openssh().unwrap();
        verifier.is_authorized(&offered).unwrap();

        let challenge = new_challenge();
        let sig = private
            .sign(SSH_NAMESPACE, HashAlg::Sha512, &challenge)
            .unwrap();
        let pem = sig.to_pem(ssh_key::LineEnding::LF).unwrap();

        let identity = verifier
            .verify_response(b"", &challenge, pem.as_bytes())
            .unwrap();
        assert!(identity.fingerprint.starts_with("SHA256:"));
    }

    #[test]
    fn unauthorized_key_is_rejected() {
        let (_authorized_priv, authorized_line) = keypair();
        let verifier = SshVerifier::from_authorized_keys(&authorized_line).unwrap();

        let (attacker, _) = keypair();
        let offered = attacker.public_key().to_openssh().unwrap();
        assert!(matches!(
            verifier.is_authorized(&offered),
            Err(SshError::KeyNotAuthorized)
        ));

        // Even with a valid signature, an unauthorized key fails verification.
        let challenge = new_challenge();
        let sig = attacker
            .sign(SSH_NAMESPACE, HashAlg::Sha512, &challenge)
            .unwrap();
        let pem = sig.to_pem(ssh_key::LineEnding::LF).unwrap();
        assert!(matches!(
            verifier.verify_response(b"", &challenge, pem.as_bytes()),
            Err(SshError::KeyNotAuthorized)
        ));
    }

    #[test]
    fn channel_binding_defeats_a_relayed_signature() {
        // The client signs over its channel binding + the nonce. A verifier
        // presenting a *different* binding (a relay forwarding to the real
        // server R while the client signed against attacker M's channel) must
        // reject, even though the key is authorized and the nonce matches.
        let (private, authorized_line) = keypair();
        let verifier = SshVerifier::from_authorized_keys(&authorized_line).unwrap();

        let challenge = new_challenge();
        let attacker_binding = [0xAAu8; 32]; // M's cert hash, what the client saw
        let real_binding = [0xBBu8; 32]; // R's cert hash, what R verifies against

        let signed = channel_bound_message(&attacker_binding, &challenge);
        let sig = private
            .sign(SSH_NAMESPACE, HashAlg::Sha512, &signed)
            .unwrap();
        let pem = sig.to_pem(ssh_key::LineEnding::LF).unwrap();

        // R (real binding) rejects the relayed signature.
        assert!(matches!(
            verifier.verify_response(&real_binding, &challenge, pem.as_bytes()),
            Err(SshError::BadSignature)
        ));
        // The same signature verifies against the binding it was made for.
        assert!(verifier
            .verify_response(&attacker_binding, &challenge, pem.as_bytes())
            .is_ok());
    }

    #[test]
    fn signature_over_wrong_challenge_fails() {
        let (private, authorized_line) = keypair();
        let verifier = SshVerifier::from_authorized_keys(&authorized_line).unwrap();

        let signed_challenge = new_challenge();
        let sig = private
            .sign(SSH_NAMESPACE, HashAlg::Sha512, &signed_challenge)
            .unwrap();
        let pem = sig.to_pem(ssh_key::LineEnding::LF).unwrap();

        let server_challenge = new_challenge(); // different nonce
        assert!(matches!(
            verifier.verify_response(b"", &server_challenge, pem.as_bytes()),
            Err(SshError::BadSignature)
        ));
    }

    #[test]
    fn wrong_namespace_rejected() {
        let (private, authorized_line) = keypair();
        let verifier = SshVerifier::from_authorized_keys(&authorized_line).unwrap();
        let challenge = new_challenge();
        let sig = private
            .sign("some-other-namespace", HashAlg::Sha512, &challenge)
            .unwrap();
        let pem = sig.to_pem(ssh_key::LineEnding::LF).unwrap();
        assert!(matches!(
            verifier.verify_response(b"", &challenge, pem.as_bytes()),
            Err(SshError::BadSignature)
        ));
    }

    #[test]
    fn multiple_authorized_keys_any_matches() {
        let (p1, line1) = keypair();
        let (_p2, line2) = keypair();
        let verifier = SshVerifier::from_authorized_keys(&format!("{line1}\n{line2}\n")).unwrap();
        let challenge = new_challenge();
        let sig = p1.sign(SSH_NAMESPACE, HashAlg::Sha512, &challenge).unwrap();
        let pem = sig.to_pem(ssh_key::LineEnding::LF).unwrap();
        assert!(verifier
            .verify_response(b"", &challenge, pem.as_bytes())
            .is_ok());
    }

    #[test]
    fn empty_authorized_keys_errors() {
        assert!(matches!(
            SshVerifier::from_authorized_keys("# only a comment\n"),
            Err(SshError::NoAuthorizedKeys)
        ));
    }

    #[test]
    fn keys_with_options_are_skipped_not_granted_full_access() {
        // A key an admin deliberately restricted must not authenticate with
        // full access. Holdfast can't honor the restriction, so it fails closed.
        let (private, line) = keypair();
        for opts in [
            "command=\"/usr/bin/backup\"",
            "restrict",
            "from=\"10.0.0.0/8\"",
            "no-pty",
        ] {
            let restricted = format!("{opts} {line}");
            // The only entry is restricted → nothing authorizable remains.
            assert!(
                matches!(
                    SshVerifier::from_authorized_keys(&restricted),
                    Err(SshError::NoAuthorizedKeys)
                ),
                "restricted-only file must yield no authorized keys ({opts})"
            );
            // And the restricted key genuinely cannot authenticate.
            if let Ok(v) = SshVerifier::from_authorized_keys(&restricted) {
                let offered = private.public_key().to_openssh().unwrap();
                assert!(v.is_authorized(&offered).is_err());
            }
        }
    }

    #[test]
    fn unrestricted_key_alongside_a_restricted_one_still_works() {
        // A plain key is honored; a restricted sibling is ignored, not fatal.
        let (plain_priv, plain_line) = keypair();
        let (_restricted_priv, restricted_line) = keypair();
        let text = format!("command=\"/x\" {restricted_line}\n{plain_line}\n");
        let verifier = SshVerifier::from_authorized_keys(&text).unwrap();
        let offered = plain_priv.public_key().to_openssh().unwrap();
        assert!(
            verifier.is_authorized(&offered).is_ok(),
            "the unrestricted key authenticates"
        );
    }
}
