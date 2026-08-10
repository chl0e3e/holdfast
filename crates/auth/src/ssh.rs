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
//!
//! FIDO security keys (YubiKey and friends) work through the same flow with
//! no protocol change: `sk-ssh-ed25519@openssh.com` and
//! `sk-ecdsa-sha2-nistp256@openssh.com` keys are ordinary `authorized_keys`
//! entries, and `ssh-keygen -Y sign` drives the authenticator. What they add
//! is a trailing flags/counter block on the signature, which this module
//! *checks*: a signature that does not prove user presence is rejected, so a
//! key that was never touched cannot authenticate (see
//! [`SshError::UserPresenceMissing`]).

use ssh_key::public::KeyData;
use ssh_key::{Algorithm, AuthorizedKeys, HashAlg, PublicKey, SshSig};

use crate::SSH_NAMESPACE;

/// Trailer every security-key signature carries after the signature proper:
/// the authenticator's flags byte followed by its big-endian u32 counter.
const SK_SIGNATURE_TRAILER: usize = 5;
/// CTAP2 authenticator-data flag bit 0: a human was present at the
/// authenticator — for a YubiKey, that it was physically touched.
const FIDO_FLAG_USER_PRESENT: u8 = 0x01;
/// CTAP2 authenticator-data flag bit 2: the human was *verified* (PIN or
/// biometric), a strictly stronger statement than presence. Recorded for the
/// audit trail; not required, because `ssh-keygen -O verify-required` is a
/// per-key deployment choice rather than something this issuer can mandate.
const FIDO_FLAG_USER_VERIFIED: u8 = 0x04;

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
    #[error("security key did not prove user presence (the key was not touched)")]
    UserPresenceMissing,
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

        // Only now are the authenticator flags trustworthy: they are folded
        // into the bytes the signature covers, so reading them before the
        // verification above would be reading attacker-chosen input.
        let attestation = if is_security_key(signer_key) {
            let flags = sk_flags(&sig)?;
            if flags & FIDO_FLAG_USER_PRESENT == 0 {
                // sshd enforces the same thing unless the authorized_keys
                // entry carries `no-touch-required` — an option this crate
                // refuses to honor at all (see `from_authorized_keys`), so
                // every security key reaching here is one whose owner
                // intended a touch. Fail closed.
                return Err(SshError::UserPresenceMissing);
            }
            Some(SecurityKeyAttestation {
                user_verified: flags & FIDO_FLAG_USER_VERIFIED != 0,
            })
        } else {
            None
        };

        Ok(VerifiedIdentity {
            fingerprint: authorized_match.fingerprint(HashAlg::Sha256).to_string(),
            security_key: attestation,
        })
    }
}

/// Is this a FIDO security-key type, whose signatures carry a flags/counter
/// trailer? Both types OpenSSH defines are hardware-backed by construction.
fn is_security_key(key: &KeyData) -> bool {
    matches!(
        key.algorithm(),
        Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256
    )
}

/// The authenticator's flags byte, which sits immediately before the 4-byte
/// counter at the end of a security-key signature.
fn sk_flags(sig: &SshSig) -> Result<u8, SshError> {
    let bytes = sig.signature_bytes();
    bytes
        .len()
        .checked_sub(SK_SIGNATURE_TRAILER)
        .and_then(|index| bytes.get(index))
        .copied()
        .ok_or(SshError::MalformedSignature)
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
    /// `Some` when the key was a FIDO security key, in which case user
    /// presence has already been enforced. `None` for a software key.
    pub security_key: Option<SecurityKeyAttestation>,
}

/// What the authenticator attested beyond possession of the key. User presence
/// is not represented because verification fails without it.
#[derive(Debug, Clone)]
pub struct SecurityKeyAttestation {
    /// The authenticator verified the human (PIN or biometric), not merely
    /// their presence — i.e. the key was created with `-O verify-required`.
    pub user_verified: bool,
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

    /// A stand-in for the FIDO authenticator inside a YubiKey, so the
    /// verification path can be tested without hardware. It reproduces the
    /// construction from the `sk-ssh-ed25519@openssh.com` spec exactly: the
    /// device signs `sha256(application) || flags || counter || sha256(blob)`
    /// and returns the raw signature with the flags and counter appended.
    struct SecurityKey {
        signing: ed25519_dalek::SigningKey,
        application: String,
        public: PublicKey,
    }

    impl SecurityKey {
        fn new(seed: u8) -> SecurityKey {
            Self::with_application(seed, "ssh:")
        }

        fn with_application(seed: u8, application: &str) -> SecurityKey {
            let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
            let point = ssh_key::public::Ed25519PublicKey(signing.verifying_key().to_bytes());
            let public = PublicKey::new(
                KeyData::SkEd25519(ssh_key::public::SkEd25519::new(point, application)),
                "yubikey",
            );
            SecurityKey {
                signing,
                application: application.to_string(),
                public,
            }
        }

        fn authorized_line(&self) -> String {
            self.public.to_openssh().unwrap()
        }

        /// Sign as the authenticator would. `flags` is the CTAP2 flags byte —
        /// tests pass `0` to model a device that never saw a touch.
        fn sign(&self, message: &[u8], flags: u8, counter: u32) -> String {
            use ed25519_dalek::Signer as _;
            use sha2::{Digest, Sha256};

            let blob = SshSig::signed_data(SSH_NAMESPACE, HashAlg::Sha512, message).unwrap();
            let trailer = {
                let mut trailer = vec![flags];
                trailer.extend(counter.to_be_bytes());
                trailer
            };

            let mut signed = Vec::new();
            signed.extend(Sha256::digest(self.application.as_bytes()));
            signed.extend(&trailer);
            signed.extend(Sha256::digest(&blob));

            let mut data = self.signing.sign(&signed).to_bytes().to_vec();
            data.extend(&trailer);

            let signature = ssh_key::Signature::new(Algorithm::SkEd25519, data).unwrap();
            let sig = SshSig::new(
                self.public.key_data().clone(),
                SSH_NAMESPACE,
                HashAlg::Sha512,
                signature,
            )
            .unwrap();
            sig.to_pem(ssh_key::LineEnding::LF).unwrap()
        }
    }

    #[test]
    fn touched_security_key_authenticates() {
        let key = SecurityKey::new(1);
        let verifier = SshVerifier::from_authorized_keys(&key.authorized_line()).unwrap();
        verifier.is_authorized(&key.authorized_line()).unwrap();

        let challenge = new_challenge();
        let binding = [0xCDu8; 32];
        let message = channel_bound_message(&binding, &challenge);
        let pem = key.sign(&message, FIDO_FLAG_USER_PRESENT, 7);

        let identity = verifier
            .verify_response(&binding, &challenge, pem.as_bytes())
            .unwrap();
        assert!(identity.fingerprint.starts_with("SHA256:"));
        let attestation = identity
            .security_key
            .expect("a security key must be reported as one");
        assert!(
            !attestation.user_verified,
            "presence alone is not user verification"
        );
    }

    #[test]
    fn untouched_security_key_is_rejected() {
        // The signature is cryptographically valid and the key is authorized;
        // only the user-presence bit is clear. That must not authenticate, or
        // a key sitting plugged in overnight would be as good as a password.
        let key = SecurityKey::new(2);
        let verifier = SshVerifier::from_authorized_keys(&key.authorized_line()).unwrap();

        let challenge = new_challenge();
        let message = channel_bound_message(b"", &challenge);
        let pem = key.sign(&message, 0, 1);

        assert!(matches!(
            verifier.verify_response(b"", &challenge, pem.as_bytes()),
            Err(SshError::UserPresenceMissing)
        ));
    }

    #[test]
    fn user_verified_security_key_is_reported() {
        let key = SecurityKey::new(3);
        let verifier = SshVerifier::from_authorized_keys(&key.authorized_line()).unwrap();

        let challenge = new_challenge();
        let message = channel_bound_message(b"", &challenge);
        let pem = key.sign(&message, FIDO_FLAG_USER_PRESENT | FIDO_FLAG_USER_VERIFIED, 9);

        let identity = verifier
            .verify_response(b"", &challenge, pem.as_bytes())
            .unwrap();
        assert!(identity.security_key.unwrap().user_verified);
    }

    #[test]
    fn security_key_signature_is_channel_bound_too() {
        // ADR 0008 must hold for hardware keys as well: the authenticator
        // signs over the binding, so a relayed signature still fails.
        let key = SecurityKey::new(4);
        let verifier = SshVerifier::from_authorized_keys(&key.authorized_line()).unwrap();

        let challenge = new_challenge();
        let attacker_binding = [0xAAu8; 32];
        let real_binding = [0xBBu8; 32];
        let pem = key.sign(
            &channel_bound_message(&attacker_binding, &challenge),
            FIDO_FLAG_USER_PRESENT,
            1,
        );

        assert!(matches!(
            verifier.verify_response(&real_binding, &challenge, pem.as_bytes()),
            Err(SshError::BadSignature)
        ));
        assert!(verifier
            .verify_response(&attacker_binding, &challenge, pem.as_bytes())
            .is_ok());
    }

    #[test]
    fn a_different_authenticator_application_is_a_different_key() {
        // The application string is part of the key, so a credential scoped to
        // another relying party cannot stand in for this one.
        let enrolled = SecurityKey::with_application(5, "ssh:");
        let other = SecurityKey::with_application(5, "ssh:somewhere-else");
        let verifier = SshVerifier::from_authorized_keys(&enrolled.authorized_line()).unwrap();

        assert!(matches!(
            verifier.is_authorized(&other.authorized_line()),
            Err(SshError::KeyNotAuthorized)
        ));

        let challenge = new_challenge();
        let pem = other.sign(
            &channel_bound_message(b"", &challenge),
            FIDO_FLAG_USER_PRESENT,
            1,
        );
        assert!(matches!(
            verifier.verify_response(b"", &challenge, pem.as_bytes()),
            Err(SshError::KeyNotAuthorized)
        ));
    }

    #[test]
    fn software_keys_report_no_security_key() {
        let (private, authorized_line) = keypair();
        let verifier = SshVerifier::from_authorized_keys(&authorized_line).unwrap();
        let challenge = new_challenge();
        let sig = private
            .sign(SSH_NAMESPACE, HashAlg::Sha512, &challenge)
            .unwrap();
        let pem = sig.to_pem(ssh_key::LineEnding::LF).unwrap();

        let identity = verifier
            .verify_response(b"", &challenge, pem.as_bytes())
            .unwrap();
        assert!(identity.security_key.is_none());
    }

    /// The same construction for `sk-ecdsa-sha2-nistp256@openssh.com`, the
    /// type every FIDO2 YubiKey can do (`ed25519-sk` needs firmware 5.2.3+).
    /// Its verification lives behind ssh-key's "p256" feature, so this test is
    /// what proves that feature is actually enabled — without it the key type
    /// is rejected as unsupported rather than verified.
    fn sk_ecdsa_signed_pem(
        signing: &p256::ecdsa::SigningKey,
        application: &str,
        message: &[u8],
        flags: u8,
        counter: u32,
    ) -> (PublicKey, String) {
        use p256::ecdsa::signature::Signer as _;
        use sha2::{Digest, Sha256};

        let point = signing.verifying_key().to_encoded_point(false);
        let public = PublicKey::new(
            // ssh-key's `EcdsaNistP256PublicKey` is p256's own SEC1 encoded
            // point (`sec1::EncodedPoint<U32>`); it just is not re-exported.
            KeyData::SkEcdsaSha2NistP256(ssh_key::public::SkEcdsaSha2NistP256::new(
                point,
                application,
            )),
            "yubikey",
        );

        let blob = SshSig::signed_data(SSH_NAMESPACE, HashAlg::Sha512, message).unwrap();
        let mut trailer = vec![flags];
        trailer.extend(counter.to_be_bytes());

        let mut signed = Vec::new();
        signed.extend(Sha256::digest(application.as_bytes()));
        signed.extend(&trailer);
        signed.extend(Sha256::digest(&blob));

        let signature: p256::ecdsa::Signature = signing.sign(&signed);
        let (r, s) = signature.split_bytes();
        let mut rs = mpint(&r);
        rs.extend(mpint(&s));

        // Assembled by hand rather than via `SshSig::to_pem`, because
        // ssh-key 0.6's *encoder* only splits the flags/counter trailer back
        // out for sk-ed25519 — an sk-ecdsa signature it wrote would not
        // survive its own decoder. Nothing in Holdfast encodes one; this
        // reproduces the bytes `ssh-keygen` actually puts on the wire, so the
        // decode-and-verify path under test is the production one.
        let mut signature_blob = ssh_string(b"sk-ecdsa-sha2-nistp256@openssh.com");
        signature_blob.extend(ssh_string(&rs));
        signature_blob.extend(&trailer);

        (public.clone(), armored_sshsig(&public, &signature_blob))
    }

    /// An OpenSSH `string`: big-endian u32 length followed by the bytes.
    fn ssh_string(bytes: &[u8]) -> Vec<u8> {
        let mut out = (bytes.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(bytes);
        out
    }

    /// The armored `SSHSIG` container from OpenSSH's PROTOCOL.sshsig.
    fn armored_sshsig(public: &PublicKey, signature_blob: &[u8]) -> String {
        use base64::Engine as _;

        let mut blob = b"SSHSIG".to_vec();
        blob.extend(1u32.to_be_bytes()); // version
        blob.extend(ssh_string(&public.to_bytes().unwrap()));
        blob.extend(ssh_string(SSH_NAMESPACE.as_bytes()));
        blob.extend(ssh_string(b"")); // reserved
        blob.extend(ssh_string(b"sha512"));
        blob.extend(ssh_string(signature_blob));

        let encoded = base64::engine::general_purpose::STANDARD.encode(&blob);
        let mut pem = String::from("-----BEGIN SSH SIGNATURE-----\n");
        for line in encoded.as_bytes().chunks(70) {
            pem.push_str(std::str::from_utf8(line).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END SSH SIGNATURE-----\n");
        pem
    }

    /// OpenSSH `mpint`: a length-prefixed big-endian integer, zero-padded when
    /// the top bit would otherwise read as a negative number.
    fn mpint(bytes: &[u8]) -> Vec<u8> {
        let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
        let trimmed = &bytes[start..];
        let mut body = Vec::new();
        if trimmed.first().is_some_and(|b| b & 0x80 != 0) {
            body.push(0);
        }
        body.extend_from_slice(trimmed);
        let mut out = (body.len() as u32).to_be_bytes().to_vec();
        out.extend(body);
        out
    }

    #[test]
    fn touched_ecdsa_security_key_authenticates() {
        let signing = p256::ecdsa::SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let challenge = new_challenge();
        let message = channel_bound_message(b"", &challenge);
        let (public, pem) =
            sk_ecdsa_signed_pem(&signing, "ssh:", &message, FIDO_FLAG_USER_PRESENT, 3);

        let verifier = SshVerifier::from_authorized_keys(&public.to_openssh().unwrap()).unwrap();
        let identity = verifier
            .verify_response(b"", &challenge, pem.as_bytes())
            .expect("sk-ecdsa must verify — needs ssh-key's \"p256\" feature");
        assert!(identity.security_key.is_some());
    }

    #[test]
    fn untouched_ecdsa_security_key_is_rejected() {
        let signing = p256::ecdsa::SigningKey::from_bytes(&[11u8; 32].into()).unwrap();
        let challenge = new_challenge();
        let message = channel_bound_message(b"", &challenge);
        let (public, pem) = sk_ecdsa_signed_pem(&signing, "ssh:", &message, 0, 4);

        let verifier = SshVerifier::from_authorized_keys(&public.to_openssh().unwrap()).unwrap();
        assert!(matches!(
            verifier.verify_response(b"", &challenge, pem.as_bytes()),
            Err(SshError::UserPresenceMissing)
        ));
    }

    #[test]
    fn security_keys_with_options_are_skipped_like_any_other() {
        // `no-touch-required` is the option that would disable the presence
        // check. Holdfast honors no options, so such a key is skipped outright
        // rather than silently authenticating without a touch.
        let key = SecurityKey::new(6);
        let restricted = format!("no-touch-required {}", key.authorized_line());
        assert!(matches!(
            SshVerifier::from_authorized_keys(&restricted),
            Err(SshError::NoAuthorizedKeys)
        ));
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
