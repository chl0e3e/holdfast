//! Connection grants (spec §5, "Connection grants and resume tokens").
//!
//! A grant is `base64url(claims_json) "." base64url(ed25519_sig)`. The issuer
//! holds the signing key; verifiers hold only the public key, so a
//! gateway/daemon validates a grant with no call back to the issuer
//! (asymmetric signatures, threat model T4). Claims carry the audience, the
//! allowed operations, an expiry and a unique token id.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GrantError {
    #[error("malformed grant encoding")]
    Malformed,
    #[error("invalid signature")]
    BadSignature,
    #[error("grant is for audience {found:?}, expected {expected:?}")]
    WrongAudience { found: String, expected: String },
    #[error("grant expired at {expires_at_ms} (now {now_ms})")]
    Expired { expires_at_ms: i64, now_ms: i64 },
    #[error("grant not yet valid (issued_at {issued_at_ms}, now {now_ms})")]
    NotYetValid { issued_at_ms: i64, now_ms: i64 },
}

/// Signed claims. Field names are stable wire format; keep them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantClaims {
    /// Authenticated user id (subject).
    pub sub: String,
    /// Gateway/daemon audience this grant is bound to (server id hex or host).
    pub aud: String,
    /// Allowed server ids (hex); empty = the issuing daemon's own server only.
    #[serde(default)]
    pub servers: Vec<String>,
    /// Allowed operations (e.g. "open", "attach", "terminate", "list").
    /// Empty = all operations the daemon supports.
    #[serde(default)]
    pub ops: Vec<String>,
    pub iat_ms: i64,
    pub exp_ms: i64,
    /// Unique token id (jti), for audit/replay tracing.
    pub jti: String,
}

impl GrantClaims {
    pub fn permits(&self, op: &str) -> bool {
        self.ops.is_empty() || self.ops.iter().any(|o| o == op)
    }
}

/// Holds the ed25519 signing key (issuer side only).
pub struct GrantSigner {
    signing: SigningKey,
}

impl GrantSigner {
    pub fn generate() -> GrantSigner {
        GrantSigner { signing: SigningKey::from_bytes(&rand::random()) }
    }

    pub fn from_bytes(secret: &[u8; 32]) -> GrantSigner {
        GrantSigner { signing: SigningKey::from_bytes(secret) }
    }

    pub fn verifier(&self) -> GrantVerifier {
        GrantVerifier { verifying: self.signing.verifying_key() }
    }

    pub fn issue(&self, claims: &GrantClaims) -> ConnectionGrant {
        let payload = serde_json::to_vec(claims).expect("claims serialize");
        let sig = self.signing.sign(&payload);
        let token = format!("{}.{}", B64.encode(&payload), B64.encode(sig.to_bytes()));
        ConnectionGrant(token)
    }
}

/// Holds only the public verification key.
#[derive(Clone)]
pub struct GrantVerifier {
    verifying: VerifyingKey,
}

impl GrantVerifier {
    pub fn from_public_bytes(bytes: &[u8; 32]) -> Result<GrantVerifier, GrantError> {
        VerifyingKey::from_bytes(bytes)
            .map(|verifying| GrantVerifier { verifying })
            .map_err(|_| GrantError::Malformed)
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.verifying.to_bytes()
    }

    /// Verify signature, audience and time window. Returns the claims on
    /// success so the caller can enforce per-operation scope.
    pub fn verify(
        &self,
        grant: &ConnectionGrant,
        expected_audience: &str,
        now_ms: i64,
    ) -> Result<GrantClaims, GrantError> {
        let (payload_b64, sig_b64) = grant.0.split_once('.').ok_or(GrantError::Malformed)?;
        let payload = B64.decode(payload_b64).map_err(|_| GrantError::Malformed)?;
        let sig_bytes = B64.decode(sig_b64).map_err(|_| GrantError::Malformed)?;
        let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| GrantError::Malformed)?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);

        self.verifying
            .verify(&payload, &signature)
            .map_err(|_| GrantError::BadSignature)?;

        let claims: GrantClaims =
            serde_json::from_slice(&payload).map_err(|_| GrantError::Malformed)?;

        if claims.aud != expected_audience {
            return Err(GrantError::WrongAudience {
                found: claims.aud.clone(),
                expected: expected_audience.to_string(),
            });
        }
        if now_ms >= claims.exp_ms {
            return Err(GrantError::Expired { expires_at_ms: claims.exp_ms, now_ms });
        }
        // Small clock-skew tolerance. Saturating so a near-i64::MAX host clock
        // wraps to a rejection, never a debug-build panic.
        if now_ms.saturating_add(60_000) < claims.iat_ms {
            return Err(GrantError::NotYetValid { issued_at_ms: claims.iat_ms, now_ms });
        }
        Ok(claims)
    }
}

/// The opaque grant token as it crosses the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionGrant(pub String);

impl ConnectionGrant {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
    pub fn from_wire(bytes: &[u8]) -> Result<ConnectionGrant, GrantError> {
        std::str::from_utf8(bytes)
            .map(|s| ConnectionGrant(s.to_string()))
            .map_err(|_| GrantError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(now: i64) -> GrantClaims {
        GrantClaims {
            sub: "alice".into(),
            aud: "srv_abc".into(),
            servers: vec![],
            ops: vec!["open".into(), "attach".into()],
            iat_ms: now,
            exp_ms: now + 60_000,
            jti: "jti-1".into(),
        }
    }

    #[test]
    fn issue_and_verify_roundtrip() {
        let signer = GrantSigner::generate();
        let grant = signer.issue(&claims(1000));
        let got = signer.verifier().verify(&grant, "srv_abc", 2000).unwrap();
        assert_eq!(got.sub, "alice");
        assert!(got.permits("open"));
        assert!(!got.permits("terminate"));
    }

    #[test]
    fn expired_grant_rejected() {
        let signer = GrantSigner::generate();
        let grant = signer.issue(&claims(1000));
        assert!(matches!(
            signer.verifier().verify(&grant, "srv_abc", 61_001),
            Err(GrantError::Expired { .. })
        ));
    }

    #[test]
    fn wrong_audience_rejected() {
        let signer = GrantSigner::generate();
        let grant = signer.issue(&claims(1000));
        assert!(matches!(
            signer.verifier().verify(&grant, "srv_other", 2000),
            Err(GrantError::WrongAudience { .. })
        ));
    }

    #[test]
    fn tampered_payload_fails_signature() {
        let signer = GrantSigner::generate();
        let grant = signer.issue(&claims(1000));
        // Flip a character in the payload segment.
        let (payload, sig) = grant.0.split_once('.').unwrap();
        let mut bytes = payload.as_bytes().to_vec();
        bytes[0] ^= 0x01;
        let tampered = ConnectionGrant(format!(
            "{}.{}",
            String::from_utf8_lossy(&bytes),
            sig
        ));
        assert!(matches!(
            signer.verifier().verify(&tampered, "srv_abc", 2000),
            Err(GrantError::BadSignature) | Err(GrantError::Malformed)
        ));
    }

    #[test]
    fn different_key_rejects() {
        let signer = GrantSigner::generate();
        let grant = signer.issue(&claims(1000));
        let other = GrantSigner::generate();
        assert!(matches!(
            other.verifier().verify(&grant, "srv_abc", 2000),
            Err(GrantError::BadSignature)
        ));
    }

    #[test]
    fn verifier_survives_public_key_roundtrip() {
        let signer = GrantSigner::generate();
        let pubkey = signer.verifier().public_bytes();
        let verifier = GrantVerifier::from_public_bytes(&pubkey).unwrap();
        let grant = signer.issue(&claims(1000));
        assert!(verifier.verify(&grant, "srv_abc", 2000).is_ok());
    }
}
