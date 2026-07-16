//! Resume tokens (spec §12): random, rotated on every successful attach,
//! stored server-side only as a SHA-256 hash. Opaque to clients.

use sha2::{Digest, Sha256};

#[derive(Clone, PartialEq, Eq)]
pub struct ResumeToken([u8; 32]);

impl ResumeToken {
    pub fn generate() -> ResumeToken {
        ResumeToken(rand::random())
    }

    pub fn from_wire(bytes: &[u8]) -> Option<ResumeToken> {
        bytes.try_into().ok().map(ResumeToken)
    }

    pub fn to_wire(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// The only form the server retains (spec §12).
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }
}

/// Never print token material (threat model T10).
impl std::fmt::Debug for ResumeToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResumeToken(redacted)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_and_wire_roundtrip() {
        let a = ResumeToken::generate();
        let b = ResumeToken::generate();
        assert_ne!(a.hash(), b.hash());
        let back = ResumeToken::from_wire(&a.to_wire()).unwrap();
        assert_eq!(back.hash(), a.hash());
        assert!(ResumeToken::from_wire(&[1, 2, 3]).is_none());
    }

    #[test]
    fn debug_redacts_material() {
        assert_eq!(format!("{:?}", ResumeToken::generate()), "ResumeToken(redacted)");
    }
}
