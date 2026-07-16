//! Opaque 128-bit identifiers (spec §15). Authorization keys are these IDs,
//! never display names. Rendered as lowercase hex with a type prefix.

use std::fmt;

macro_rules! opaque_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub [u8; 16]);

        impl $name {
            pub const WIRE_LEN: usize = 16;

            /// Parse from wire bytes; rejects any length other than 16.
            pub fn from_wire(bytes: &[u8]) -> Result<$name, IdError> {
                let arr: [u8; 16] =
                    bytes.try_into().map_err(|_| IdError::BadLength(bytes.len()))?;
                Ok($name(arr))
            }

            pub fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }

            pub fn to_wire(&self) -> Vec<u8> {
                self.0.to_vec()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}_", $prefix)?;
                for b in self.0 {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self, f)
            }
        }
    };
}

opaque_id!(ServerId, "srv");
opaque_id!(ShellId, "sh");

#[derive(Debug, thiserror::Error)]
pub enum IdError {
    #[error("opaque ID must be 16 bytes, got {0}")]
    BadLength(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_roundtrip_and_display() {
        let id = ShellId([0xAB; 16]);
        assert_eq!(ShellId::from_wire(&id.to_wire()).unwrap(), id);
        assert_eq!(id.to_string(), format!("sh_{}", "ab".repeat(16)));
        assert!(ServerId::from_wire(&[1, 2, 3]).is_err());
        assert!(ServerId::from_wire(&[]).is_err());
    }
}
