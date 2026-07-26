//! Opaque 128-bit identifiers (spec §15). Authorization keys are these IDs,
//! never display names. Rendered as lowercase hex with a type prefix.

use std::{fmt, str::FromStr};

macro_rules! opaque_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub [u8; 16]);

        impl $name {
            pub const WIRE_LEN: usize = 16;

            /// Parse from wire bytes; rejects any length other than 16.
            pub fn from_wire(bytes: &[u8]) -> Result<$name, IdError> {
                let arr: [u8; 16] = bytes
                    .try_into()
                    .map_err(|_| IdError::BadLength(bytes.len()))?;
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

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let hex = value.strip_prefix(concat!($prefix, "_")).unwrap_or(value);
                if hex.len() != 32 {
                    return Err(IdError::BadEncoding);
                }
                let mut bytes = [0u8; 16];
                for (index, slot) in bytes.iter_mut().enumerate() {
                    *slot = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
                        .map_err(|_| IdError::BadEncoding)?;
                }
                Ok($name(bytes))
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
    #[error("opaque ID must be 32 hexadecimal digits, optionally with its type prefix")]
    BadEncoding,
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
        let server = ServerId([0x12; 16]);
        assert_eq!(server.to_string().parse::<ServerId>().unwrap(), server);
        assert_eq!("12".repeat(16).parse::<ServerId>().unwrap(), server);
        assert!("srv_not-hex".parse::<ServerId>().is_err());
    }
}
