//! Version and capability negotiation (spec §4).

use crate::pb::{Capability, ClientHello, Encoding, ServerHello};
use crate::{FRAME_BYTES_CEILING, FRAME_BYTES_FLOOR, PROTOCOL_MAJOR, PROTOCOL_MINOR};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    pub protocol_major: u32,
    pub protocol_minor: u32,
    pub capabilities: Vec<Capability>,
    pub max_frame_bytes: u32,
    pub max_datagram_bytes: u32,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NegotiationError {
    #[error("incompatible protocol major version {client} (server implements {server})")]
    MajorVersion { client: u32, server: u32 },
    #[error("client does not support UTF-8 encoding")]
    NoUtf8,
    #[error("proposed max_frame_bytes {0} is below the protocol floor {FRAME_BYTES_FLOOR}")]
    FrameLimitTooSmall(u32),
}

/// Server-side negotiation over a received `ClientHello`.
///
/// `server_capabilities` lists what this deployment enables;
/// `transport_supports_datagrams` reflects the actual transport (spec §2 —
/// WebSocket fallback reports false, which strips `CAPABILITY_DATAGRAMS`
/// regardless of what both sides wanted).
pub fn negotiate_server(
    hello: &ClientHello,
    server_capabilities: &[Capability],
    server_max_frame_bytes: u32,
    server_max_datagram_bytes: u32,
    transport_supports_datagrams: bool,
) -> Result<Negotiated, NegotiationError> {
    if hello.protocol_major != PROTOCOL_MAJOR {
        return Err(NegotiationError::MajorVersion {
            client: hello.protocol_major,
            server: PROTOCOL_MAJOR,
        });
    }
    if !hello.encodings.contains(&(Encoding::Utf8 as i32)) {
        return Err(NegotiationError::NoUtf8);
    }
    if hello.max_frame_bytes < FRAME_BYTES_FLOOR {
        return Err(NegotiationError::FrameLimitTooSmall(hello.max_frame_bytes));
    }

    // A capability is enabled only if both sides listed it (spec §4).
    let mut capabilities: Vec<Capability> = server_capabilities
        .iter()
        .copied()
        .filter(|c| hello.capabilities.contains(&(*c as i32)))
        .collect();
    if !transport_supports_datagrams {
        capabilities.retain(|c| *c != Capability::Datagrams);
    }

    Ok(Negotiated {
        protocol_major: PROTOCOL_MAJOR,
        // Both sides behave as the lower minor version.
        protocol_minor: hello.protocol_minor.min(PROTOCOL_MINOR),
        capabilities,
        max_frame_bytes: hello
            .max_frame_bytes
            .min(server_max_frame_bytes)
            .min(FRAME_BYTES_CEILING),
        max_datagram_bytes: hello.max_datagram_bytes.min(server_max_datagram_bytes),
    })
}

/// Build the `ServerHello` announcing the negotiated parameters.
pub fn server_hello(negotiated: &Negotiated, keepalive_interval_ms: u32) -> ServerHello {
    ServerHello {
        protocol_major: negotiated.protocol_major,
        protocol_minor: negotiated.protocol_minor,
        capabilities: negotiated.capabilities.iter().map(|c| *c as i32).collect(),
        max_frame_bytes: negotiated.max_frame_bytes,
        max_datagram_bytes: negotiated.max_datagram_bytes,
        keepalive_interval_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::ClientKind;

    fn hello() -> ClientHello {
        ClientHello {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: 7, // newer client minor than ours
            client_kind: ClientKind::NativeQuic as i32,
            client_build: "test".into(),
            capabilities: vec![Capability::Datagrams as i32, Capability::Clipboard as i32],
            max_frame_bytes: 512 * 1024,
            max_datagram_bytes: 1400,
            encodings: vec![Encoding::Utf8 as i32],
        }
    }

    const SERVER_CAPS: &[Capability] = &[Capability::Datagrams];

    #[test]
    fn happy_path_intersects_and_clamps() {
        let n = negotiate_server(&hello(), SERVER_CAPS, 256 * 1024, 1200, true).unwrap();
        assert_eq!(n.protocol_minor, PROTOCOL_MINOR, "lower minor wins");
        // Clipboard offered by client only; Datagrams by both.
        assert_eq!(n.capabilities, vec![Capability::Datagrams]);
        assert_eq!(n.max_frame_bytes, 256 * 1024, "min of both sides");
        assert_eq!(n.max_datagram_bytes, 1200);
    }

    #[test]
    fn major_mismatch_is_fatal() {
        let mut h = hello();
        h.protocol_major = 1;
        assert_eq!(
            negotiate_server(&h, SERVER_CAPS, 256 * 1024, 1200, true),
            Err(NegotiationError::MajorVersion {
                client: 1,
                server: 0
            })
        );
    }

    #[test]
    fn transport_without_datagrams_strips_the_capability() {
        let n = negotiate_server(&hello(), SERVER_CAPS, 256 * 1024, 1200, false).unwrap();
        assert!(n.capabilities.is_empty());
    }

    #[test]
    fn utf8_is_mandatory() {
        let mut h = hello();
        h.encodings.clear();
        assert_eq!(
            negotiate_server(&h, SERVER_CAPS, 256 * 1024, 1200, true),
            Err(NegotiationError::NoUtf8)
        );
    }

    #[test]
    fn tiny_frame_limit_rejected() {
        let mut h = hello();
        h.max_frame_bytes = 512;
        assert!(matches!(
            negotiate_server(&h, SERVER_CAPS, 256 * 1024, 1200, true),
            Err(NegotiationError::FrameLimitTooSmall(512))
        ));
    }

    #[test]
    fn frame_ceiling_is_enforced_even_if_both_sides_ask_higher() {
        let mut h = hello();
        h.max_frame_bytes = 8 * 1024 * 1024;
        let n = negotiate_server(&h, SERVER_CAPS, 8 * 1024 * 1024, 1200, true).unwrap();
        assert_eq!(n.max_frame_bytes, crate::FRAME_BYTES_CEILING);
    }
}
