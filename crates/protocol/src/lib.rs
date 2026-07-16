//! Wire schemas, framing and version negotiation.
//!
//! `protocol/messages.proto` is the authority on encoding;
//! `protocol/specification.md` on semantics. This crate is
//! transport-independent: no HTTP, QUIC or WebSocket imports, ever.

pub mod framing;
pub mod ids;
pub mod negotiate;

/// Generated protobuf types for `holdfast.v0`.
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/holdfast.v0.rs"));
}

/// Protocol version implemented by this crate (spec §4).
pub const PROTOCOL_MAJOR: u32 = 0;
pub const PROTOCOL_MINOR: u32 = 1;

/// Absolute ceiling for a reliable frame payload (spec §3). Negotiated values
/// may be lower, never higher.
pub const FRAME_BYTES_CEILING: u32 = 1024 * 1024;
/// Default negotiated maximum frame payload size.
pub const FRAME_BYTES_DEFAULT: u32 = 256 * 1024;
/// Smallest maximum a peer may propose; below this the protocol cannot carry
/// a useful snapshot or history chunk.
pub const FRAME_BYTES_FLOOR: u32 = 4096;
