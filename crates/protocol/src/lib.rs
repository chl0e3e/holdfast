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
/// Smallest maximum a peer may propose. Must exceed a single PTY output chunk
/// (8 KiB, `hf-pty`) plus envelope/protobuf overhead, so that a live
/// `TerminalOutput` frame always fits within any negotiated limit — otherwise a
/// peer that negotiated a tiny frame would treat ordinary shell output as an
/// oversized (fatal) frame. 16 KiB leaves comfortable headroom.
pub const FRAME_BYTES_FLOOR: u32 = 16 * 1024;

/// Dedicated ALPN for the managed-server agent link (spec §16). Keeping this
/// distinct from browser/client ALPNs makes the TLS trust roles unambiguous.
pub const AGENT_ALPN: &[u8] = b"holdfast-agent/0";
/// Registration and keepalive are deliberately small control messages. Later
/// terminal streams negotiate their own bounds instead of raising this one.
pub const AGENT_CONTROL_FRAME_BYTES_MAX: u32 = 16 * 1024;
pub const AGENT_CONTROL_FRAME_BYTES_MIN: u32 = 1024;
pub const AGENT_BUILD_BYTES_MAX: usize = 128;
pub const AGENT_USER_ID_BYTES_MAX: usize = 128;
pub const AGENT_UNIX_ACCOUNT_BYTES_MAX: usize = 128;
pub const AGENT_COMMAND_BYTES_MAX: usize = 4096;
pub const AGENT_GRANT_BYTES_MAX: usize = 8192;
pub const AGENT_AUDIENCE_BYTES_MAX: usize = 256;
/// Agent attachment streams carry terminal output and paged history separately
/// from the 16-KiB control channel. This is a fixed protocol ceiling in v0.
pub const AGENT_ATTACHMENT_FRAME_BYTES_MAX: u32 = FRAME_BYTES_DEFAULT;
/// Maximum raw input accepted in one attachment frame. Input is processed
/// directly and never enters an application queue.
pub const AGENT_TERMINAL_INPUT_BYTES_MAX: usize = 64 * 1024;
pub const AGENT_TERMINAL_OUTPUT_BYTES_MAX: usize = 8 * 1024;
pub const AGENT_ATTACHMENT_OUTPUT_QUEUE_MESSAGES: usize = 64;
pub const AGENT_ATTACHMENT_OUTPUT_QUEUE_BYTES: usize =
    AGENT_ATTACHMENT_OUTPUT_QUEUE_MESSAGES * AGENT_TERMINAL_OUTPUT_BYTES_MAX;
/// One control stream plus this many gateway-opened attachment streams.
pub const AGENT_ATTACHMENT_STREAMS_MAX: u32 = 64;
pub const AGENT_CONNECTION_FLOW_WINDOW_BYTES: u64 =
    AGENT_ATTACHMENT_FRAME_BYTES_MAX as u64 * AGENT_ATTACHMENT_STREAMS_MAX as u64;
pub const AGENT_HISTORY_LINES_MAX: u32 = 10_000;
