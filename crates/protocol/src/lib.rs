//! Wire schemas, framing and version negotiation.
//!
//! `protocol/messages.proto` is the authority on encoding;
//! `protocol/specification.md` on semantics. This crate is
//! transport-independent: no HTTP, QUIC or WebSocket imports, ever.

pub mod framing;
pub mod ids;
pub mod negotiate;
pub mod upload;

/// Generated protobuf types for `holdfast.v0`.
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/holdfast.v0.rs"));
}

/// Protocol version implemented by this crate (spec §4).
pub const PROTOCOL_MAJOR: u32 = 0;
pub const PROTOCOL_MINOR: u32 = 2;

/// File transfer was added as an optional capability in protocol minor 2.
pub const FILE_TRANSFER_PROTOCOL_MINOR: u32 = 2;
/// Absolute per-chunk payload ceiling. A server selects a lower value when the
/// negotiated frame limit cannot carry this payload plus protobuf overhead.
pub const UPLOAD_CHUNK_BYTES_MAX: usize = 64 * 1024;
pub const UPLOAD_FILE_BYTES_DEFAULT: u64 = 256 * 1024 * 1024;
pub const UPLOAD_FILE_BYTES_HARD_MAX: u64 = 4 * 1024 * 1024 * 1024;
pub const UPLOAD_ORIGINAL_NAME_BYTES_MAX: usize = 255;
pub const UPLOAD_ID_BYTES: usize = 16;
pub const UPLOAD_SHA256_BYTES: usize = 32;
pub const UPLOAD_ABORT_REASON_BYTES_MAX: usize = 128;

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
/// How long an agent↔gateway connection may go completely silent before QUIC
/// tears it down. quinn's default is 30s, which a healthy but idle managed
/// server exceeds constantly: the link carries nothing at all until someone
/// opens a shell through it, so the connection died and re-registered every
/// half minute — churning the registration counter and leaving a routing gap
/// each cycle.
pub const AGENT_MAX_IDLE_TIMEOUT_MS: u32 = 60_000;
/// QUIC PING interval for that link. This is what actually keeps it up: the
/// application-level `AgentPing` exists and its interval is negotiated at
/// registration, but nothing has ever scheduled it (see
/// `RegisteredLink::ping`), and it cannot be driven from the serve loop
/// without a second reader on the control stream. Keeping liveness at the
/// transport layer needs no protocol change and covers both directions.
///
/// 10s is not arbitrary. The effective idle limit is the *lower* of the two
/// peers', so this has to fit inside quinn's un-raised 30s — and fit twice
/// over, or one dropped ping packet ends the connection at exactly the
/// deadline. That rules out anything from 15s up. It also lands on the
/// interval the gateway already advertises for the application-level
/// keepalive, so both layers pace the link identically.
pub const AGENT_KEEP_ALIVE_INTERVAL_MS: u64 = 10_000;

#[cfg(test)]
mod agent_liveness_tests {
    use super::{AGENT_KEEP_ALIVE_INTERVAL_MS, AGENT_MAX_IDLE_TIMEOUT_MS};

    /// quinn's own default, which is what an un-updated peer will be enforcing.
    const QUINN_DEFAULT_IDLE_TIMEOUT_MS: u64 = 30_000;

    #[test]
    fn keepalive_outpaces_every_idle_limit_that_can_apply() {
        let keepalive = AGENT_KEEP_ALIVE_INTERVAL_MS;
        let idle = u64::from(AGENT_MAX_IDLE_TIMEOUT_MS);

        // The negotiated idle limit is the LOWER of the two peers', so pacing
        // against our own is not enough: a peer built before this change still
        // enforces quinn's 30s and must be pinged inside it.
        assert!(
            keepalive < QUINN_DEFAULT_IDLE_TIMEOUT_MS,
            "keepalive {keepalive}ms must fit inside an un-updated peer's {QUINN_DEFAULT_IDLE_TIMEOUT_MS}ms idle limit",
        );

        // Survive a lost ping rather than dying on the first dropped packet.
        assert!(
            keepalive * 2 < idle,
            "keepalive {keepalive}ms must leave room for a retry before the {idle}ms idle limit",
        );
        assert!(
            keepalive * 2 < QUINN_DEFAULT_IDLE_TIMEOUT_MS,
            "keepalive {keepalive}ms must leave retry room against an un-updated peer too",
        );
    }

    #[test]
    fn raising_the_idle_limit_is_what_makes_the_link_outlive_quinns_default() {
        assert!(
            u64::from(AGENT_MAX_IDLE_TIMEOUT_MS) > QUINN_DEFAULT_IDLE_TIMEOUT_MS,
            "the whole point is to outlive quinn's default; lowering this re-introduces the churn",
        );
    }
}
