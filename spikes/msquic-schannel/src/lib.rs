//! Spike support code. Disposable — production crates must not import this.

/// An `h3::quic` transport adapter over `msquic-async`, written because
/// `msquic-h3` does not implement `SendStreamUnframed` (see README).
pub mod adapter;
