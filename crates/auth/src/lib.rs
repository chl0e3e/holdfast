//! Authentication for Holdfast (spec §5).
//!
//! Two concerns, kept separate:
//! - [`grant`] — connection grants: short-lived ed25519-signed claims the
//!   terminal endpoint verifies without contacting the issuer. Used by both
//!   the local issuer (this crate, [`ssh`]) and the future central control
//!   plane (overlay).
//! - [`ssh`] — the local issuer's authentication step: an SSH public-key
//!   challenge/response verified against a user's `authorized_keys`.
//!
//! This crate performs no I/O beyond reading key files and never parses
//! terminal bytes.

pub mod grant;
pub mod ssh;

pub use grant::{ConnectionGrant, GrantClaims, GrantError, GrantSigner, GrantVerifier};
pub use ssh::{SshError, SshVerifier};

/// The signature namespace for Holdfast SSH auth challenges
/// (`ssh-keygen -Y sign -n holdfast-auth@v0`).
pub const SSH_NAMESPACE: &str = "holdfast-auth@v0";
