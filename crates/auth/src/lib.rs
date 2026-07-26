//! Authentication for Holdfast (spec §5).
//!
//! Two concerns, kept separate:
//! - [`grant`] — connection grants: short-lived ed25519-signed claims the
//!   terminal endpoint verifies without contacting the issuer. Used by both
//!   the local issuer (this crate, [`ssh`]) and the future central control
//!   plane (overlay).
//! - [`ssh`] — the local issuer's authentication step: an SSH public-key
//!   challenge/response verified against a user's `authorized_keys`.
//! - [`password`]/[`pam`] — opt-in local password verification (ADRs
//!   0015/0016), shared by the SSH compatibility adapter and the daemon's
//!   local issuer.
//!
//! This crate performs no I/O beyond reading key files — and, only when a
//! caller opts into password authentication, the PAM conversation — and never
//! parses terminal bytes.

pub mod grant;
#[cfg(unix)]
pub mod pam;
pub mod password;
pub mod ssh;

pub use grant::{ConnectionGrant, GrantClaims, GrantError, GrantSigner, GrantVerifier};
pub use password::{PasswordVerifier, MAX_PASSWORD_BYTES, MAX_USERNAME_BYTES};
pub use ssh::{SshError, SshVerifier};

/// The signature namespace for Holdfast SSH auth challenges
/// (`ssh-keygen -Y sign -n holdfast-auth@v0`).
pub const SSH_NAMESPACE: &str = "holdfast-auth@v0";
