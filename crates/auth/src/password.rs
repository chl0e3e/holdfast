//! Local password verification (ADRs 0015/0016).
//!
//! The trait is transport-agnostic: the SSH compatibility adapter and the
//! daemon's local issuer both consume it, injecting [`crate::pam`] in
//! production and deterministic fakes in tests. Callers enforce the input
//! bounds below *before* invoking a verifier, so no backend work can be spent
//! on oversized or empty credentials.

/// Upper bound callers must enforce on submitted passwords.
pub const MAX_PASSWORD_BYTES: usize = 1024;
/// Upper bound callers must enforce on submitted usernames.
pub const MAX_USERNAME_BYTES: usize = 128;

/// Blocking local password verification. Implementations must fail closed:
/// any error is a rejection. Call on a blocking thread, never on a
/// connection task.
pub trait PasswordVerifier: Send + Sync {
    fn verify(&self, user: &str, password: &str) -> bool;
}

/// Plain closures act as verifiers, which keeps test injection trivial.
impl<F> PasswordVerifier for F
where
    F: Fn(&str, &str) -> bool + Send + Sync,
{
    fn verify(&self, user: &str, password: &str) -> bool {
        self(user, password)
    }
}
