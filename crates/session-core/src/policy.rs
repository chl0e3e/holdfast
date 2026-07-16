//! Access policy for shell creation (spec: control plane authorizes, the
//! plan's `AccessPolicy` entity): which authenticated user may run a shell
//! under which Unix account.
//!
//! This is the **authorization** half of privilege separation (threat model
//! T12). Enforcing the *mechanism* — actually dropping to the resolved
//! account's uid/gid — is a deployment integration point (see ADR 0007); the
//! resolved account name returned here is what a privilege-dropping exec
//! wrapper would switch to.

use std::collections::HashMap;

/// Denial reason (kept coarse on purpose; do not leak which accounts exist).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied;

/// Decides the Unix account a shell runs under.
pub trait AccessPolicy: Send + Sync {
    /// Resolve `requested` (from the client, may be empty/None) for
    /// authenticated `user`. Returns the account name to run under, or
    /// `Denied`. Returning `Ok(None)` means "the daemon's own account"
    /// (no switch).
    fn resolve(&self, user: &str, requested: Option<&str>) -> Result<Option<String>, Denied>;
}

/// Development default: allow anything, always run as the daemon's own
/// account. Used in dev mode and by tests.
pub struct AllowAll;

impl AccessPolicy for AllowAll {
    fn resolve(&self, _user: &str, requested: Option<&str>) -> Result<Option<String>, Denied> {
        Ok(requested.filter(|s| !s.is_empty()).map(str::to_string))
    }
}

/// Static allowlist: each user maps to the Unix accounts they may request.
/// An empty requested account resolves to the user's default (first listed,
/// or `Ok(None)` if they have a default-self entry).
pub struct StaticPolicy {
    /// user → allowed account names. The first entry is the default.
    allowed: HashMap<String, Vec<String>>,
}

impl StaticPolicy {
    pub fn new(allowed: HashMap<String, Vec<String>>) -> StaticPolicy {
        StaticPolicy { allowed }
    }
}

impl AccessPolicy for StaticPolicy {
    fn resolve(&self, user: &str, requested: Option<&str>) -> Result<Option<String>, Denied> {
        let accounts = self.allowed.get(user).ok_or(Denied)?;
        match requested.filter(|s| !s.is_empty()) {
            // No explicit request → the user's default (first listed).
            None => Ok(accounts.first().cloned()),
            // Explicit request must be in the user's allowlist.
            Some(req) if accounts.iter().any(|a| a == req) => Ok(Some(req.to_string())),
            Some(_) => Err(Denied),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_all_passes_requested_through() {
        let p = AllowAll;
        assert_eq!(p.resolve("anyone", None), Ok(None));
        assert_eq!(p.resolve("anyone", Some("")), Ok(None));
        assert_eq!(p.resolve("anyone", Some("deploy")), Ok(Some("deploy".into())));
    }

    #[test]
    fn static_policy_enforces_allowlist() {
        let mut allowed = HashMap::new();
        allowed.insert("alice".to_string(), vec!["alice".to_string(), "deploy".to_string()]);
        let p = StaticPolicy::new(allowed);

        // Default = first listed.
        assert_eq!(p.resolve("alice", None), Ok(Some("alice".into())));
        // Allowed explicit request.
        assert_eq!(p.resolve("alice", Some("deploy")), Ok(Some("deploy".into())));
        // Disallowed account.
        assert_eq!(p.resolve("alice", Some("root")), Err(Denied));
        // Unknown user.
        assert_eq!(p.resolve("mallory", None), Err(Denied));
        assert_eq!(p.resolve("mallory", Some("alice")), Err(Denied));
    }
}
