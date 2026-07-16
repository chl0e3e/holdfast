//! Daemon-side authentication (spec §5): the local SSH-key issuer, connection
//! grant verification, and source-address rate limiting.
//!
//! `AuthMode::DevInsecure` keeps the loopback-only accept-anything path for
//! development and tests. `AuthMode::SshKeys` is the real local issuer: a
//! per-user `authorized_keys` set plus a self-held ed25519 grant signing key.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use hf_auth::{GrantSigner, GrantVerifier, SshVerifier};

/// How the daemon authenticates clients.
pub enum AuthMode {
    /// Accept any `Authenticate`. Permitted only on loopback binds.
    DevInsecure,
    /// SSH public-key challenge/response against per-user authorized_keys.
    SshKeys {
        /// username → their authorized keys.
        users: HashMap<String, SshVerifier>,
    },
}

pub struct AuthState {
    pub mode: AuthMode,
    /// Local grant issuer key (this daemon signs the grants it later accepts).
    pub grant_signer: GrantSigner,
    pub grant_verifier: GrantVerifier,
    /// Audience string grants are bound to (this daemon's server id hex).
    pub audience: String,
    pub rate_limiter: RateLimiter,
}

impl AuthState {
    pub fn new(mode: AuthMode, audience: String) -> AuthState {
        let grant_signer = GrantSigner::generate();
        let grant_verifier = grant_signer.verifier();
        AuthState {
            mode,
            grant_signer,
            grant_verifier,
            audience,
            rate_limiter: RateLimiter::new(RateLimitPolicy::default()),
        }
    }

    pub fn ssh_verifier(&self, username: &str) -> Option<&SshVerifier> {
        match &self.mode {
            AuthMode::SshKeys { users } => users.get(username),
            AuthMode::DevInsecure => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RateLimitPolicy {
    /// Failed auth attempts allowed within `window` before lockout.
    pub max_failures: u32,
    pub window: Duration,
    pub lockout: Duration,
}

impl Default for RateLimitPolicy {
    fn default() -> RateLimitPolicy {
        RateLimitPolicy {
            max_failures: 5,
            window: Duration::from_secs(60),
            lockout: Duration::from_secs(60),
        }
    }
}

struct Bucket {
    failures: Vec<Instant>,
    locked_until: Option<Instant>,
}

/// Per-source-address failed-attempt limiter (threat model T1/rate limiting).
/// Successful auth clears the record.
pub struct RateLimiter {
    policy: RateLimitPolicy,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl RateLimiter {
    pub fn new(policy: RateLimitPolicy) -> RateLimiter {
        RateLimiter { policy, buckets: Mutex::new(HashMap::new()) }
    }

    /// True if `ip` is currently allowed to attempt authentication.
    pub fn check(&self, ip: IpAddr, now: Instant) -> bool {
        let mut buckets = self.buckets.lock().unwrap();
        match buckets.get_mut(&ip) {
            Some(bucket) => match bucket.locked_until {
                Some(until) if now < until => false,
                Some(_) => {
                    // Lockout elapsed: reset.
                    bucket.locked_until = None;
                    bucket.failures.clear();
                    true
                }
                None => true,
            },
            None => true,
        }
    }

    /// Record a failed attempt; may trigger lockout.
    pub fn record_failure(&self, ip: IpAddr, now: Instant) {
        let mut buckets = self.buckets.lock().unwrap();
        let bucket = buckets.entry(ip).or_insert_with(|| Bucket {
            failures: Vec::new(),
            locked_until: None,
        });
        let window = self.policy.window;
        bucket.failures.retain(|t| now.duration_since(*t) < window);
        bucket.failures.push(now);
        if bucket.failures.len() as u32 >= self.policy.max_failures {
            bucket.locked_until = Some(now + self.policy.lockout);
        }
    }

    pub fn record_success(&self, ip: IpAddr) {
        self.buckets.lock().unwrap().remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockout_after_max_failures_then_recovers() {
        let limiter = RateLimiter::new(RateLimitPolicy {
            max_failures: 3,
            window: Duration::from_secs(60),
            lockout: Duration::from_secs(30),
        });
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let t0 = Instant::now();

        assert!(limiter.check(ip, t0));
        for _ in 0..3 {
            limiter.record_failure(ip, t0);
        }
        assert!(!limiter.check(ip, t0), "locked out after 3 failures");
        assert!(!limiter.check(ip, t0 + Duration::from_secs(29)), "still locked");
        assert!(limiter.check(ip, t0 + Duration::from_secs(31)), "recovers after lockout");
    }

    #[test]
    fn success_clears_the_record() {
        let limiter = RateLimiter::new(RateLimitPolicy {
            max_failures: 2,
            window: Duration::from_secs(60),
            lockout: Duration::from_secs(30),
        });
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        let t0 = Instant::now();
        limiter.record_failure(ip, t0);
        limiter.record_success(ip);
        limiter.record_failure(ip, t0);
        assert!(limiter.check(ip, t0), "one failure after reset is fine");
    }

    #[test]
    fn old_failures_age_out_of_the_window() {
        let limiter = RateLimiter::new(RateLimitPolicy {
            max_failures: 3,
            window: Duration::from_secs(10),
            lockout: Duration::from_secs(30),
        });
        let ip: IpAddr = "10.0.0.3".parse().unwrap();
        let t0 = Instant::now();
        limiter.record_failure(ip, t0);
        limiter.record_failure(ip, t0 + Duration::from_secs(11));
        limiter.record_failure(ip, t0 + Duration::from_secs(12));
        // Only 2 failures inside any 10s window → not locked.
        assert!(limiter.check(ip, t0 + Duration::from_secs(12)));
    }
}
