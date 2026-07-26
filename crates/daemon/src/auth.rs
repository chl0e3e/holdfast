//! Daemon-side authentication (spec §5): the local SSH-key issuer, connection
//! grant verification, and source-address rate limiting.
//!
//! `AuthMode::DevInsecure` keeps the loopback-only accept-anything path for
//! development and tests. `AuthMode::SshKeys` is the real local issuer: a
//! per-user `authorized_keys` set plus a self-held ed25519 grant signing key.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hf_auth::{GrantSigner, GrantVerifier, PasswordVerifier, SshVerifier};

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

/// Opt-in local password login (ADR 0016): the allowlisted usernames and the
/// verifier that checks their passwords (PAM in production, fakes in tests).
pub struct PasswordAuth {
    pub users: BTreeSet<String>,
    pub verifier: Arc<dyn PasswordVerifier>,
}

pub struct AuthState {
    pub mode: AuthMode,
    /// Password login for allowlisted users; `None` = key-only (the default).
    pub password: Option<PasswordAuth>,
    /// Local grant issuer key (this daemon signs the grants it later accepts).
    pub grant_signer: GrantSigner,
    pub grant_verifier: GrantVerifier,
    /// Audience string grants are bound to (this daemon's server id hex).
    pub audience: String,
    pub rate_limiter: RateLimiter,
}

impl AuthState {
    pub fn new(
        mode: AuthMode,
        password: Option<PasswordAuth>,
        audience: String,
        grant_key: Option<[u8; 32]>,
    ) -> AuthState {
        let grant_signer = match grant_key {
            Some(seed) => GrantSigner::from_bytes(&seed),
            None => GrantSigner::generate(),
        };
        let grant_verifier = grant_signer.verifier();
        AuthState {
            mode,
            password,
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

    /// The password verifier, only for usernames explicitly allowlisted.
    pub fn password_verifier(&self, username: &str) -> Option<Arc<dyn PasswordVerifier>> {
        self.password
            .as_ref()
            .filter(|p| p.users.contains(username))
            .map(|p| p.verifier.clone())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RateLimitPolicy {
    /// Failed auth attempts allowed within `window` before lockout.
    pub max_failures: u32,
    pub window: Duration,
    pub lockout: Duration,
    /// Hard cap on tracked source addresses. Bounds memory under a flood from
    /// many distinct IPs (threat model T1/T5): once exceeded, the buckets
    /// closest to expiry are evicted. Dead buckets are also swept out
    /// periodically, so this ceiling is only reached under genuine pressure.
    pub max_tracked: usize,
}

impl Default for RateLimitPolicy {
    fn default() -> RateLimitPolicy {
        RateLimitPolicy {
            max_failures: 5,
            window: Duration::from_secs(60),
            lockout: Duration::from_secs(60),
            max_tracked: 100_000,
        }
    }
}

struct Bucket {
    failures: Vec<Instant>,
    locked_until: Option<Instant>,
}

impl Bucket {
    /// A bucket carries no state worth keeping once it is neither locked out
    /// nor holding any in-window failures — it is then indistinguishable from
    /// an absent entry, so it can be dropped.
    fn is_dead(&self, now: Instant, window: Duration) -> bool {
        let locked = self.locked_until.map_or(false, |until| now < until);
        let has_recent_failure = self
            .failures
            .iter()
            .any(|t| now.duration_since(*t) < window);
        !locked && !has_recent_failure
    }

    /// The instant after which this bucket becomes dead — used to evict the
    /// soonest-to-expire entries first when the hard cap is hit. A bucket with
    /// no live state expires at `now` (it should already have been swept).
    fn expires_at(&self, now: Instant, window: Duration) -> Instant {
        let failure_deadline = self.failures.iter().max().map(|t| *t + window);
        match (self.locked_until, failure_deadline) {
            (Some(a), Some(b)) => a.max(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => now,
        }
    }
}

struct Inner {
    map: HashMap<IpAddr, Bucket>,
    /// Last time a full dead-bucket sweep ran; throttles the sweep to once per
    /// window so `record_failure` stays amortized O(1).
    last_sweep: Option<Instant>,
}

/// Per-source-address failed-attempt limiter (threat model T1/rate limiting).
/// Successful auth clears the record; stale records are evicted so the map
/// cannot grow without bound.
pub struct RateLimiter {
    policy: RateLimitPolicy,
    inner: Mutex<Inner>,
}

impl RateLimiter {
    pub fn new(policy: RateLimitPolicy) -> RateLimiter {
        RateLimiter {
            policy,
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                last_sweep: None,
            }),
        }
    }

    /// True if `ip` is currently allowed to attempt authentication.
    pub fn check(&self, ip: IpAddr, now: Instant) -> bool {
        let mut inner = self.inner.lock().unwrap();
        match inner.map.get_mut(&ip) {
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

    /// Record a failed attempt; may trigger lockout. Also prunes stale state so
    /// a stream of one-shot failures from many IPs cannot leak memory.
    pub fn record_failure(&self, ip: IpAddr, now: Instant) {
        let mut inner = self.inner.lock().unwrap();
        let window = self.policy.window;
        let bucket = inner.map.entry(ip).or_insert_with(|| Bucket {
            failures: Vec::new(),
            locked_until: None,
        });
        bucket.failures.retain(|t| now.duration_since(*t) < window);
        bucket.failures.push(now);
        if bucket.failures.len() as u32 >= self.policy.max_failures {
            bucket.locked_until = Some(now + self.policy.lockout);
        }
        self.prune(&mut inner, now);
    }

    pub fn record_success(&self, ip: IpAddr) {
        self.inner.lock().unwrap().map.remove(&ip);
    }

    /// Amortized cleanup: a full dead-bucket sweep at most once per window, then
    /// a hard-cap eviction of the soonest-to-expire buckets if still over.
    fn prune(&self, inner: &mut Inner, now: Instant) {
        let window = self.policy.window;
        let due = inner
            .last_sweep
            .map_or(true, |t| now.duration_since(t) >= window);
        // Sweep when the throttle is due, or unconditionally when over the cap
        // (so eviction below only ever sees live buckets).
        if due || inner.map.len() > self.policy.max_tracked {
            inner.map.retain(|_, b| !b.is_dead(now, window));
            inner.last_sweep = Some(now);
        }
        if inner.map.len() > self.policy.max_tracked {
            let overflow = inner.map.len() - self.policy.max_tracked;
            let mut by_expiry: Vec<(IpAddr, Instant)> = inner
                .map
                .iter()
                .map(|(ip, b)| (*ip, b.expires_at(now, window)))
                .collect();
            by_expiry.sort_by_key(|(_, exp)| *exp);
            for (ip, _) in by_expiry.into_iter().take(overflow) {
                inner.map.remove(&ip);
            }
        }
    }

    /// Number of tracked source addresses (for tests/diagnostics).
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.inner.lock().unwrap().map.len()
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
            ..RateLimitPolicy::default()
        });
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let t0 = Instant::now();

        assert!(limiter.check(ip, t0));
        for _ in 0..3 {
            limiter.record_failure(ip, t0);
        }
        assert!(!limiter.check(ip, t0), "locked out after 3 failures");
        assert!(
            !limiter.check(ip, t0 + Duration::from_secs(29)),
            "still locked"
        );
        assert!(
            limiter.check(ip, t0 + Duration::from_secs(31)),
            "recovers after lockout"
        );
    }

    #[test]
    fn success_clears_the_record() {
        let limiter = RateLimiter::new(RateLimitPolicy {
            max_failures: 2,
            window: Duration::from_secs(60),
            lockout: Duration::from_secs(30),
            ..RateLimitPolicy::default()
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
            ..RateLimitPolicy::default()
        });
        let ip: IpAddr = "10.0.0.3".parse().unwrap();
        let t0 = Instant::now();
        limiter.record_failure(ip, t0);
        limiter.record_failure(ip, t0 + Duration::from_secs(11));
        limiter.record_failure(ip, t0 + Duration::from_secs(12));
        // Only 2 failures inside any 10s window → not locked.
        assert!(limiter.check(ip, t0 + Duration::from_secs(12)));
    }

    fn ip(n: u32) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::from(n))
    }

    #[test]
    fn dead_buckets_are_swept_after_the_window() {
        let limiter = RateLimiter::new(RateLimitPolicy {
            max_failures: 5,
            window: Duration::from_secs(60),
            lockout: Duration::from_secs(60),
            ..RateLimitPolicy::default()
        });
        let t0 = Instant::now();
        // 1000 IPs each fail once, then never return.
        for i in 0..1000 {
            limiter.record_failure(ip(i), t0);
        }
        assert_eq!(
            limiter.tracked(),
            1000,
            "all tracked while failures are fresh"
        );

        // A later failure (past the window) triggers the throttled sweep: every
        // one-shot bucket is now dead and reclaimed.
        limiter.record_failure(ip(9_999), t0 + Duration::from_secs(61));
        assert_eq!(
            limiter.tracked(),
            1,
            "stale one-shot buckets swept, only the fresh one remains"
        );
    }

    #[test]
    fn hard_cap_bounds_the_map_under_a_flood() {
        let limiter = RateLimiter::new(RateLimitPolicy {
            max_failures: 5,
            window: Duration::from_secs(60),
            lockout: Duration::from_secs(60),
            max_tracked: 100,
        });
        let t0 = Instant::now();
        // 500 distinct IPs fail within the window (all buckets live, not dead) —
        // the hard cap must still bound the map.
        for i in 0..500 {
            limiter.record_failure(ip(i), t0 + Duration::from_millis(i as u64));
        }
        assert!(
            limiter.tracked() <= 100,
            "map bounded to max_tracked, got {}",
            limiter.tracked()
        );
    }

    #[test]
    fn eviction_keeps_the_longest_lived_buckets() {
        let limiter = RateLimiter::new(RateLimitPolicy {
            max_failures: 5,
            window: Duration::from_secs(60),
            lockout: Duration::from_secs(60),
            max_tracked: 2,
        });
        let t0 = Instant::now();
        // Three IPs fail at increasing times; the earliest-expiring is evicted.
        limiter.record_failure(ip(1), t0);
        limiter.record_failure(ip(2), t0 + Duration::from_secs(1));
        limiter.record_failure(ip(3), t0 + Duration::from_secs(2));
        assert_eq!(limiter.tracked(), 2);
        // ip(1) expired soonest → evicted; ip(2)/ip(3) retained (still tracked,
        // so a follow-up failure builds on their history).
        limiter.record_failure(ip(2), t0 + Duration::from_secs(3));
        // ip(2) now has 2 in-window failures; give it 3 more to confirm it was
        // never reset by eviction.
        for k in 4..7 {
            limiter.record_failure(ip(2), t0 + Duration::from_secs(k));
        }
        assert!(
            !limiter.check(ip(2), t0 + Duration::from_secs(6)),
            "ip(2) history survived eviction of others"
        );
    }
}
