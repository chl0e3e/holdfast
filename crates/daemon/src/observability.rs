//! Bounded, content-free audit events and operational counters (Phase 7).
//!
//! This module deliberately exposes a closed event schema. Callers can record
//! lifecycle metadata, but there is no field for terminal bytes, commands,
//! connection grants, signatures, or resume tokens. User/account metadata is
//! stripped of control characters and capped before it reaches memory or logs.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use hf_protocol::ids::{ServerId, ShellId};

/// Explicit bound for the in-memory audit ring (AGENTS.md rule 7).
pub const DEFAULT_AUDIT_CAPACITY: usize = 4_096;
const MAX_METADATA_CHARS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    Development,
    ConnectionGrant,
    SshKey,
    Password,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellOperation {
    Open,
    Attach,
    Detach,
    Terminate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadOutcome {
    Cancelled,
    TimedOut,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    RateLimited,
    Forbidden,
    NotFound,
    InvalidToken,
    /// A superseded (once-valid) resume token was presented — possible theft
    /// (spec §12). Counted separately so operators can alert on it.
    TokenReplayed,
    LimitExceeded,
    NotRunning,
    InvalidRequest,
    Internal,
}

/// Closed audit schema. Secret/content-bearing fields intentionally do not
/// exist; adding one requires an explicit security review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent {
    AuthenticationSucceeded {
        user: String,
        source_ip: IpAddr,
        method: AuthMethod,
    },
    AuthenticationFailed {
        source_ip: IpAddr,
        reason: RejectReason,
    },
    ShellOpened {
        user: String,
        shell_id: ShellId,
        account: Option<String>,
        reused: bool,
    },
    ShellOperationRejected {
        user: String,
        shell_id: Option<ShellId>,
        operation: ShellOperation,
        reason: RejectReason,
    },
    ShellAttached {
        user: String,
        shell_id: ShellId,
    },
    ShellDetached {
        user: String,
        shell_id: ShellId,
    },
    ShellTerminated {
        user: String,
        shell_id: ShellId,
        exit_code: u32,
    },
    /// The idle-expiry reaper reclaimed an abandoned shell (ADR 0021) —
    /// distinct from a user/admin `TerminateShell`.
    ShellExpired {
        user: String,
        shell_id: ShellId,
        exit_code: u32,
    },
    UploadStarted {
        user: String,
        shell_id: ShellId,
        original_name: String,
        bytes: u64,
    },
    UploadCompleted {
        user: String,
        shell_id: ShellId,
        stored_basename: String,
        bytes: u64,
        duration_ms: u64,
    },
    UploadEnded {
        user: String,
        shell_id: ShellId,
        outcome: UploadOutcome,
    },
    UploadRejected {
        user: String,
        shell_id: Option<ShellId>,
        reason: RejectReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub timestamp_ms: i64,
    pub server_id: ServerId,
    pub event: AuditEvent,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub authentication_succeeded: u64,
    pub authentication_failed: u64,
    pub authentication_rate_limited: u64,
    pub shells_opened: u64,
    pub shell_opens_reused: u64,
    pub shell_operations_rejected: u64,
    pub attachments_opened: u64,
    pub attachments_detached: u64,
    pub shells_terminated: u64,
    pub limit_hits: u64,
    pub token_replays_detected: u64,
    pub shells_expired: u64,
    pub uploads_active: u64,
    pub uploads_completed: u64,
    pub uploads_cancelled: u64,
    pub uploads_timed_out: u64,
    pub uploads_failed: u64,
    pub uploads_rejected: u64,
    pub upload_bytes_completed: u64,
}

#[derive(Default)]
struct Counters {
    authentication_succeeded: AtomicU64,
    authentication_failed: AtomicU64,
    authentication_rate_limited: AtomicU64,
    shells_opened: AtomicU64,
    shell_opens_reused: AtomicU64,
    shell_operations_rejected: AtomicU64,
    attachments_opened: AtomicU64,
    attachments_detached: AtomicU64,
    shells_terminated: AtomicU64,
    limit_hits: AtomicU64,
    token_replays_detected: AtomicU64,
    shells_expired: AtomicU64,
    uploads_active: AtomicU64,
    uploads_completed: AtomicU64,
    uploads_cancelled: AtomicU64,
    uploads_timed_out: AtomicU64,
    uploads_failed: AtomicU64,
    uploads_rejected: AtomicU64,
    upload_bytes_completed: AtomicU64,
}

struct AuditRing {
    capacity: usize,
    records: VecDeque<AuditRecord>,
}

struct Inner {
    server_id: ServerId,
    audit: Mutex<AuditRing>,
    counters: Counters,
}

/// Cloneable observability handle shared by all transport connections.
#[derive(Clone)]
pub struct Observability(Arc<Inner>);

impl Observability {
    pub fn new(server_id: ServerId, audit_capacity: usize) -> Observability {
        let capacity = audit_capacity.min(DEFAULT_AUDIT_CAPACITY);
        Observability(Arc::new(Inner {
            server_id,
            audit: Mutex::new(AuditRing {
                capacity,
                records: VecDeque::with_capacity(capacity),
            }),
            counters: Counters::default(),
        }))
    }

    pub fn record(&self, event: AuditEvent) {
        let event = sanitize_event(event);
        self.increment(&event);

        // Fixed event schema + escaped structured fields. Debug never contains
        // terminal data or credentials because AuditEvent has no such fields.
        tracing::info!(target: "holdfast::audit", server_id = %self.0.server_id, event = ?event, "audit");

        let record = AuditRecord {
            timestamp_ms: now_ms(),
            server_id: self.0.server_id,
            event,
        };
        let mut audit = self.0.audit.lock().unwrap();
        if audit.capacity == 0 {
            return;
        }
        if audit.records.len() == audit.capacity {
            audit.records.pop_front();
        }
        audit.records.push_back(record);
    }

    pub fn audit_events(&self) -> Vec<AuditRecord> {
        self.0
            .audit
            .lock()
            .unwrap()
            .records
            .iter()
            .cloned()
            .collect()
    }

    pub fn metrics(&self) -> MetricsSnapshot {
        let c = &self.0.counters;
        MetricsSnapshot {
            authentication_succeeded: c.authentication_succeeded.load(Ordering::Relaxed),
            authentication_failed: c.authentication_failed.load(Ordering::Relaxed),
            authentication_rate_limited: c.authentication_rate_limited.load(Ordering::Relaxed),
            shells_opened: c.shells_opened.load(Ordering::Relaxed),
            shell_opens_reused: c.shell_opens_reused.load(Ordering::Relaxed),
            shell_operations_rejected: c.shell_operations_rejected.load(Ordering::Relaxed),
            attachments_opened: c.attachments_opened.load(Ordering::Relaxed),
            attachments_detached: c.attachments_detached.load(Ordering::Relaxed),
            shells_terminated: c.shells_terminated.load(Ordering::Relaxed),
            limit_hits: c.limit_hits.load(Ordering::Relaxed),
            token_replays_detected: c.token_replays_detected.load(Ordering::Relaxed),
            shells_expired: c.shells_expired.load(Ordering::Relaxed),
            uploads_active: c.uploads_active.load(Ordering::Relaxed),
            uploads_completed: c.uploads_completed.load(Ordering::Relaxed),
            uploads_cancelled: c.uploads_cancelled.load(Ordering::Relaxed),
            uploads_timed_out: c.uploads_timed_out.load(Ordering::Relaxed),
            uploads_failed: c.uploads_failed.load(Ordering::Relaxed),
            uploads_rejected: c.uploads_rejected.load(Ordering::Relaxed),
            upload_bytes_completed: c.upload_bytes_completed.load(Ordering::Relaxed),
        }
    }

    fn increment(&self, event: &AuditEvent) {
        let c = &self.0.counters;
        match event {
            AuditEvent::AuthenticationSucceeded { .. } => {
                c.authentication_succeeded.fetch_add(1, Ordering::Relaxed);
            }
            AuditEvent::AuthenticationFailed { reason, .. } => {
                c.authentication_failed.fetch_add(1, Ordering::Relaxed);
                if *reason == RejectReason::RateLimited {
                    c.authentication_rate_limited
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            AuditEvent::ShellOpened { reused, .. } => {
                if *reused {
                    c.shell_opens_reused.fetch_add(1, Ordering::Relaxed);
                } else {
                    c.shells_opened.fetch_add(1, Ordering::Relaxed);
                }
            }
            AuditEvent::ShellOperationRejected { reason, .. } => {
                c.shell_operations_rejected.fetch_add(1, Ordering::Relaxed);
                if *reason == RejectReason::LimitExceeded {
                    c.limit_hits.fetch_add(1, Ordering::Relaxed);
                }
                if *reason == RejectReason::TokenReplayed {
                    c.token_replays_detected.fetch_add(1, Ordering::Relaxed);
                }
            }
            AuditEvent::ShellAttached { .. } => {
                c.attachments_opened.fetch_add(1, Ordering::Relaxed);
            }
            AuditEvent::ShellDetached { .. } => {
                c.attachments_detached.fetch_add(1, Ordering::Relaxed);
            }
            AuditEvent::ShellTerminated { .. } => {
                c.shells_terminated.fetch_add(1, Ordering::Relaxed);
            }
            AuditEvent::ShellExpired { .. } => {
                c.shells_expired.fetch_add(1, Ordering::Relaxed);
            }
            AuditEvent::UploadStarted { .. } => {
                c.uploads_active.fetch_add(1, Ordering::Relaxed);
            }
            AuditEvent::UploadCompleted { bytes, .. } => {
                let _ =
                    c.uploads_active
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
                            Some(active.saturating_sub(1))
                        });
                c.uploads_completed.fetch_add(1, Ordering::Relaxed);
                c.upload_bytes_completed
                    .fetch_add(*bytes, Ordering::Relaxed);
            }
            AuditEvent::UploadEnded { outcome, .. } => {
                let _ =
                    c.uploads_active
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |active| {
                            Some(active.saturating_sub(1))
                        });
                match outcome {
                    UploadOutcome::Cancelled => &c.uploads_cancelled,
                    UploadOutcome::TimedOut => &c.uploads_timed_out,
                    UploadOutcome::Failed => &c.uploads_failed,
                }
                .fetch_add(1, Ordering::Relaxed);
            }
            AuditEvent::UploadRejected { reason, .. } => {
                c.uploads_rejected.fetch_add(1, Ordering::Relaxed);
                if *reason == RejectReason::LimitExceeded {
                    c.limit_hits.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

fn sanitize_event(event: AuditEvent) -> AuditEvent {
    match event {
        AuditEvent::AuthenticationSucceeded {
            user,
            source_ip,
            method,
        } => AuditEvent::AuthenticationSucceeded {
            user: safe_metadata(&user),
            source_ip,
            method,
        },
        AuditEvent::ShellOpened {
            user,
            shell_id,
            account,
            reused,
        } => AuditEvent::ShellOpened {
            user: safe_metadata(&user),
            shell_id,
            account: account.map(|value| safe_metadata(&value)),
            reused,
        },
        AuditEvent::ShellOperationRejected {
            user,
            shell_id,
            operation,
            reason,
        } => AuditEvent::ShellOperationRejected {
            user: safe_metadata(&user),
            shell_id,
            operation,
            reason,
        },
        AuditEvent::ShellAttached { user, shell_id } => AuditEvent::ShellAttached {
            user: safe_metadata(&user),
            shell_id,
        },
        AuditEvent::ShellDetached { user, shell_id } => AuditEvent::ShellDetached {
            user: safe_metadata(&user),
            shell_id,
        },
        AuditEvent::ShellTerminated {
            user,
            shell_id,
            exit_code,
        } => AuditEvent::ShellTerminated {
            user: safe_metadata(&user),
            shell_id,
            exit_code,
        },
        AuditEvent::ShellExpired {
            user,
            shell_id,
            exit_code,
        } => AuditEvent::ShellExpired {
            user: safe_metadata(&user),
            shell_id,
            exit_code,
        },
        AuditEvent::UploadStarted {
            user,
            shell_id,
            original_name,
            bytes,
        } => AuditEvent::UploadStarted {
            user: safe_metadata(&user),
            shell_id,
            original_name: safe_metadata(&original_name),
            bytes,
        },
        AuditEvent::UploadCompleted {
            user,
            shell_id,
            stored_basename,
            bytes,
            duration_ms,
        } => AuditEvent::UploadCompleted {
            user: safe_metadata(&user),
            shell_id,
            stored_basename: safe_metadata(&stored_basename),
            bytes,
            duration_ms,
        },
        AuditEvent::UploadEnded {
            user,
            shell_id,
            outcome,
        } => AuditEvent::UploadEnded {
            user: safe_metadata(&user),
            shell_id,
            outcome,
        },
        AuditEvent::UploadRejected {
            user,
            shell_id,
            reason,
        } => AuditEvent::UploadRejected {
            user: safe_metadata(&user),
            shell_id,
            reason,
        },
        failed @ AuditEvent::AuthenticationFailed { .. } => failed,
    }
}

fn safe_metadata(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control())
        .take(MAX_METADATA_CHARS)
        .collect()
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_ring_is_bounded_and_metadata_is_sanitized() {
        let server_id = ServerId([1; 16]);
        let shell_id = ShellId([2; 16]);
        let obs = Observability::new(server_id, 2);
        for user in ["first", "second\nforged", "third"] {
            obs.record(AuditEvent::ShellAttached {
                user: user.into(),
                shell_id,
            });
        }

        let records = obs.audit_events();
        assert_eq!(records.len(), 2);
        assert!(matches!(
            &records[0].event,
            AuditEvent::ShellAttached { user, .. } if user == "secondforged"
        ));
        assert!(matches!(
            &records[1].event,
            AuditEvent::ShellAttached { user, .. } if user == "third"
        ));

        let capped = Observability::new(server_id, usize::MAX);
        assert_eq!(
            capped.0.audit.lock().unwrap().capacity,
            DEFAULT_AUDIT_CAPACITY,
            "callers cannot raise the audit ring above its hard ceiling"
        );
    }

    #[test]
    fn counters_follow_events_without_user_derived_labels() {
        let obs = Observability::new(ServerId([3; 16]), 0);
        obs.record(AuditEvent::AuthenticationFailed {
            source_ip: "127.0.0.1".parse().unwrap(),
            reason: RejectReason::RateLimited,
        });
        obs.record(AuditEvent::ShellOperationRejected {
            user: "alice".into(),
            shell_id: None,
            operation: ShellOperation::Open,
            reason: RejectReason::LimitExceeded,
        });
        obs.record(AuditEvent::UploadStarted {
            user: "alice".into(),
            shell_id: ShellId([4; 16]),
            original_name: "payload\nforged".into(),
            bytes: 12,
        });
        obs.record(AuditEvent::UploadCompleted {
            user: "alice".into(),
            shell_id: ShellId([4; 16]),
            stored_basename: "payload.txt".into(),
            bytes: 12,
            duration_ms: 5,
        });
        let metrics = obs.metrics();
        assert_eq!(metrics.authentication_failed, 1);
        assert_eq!(metrics.authentication_rate_limited, 1);
        assert_eq!(metrics.shell_operations_rejected, 1);
        assert_eq!(metrics.limit_hits, 1);
        assert_eq!(metrics.uploads_active, 0);
        assert_eq!(metrics.uploads_completed, 1);
        assert_eq!(metrics.upload_bytes_completed, 12);
        assert!(
            obs.audit_events().is_empty(),
            "capacity zero disables retention"
        );
    }

    #[test]
    fn schema_has_no_place_for_secret_or_terminal_content() {
        let event = AuditEvent::ShellOpened {
            user: "alice".into(),
            shell_id: ShellId([4; 16]),
            account: Some("alice".into()),
            reused: false,
        };
        let rendered = format!("{event:?}");
        for forbidden in [
            "resume_token",
            "connection_grant",
            "terminal_output",
            "command",
        ] {
            assert!(!rendered.contains(forbidden));
        }

        let upload = AuditEvent::UploadCompleted {
            user: "alice".into(),
            shell_id: ShellId([5; 16]),
            stored_basename: "safe.txt".into(),
            bytes: 9,
            duration_ms: 3,
        };
        let rendered = format!("{upload:?}");
        assert!(!rendered.contains("remote_path"));
        assert!(!rendered.contains("local_path"));
        assert!(!rendered.contains("sha256"));
    }
}
