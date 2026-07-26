//! Shell and attachment lifecycle (spec §11), independent of any transport.
//!
//! A **shell** is a persistent PTY + terminal model addressed by
//! `(server_id, shell_id)`; an **attachment** is a temporary, bounded event
//! channel bound to a shell. Detaching never kills a shell; only
//! [`ShellManager::terminate`], process exit or (later) expiry policy does.
//!
//! Concurrency model: one pump thread per shell drains PTY output into the
//! terminal model and fans it out to attachments. Attachment queues are
//! bounded sync channels (`max_queued_chunks` messages × ≤8 KiB PTY chunks —
//! explicit message AND byte bound per spec §8); a full queue detaches that
//! attachment (the wire layer maps this to `ERR_TOO_SLOW`), never blocking
//! the shell or other attachments.
//!
//! Per-user isolation (threat model T12): shells carry an immutable `owner`;
//! listing, termination and idempotency reuse are scoped to it, so one
//! authenticated user cannot see, kill, or hijack another's shells. Still not
//! here: a per-user shell/resource quota (the `max_shells` cap is global) and
//! the idle-shell expiry reaper.

mod launch;
mod policy;
mod token;

use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hf_protocol::ids::ShellId;
use hf_pty::{ExitSummary, PtyConfig, PtyError, PtyProcess};

use hf_terminal_model::{HistoryRange, TerminalModel, TerminalModelConfig, MIN_COLS, MIN_ROWS};
pub use policy::{AccessPolicy, AllowAll, Denied, StaticPolicy};

pub use token::ResumeToken;

/// Hard resource limits inherited by every shell process and its descendants
/// (threat model T6, ADR 0009). `RLIMIT_NPROC` is accounted per real Unix uid
/// on Linux; the systemd cgroup adds an aggregate service ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShellResourceLimits {
    pub max_processes: u64,
    pub max_open_files: u64,
    pub max_core_bytes: u64,
}

impl Default for ShellResourceLimits {
    fn default() -> ShellResourceLimits {
        ShellResourceLimits {
            max_processes: 512,
            max_open_files: 1_024,
            max_core_bytes: 0,
        }
    }
}

/// Clamp client-supplied terminal dimensions to the safe floor the terminal
/// model enforces, so the PTY winsize and the model never disagree and neither
/// can be driven into `avt`'s degenerate 0/1-column code paths (threat model
/// T9). Applied identically to every open/attach/resize entry point.
fn clamp_dims(cols: u16, rows: u16) -> (u16, u16) {
    (cols.max(MIN_COLS), rows.max(MIN_ROWS))
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("shell not found")]
    ShellNotFound,
    #[error("shell is not running")]
    NotRunning,
    #[error("limit exceeded: {0}")]
    LimitExceeded(&'static str),
    #[error("not authorized to run a shell under the requested account")]
    Forbidden,
    #[error("invalid, expired or rotated resume token")]
    InvalidToken,
    #[error("resume token already superseded (possible replay)")]
    TokenReplayed,
    #[error(transparent)]
    Pty(#[from] PtyError),
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone)]
pub struct SessionCoreConfig {
    /// Spec §8 default: 16. Global ceiling across all users.
    pub max_shells: usize,
    /// Per-owner live-shell cap (threat model T1/T5 fairness): one authenticated
    /// user cannot consume the whole global `max_shells` and starve others.
    /// `0` disables the per-user cap (only the global one applies).
    pub max_shells_per_user: usize,
    /// Spec §8 default: 4 (multi-client attach — open question O6).
    pub max_attachments_per_shell: usize,
    /// Bound of each attachment's event queue in messages; PTY chunks are
    /// ≤ 8 KiB, so 128 messages ≈ 1 MiB (spec §8 output-queue default).
    pub max_queued_chunks: usize,
    pub scrollback_max_lines: usize,
    pub scrollback_max_bytes: usize,
    /// Enforce the uid/gid-drop *mechanism* (ADR 0007, threat model T12): when
    /// `true`, a shell whose resolved account differs from the daemon's own
    /// user is launched under that account via `setpriv`. Requires the daemon
    /// to run with enough privilege to switch (typically root) and the accounts
    /// to exist; when it cannot switch, opening fails rather than running under
    /// the wrong account. Default `false` — the standalone single-user case
    /// runs every shell as the daemon's own user (the correct, only account).
    pub privilege_drop: bool,
    /// Always-on hard limits applied by the launch wrapper before the shell is
    /// exec'd. Defaults are deliberately finite; see ADR 0009.
    pub shell_resource_limits: ShellResourceLimits,
}

impl Default for SessionCoreConfig {
    fn default() -> SessionCoreConfig {
        let tm = TerminalModelConfig::default();
        SessionCoreConfig {
            max_shells: 16,
            max_shells_per_user: 8,
            max_attachments_per_shell: 4,
            max_queued_chunks: 128,
            scrollback_max_lines: tm.max_history_lines,
            scrollback_max_bytes: tm.max_history_bytes,
            privilege_drop: false,
            shell_resource_limits: ShellResourceLimits::default(),
        }
    }
}

/// Spec §11 shell states (`creating` is unobservable: `open_shell` returns
/// only once the PTY is spawned).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellState {
    Running,
    Terminating,
    Exited,
}

#[derive(Debug, Clone)]
pub struct ShellInfo {
    pub shell_id: ShellId,
    pub state: ShellState,
    pub exit: Option<ExitSummary>,
    pub created_at_ms: i64,
    pub last_attached_at_ms: i64,
    pub attachment_count: usize,
    /// Owner (authenticated user) and the resolved Unix account, for audit
    /// and listing. Empty owner in dev/unchecked mode.
    pub owner: String,
    pub account: Option<String>,
}

/// Everything a client needs to open a shell (subset of wire `OpenShell`).
#[derive(Debug, Clone, Default)]
pub struct OpenShellRequest {
    /// Authenticated user requesting the shell (`""` in dev/unchecked mode).
    pub user: String,
    /// Unix account the client asked to run under (empty = default/self).
    /// Authorized against the [`AccessPolicy`]; the resolved name is recorded
    /// on the shell. The uid/gid switch itself is a deployment concern
    /// (ADR 0007).
    pub requested_account: Option<String>,
    /// Program to run; `None` = login shell (`$SHELL`).
    pub command: Option<String>,
    pub args: Vec<String>,
    pub cols: u16,
    pub rows: u16,
    /// Client-generated key making retries idempotent (spec §9).
    pub idempotency_key: [u8; 16],
}

#[derive(Debug)]
pub struct OpenedShell {
    pub shell_id: ShellId,
    pub resume_token: ResumeToken,
    /// True when the idempotency key matched an existing shell. The shell
    /// identity is idempotent; the token is freshly rotated (tokens are
    /// stored hashed, so the original cannot be re-issued — spec §12).
    pub reused: bool,
}

/// Events delivered to one attachment. The channel disconnecting without an
/// `Exited` event means the attachment was detached (slow consumer, explicit
/// detach elsewhere, or manager shutdown) while the shell kept running.
#[derive(Debug, Clone)]
pub enum AttachmentEvent {
    /// Raw PTY output bytes (reliable live stream, spec §7 baseline).
    Output(Vec<u8>),
    Exited(ExitSummary),
}

/// A live attachment (spec §11: returned already `live` — the snapshot in
/// this struct is the `synchronizing` payload).
pub struct Attachment {
    pub attachment_id: u64,
    pub shell_id: ShellId,
    /// Redraw sequence reconstructing the current screen.
    pub snapshot: Vec<u8>,
    pub screen_revision: u64,
    pub rotated_resume_token: ResumeToken,
    pub oldest_history_line_id: u64,
    pub newest_history_line_id: u64,
    pub events: Receiver<AttachmentEvent>,
}

/// How many superseded token hashes each shell remembers for replay
/// detection (spec §12): presenting one of these yields the distinct
/// `TokenReplayed` (possible theft) instead of the generic `InvalidToken`.
/// Bounded per AGENTS rule 7; older rotations degrade to `InvalidToken`.
const SUPERSEDED_TOKEN_HISTORY: usize = 64;

struct Runtime {
    state: ShellState,
    model: TerminalModel,
    pty: Option<PtyProcess>,
    attachments: HashMap<u64, SyncSender<AttachmentEvent>>,
    next_attachment_id: u64,
    token_hash: [u8; 32],
    /// Hashes of tokens this shell rotated away, newest last (bounded ring).
    superseded_token_hashes: VecDeque<[u8; 32]>,
    exit: Option<ExitSummary>,
    last_attached_at_ms: i64,
}

impl Runtime {
    /// Rotate the resume token, remembering the superseded hash for replay
    /// detection. Every rotation site must go through here.
    fn rotate_token(&mut self) -> ResumeToken {
        let token = ResumeToken::generate();
        if self.superseded_token_hashes.len() == SUPERSEDED_TOKEN_HISTORY {
            self.superseded_token_hashes.pop_front();
        }
        self.superseded_token_hashes.push_back(self.token_hash);
        self.token_hash = token.hash();
        token
    }
}

struct ShellEntry {
    id: ShellId,
    created_at_ms: i64,
    owner: String,
    account: Option<String>,
    runtime: Mutex<Runtime>,
    exited: Condvar,
}

/// Owner of all shells on one server. Cheap to clone handles out of via
/// `Arc`; all methods take `&self`.
pub struct ShellManager {
    config: SessionCoreConfig,
    policy: Arc<dyn AccessPolicy>,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    shells: HashMap<ShellId, Arc<ShellEntry>>,
    /// Keyed by (owner, idempotency_key) so one user's retry never resolves to
    /// — or overwrites — another user's shell (threat model T12). In dev/
    /// single-user mode the owner is constant, so this is the plain per-key map.
    idempotency: HashMap<(String, [u8; 16]), ShellId>,
}

impl ShellManager {
    /// Development default: permissive account policy ([`AllowAll`]).
    pub fn new(config: SessionCoreConfig) -> ShellManager {
        ShellManager::with_policy(config, Arc::new(AllowAll))
    }

    /// Enforce `policy` when resolving the Unix account for new shells.
    pub fn with_policy(config: SessionCoreConfig, policy: Arc<dyn AccessPolicy>) -> ShellManager {
        ShellManager {
            config,
            policy,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Create a shell, or return the existing one for a repeated idempotency
    /// key (spec §9: retrying after a timeout must not create duplicates).
    pub fn open_shell(&self, req: &OpenShellRequest) -> Result<OpenedShell, SessionError> {
        let mut inner = self.inner.lock().unwrap();

        // Idempotency is scoped to (owner, key): a repeated key from the same
        // user returns their existing shell with a freshly rotated token; the
        // same key from a *different* user cannot resolve to — nor, below,
        // overwrite — this shell (threat model T12).
        let idem_key = (req.user.clone(), req.idempotency_key);
        if let Some(existing) = inner.idempotency.get(&idem_key) {
            if let Some(entry) = inner.shells.get(existing) {
                let mut rt = entry.runtime.lock().unwrap();
                let token = rt.rotate_token();
                return Ok(OpenedShell {
                    shell_id: entry.id,
                    resume_token: token,
                    reused: true,
                });
            }
        }

        // Authorize the requested account before spending any resources
        // (threat model T12, authorization half).
        let account = self
            .policy
            .resolve(&req.user, req.requested_account.as_deref())
            .map_err(|_| SessionError::Forbidden)?;

        let live_shells: Vec<&Arc<ShellEntry>> = inner
            .shells
            .values()
            .filter(|e| e.runtime.lock().unwrap().state != ShellState::Exited)
            .collect();
        if live_shells.len() >= self.config.max_shells {
            return Err(SessionError::LimitExceeded("max_shells"));
        }
        // Per-owner fairness cap: one user must not exhaust the global pool.
        if self.config.max_shells_per_user > 0 {
            let owned = live_shells.iter().filter(|e| e.owner == req.user).count();
            if owned >= self.config.max_shells_per_user {
                return Err(SessionError::LimitExceeded("max_shells_per_user"));
            }
        }

        // Resolve how to launch: when privilege drop is enabled and the
        // account differs from the daemon's own user, this wraps the command
        // in `setpriv` (ADR 0007). Errors here (missing account, cannot switch)
        // abort the open — never a silent unprivileged fallback.
        let launch = launch::build_launch(
            self.config.privilege_drop,
            self.config.shell_resource_limits,
            account.as_deref(),
            req.command.as_deref(),
            &req.args,
        )?;

        // 0 means "client didn't say"; fall back to the conventional 80x24,
        // then clamp to the model's safe floor.
        let (cols, rows) = clamp_dims(
            if req.cols == 0 { 80 } else { req.cols },
            if req.rows == 0 { 24 } else { req.rows },
        );
        let mut pty = PtyProcess::spawn(&PtyConfig {
            program: launch.program,
            args: launch.args,
            env: vec![],
            cwd: None,
            cols,
            rows,
        })?;
        let output = pty
            .take_output()
            .ok_or_else(|| SessionError::Internal("PTY output already taken".into()))?;

        let token = ResumeToken::generate();
        let shell_id = ShellId(rand::random());
        let entry = Arc::new(ShellEntry {
            id: shell_id,
            created_at_ms: now_ms(),
            owner: req.user.clone(),
            account,
            runtime: Mutex::new(Runtime {
                state: ShellState::Running,
                model: TerminalModel::new(TerminalModelConfig {
                    cols,
                    rows,
                    max_history_lines: self.config.scrollback_max_lines,
                    max_history_bytes: self.config.scrollback_max_bytes,
                }),
                pty: Some(pty),
                attachments: HashMap::new(),
                next_attachment_id: 1,
                token_hash: token.hash(),
                superseded_token_hashes: VecDeque::new(),
                exit: None,
                last_attached_at_ms: 0,
            }),
            exited: Condvar::new(),
        });

        let pump_entry = Arc::clone(&entry);
        std::thread::Builder::new()
            .name(format!("hf-shell-pump-{shell_id}"))
            .spawn(move || pump(pump_entry, output))
            .map_err(|e| SessionError::Internal(format!("spawn pump thread: {e}")))?;

        inner.shells.insert(shell_id, entry);
        inner.idempotency.insert(idem_key, shell_id);
        Ok(OpenedShell {
            shell_id,
            resume_token: token,
            reused: false,
        })
    }

    /// Attach to a running shell with a valid resume token. Rotates the token
    /// (spec §12) and resizes the shell to the client's dimensions.
    pub fn attach(
        &self,
        owner: &str,
        shell_id: &ShellId,
        token: &ResumeToken,
        cols: u16,
        rows: u16,
    ) -> Result<Attachment, SessionError> {
        let entry = self.entry(shell_id)?;
        // Resume tokens are scoped to the authenticated owner as well as the
        // shell (spec §12). Use the unknown-shell shape so this is not an
        // ownership oracle, and reject before validating/rotating the token.
        if entry.owner != owner {
            return Err(SessionError::ShellNotFound);
        }
        let mut rt = entry.runtime.lock().unwrap();
        if rt.token_hash != token.hash() {
            // A superseded token is distinct from garbage: someone presented
            // a credential that *was* valid — possible theft (spec §12).
            if rt.superseded_token_hashes.contains(&token.hash()) {
                return Err(SessionError::TokenReplayed);
            }
            return Err(SessionError::InvalidToken);
        }
        self.attach_runtime(*shell_id, &mut rt, cols, rows)
    }

    /// Attach after a transport boundary has independently authenticated the
    /// owner and authorized the `attach` operation. Agent mode uses this so a
    /// gateway never receives the daemon's local resume-token secret. Owner
    /// mismatch deliberately has the same shape as an unknown shell.
    pub fn attach_authorized(
        &self,
        owner: &str,
        shell_id: &ShellId,
        cols: u16,
        rows: u16,
    ) -> Result<Attachment, SessionError> {
        let entry = self.entry(shell_id)?;
        if entry.owner != owner {
            return Err(SessionError::ShellNotFound);
        }
        let mut rt = entry.runtime.lock().unwrap();
        self.attach_runtime(*shell_id, &mut rt, cols, rows)
    }

    /// Detach an attachment. The shell keeps running (spec §11).
    pub fn detach(&self, shell_id: &ShellId, attachment_id: u64) -> Result<(), SessionError> {
        let entry = self.entry(shell_id)?;
        let mut rt = entry.runtime.lock().unwrap();
        rt.attachments.remove(&attachment_id);
        Ok(())
    }

    /// Write client input to the shell's PTY (reliable, ordered — spec §9).
    pub fn write_input(&self, shell_id: &ShellId, data: &[u8]) -> Result<(), SessionError> {
        let entry = self.entry(shell_id)?;
        let mut rt = entry.runtime.lock().unwrap();
        match rt.pty.as_mut() {
            Some(pty) => Ok(pty.write(data)?),
            None => Err(SessionError::NotRunning),
        }
    }

    /// Resize the shell (newest size wins; callers may coalesce — spec §9).
    pub fn resize(&self, shell_id: &ShellId, cols: u16, rows: u16) -> Result<(), SessionError> {
        // 0 means "unknown/keep current"; any other value is clamped to the
        // model's safe floor so the PTY and model stay in sync and neither
        // reaches avt's degenerate 0/1-column paths (threat model T9).
        if cols == 0 || rows == 0 {
            return Ok(());
        }
        let (cols, rows) = clamp_dims(cols, rows);
        let entry = self.entry(shell_id)?;
        let mut rt = entry.runtime.lock().unwrap();
        match rt.pty.as_mut() {
            Some(pty) => {
                pty.resize(cols, rows)?;
                rt.model.resize(cols, rows);
                Ok(())
            }
            None => Err(SessionError::NotRunning),
        }
    }

    /// Kill the shell and wait for it to be reaped. Idempotent (spec §9):
    /// terminating an exited shell returns the recorded exit status.
    pub fn terminate(&self, shell_id: &ShellId) -> Result<ExitSummary, SessionError> {
        let entry = self.entry(shell_id)?;
        let mut rt = entry.runtime.lock().unwrap();
        if let Some(exit) = rt.exit {
            return Ok(exit);
        }
        rt.state = ShellState::Terminating;
        if let Some(pty) = rt.pty.as_mut() {
            pty.kill()?;
        }
        // The pump thread observes EOF, reaps the child, records the exit and
        // notifies. Condvar wait releases the runtime lock meanwhile.
        let (mut rt, timeout) = entry
            .exited
            .wait_timeout_while(rt, Duration::from_secs(10), |rt| rt.exit.is_none())
            .map_err(|e| SessionError::Internal(format!("poisoned: {e}")))?;
        if timeout.timed_out() {
            return Err(SessionError::Internal(
                "shell did not exit after kill".into(),
            ));
        }
        rt.state = ShellState::Exited;
        Ok(rt.exit.expect("exit recorded"))
    }

    /// Range read of retained scrollback (spec §10).
    pub fn history(
        &self,
        shell_id: &ShellId,
        before_line_id: u64,
        maximum_lines: u32,
        maximum_bytes: u32,
    ) -> Result<HistoryRange, SessionError> {
        let entry = self.entry(shell_id)?;
        let rt = entry.runtime.lock().unwrap();
        Ok(rt
            .model
            .history_range(before_line_id, maximum_lines, maximum_bytes))
    }

    /// (oldest retained, newest committed) history line IDs; 0 = none.
    pub fn history_bounds(&self, shell_id: &ShellId) -> Result<(u64, u64), SessionError> {
        let entry = self.entry(shell_id)?;
        let rt = entry.runtime.lock().unwrap();
        Ok((rt.model.oldest_line_id(), rt.model.newest_line_id()))
    }

    pub fn shell_info(&self, shell_id: &ShellId) -> Result<ShellInfo, SessionError> {
        let entry = self.entry(shell_id)?;
        let rt = entry.runtime.lock().unwrap();
        Ok(ShellInfo {
            shell_id: entry.id,
            state: rt.state,
            exit: rt.exit,
            created_at_ms: entry.created_at_ms,
            last_attached_at_ms: rt.last_attached_at_ms,
            attachment_count: rt.attachments.len(),
            owner: entry.owner.clone(),
            account: entry.account.clone(),
        })
    }

    pub fn list_shells(&self) -> Vec<ShellInfo> {
        let inner = self.inner.lock().unwrap();
        let mut infos: Vec<ShellInfo> = inner
            .shells
            .values()
            .map(|e| {
                let rt = e.runtime.lock().unwrap();
                ShellInfo {
                    shell_id: e.id,
                    state: rt.state,
                    exit: rt.exit,
                    created_at_ms: e.created_at_ms,
                    last_attached_at_ms: rt.last_attached_at_ms,
                    attachment_count: rt.attachments.len(),
                    owner: e.owner.clone(),
                    account: e.account.clone(),
                }
            })
            .collect();
        infos.sort_by_key(|i| i.created_at_ms);
        infos
    }

    /// Drop an exited shell and its retained scrollback.
    pub fn remove_exited(&self, shell_id: &ShellId) -> Result<(), SessionError> {
        let mut inner = self.inner.lock().unwrap();
        let entry = inner
            .shells
            .get(shell_id)
            .ok_or(SessionError::ShellNotFound)?;
        if entry.runtime.lock().unwrap().state != ShellState::Exited {
            return Err(SessionError::NotRunning);
        }
        inner.shells.remove(shell_id);
        inner.idempotency.retain(|_, id| id != shell_id);
        Ok(())
    }

    fn entry(&self, shell_id: &ShellId) -> Result<Arc<ShellEntry>, SessionError> {
        self.inner
            .lock()
            .unwrap()
            .shells
            .get(shell_id)
            .cloned()
            .ok_or(SessionError::ShellNotFound)
    }

    fn attach_runtime(
        &self,
        shell_id: ShellId,
        rt: &mut Runtime,
        cols: u16,
        rows: u16,
    ) -> Result<Attachment, SessionError> {
        if rt.state != ShellState::Running {
            return Err(SessionError::NotRunning);
        }
        if rt.attachments.len() >= self.config.max_attachments_per_shell {
            return Err(SessionError::LimitExceeded("max_attachments_per_shell"));
        }

        // 0 dimensions mean "keep the current size" on reattach; otherwise
        // clamp to the model's safe floor before touching the PTY or model.
        if cols != 0 && rows != 0 {
            let (cols, rows) = clamp_dims(cols, rows);
            if rt.model.size() != (cols, rows) {
                if let Some(pty) = rt.pty.as_mut() {
                    pty.resize(cols, rows)?;
                }
                rt.model.resize(cols, rows);
            }
        }

        // Keep the core invariant that every successful attachment rotates
        // the local token, even when the overlay deliberately does not expose
        // that token outside the managed server.
        let rotated = rt.rotate_token();
        rt.last_attached_at_ms = now_ms();

        let attachment_id = rt.next_attachment_id;
        rt.next_attachment_id += 1;
        let (tx, rx) = std::sync::mpsc::sync_channel(self.config.max_queued_chunks);
        rt.attachments.insert(attachment_id, tx);

        Ok(Attachment {
            attachment_id,
            shell_id,
            snapshot: rt.model.snapshot(),
            screen_revision: rt.model.revision(),
            rotated_resume_token: rotated,
            oldest_history_line_id: rt.model.oldest_line_id(),
            newest_history_line_id: rt.model.newest_line_id(),
            events: rx,
        })
    }
}

/// Per-shell pump: PTY output → terminal model → attachment fan-out.
fn pump(entry: Arc<ShellEntry>, output: Receiver<Vec<u8>>) {
    for chunk in output.iter() {
        let mut rt = entry.runtime.lock().unwrap();
        rt.model.feed(&chunk);
        let mut too_slow: Vec<u64> = Vec::new();
        for (id, tx) in &rt.attachments {
            match tx.try_send(AttachmentEvent::Output(chunk.clone())) {
                Ok(()) => {}
                // Full queue = slow consumer: detach it, never block the
                // shell (spec §8, ERR_TOO_SLOW at the wire layer).
                Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                    too_slow.push(*id);
                }
            }
        }
        for id in too_slow {
            rt.attachments.remove(&id);
        }
    }

    // PTY EOF: reap the child and record the exit.
    let mut rt = entry.runtime.lock().unwrap();
    let exit = match rt.pty.take() {
        Some(mut pty) => pty.wait().unwrap_or(ExitSummary {
            success: false,
            exit_code: 255,
        }),
        None => ExitSummary {
            success: false,
            exit_code: 255,
        },
    };
    rt.state = ShellState::Exited;
    rt.exit = Some(exit);
    for (_, tx) in rt.attachments.drain() {
        let _ = tx.try_send(AttachmentEvent::Exited(exit));
    }
    drop(rt);
    entry.exited.notify_all();
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
