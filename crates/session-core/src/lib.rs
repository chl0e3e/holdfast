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
//! Not yet here (Phase 2+): per-user scoping (arrives with authentication)
//! and the idle-shell expiry reaper.

mod policy;
mod token;

use std::collections::HashMap;
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hf_protocol::ids::ShellId;
use hf_pty::{ExitSummary, PtyConfig, PtyError, PtyProcess};

pub use policy::{AccessPolicy, AllowAll, Denied, StaticPolicy};
use hf_terminal_model::{HistoryRange, TerminalModel, TerminalModelConfig, MIN_COLS, MIN_ROWS};

pub use token::ResumeToken;

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
    #[error(transparent)]
    Pty(#[from] PtyError),
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Clone)]
pub struct SessionCoreConfig {
    /// Spec §8 default: 16. Per-manager until per-user auth lands.
    pub max_shells: usize,
    /// Spec §8 default: 4 (multi-client attach — open question O6).
    pub max_attachments_per_shell: usize,
    /// Bound of each attachment's event queue in messages; PTY chunks are
    /// ≤ 8 KiB, so 128 messages ≈ 1 MiB (spec §8 output-queue default).
    pub max_queued_chunks: usize,
    pub scrollback_max_lines: usize,
    pub scrollback_max_bytes: usize,
}

impl Default for SessionCoreConfig {
    fn default() -> SessionCoreConfig {
        let tm = TerminalModelConfig::default();
        SessionCoreConfig {
            max_shells: 16,
            max_attachments_per_shell: 4,
            max_queued_chunks: 128,
            scrollback_max_lines: tm.max_history_lines,
            scrollback_max_bytes: tm.max_history_bytes,
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

struct Runtime {
    state: ShellState,
    model: TerminalModel,
    pty: Option<PtyProcess>,
    attachments: HashMap<u64, SyncSender<AttachmentEvent>>,
    next_attachment_id: u64,
    token_hash: [u8; 32],
    exit: Option<ExitSummary>,
    last_attached_at_ms: i64,
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
    idempotency: HashMap<[u8; 16], ShellId>,
}

impl ShellManager {
    /// Development default: permissive account policy ([`AllowAll`]).
    pub fn new(config: SessionCoreConfig) -> ShellManager {
        ShellManager::with_policy(config, Arc::new(AllowAll))
    }

    /// Enforce `policy` when resolving the Unix account for new shells.
    pub fn with_policy(config: SessionCoreConfig, policy: Arc<dyn AccessPolicy>) -> ShellManager {
        ShellManager { config, policy, inner: Mutex::new(Inner::default()) }
    }

    /// Create a shell, or return the existing one for a repeated idempotency
    /// key (spec §9: retrying after a timeout must not create duplicates).
    pub fn open_shell(&self, req: &OpenShellRequest) -> Result<OpenedShell, SessionError> {
        let mut inner = self.inner.lock().unwrap();

        if let Some(existing) = inner.idempotency.get(&req.idempotency_key) {
            if let Some(entry) = inner.shells.get(existing) {
                let mut rt = entry.runtime.lock().unwrap();
                let token = ResumeToken::generate();
                rt.token_hash = token.hash();
                return Ok(OpenedShell { shell_id: entry.id, resume_token: token, reused: true });
            }
        }

        // Authorize the requested account before spending any resources
        // (threat model T12, authorization half).
        let account = self
            .policy
            .resolve(&req.user, req.requested_account.as_deref())
            .map_err(|_| SessionError::Forbidden)?;

        let live = inner
            .shells
            .values()
            .filter(|e| e.runtime.lock().unwrap().state != ShellState::Exited)
            .count();
        if live >= self.config.max_shells {
            return Err(SessionError::LimitExceeded("max_shells"));
        }

        // 0 means "client didn't say"; fall back to the conventional 80x24,
        // then clamp to the model's safe floor.
        let (cols, rows) = clamp_dims(
            if req.cols == 0 { 80 } else { req.cols },
            if req.rows == 0 { 24 } else { req.rows },
        );
        let mut pty = PtyProcess::spawn(&PtyConfig {
            program: req.command.clone(),
            args: req.args.clone(),
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
        inner.idempotency.insert(req.idempotency_key, shell_id);
        Ok(OpenedShell { shell_id, resume_token: token, reused: false })
    }

    /// Attach to a running shell with a valid resume token. Rotates the token
    /// (spec §12) and resizes the shell to the client's dimensions.
    pub fn attach(
        &self,
        shell_id: &ShellId,
        token: &ResumeToken,
        cols: u16,
        rows: u16,
    ) -> Result<Attachment, SessionError> {
        let entry = self.entry(shell_id)?;
        let mut rt = entry.runtime.lock().unwrap();

        if rt.state != ShellState::Running {
            return Err(SessionError::NotRunning);
        }
        if rt.token_hash != token.hash() {
            return Err(SessionError::InvalidToken);
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

        let rotated = ResumeToken::generate();
        rt.token_hash = rotated.hash();
        rt.last_attached_at_ms = now_ms();

        let attachment_id = rt.next_attachment_id;
        rt.next_attachment_id += 1;
        let (tx, rx) = std::sync::mpsc::sync_channel(self.config.max_queued_chunks);
        rt.attachments.insert(attachment_id, tx);

        Ok(Attachment {
            attachment_id,
            shell_id: *shell_id,
            snapshot: rt.model.snapshot(),
            screen_revision: rt.model.revision(),
            rotated_resume_token: rotated,
            oldest_history_line_id: rt.model.oldest_line_id(),
            newest_history_line_id: rt.model.newest_line_id(),
            events: rx,
        })
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
            return Err(SessionError::Internal("shell did not exit after kill".into()));
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
        Ok(rt.model.history_range(before_line_id, maximum_lines, maximum_bytes))
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
        let entry = inner.shells.get(shell_id).ok_or(SessionError::ShellNotFound)?;
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
        Some(mut pty) => {
            pty.wait().unwrap_or(ExitSummary { success: false, exit_code: 255 })
        }
        None => ExitSummary { success: false, exit_code: 255 },
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
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}
