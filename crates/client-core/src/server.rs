//! Per-server supervision: one supervisor task per configured server owning
//! the connection lifecycle (connect → auth → resolve pending opens → serve
//! commands → reconnect with backoff), plus a control-channel actor that
//! multiplexes request/response over the control stream and runs the client
//! keepalive (ADR 0020).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use hf_native_client::{
    attach_failure_action, attach_shell, connect_with, AuthMethod, Chan, Connection, FailureAction,
    ServerConn,
};
use hf_protocol::pb::{self, envelope::Message as Msg, Envelope};
use tokio::sync::{mpsc, oneshot, watch};

use crate::shell::{spawn_pumps, PumpCtx, WriterCmd};
use crate::store::{hex, unhex, Store};
use crate::{now_ms, AttachInfo, CoreEvent, HistoryPage, ServerStatus, ShellRow, ShellStateEvent};

/// In-flight control requests are bounded; beyond this the caller gets an
/// immediate error instead of unbounded queueing (AGENTS rule 7).
const MAX_INFLIGHT_CONTROL: usize = 32;
/// Keepalive misses before the connection is declared dead (spec §14).
const MAX_MISSED_PONGS: u32 = 3;
/// Fallback when the server does not advertise an interval.
const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(15);
const BACKOFF_START: Duration = Duration::from_secs(1);
const BACKOFF_CAP: Duration = Duration::from_secs(15);

pub enum ServerCmd {
    Open {
        name: String,
        cols: u16,
        rows: u16,
        reply: oneshot::Sender<Result<String>>,
    },
    Attach {
        shell_hex: String,
        cols: u16,
        rows: u16,
        output: mpsc::Sender<Vec<u8>>,
        reply: oneshot::Sender<Result<AttachInfo>>,
    },
    Input {
        shell_hex: String,
        bytes: Vec<u8>,
    },
    Resize {
        shell_hex: String,
        cols: u16,
        rows: u16,
    },
    Detach {
        shell_hex: String,
    },
    Terminate {
        shell_hex: String,
        reply: oneshot::Sender<Result<i32>>,
    },
    History {
        shell_hex: String,
        before_line_id: u64,
        max_lines: u32,
        reply: oneshot::Sender<Result<HistoryPage>>,
    },
    /// Password for a password-auth server (ADR 0016). Held in memory for a
    /// single connect attempt, then dropped — never persisted. The outcome
    /// arrives as a `ServerStatus` event (`Connected` or `AuthRequired` again
    /// with a detail message).
    Login {
        password: String,
    },
}

/// Marker error: the record is configured for password login (username set,
/// no SSH key) and no password is available — the GUI must supply one.
#[derive(Debug)]
struct PasswordRequired;

impl std::fmt::Display for PasswordRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("password required")
    }
}

impl std::error::Error for PasswordRequired {}

pub struct SupervisorCtx {
    pub server_key: String,
    pub store: Arc<Store>,
    pub events: mpsc::Sender<CoreEvent>,
}

// ---------------------------------------------------------------------------
// Control-channel actor
// ---------------------------------------------------------------------------

struct ControlReq {
    env: Envelope,
    reply: oneshot::Sender<Result<Envelope>>,
}

#[derive(Clone)]
struct ControlHandle {
    tx: mpsc::Sender<ControlReq>,
    next_request: Arc<std::sync::atomic::AtomicU64>,
}

impl ControlHandle {
    async fn request(&self, mut env: Envelope) -> Result<Envelope> {
        let request_id = self
            .next_request
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        env.request_id = request_id;
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(ControlReq {
                env,
                reply: reply_tx,
            })
            .await
            .map_err(|_| anyhow!("control channel closed"))?;
        reply_rx.await.map_err(|_| anyhow!("control channel closed"))?
    }

    async fn list_shells(&self) -> Result<Vec<pb::ShellInfo>> {
        let reply = self
            .request(plain(Msg::ListShells(pb::ListShells {})))
            .await?;
        match reply.message {
            Some(Msg::ShellList(list)) => Ok(list.shells),
            Some(Msg::Error(e)) => bail!("list failed: {}", e.human_message),
            _ => bail!("unexpected reply to ListShells"),
        }
    }

    /// Returns (shell_id wire bytes, resume token).
    async fn open_shell(
        &self,
        command: Option<&str>,
        cols: u16,
        rows: u16,
        idempotency_key: [u8; 16],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let reply = self
            .request(plain(Msg::OpenShell(pb::OpenShell {
                unix_account: String::new(),
                command: command.unwrap_or("").to_string(),
                initial_cols: cols as u32,
                initial_rows: rows as u32,
                idempotency_key: idempotency_key.to_vec(),
            })))
            .await?;
        match reply.message {
            Some(Msg::ShellOpened(o)) => Ok((reply.shell_id, o.resume_token)),
            Some(Msg::Error(e)) => bail!("open failed: {}", e.human_message),
            _ => bail!("unexpected reply to OpenShell"),
        }
    }

    async fn terminate(&self, shell_id: &[u8]) -> Result<i32> {
        let mut env = plain(Msg::TerminateShell(pb::TerminateShell {}));
        env.shell_id = shell_id.to_vec();
        let reply = self.request(env).await?;
        match reply.message {
            Some(Msg::ShellExited(e)) => Ok(e.exit_code),
            Some(Msg::Error(e)) => bail!("terminate failed: {}", e.human_message),
            _ => bail!("unexpected reply to TerminateShell"),
        }
    }
}

fn plain(message: Msg) -> Envelope {
    Envelope {
        request_id: 0,
        server_id: vec![],
        shell_id: vec![],
        message: Some(message),
    }
}

/// Owns the control [`Chan`]: multiplexes request/response by `request_id`,
/// answers server pings, and drives the client keepalive — send `Ping` every
/// `keepalive`, declare the connection dead after 3 unanswered (ADR 0020).
/// `dead` flips to true when the actor exits for any reason.
fn spawn_control(mut chan: Chan, keepalive: Duration) -> (ControlHandle, watch::Receiver<bool>) {
    let (tx, mut rx) = mpsc::channel::<ControlReq>(MAX_INFLIGHT_CONTROL);
    let (dead_tx, dead_rx) = watch::channel(false);
    tokio::spawn(async move {
        let mut pending: HashMap<u64, oneshot::Sender<Result<Envelope>>> = HashMap::new();
        let mut ticker = tokio::time::interval(keepalive);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.reset(); // first tick after one full interval
        let mut outstanding_pings: u32 = 0;
        let mut nonce: u64 = 0;
        loop {
            tokio::select! {
                req = rx.recv() => {
                    let Some(req) = req else { break }; // supervisor gone
                    if pending.len() >= MAX_INFLIGHT_CONTROL {
                        let _ = req.reply.send(Err(anyhow!("too many in-flight control requests")));
                        continue;
                    }
                    let request_id = req.env.request_id;
                    if let Err(e) = chan.send_env(req.env).await {
                        let _ = req.reply.send(Err(e));
                        break;
                    }
                    pending.insert(request_id, req.reply);
                }
                env = chan.recv_env() => {
                    let env = match env { Ok(env) => env, Err(_) => break };
                    match &env.message {
                        Some(Msg::Ping(p)) => {
                            let pong = plain(Msg::Pong(pb::Pong { nonce: p.nonce }));
                            if chan.send_env(pong).await.is_err() { break; }
                        }
                        Some(Msg::Pong(_)) => outstanding_pings = 0,
                        _ => {
                            if let Some(reply) = pending.remove(&env.request_id) {
                                let _ = reply.send(Ok(env));
                            }
                        }
                    }
                }
                _ = ticker.tick() => {
                    if outstanding_pings >= MAX_MISSED_PONGS {
                        break; // connection is dead; supervisor reconnects
                    }
                    nonce += 1;
                    outstanding_pings += 1;
                    if chan.send_env(plain(Msg::Ping(pb::Ping { nonce }))).await.is_err() {
                        break;
                    }
                }
            }
        }
        // Dropping `pending` fails all outstanding requests.
        let _ = dead_tx.send(true);
    });
    (
        ControlHandle {
            tx,
            next_request: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        },
        dead_rx,
    )
}

// ---------------------------------------------------------------------------
// Supervisor
// ---------------------------------------------------------------------------

pub async fn run_supervisor(ctx: SupervisorCtx, mut rx: mpsc::Receiver<ServerCmd>) {
    let mut backoff = BACKOFF_START;
    let mut first = true;
    // One-shot password from a Login command; taken on the next connect
    // attempt and never retained past it.
    let mut password: Option<String> = None;
    'outer: loop {
        let status = if first {
            ServerStatus::Connecting
        } else {
            ServerStatus::Reconnecting
        };
        first = false;
        ctx.emit_status(status, None).await;

        let attempted_password = password.is_some();
        let conn = match connect_and_auth(&ctx, password.take()).await {
            Ok(conn) => conn,
            Err(e) => {
                // Password auth is interactive: without a (correct) password
                // reconnecting cannot succeed, so instead of the backoff loop
                // we surface `AuthRequired` and wait for the GUI's Login.
                if attempted_password || e.downcast_ref::<PasswordRequired>().is_some() {
                    let detail = attempted_password.then(|| e.to_string());
                    ctx.emit_status(ServerStatus::AuthRequired, detail).await;
                    loop {
                        match rx.recv().await {
                            None => return, // Core dropped this server
                            Some(ServerCmd::Login { password: p }) => {
                                password = Some(p);
                                continue 'outer;
                            }
                            Some(cmd) => refuse_unauthenticated(cmd),
                        }
                    }
                }
                ctx.emit_status(ServerStatus::Reconnecting, Some(e.to_string()))
                    .await;
                // Commands queue in the bounded channel meanwhile; if the
                // Core handle is gone, stop retrying a dead server.
                if rx.is_closed() {
                    return;
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_CAP);
                continue;
            }
        };
        backoff = BACKOFF_START;

        let (connection, chan, grant, hello) = conn.into_parts();
        if let Err(e) = ctx.store.set_grant(&ctx.server_key, &grant) {
            ctx.emit_warning(format!("persist grant: {e}")).await;
        }
        let keepalive = if hello.keepalive_interval_ms > 0 {
            Duration::from_millis(hello.keepalive_interval_ms as u64)
        } else {
            DEFAULT_KEEPALIVE
        };
        let (control, mut dead) = spawn_control(chan, keepalive);

        // Crash-window recovery (ADR 0018): keys persisted before their
        // OpenShell was confirmed resolve to the same shell on re-open.
        resolve_pending_opens(&ctx, &control).await;

        match control.list_shells().await {
            Ok(shells) => ctx.emit_shells(&shells).await,
            Err(_) => continue 'outer,
        }
        ctx.emit_status(ServerStatus::Connected, None).await;

        let mut live: HashMap<String, mpsc::Sender<WriterCmd>> = HashMap::new();
        loop {
            tokio::select! {
                cmd = rx.recv() => {
                    let Some(cmd) = cmd else { return }; // Core dropped this server
                    handle_cmd(&ctx, cmd, &connection, &control, &mut live).await;
                }
                _ = dead.changed() => {
                    // Attachment pumps die with their streams; the frontend
                    // re-attaches when it sees `connected` again.
                    continue 'outer;
                }
            }
        }
    }
}

async fn connect_and_auth(ctx: &SupervisorCtx, password: Option<String>) -> Result<ServerConn> {
    let record = ctx
        .store
        .server(&ctx.server_key)
        .context("server removed from store")?;
    // Cheap path first: the stored grant (12h TTL, refreshed on every auth).
    if let Some(grant_b64) = &record.grant {
        if let Ok(grant) = base64::engine::general_purpose::STANDARD.decode(grant_b64) {
            if let Ok(conn) = connect_with(&record.url, AuthMethod::Grant(grant)).await {
                return Ok(conn);
            }
        }
    }
    // Full auth: username + key = SSH challenge; username alone = password
    // login (ADR 0016, needs the GUI to supply one); neither = dev (loopback).
    let method = match (&record.username, &record.ssh_key_path) {
        (Some(username), Some(path)) => AuthMethod::SshKey {
            username: username.clone(),
            private_key_path: path.clone(),
        },
        (Some(username), None) => {
            let Some(password) = password else {
                return Err(PasswordRequired.into());
            };
            AuthMethod::Password {
                username: username.clone(),
                password,
            }
        }
        _ => AuthMethod::Dev,
    };
    connect_with(&record.url, method).await
}

/// Fail a command that cannot proceed while the server waits for a login.
/// Replies carry the reason; fire-and-forget commands are dropped.
fn refuse_unauthenticated(cmd: ServerCmd) {
    let refusal = || anyhow!("authentication required: log in to this server first");
    match cmd {
        ServerCmd::Open { reply, .. } => {
            let _ = reply.send(Err(refusal()));
        }
        ServerCmd::Attach { reply, .. } => {
            let _ = reply.send(Err(refusal()));
        }
        ServerCmd::Terminate { reply, .. } => {
            let _ = reply.send(Err(refusal()));
        }
        ServerCmd::History { reply, .. } => {
            let _ = reply.send(Err(refusal()));
        }
        ServerCmd::Input { .. }
        | ServerCmd::Resize { .. }
        | ServerCmd::Detach { .. }
        | ServerCmd::Login { .. } => {}
    }
}

async fn resolve_pending_opens(ctx: &SupervisorCtx, control: &ControlHandle) {
    let Some(record) = ctx.store.server(&ctx.server_key) else {
        return;
    };
    for pending in record.pending_opens {
        let Some(key) = unhex(&pending.idempotency_key)
            .and_then(|k| <[u8; 16]>::try_from(k).ok())
        else {
            let _ = ctx
                .store
                .drop_pending_open(&ctx.server_key, &pending.idempotency_key);
            continue;
        };
        match control.open_shell(None, 0, 0, key).await {
            Ok((shell_id, token)) => {
                let _ = ctx.store.resolve_pending_open(
                    &ctx.server_key,
                    &pending.idempotency_key,
                    &hex(&shell_id),
                    &token,
                    now_ms(),
                );
            }
            Err(_) => {
                // Server refused (e.g. limits): drop the journal entry so it
                // is not retried forever; the shell — if it ever existed —
                // still shows up in ListShells.
                let _ = ctx
                    .store
                    .drop_pending_open(&ctx.server_key, &pending.idempotency_key);
            }
        }
    }
}

async fn handle_cmd(
    ctx: &SupervisorCtx,
    cmd: ServerCmd,
    connection: &Connection,
    control: &ControlHandle,
    live: &mut HashMap<String, mpsc::Sender<WriterCmd>>,
) {
    match cmd {
        ServerCmd::Open {
            name,
            cols,
            rows,
            reply,
        } => {
            let idempotency_key: [u8; 16] = rand::random();
            let key_hex = hex(&idempotency_key);
            // Journal the key BEFORE the request leaves (ADR 0018).
            if let Err(e) = ctx.store.push_pending_open(&ctx.server_key, &key_hex, &name) {
                let _ = reply.send(Err(e));
                return;
            }
            match control.open_shell(None, cols, rows, idempotency_key).await {
                Ok((shell_id, token)) => {
                    let shell_hex = hex(&shell_id);
                    let result = ctx
                        .store
                        .resolve_pending_open(&ctx.server_key, &key_hex, &shell_hex, &token, now_ms())
                        .map(|()| shell_hex);
                    let _ = reply.send(result);
                }
                Err(e) => {
                    let _ = ctx.store.drop_pending_open(&ctx.server_key, &key_hex);
                    let _ = reply.send(Err(e));
                }
            }
        }
        ServerCmd::Attach {
            shell_hex,
            cols,
            rows,
            output,
            reply,
        } => {
            let result = attach_with_recovery(ctx, connection, control, &shell_hex, cols, rows, output)
                .await;
            match result {
                Ok((info, writer)) => {
                    live.insert(shell_hex.clone(), writer);
                    ctx.emit_shell_state(&shell_hex, ShellStateEvent::Attached, None)
                        .await;
                    let _ = reply.send(Ok(info));
                }
                Err(e) => {
                    let _ = reply.send(Err(e));
                }
            }
        }
        ServerCmd::Input { shell_hex, bytes } => {
            forward(live, &shell_hex, WriterCmd::Input(bytes)).await;
        }
        ServerCmd::Resize {
            shell_hex,
            cols,
            rows,
        } => {
            forward(live, &shell_hex, WriterCmd::Resize(cols, rows)).await;
        }
        ServerCmd::Detach { shell_hex } => {
            if let Some(writer) = live.remove(&shell_hex) {
                let _ = writer.send(WriterCmd::Detach).await;
            }
            ctx.emit_shell_state(&shell_hex, ShellStateEvent::Detached, None)
                .await;
        }
        ServerCmd::Terminate { shell_hex, reply } => {
            let Some(shell_id) = unhex(&shell_hex) else {
                let _ = reply.send(Err(anyhow!("malformed shell id")));
                return;
            };
            live.remove(&shell_hex);
            let result = control.terminate(&shell_id).await;
            if result.is_ok() {
                let _ = ctx.store.remove_shell(&ctx.server_key, &shell_hex);
                ctx.emit_shell_state(&shell_hex, ShellStateEvent::Exited, result.as_ref().ok().copied())
                    .await;
            }
            let _ = reply.send(result);
        }
        // Already authenticated (the grant is fresh): nothing to do. The
        // password is dropped here, not remembered.
        ServerCmd::Login { .. } => {}
        ServerCmd::History {
            shell_hex,
            before_line_id,
            max_lines,
            reply,
        } => {
            let Some(writer) = live.get(&shell_hex) else {
                let _ = reply.send(Err(anyhow!("shell is not attached")));
                return;
            };
            let cmd = WriterCmd::History {
                before_line_id,
                max_lines,
                reply,
            };
            if let Err(tokio::sync::mpsc::error::SendError(WriterCmd::History { reply, .. })) =
                writer.send(cmd).await
            {
                let _ = reply.send(Err(anyhow!("attachment closed")));
            }
        }
    }
}

async fn forward(
    live: &mut HashMap<String, mpsc::Sender<WriterCmd>>,
    shell_hex: &str,
    cmd: WriterCmd,
) {
    if let Some(writer) = live.get(shell_hex) {
        if writer.send(cmd).await.is_err() {
            live.remove(shell_hex);
        }
    }
}

/// Attach with the shared retry policy (ADR 0018). Transient failures are
/// returned to the caller (the frontend re-attaches on the next `connected`);
/// superseded tokens recover automatically via the stored idempotency key.
async fn attach_with_recovery(
    ctx: &SupervisorCtx,
    connection: &Connection,
    control: &ControlHandle,
    shell_hex: &str,
    cols: u16,
    rows: u16,
    output: mpsc::Sender<Vec<u8>>,
) -> Result<(AttachInfo, mpsc::Sender<WriterCmd>)> {
    let record = ctx
        .store
        .shell(&ctx.server_key, shell_hex)
        .with_context(|| format!("no stored shell {shell_hex}"))?;
    let shell_id = unhex(shell_hex).context("malformed shell id")?;
    let mut token = base64::engine::general_purpose::STANDARD
        .decode(&record.token)
        .context("corrupt stored token")?;
    let recovery_key = record
        .idempotency_key
        .as_deref()
        .and_then(unhex)
        .and_then(|k| <[u8; 16]>::try_from(k).ok());

    let mut recovered = false;
    loop {
        match attach_shell(connection, &shell_id, &token, cols, rows).await {
            Ok(shell) => {
                let _ = ctx
                    .store
                    .update_token(&ctx.server_key, shell_hex, &shell.rotated_token, now_ms());
                let info = AttachInfo {
                    snapshot: shell.snapshot.clone(),
                    oldest_history_line_id: shell.oldest_history_line_id,
                    newest_history_line_id: shell.newest_history_line_id,
                };
                let writer = spawn_pumps(
                    shell,
                    output,
                    PumpCtx {
                        server_key: ctx.server_key.clone(),
                        shell_hex: shell_hex.to_string(),
                        store: Arc::clone(&ctx.store),
                        events: ctx.events.clone(),
                    },
                );
                return Ok((info, writer));
            }
            Err(e) => match attach_failure_action(&e, recovery_key.is_some() && !recovered) {
                FailureAction::Retry | FailureAction::ExitKeepToken => {
                    return Err(e.into());
                }
                FailureAction::ForgetAndExit => {
                    let _ = ctx.store.remove_shell(&ctx.server_key, shell_hex);
                    ctx.emit_shell_state(shell_hex, ShellStateEvent::Exited, None)
                        .await;
                    return Err(e.into());
                }
                FailureAction::RecoverViaIdempotency => {
                    recovered = true; // at most one recovery round
                    let key = recovery_key.expect("checked by attach_failure_action");
                    match recover_token(ctx, control, &shell_id, key).await {
                        Ok(fresh) => {
                            token = fresh;
                            continue;
                        }
                        Err(recover_err) => {
                            ctx.emit_shell_state(shell_hex, ShellStateEvent::Orphaned, None)
                                .await;
                            return Err(recover_err);
                        }
                    }
                }
            },
        }
    }
}

/// Same recovery contract as the CLI (ADR 0018): presence-check first, then
/// idempotent re-open, refusing to adopt a different shell.
async fn recover_token(
    ctx: &SupervisorCtx,
    control: &ControlHandle,
    shell_id: &[u8],
    key: [u8; 16],
) -> Result<Vec<u8>> {
    let shells = control.list_shells().await?;
    let running = shells
        .iter()
        .any(|s| s.shell_id == shell_id && s.state == pb::ShellState::Running as i32);
    if !running {
        let _ = ctx.store.remove_shell(&ctx.server_key, &hex(shell_id));
        bail!("shell no longer running on the server");
    }
    let (new_id, new_token) = control.open_shell(None, 0, 0, key).await?;
    if new_id != shell_id {
        let _ = control.terminate(&new_id).await;
        bail!("idempotency key resolved to a different shell");
    }
    let _ = ctx
        .store
        .update_token(&ctx.server_key, &hex(shell_id), &new_token, now_ms());
    Ok(new_token)
}

impl SupervisorCtx {
    async fn emit_status(&self, status: ServerStatus, detail: Option<String>) {
        let _ = self
            .events
            .send(CoreEvent::ServerStatus {
                server: self.server_key.clone(),
                status,
                detail,
            })
            .await;
    }

    async fn emit_warning(&self, message: String) {
        let _ = self.events.send(CoreEvent::StoreWarning { message }).await;
    }

    async fn emit_shell_state(&self, shell_hex: &str, state: ShellStateEvent, exit_code: Option<i32>) {
        let _ = self
            .events
            .send(CoreEvent::ShellState {
                server: self.server_key.clone(),
                shell: shell_hex.to_string(),
                state,
                exit_code,
            })
            .await;
    }

    async fn emit_shells(&self, shells: &[pb::ShellInfo]) {
        let known = self
            .store
            .server(&self.server_key)
            .map(|s| s.shells)
            .unwrap_or_default();
        let rows = shells
            .iter()
            .map(|s| {
                let shell_hex = hex(&s.shell_id);
                ShellRow {
                    name: known.get(&shell_hex).map(|r| r.name.clone()),
                    has_token: known.contains_key(&shell_hex),
                    state: match s.state {
                        x if x == pb::ShellState::Running as i32 => "running",
                        x if x == pb::ShellState::Exited as i32 => "exited",
                        x if x == pb::ShellState::Terminating as i32 => "terminating",
                        _ => "unknown",
                    }
                    .to_string(),
                    shell: shell_hex,
                }
            })
            .collect();
        let _ = self
            .events
            .send(CoreEvent::ShellsUpdated {
                server: self.server_key.clone(),
                shells: rows,
            })
            .await;
    }
}
