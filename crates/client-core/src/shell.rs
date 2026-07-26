//! Per-attachment pumps: a reader task draining the attachment stream into
//! the GUI's bounded output sink, and a writer task serializing input,
//! resize, pong, history and detach onto the write half. Both die with their
//! stream; the supervisor-level reconnect brings the shell back.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use hf_native_client::AttachedShell;
use hf_protocol::pb::envelope::Message as Msg;
use tokio::sync::{mpsc, oneshot};

use crate::store::Store;
use crate::{CoreEvent, HistoryPage, ShellStateEvent};

/// Commands accepted by the writer task (bounded queue, 64).
pub enum WriterCmd {
    Input(Vec<u8>),
    Resize(u16, u16),
    History {
        before_line_id: u64,
        max_lines: u32,
        reply: oneshot::Sender<Result<HistoryPage>>,
    },
    Detach,
}

/// At most this many history requests may be awaiting their chunks.
const MAX_PENDING_HISTORY: usize = 4;
/// Writer command queue bound.
const WRITER_QUEUE: usize = 64;

pub struct PumpCtx {
    pub server_key: String,
    pub shell_hex: String,
    pub store: Arc<Store>,
    pub events: mpsc::Sender<CoreEvent>,
}

/// Spawn reader + writer for an attached shell. Returns the writer handle;
/// the caller keeps it in its live map and routes Input/Resize/History/Detach
/// through it. `output` is the GUI-owned bounded sink: when it fills, the
/// reader awaits, QUIC flow control backpressures, and the *server's*
/// slow-consumer policy decides (spec §8) — this process never buffers
/// unboundedly.
pub fn spawn_pumps(
    shell: AttachedShell,
    output: mpsc::Sender<Vec<u8>>,
    ctx: PumpCtx,
) -> mpsc::Sender<WriterCmd> {
    let (writer_tx, mut writer_rx) = mpsc::channel::<WriterCmd>(WRITER_QUEUE);
    let (mut writer, mut reader) = shell.split();
    // History replies arrive on the read half but are requested through the
    // write half; this bounded FIFO pairs them up.
    let pending_history: Arc<Mutex<VecDeque<oneshot::Sender<Result<HistoryPage>>>>> =
        Arc::new(Mutex::new(VecDeque::new()));

    // Internal channel so the reader can ask the writer to pong (spec §14).
    let (pong_tx, mut pong_rx) = mpsc::channel::<u64>(8);

    let history_for_writer = Arc::clone(&pending_history);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                cmd = writer_rx.recv() => {
                    let Some(cmd) = cmd else { break };
                    let result = match cmd {
                        WriterCmd::Input(bytes) => writer.input(&bytes).await,
                        WriterCmd::Resize(cols, rows) => writer.resize(cols, rows).await,
                        WriterCmd::History { before_line_id, max_lines, reply } => {
                            // Scope the guard so the future stays Send.
                            let rejected = {
                                let mut queue = history_for_writer.lock().unwrap();
                                if queue.len() >= MAX_PENDING_HISTORY {
                                    Some(reply)
                                } else {
                                    queue.push_back(reply);
                                    None
                                }
                            };
                            if let Some(reply) = rejected {
                                let _ = reply.send(Err(anyhow!("too many pending history requests")));
                                continue;
                            }
                            writer.request_history(before_line_id, max_lines).await
                        }
                        WriterCmd::Detach => {
                            let _ = writer.detach().await;
                            break;
                        }
                    };
                    if result.is_err() {
                        break; // stream dead; reader notices too
                    }
                }
                nonce = pong_rx.recv() => {
                    let Some(nonce) = nonce else { break };
                    if writer.pong(nonce).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    tokio::spawn(async move {
        loop {
            let envelope = match reader.next_envelope().await {
                Ok(envelope) => envelope,
                Err(_) => {
                    // Transport died. The shell keeps running server-side;
                    // the frontend re-attaches after the next `connected`.
                    emit(&ctx, ShellStateEvent::Detached, None).await;
                    break;
                }
            };
            match envelope.message {
                Some(Msg::TerminalOutput(out)) => {
                    if output.send(out.data).await.is_err() {
                        break; // GUI dropped the sink (tab closed)
                    }
                }
                Some(Msg::Ping(p)) => {
                    if pong_tx.send(p.nonce).await.is_err() {
                        break;
                    }
                }
                Some(Msg::HistoryChunk(chunk)) => {
                    if let Some(reply) = ctx_pop(&pending_history) {
                        let _ = reply.send(Ok(HistoryPage {
                            lines: chunk.lines,
                            first_line_id: chunk.first_line_id,
                            truncated_by_eviction: chunk.truncated_by_eviction,
                        }));
                    }
                }
                Some(Msg::HistoryEnd(_)) => {
                    // A request that yielded no chunk still gets an answer.
                    if let Some(reply) = ctx_pop(&pending_history) {
                        let _ = reply.send(Ok(HistoryPage {
                            lines: Vec::new(),
                            first_line_id: 0,
                            truncated_by_eviction: false,
                        }));
                    }
                }
                Some(Msg::ShellExited(e)) => {
                    let _ = ctx.store.remove_shell(&ctx.server_key, &ctx.shell_hex);
                    emit(&ctx, ShellStateEvent::Exited, Some(e.exit_code)).await;
                    break;
                }
                _ => {}
            }
        }
    });

    writer_tx
}

fn ctx_pop(
    queue: &Arc<Mutex<VecDeque<oneshot::Sender<Result<HistoryPage>>>>>,
) -> Option<oneshot::Sender<Result<HistoryPage>>> {
    queue.lock().unwrap().pop_front()
}

async fn emit(ctx: &PumpCtx, state: ShellStateEvent, exit_code: Option<i32>) {
    let _ = ctx
        .events
        .send(CoreEvent::ShellState {
            server: ctx.server_key.clone(),
            shell: ctx.shell_hex.clone(),
            state,
            exit_code,
        })
        .await;
}

