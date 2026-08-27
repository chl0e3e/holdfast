//! Tauri command surface (ADR 0019): thin async wrappers over
//! `hf_client_core::Core`.
//!
//! Terminal bytes travel in JSON-safe encodings: output flows down a
//! per-attachment `tauri::ipc::Channel` as bounded-window base64 packets (first
//! message = the screen snapshot, then live PTY bytes), input as a plain
//! byte-array argument. WebView2 delivers raw invoke bodies as JSON and drops raw
//! channel payloads (observed 2026-08-03: every keystroke rejected with
//! "requires a raw body", snapshots never rendered), so the raw hot path
//! cannot be used on Windows.

use base64::Engine as _;
use hf_client_core::{AttachInfo, BootstrapView, HistoryPage, ServerConfig, UploadReply};
use serde::Serialize;
use tauri::ipc::Channel;
use tauri::State;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};

use crate::AppState;

type CmdResult<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

#[tauri::command]
pub async fn bootstrap(state: State<'_, AppState>) -> CmdResult<BootstrapView> {
    Ok(state.core.bootstrap().await)
}

#[tauri::command]
pub async fn add_server(
    state: State<'_, AppState>,
    url: String,
    display_name: String,
    username: Option<String>,
    ssh_key_path: Option<String>,
) -> CmdResult<String> {
    state
        .core
        .add_server(ServerConfig {
            url,
            display_name,
            username,
            ssh_key_path: ssh_key_path.map(Into::into),
        })
        .await
        .map_err(err)
}

#[tauri::command]
pub async fn remove_server(state: State<'_, AppState>, server: String) -> CmdResult<()> {
    state.core.remove_server(&server).await.map_err(err)
}

/// Continue one interactive auth attempt: a password, or an empty value for an
/// explicit SSH-key retry. Passwords are never persisted; the outcome arrives
/// as a `server-status` event.
#[tauri::command]
pub async fn login(state: State<'_, AppState>, server: String, password: String) -> CmdResult<()> {
    state.core.login(&server, password).await.map_err(err)
}

#[tauri::command]
pub async fn open_shell(
    state: State<'_, AppState>,
    server: String,
    name: String,
    cols: u16,
    rows: u16,
) -> CmdResult<String> {
    state
        .core
        .open_shell(&server, &name, cols, rows)
        .await
        .map_err(err)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachReply {
    pub oldest_history_line_id: u64,
    pub newest_history_line_id: u64,
}

/// Bound on the core→IPC staging queue per attachment. Each decoded protocol
/// frame is at most 1 MiB, so this queue is bounded to 32 MiB in the hostile
/// case (ordinary PTY reads are at most 8 KiB).
const OUTPUT_QUEUE: usize = 32;
/// Permit a small, explicit window instead of a stop-and-wait IPC round trip
/// for every PTY read. Two hostile-size frames bound Tauri's decoded callback
/// backlog to 2 MiB (under 3 MiB base64-encoded); ordinary coalesced output is
/// capped at the frontend's 256-KiB live-presentation bound. The webview returns
/// credit only after xterm parses the window edge.
const OUTPUT_PACKET_WINDOW: u64 = 2;
/// Coalesce a queued redraw burst so xterm parses fewer writes. A single
/// already-bounded protocol frame may exceed this target and is sent alone.
const OUTPUT_BATCH_BYTES: usize = 128 * 1024;
const OUTPUT_BATCH_CHUNKS: usize = OUTPUT_QUEUE;
const OUTPUT_ACK_TIMEOUT: Duration = Duration::from_secs(30);

fn output_packet_requires_ack(sequence: u64) -> bool {
    sequence == 0 || sequence % OUTPUT_PACKET_WINDOW == 0
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputPacket {
    pub attachment_id: u64,
    pub sequence: u64,
    pub requires_ack: bool,
    pub data: String,
}

fn append_to_output_batch(
    batch: &mut Vec<u8>,
    chunks: &mut usize,
    next: Vec<u8>,
) -> Option<Vec<u8>> {
    if *chunks >= OUTPUT_BATCH_CHUNKS || next.len() > OUTPUT_BATCH_BYTES.saturating_sub(batch.len())
    {
        return Some(next);
    }
    batch.extend_from_slice(&next);
    *chunks += 1;
    None
}

fn drain_output_batch(
    first: Vec<u8>,
    sink_rx: &mut mpsc::Receiver<Vec<u8>>,
) -> (Vec<u8>, Option<Vec<u8>>) {
    let mut batch = first;
    let mut chunks = 1;
    while chunks < OUTPUT_BATCH_CHUNKS {
        match sink_rx.try_recv() {
            Ok(next) => {
                if let Some(leftover) = append_to_output_batch(&mut batch, &mut chunks, next) {
                    return (batch, Some(leftover));
                }
            }
            Err(_) => break,
        }
    }
    (batch, None)
}

#[tauri::command]
pub async fn attach_shell(
    state: State<'_, AppState>,
    server: String,
    shell: String,
    cols: u16,
    rows: u16,
    output: Channel<OutputPacket>,
) -> CmdResult<AttachReply> {
    let (attachment_id, mut acknowledgements) = state.output_acks.register()?;
    let (sink_tx, mut sink_rx) = mpsc::channel::<Vec<u8>>(OUTPUT_QUEUE);
    let info: AttachInfo = match state
        .core
        .attach_shell(&server, &shell, cols, rows, sink_tx)
        .await
    {
        Ok(info) => info,
        Err(error) => {
            state.output_acks.remove(attachment_id);
            return Err(err(error));
        }
    };

    // The snapshot is simply the first payload down the channel, so the
    // frontend consumes one uniform byte stream in order.
    let reply = AttachReply {
        oldest_history_line_id: info.oldest_history_line_id,
        newest_history_line_id: info.newest_history_line_id,
    };
    let acknowledger = state.output_acks.clone();
    let b64 = base64::engine::general_purpose::STANDARD;
    tauri::async_runtime::spawn(async move {
        let mut sequence = 0u64;
        let send = |bytes: &[u8], sequence, requires_ack| {
            output.send(OutputPacket {
                attachment_id,
                sequence,
                requires_ack,
                data: b64.encode(bytes),
            })
        };
        // Always sent, even when empty: the frontend relies on "first
        // channel message = snapshot" to delimit redraw from live output.
        if send(
            &info.snapshot,
            sequence,
            output_packet_requires_ack(sequence),
        )
        .is_ok()
        {
            let mut pending = None;
            loop {
                match timeout(OUTPUT_ACK_TIMEOUT, acknowledgements.recv()).await {
                    Ok(Some(ack)) if ack == sequence => {}
                    _ => break,
                }

                for _ in 0..OUTPUT_PACKET_WINDOW {
                    let first = match pending.take() {
                        Some(bytes) => bytes,
                        None => match sink_rx.recv().await {
                            Some(bytes) => bytes,
                            None => return acknowledger.remove(attachment_id),
                        },
                    };
                    let (batch, leftover) = drain_output_batch(first, &mut sink_rx);
                    pending = leftover;

                    sequence = sequence.saturating_add(1);
                    let requires_ack = output_packet_requires_ack(sequence);
                    if send(&batch, sequence, requires_ack).is_err() {
                        return acknowledger.remove(attachment_id);
                    }
                    if requires_ack {
                        break;
                    }
                }
            }
        }
        acknowledger.remove(attachment_id);
        // Ending this task drops `sink_rx`, so the attachment reader stops
        // draining QUIC. Do not call the shell-wide detach command here: this
        // task may belong to an attachment that a newer one has replaced.
        // When a stalled webview resumes, its rejected stale ACK tells the
        // frontend to detach/re-attach the current generation safely.
    });
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::{
        append_to_output_batch, drain_output_batch, output_packet_requires_ack, OUTPUT_BATCH_BYTES,
        OUTPUT_BATCH_CHUNKS, OUTPUT_PACKET_WINDOW, OUTPUT_QUEUE,
    };

    #[test]
    fn output_ack_is_requested_only_at_bounded_window_edges() {
        assert!(output_packet_requires_ack(0));
        for sequence in 1..OUTPUT_PACKET_WINDOW {
            assert!(!output_packet_requires_ack(sequence));
        }
        assert!(output_packet_requires_ack(OUTPUT_PACKET_WINDOW));
        assert!(output_packet_requires_ack(OUTPUT_PACKET_WINDOW * 2));
    }

    #[test]
    fn output_batch_preserves_order_within_byte_bound() {
        let mut batch = vec![1, 2];
        let mut chunks = 1;
        assert!(append_to_output_batch(&mut batch, &mut chunks, vec![3, 4]).is_none());
        assert_eq!(batch, vec![1, 2, 3, 4]);
        assert_eq!(chunks, 2);
    }

    #[test]
    fn output_batch_leaves_byte_overflow_for_next_packet() {
        let mut batch = vec![0; OUTPUT_BATCH_BYTES - 1];
        let mut chunks = 1;
        let leftover = append_to_output_batch(&mut batch, &mut chunks, vec![1, 2]);
        assert_eq!(leftover, Some(vec![1, 2]));
        assert_eq!(batch.len(), OUTPUT_BATCH_BYTES - 1);
        assert_eq!(chunks, 1);
    }

    #[test]
    fn output_batch_leaves_chunk_overflow_for_next_packet() {
        let mut batch = vec![0];
        let mut chunks = OUTPUT_BATCH_CHUNKS;
        let leftover = append_to_output_batch(&mut batch, &mut chunks, vec![1]);
        assert_eq!(leftover, Some(vec![1]));
        assert_eq!(batch, vec![0]);
        assert_eq!(chunks, OUTPUT_BATCH_CHUNKS);
    }

    #[test]
    fn big_pty_burst_is_coalesced_without_reordering() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(OUTPUT_QUEUE);
        for value in 1u8..32 {
            tx.try_send(vec![value; 8 * 1024]).unwrap();
        }

        let (first, pending) = drain_output_batch(vec![0; 8 * 1024], &mut rx);
        let (second, pending) = drain_output_batch(pending.unwrap(), &mut rx);

        assert_eq!(first.len(), OUTPUT_BATCH_BYTES);
        assert_eq!(second.len(), OUTPUT_BATCH_BYTES);
        assert!(pending.is_none());
        for (index, chunk) in first.chunks_exact(8 * 1024).enumerate() {
            assert!(chunk.iter().all(|byte| *byte == index as u8));
        }
        for (index, chunk) in second.chunks_exact(8 * 1024).enumerate() {
            assert!(chunk.iter().all(|byte| *byte == (index + 16) as u8));
        }
    }
}

#[tauri::command]
pub async fn ack_terminal_output(
    state: State<'_, AppState>,
    attachment_id: u64,
    sequence: u64,
) -> CmdResult<()> {
    state.output_acks.acknowledge(attachment_id, sequence)
}

/// Keystroke path. `data` rides in the JSON args (see module docs for why
/// not a raw body); keystrokes are tiny, so the overhead is noise.
#[tauri::command]
pub async fn shell_input(
    state: State<'_, AppState>,
    server: String,
    shell: String,
    data: Vec<u8>,
) -> CmdResult<()> {
    state
        .core
        .shell_input(&server, &shell, data)
        .await
        .map_err(err)
}

#[tauri::command]
pub async fn resize_shell(
    state: State<'_, AppState>,
    server: String,
    shell: String,
    cols: u16,
    rows: u16,
) -> CmdResult<()> {
    state
        .core
        .resize_shell(&server, &shell, cols, rows)
        .await
        .map_err(err)
}

#[tauri::command]
pub async fn detach_shell(
    state: State<'_, AppState>,
    server: String,
    shell: String,
) -> CmdResult<()> {
    state.core.detach_shell(&server, &shell).await.map_err(err)
}

#[tauri::command]
pub async fn terminate_shell(
    state: State<'_, AppState>,
    server: String,
    shell: String,
) -> CmdResult<i32> {
    state
        .core
        .terminate_shell(&server, &shell)
        .await
        .map_err(err)
}

#[tauri::command]
pub async fn request_history(
    state: State<'_, AppState>,
    server: String,
    shell: String,
    before_line_id: u64,
    max_lines: u32,
) -> CmdResult<HistoryPage> {
    state
        .core
        .request_history(&server, &shell, before_line_id, max_lines)
        .await
        .map_err(err)
}

#[tauri::command]
pub async fn forget_shell(
    state: State<'_, AppState>,
    server: String,
    shell: String,
) -> CmdResult<()> {
    state.core.forget_shell(&server, &shell).await.map_err(err)
}

#[tauri::command]
pub async fn rename_shell(
    state: State<'_, AppState>,
    server: String,
    shell: String,
    name: String,
) -> CmdResult<()> {
    state
        .core
        .rename_shell(&server, &shell, &name)
        .await
        .map_err(err)
}

/// Open the OS picker on the Rust side, retain its path here, and stream the
/// selected handle through client-core. There is deliberately no `path`
/// command argument: a compromised webview cannot nominate arbitrary files.
#[tauri::command]
pub async fn pick_and_upload(
    state: State<'_, AppState>,
    server: String,
    shell: String,
) -> CmdResult<Option<UploadReply>> {
    #[cfg(not(windows))]
    {
        let _ = (state, server, shell);
        return Err(
            "the native upload picker is currently available in the Windows desktop client".into(),
        );
    }
    #[cfg(windows)]
    let selected = tauri::async_runtime::spawn_blocking(|| {
        rfd::FileDialog::new()
            .set_title("Upload file to shell")
            .pick_file()
    })
    .await
    .map_err(err)?;
    #[cfg(windows)]
    let Some(path) = selected
    else {
        return Ok(None);
    };
    #[cfg(windows)]
    state
        .core
        .upload_file(&server, &shell, path)
        .await
        .map(Some)
        .map_err(err)
}

#[tauri::command]
pub async fn cancel_upload(
    state: State<'_, AppState>,
    server: String,
    shell: String,
) -> CmdResult<()> {
    state.core.cancel_upload(&server, &shell).await.map_err(err)
}

/// Open an http(s) URL in the OS default browser (terminal link popover).
/// The scheme is validated HERE, not just in the frontend: terminal output
/// is attacker-controlled (T9) and a compromised webview must not be able
/// to launch arbitrary programs through custom URL scheme handlers.
#[tauri::command]
pub async fn open_external(url: String) -> CmdResult<()> {
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return Err("only http(s) URLs can be opened".into());
    }
    // `open::that` can block on the spawned handler; keep it off the runtime.
    tauri::async_runtime::spawn_blocking(move || open::that(url))
        .await
        .map_err(err)?
        .map_err(err)
}
