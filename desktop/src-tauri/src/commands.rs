//! Tauri command surface (ADR 0019): thin async wrappers over
//! `hf_client_core::Core`.
//!
//! Terminal bytes travel in JSON-safe encodings: output flows down a
//! per-attachment `tauri::ipc::Channel` as acknowledged base64 packets (first
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

/// Bound on the core→IPC staging queue per attachment. The bridge additionally
/// permits exactly one unacknowledged webview packet, so draining this queue
/// cannot move the backlog into Tauri's internal callback storage.
const OUTPUT_QUEUE: usize = 32;
const OUTPUT_ACK_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputPacket {
    pub attachment_id: u64,
    pub sequence: u64,
    pub data: String,
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
        let send = |bytes: &[u8], sequence| {
            output.send(OutputPacket {
                attachment_id,
                sequence,
                data: b64.encode(bytes),
            })
        };
        // Always sent, even when empty: the frontend relies on "first
        // channel message = snapshot" to delimit redraw from live output.
        if send(&info.snapshot, sequence).is_ok() {
            loop {
                match timeout(OUTPUT_ACK_TIMEOUT, acknowledgements.recv()).await {
                    Ok(Some(ack)) if ack == sequence => {}
                    _ => break,
                }
                let Some(bytes) = sink_rx.recv().await else {
                    break;
                };
                sequence = sequence.saturating_add(1);
                if send(&bytes, sequence).is_err() {
                    break;
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
