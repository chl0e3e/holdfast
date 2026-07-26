//! Tauri command surface (ADR 0019): thin async wrappers over
//! `hf_client_core::Core`.
//!
//! Hot paths avoid JSON: shell output flows down a per-attachment
//! `tauri::ipc::Channel` as raw payloads (first message = the screen
//! snapshot, then live PTY bytes verbatim); input arrives as a raw-body
//! command with the shell address in request headers.

use hf_client_core::{AttachInfo, BootstrapView, HistoryPage, ServerConfig};
use serde::Serialize;
use tauri::ipc::{Channel, InvokeResponseBody, Request};
use tauri::State;
use tokio::sync::mpsc;

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

/// Bound on the core→webview output queue per attachment. When the webview
/// stalls, this fills, the reader pump awaits, and QUIC flow control pushes
/// the problem to the server's slow-consumer policy (spec §8).
const OUTPUT_QUEUE: usize = 256;

#[tauri::command]
pub async fn attach_shell(
    state: State<'_, AppState>,
    server: String,
    shell: String,
    cols: u16,
    rows: u16,
    output: Channel<InvokeResponseBody>,
) -> CmdResult<AttachReply> {
    let (sink_tx, mut sink_rx) = mpsc::channel::<Vec<u8>>(OUTPUT_QUEUE);
    let info: AttachInfo = state
        .core
        .attach_shell(&server, &shell, cols, rows, sink_tx)
        .await
        .map_err(err)?;

    // The snapshot is simply the first payload down the channel, so the
    // frontend consumes one uniform byte stream in order.
    let reply = AttachReply {
        oldest_history_line_id: info.oldest_history_line_id,
        newest_history_line_id: info.newest_history_line_id,
    };
    tauri::async_runtime::spawn(async move {
        // Always sent, even when empty: the frontend relies on "first
        // channel message = snapshot" to delimit redraw from live output.
        if output.send(InvokeResponseBody::Raw(info.snapshot)).is_err() {
            return;
        }
        while let Some(bytes) = sink_rx.recv().await {
            if output.send(InvokeResponseBody::Raw(bytes)).is_err() {
                break; // webview side gone (tab closed)
            }
        }
    });
    Ok(reply)
}

/// Raw-body input: bytes in the body, shell address in headers
/// (`x-hf-server`, `x-hf-shell`) — no JSON/base64 on the keystroke path.
#[tauri::command]
pub async fn shell_input(state: State<'_, AppState>, request: Request<'_>) -> CmdResult<()> {
    let header = |name: &str| -> CmdResult<String> {
        request
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .ok_or_else(|| format!("missing {name} header"))
    };
    let server = header("x-hf-server")?;
    let shell = header("x-hf-shell")?;
    let tauri::ipc::InvokeBody::Raw(bytes) = request.body() else {
        return Err("shell_input requires a raw body".into());
    };
    state
        .core
        .shell_input(&server, &shell, bytes.clone())
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
pub async fn detach_shell(state: State<'_, AppState>, server: String, shell: String) -> CmdResult<()> {
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
pub async fn forget_shell(state: State<'_, AppState>, server: String, shell: String) -> CmdResult<()> {
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
