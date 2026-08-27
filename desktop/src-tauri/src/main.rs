//! hf-desktop — Tauri shell around hf-client-core (ADR 0019).
//!
//! All protocol/persistence logic lives in `hf_client_core::Core`; this
//! binary only bridges it to the webview: commands in `commands.rs`,
//! `CoreEvent`s forwarded as Tauri events, terminal bytes down per-shell
//! bounded-window, JSON-safe IPC channels.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod dockerwm;

use hf_client_core::{Core, CoreEvent};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{Emitter, Manager};
use tokio::sync::mpsc;

const MAX_ACTIVE_OUTPUT_ACKS: usize = 256;

pub struct OutputAcks {
    next_id: AtomicU64,
    entries: Mutex<HashMap<u64, mpsc::Sender<u64>>>,
}

impl OutputAcks {
    fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn register(&self) -> Result<(u64, mpsc::Receiver<u64>), String> {
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= MAX_ACTIVE_OUTPUT_ACKS {
            return Err("too many active terminal output channels".into());
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(1);
        entries.insert(id, tx);
        Ok((id, rx))
    }

    fn acknowledge(&self, id: u64, sequence: u64) -> Result<(), String> {
        let entries = self.entries.lock().unwrap();
        let sender = entries
            .get(&id)
            .ok_or_else(|| "stale terminal output acknowledgement".to_string())?;
        sender
            .try_send(sequence)
            .map_err(|_| "unexpected terminal output acknowledgement".to_string())
    }

    fn remove(&self, id: u64) {
        self.entries.lock().unwrap().remove(&id);
    }
}

pub struct AppState {
    pub core: Core,
    pub output_acks: Arc<OutputAcks>,
}

fn main() {
    // One multi-thread tokio runtime shared by Tauri's async commands and
    // every client-core task (supervisors, pumps, keepalive).
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    tauri::async_runtime::set(runtime.handle().clone());

    tauri::Builder::default()
        .setup(move |app| {
            let store_path = hf_client_core::store::default_path()?;
            let (core, mut events) = tauri::async_runtime::block_on(Core::spawn(store_path))?;
            app.manage(AppState {
                core,
                output_acks: Arc::new(OutputAcks::new()),
            });

            // Low-rate lifecycle events → named Tauri events the frontend
            // subscribes to. Terminal bytes never travel this path.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                while let Some(event) = events.recv().await {
                    let name = match &event {
                        CoreEvent::ServerStatus { .. } => "server-status",
                        CoreEvent::ShellState { .. } => "shell-state",
                        CoreEvent::ShellsUpdated { .. } => "shells-updated",
                        CoreEvent::StoreWarning { .. } => "store-warning",
                        CoreEvent::ServerCapabilities { .. } => "server-capabilities",
                        CoreEvent::UploadProgress { .. } => "upload-progress",
                    };
                    let _ = handle.emit(name, &event);
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::bootstrap,
            commands::add_server,
            commands::remove_server,
            commands::login,
            commands::open_shell,
            commands::attach_shell,
            commands::ack_terminal_output,
            commands::shell_input,
            commands::resize_shell,
            commands::detach_shell,
            commands::terminate_shell,
            commands::request_history,
            commands::forget_shell,
            commands::rename_shell,
            commands::pick_and_upload,
            commands::cancel_upload,
            commands::open_external,
            dockerwm::open_in_dockerwm,
        ])
        .run(tauri::generate_context!())
        .expect("error while running holdfast desktop");
}
