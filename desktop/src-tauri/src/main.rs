//! hf-desktop — Tauri shell around hf-client-core (ADR 0019).
//!
//! All protocol/persistence logic lives in `hf_client_core::Core`; this
//! binary only bridges it to the webview: commands in `commands.rs`,
//! `CoreEvent`s forwarded as Tauri events, terminal bytes down per-shell raw
//! IPC channels.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

use hf_client_core::{Core, CoreEvent};
use tauri::{Emitter, Manager};

pub struct AppState {
    pub core: Core,
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
            app.manage(AppState { core });

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
            commands::open_shell,
            commands::attach_shell,
            commands::shell_input,
            commands::resize_shell,
            commands::detach_shell,
            commands::terminate_shell,
            commands::request_history,
            commands::forget_shell,
            commands::rename_shell,
        ])
        .run(tauri::generate_context!())
        .expect("error while running holdfast desktop");
}
