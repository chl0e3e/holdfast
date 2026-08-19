//! hf-desktop — Tauri shell around hf-client-core (ADR 0019).
//!
//! All protocol/persistence logic lives in `hf_client_core::Core`; this
//! binary only bridges it to the webview: commands in `commands.rs`,
//! `CoreEvent`s forwarded as Tauri events, terminal bytes down per-shell raw
//! IPC channels.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod dockerwm;
#[cfg(any(target_os = "windows", test))]
mod window_layout;

use hf_client_core::{Core, CoreEvent};
use tauri::{Emitter, Manager};

pub struct AppState {
    pub core: Core,
}

#[cfg(target_os = "windows")]
fn fit_main_window_to_work_area(app: &tauri::App) -> tauri::Result<()> {
    let Some(window) = app.get_webview_window("main") else {
        return Ok(());
    };
    let monitor = match window.current_monitor()? {
        Some(monitor) => Some(monitor),
        None => window.primary_monitor()?,
    };
    let Some(monitor) = monitor else {
        return Ok(());
    };

    let inner = window.inner_size()?;
    let outer = window.outer_size()?;
    let work_area = monitor.work_area().size;
    let target = window_layout::clamp_inner_to_work_area(
        window_layout::Size {
            width: inner.width,
            height: inner.height,
        },
        window_layout::Size {
            width: outer.width,
            height: outer.height,
        },
        window_layout::Size {
            width: work_area.width,
            height: work_area.height,
        },
    );

    if target.width != inner.width || target.height != inner.height {
        window.set_size(tauri::PhysicalSize::new(target.width, target.height))?;
        window.center()?;
    }
    Ok(())
}

fn main() {
    // One multi-thread tokio runtime shared by Tauri's async commands and
    // every client-core task (supervisors, pumps, keepalive).
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    tauri::async_runtime::set(runtime.handle().clone());

    tauri::Builder::default()
        .setup(move |app| {
            // Configured dimensions are the webview's inner size. Keep the
            // decorated Windows window inside the usable monitor area so its
            // last terminal row cannot land underneath the taskbar.
            #[cfg(target_os = "windows")]
            if let Err(error) = fit_main_window_to_work_area(app) {
                eprintln!("could not fit the main window to the monitor work area: {error}");
            }

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
            commands::login,
            commands::open_shell,
            commands::attach_shell,
            commands::shell_input,
            commands::resize_shell,
            commands::detach_shell,
            commands::terminate_shell,
            commands::request_history,
            commands::forget_shell,
            commands::rename_shell,
            commands::open_external,
            dockerwm::open_in_dockerwm,
        ])
        .run(tauri::generate_context!())
        .expect("error while running holdfast desktop");
}
