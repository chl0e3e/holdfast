//! hf — the Holdfast native terminal client.
//!
//! ```text
//! hf [--url http://127.0.0.1:8080] list
//! hf [--url ...] open [command]      # open a shell and attach
//! hf [--url ...] attach <id-prefix>  # reattach a stored shell
//! hf [--url ...] terminate <id-prefix>
//! ```
//!
//! Inside a session: Ctrl-] detaches (the shell keeps running). Reconnection
//! with application-level resume is automatic when the connection drops.
//!
//! The CLI drives a real Unix terminal (raw mode, SIGWINCH) and is therefore
//! unix-only; the desktop app is the Windows client. `hf_native_client` (the
//! lib) stays portable.

#[cfg(unix)]
mod cli;

#[cfg(unix)]
fn main() -> anyhow::Result<()> {
    cli::main()
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("the hf CLI is Unix-only; use the Holdfast desktop app on this platform");
    std::process::ExitCode::FAILURE
}
