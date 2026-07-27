//! Multi-server smoke: several servers driven concurrently by one Core, each
//! over its own QUIC/WebTransport (HTTP/3) connection.
//!
//! ```text
//! cargo run -p hf-client-core --example multiserver -- \
//!     https://host-a user /path/to/id_ed25519 \
//!     https://host-b user /path/to/id_ed25519
//! ```
//!
//! For each server: connect (SSH-key auth), open a shell, run `id -un` and
//! print the account it ran as — proving the sessions are live and
//! independent, not merely that the URLs resolve.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use hf_client_core::{Core, CoreEvent, ServerConfig, ServerStatus};
use tokio::sync::mpsc;

/// Drop CSI/OSC escape sequences so a shell's answer can be read as text.
fn strip_ansi(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        match chars.next() {
            // CSI: parameters/intermediates, then a final byte in @..~
            Some('[') => {
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
            // OSC: terminated by BEL or ESC \
            Some(']') => {
                while let Some(c) = chars.next() {
                    if c == '\u{7}' {
                        break;
                    }
                    if c == '\u{1b}' && chars.peek() == Some(&'\\') {
                        chars.next();
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    out
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.len() % 3 != 0 {
        eprintln!("usage: multiserver <url> <user> <keypath> [<url> <user> <keypath> ...]");
        std::process::exit(2);
    }

    let dir = std::env::temp_dir().join(format!("multiserver-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let (core, mut events) = Core::spawn(dir.join("desktop.json")).await?;

    let mut names = HashMap::new();
    for chunk in args.chunks(3) {
        let (url, user, key) = (&chunk[0], &chunk[1], &chunk[2]);
        let server = core
            .add_server(ServerConfig {
                url: url.clone(),
                display_name: url.clone(),
                username: Some(user.clone()),
                ssh_key_path: Some(PathBuf::from(key)),
            })
            .await?;
        println!("added {url} as {user} (key {key}) -> {server}");
        names.insert(server, url.clone());
    }

    // Wait for every server to report Connected — they race independently.
    let mut connected: HashMap<String, bool> = HashMap::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    while connected.len() < names.len() {
        let event = tokio::select! {
            e = events.recv() => e,
            _ = tokio::time::sleep_until(deadline) => None,
        };
        let Some(event) = event else {
            println!("TIMEOUT: only {}/{} connected", connected.len(), names.len());
            break;
        };
        if let CoreEvent::ServerStatus { server, status, detail } = event {
            let url = names.get(&server).cloned().unwrap_or_default();
            println!("  [{url}] {status:?} {detail:?}");
            if status == ServerStatus::Connected {
                connected.insert(server, true);
            }
        }
    }
    println!(
        "\n{}/{} servers connected concurrently over QUIC/HTTP3\n",
        connected.len(),
        names.len()
    );

    // Independent live shell on each, concurrently.
    let mut handles = Vec::new();
    for server in connected.keys().cloned() {
        let core = core.clone();
        let url = names.get(&server).cloned().unwrap_or_default();
        handles.push(tokio::spawn(async move {
            let shell = match core.open_shell(&server, "multiserver", 80, 24).await {
                Ok(s) => s,
                Err(e) => return format!("[{url}] open_shell FAILED: {e}"),
            };
            let (tx, mut rx) = mpsc::channel(256);
            if let Err(e) = core.attach_shell(&server, &shell, 80, 24, tx).await {
                return format!("[{url}] attach FAILED: {e}");
            }
            if let Err(e) = core
                .shell_input(&server, &shell, b"id -un\r".to_vec())
                .await
            {
                return format!("[{url}] input FAILED: {e}");
            }
            let mut seen = String::new();
            let until = tokio::time::Instant::now() + Duration::from_secs(15);
            loop {
                let chunk = tokio::select! {
                    c = rx.recv() => c,
                    _ = tokio::time::sleep_until(until) => None,
                };
                let Some(chunk) = chunk else { break };
                seen.push_str(&String::from_utf8_lossy(&chunk));
                if strip_ansi(&seen)
                    .lines()
                    .any(|l| !l.trim().is_empty() && !l.contains("id -un") && !l.contains('$'))
                {
                    break;
                }
            }
            let clean = strip_ansi(&seen);
            let account = clean
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.contains("id -un") && !l.contains('$'))
                .next_back()
                .unwrap_or("(no output)")
                .to_string();
            // Terminate needs CAP_KILL on a privilege-dropping daemon: the
            // shell belongs to another uid, so without it this is EPERM.
            let terminated = match core.terminate_shell(&server, &shell).await {
                Ok(code) => format!("terminate OK (exit {code})"),
                Err(e) => format!("terminate FAILED: {e}"),
            };
            format!("[{url}] shell ran as: {account}; {terminated}")
        }));
    }
    for h in handles {
        println!("{}", h.await?);
    }
    Ok(())
}
