//! Live render probe: drives a real weechat under a live holdfastd and
//! captures both halves of the render path for offline comparison.
//!
//! The probe opens a shell, starts weechat against the fake ircd from
//! `tools/render-diff/fake-ircd.py` (which pushes a formatting torture
//! corpus), records every live output byte, then roams — detach, reattach —
//! and records the attach snapshot. Those two byte streams are what the
//! browser/desktop client renders while attached and after coming back, so
//! feeding both to xterm.js and diffing the grids says exactly what a user
//! would see change under them.
//!
//! ```text
//! cargo run -p hf-client-core --example ircprobe -- \
//!     https://iliad.asylum.st user ~/.ssh/id_ed25519 /tmp/out
//! ```
//!
//! Writes `<out>-corpus.tsv` and `<out>-model.tsv` in the same format as
//! `tools/render-diff`, so the same differ consumes them. Runs are gated by
//! the daemon's auth rate limiter — leave ~60s between attempts.

use std::path::PathBuf;
use std::time::Duration;

use hf_client_core::{Core, CoreEvent, ServerConfig, ServerStatus};
use tokio::sync::mpsc;

const DEFAULT_COLS: u16 = 80;
const DEFAULT_ROWS: u16 = 24;
/// weechat needs a moment to draw its layout before the corpus starts, and the
/// fixture paces messages at 50ms; this covers both plus slack.
const CAPTURE_SECS: u64 = 25;
const PAGE_UP: &[u8] = b"\x1b[5~";
const PAGE_DOWN: &[u8] = b"\x1b[6~";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (url, user, key, out) = match &args[..] {
        [url, user, key, out] | [url, user, key, out, ..] => (url, user, key, out),
        _ => {
            eprintln!("usage: ircprobe <url> <user> <keypath> <out-prefix> [cols] [rows]");
            std::process::exit(2);
        }
    };
    // A wide terminal is where wrapping bugs actually show; the operator's own
    // window is rarely 80 columns.
    let cols: u16 = args.get(4).and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_COLS);
    let rows: u16 = args.get(5).and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_ROWS);

    let dir = std::env::temp_dir().join(format!("ircprobe-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let (core, mut events) = Core::spawn(dir.join("desktop.json")).await?;

    let server = core
        .add_server(ServerConfig {
            url: url.clone(),
            display_name: url.clone(),
            username: Some(user.clone()),
            ssh_key_path: Some(PathBuf::from(expand(key))),
        })
        .await?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let event = tokio::select! {
            e = events.recv() => e,
            _ = tokio::time::sleep_until(deadline) => anyhow::bail!("connect timeout"),
        };
        match event {
            Some(CoreEvent::ServerStatus { status, detail, .. }) => {
                println!("status: {status:?} {detail:?}");
                if status == ServerStatus::Connected {
                    break;
                }
            }
            Some(_) => {}
            None => anyhow::bail!("event channel closed"),
        }
    }

    let shell = core.open_shell(&server, "ircprobe", cols, rows).await?;
    let (tx, mut rx) = mpsc::channel(1024);
    core.attach_shell(&server, &shell, cols, rows, tx).await?;

    // The shell runs the prepared launcher (see the README): it starts the
    // fake ircd and weechat against a throwaway config dir, so the operator's
    // own weechat is never touched.
    core.shell_input(&server, &shell, b"/tmp/hf-render/run.sh\r".to_vec())
        .await?;

    let mut live: Vec<u8> = Vec::new();
    let until = tokio::time::Instant::now() + Duration::from_secs(CAPTURE_SECS);
    loop {
        let chunk = tokio::select! {
            c = rx.recv() => c,
            _ = tokio::time::sleep_until(until) => break,
        };
        match chunk {
            Some(c) => live.extend_from_slice(&c),
            None => break,
        }
    }
    // The operator reports the corruption appears on page-up/page-down, which
    // is when weechat repaints the scrolled region under screen. Drive it.
    for key in [PAGE_UP, PAGE_UP, PAGE_DOWN, PAGE_DOWN] {
        core.shell_input(&server, &shell, key.to_vec()).await?;
        tokio::time::sleep(Duration::from_millis(700)).await;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(400);
        loop {
            tokio::select! {
                c = rx.recv() => match c {
                    Some(c) => live.extend_from_slice(&c),
                    None => break,
                },
                _ = tokio::time::sleep_until(deadline) => break,
            }
        }
    }
    println!("captured {} live bytes (including page up/down)", live.len());

    // Roam: the snapshot the daemon hands the next attachment is what a
    // reload/reconnect actually paints.
    core.detach_shell(&server, &shell).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (tx2, _rx2) = mpsc::channel(256);
    let info = core.attach_shell(&server, &shell, cols, rows, tx2).await?;
    println!("re-attached: snapshot {} bytes", info.snapshot.len());

    // Quit weechat, then take the shell down.
    core.shell_input(&server, &shell, b"/quit\r".to_vec()).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let _ = core.terminate_shell(&server, &shell).await;

    std::fs::write(
        format!("{out}-corpus.tsv"),
        format!("weechat-live\tweechat\t{{}}\t{}\n", hex(&live)),
    )?;
    // The differ's model columns: snapshot, model-text (empty — the live probe
    // has no direct view of it), chunked (same bytes, so the check is a no-op).
    std::fs::write(
        format!("{out}-model.tsv"),
        format!(
            "weechat-live\t{}\t\t{}\n",
            hex(&info.snapshot),
            hex(&info.snapshot)
        ),
    )?;
    println!("wrote {out}-corpus.tsv and {out}-model.tsv");
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn expand(p: &str) -> String {
    match p.strip_prefix("~/") {
        Some(rest) => format!("{}/{rest}", std::env::var("HOME").unwrap_or_default()),
        None => p.to_string(),
    }
}
