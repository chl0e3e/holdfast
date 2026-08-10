//! Live regression probe for the render-parity fixes (see ADR 0023 and
//! `tools/render-diff`). Runs against a deployed daemon and checks the two
//! defects that changed what a reattaching client sees:
//!
//! * 24-bit colour used to be dumped in the ambiguous `38:2:R:G:B` colon form,
//!   which a spec-following parser reads with R as the colour-space id, so
//!   orange came back dark red;
//! * narrowing the terminal used to destroy text — reflow overflow was kept
//!   neither on screen nor in history.
//!
//! Both are only visible after a roam, so the probe detaches and reattaches at
//! a NARROWER size, which is exactly the "opened it on a smaller window" case.
//!
//! ```text
//! cargo run -p hf-client-core --example parityprobe -- \
//!     https://odysseus.asylum.st development ~/.ssh/id_ed25519
//! ```
//!
//! Leave ~60s between runs or the daemon's auth rate limiter rejects the login.

use std::path::PathBuf;
use std::time::Duration;

use hf_client_core::{Core, CoreEvent, ServerConfig, ServerStatus};
use tokio::sync::mpsc;

const RUN_LEN: usize = 250;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [url, user, key] = &args[..] else {
        eprintln!("usage: parityprobe <url> <user> <keypath>");
        std::process::exit(2);
    };

    let dir = std::env::temp_dir().join(format!("parityprobe-{}", std::process::id()));
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

    let shell = core.open_shell(&server, "parityprobe", 80, 24).await?;
    let (tx, mut rx) = mpsc::channel(1024);
    core.attach_shell(&server, &shell, 80, 24, tx).await?;

    // Truecolor text, then a run that wraps across several 80-column rows and
    // re-wraps into more rows at 60. The sentinel is contiguous only in output.
    let cmd = format!(
        "clear; printf '\\033[38;2;255;100;0mORANGE\\033[0m\\n'; \
         for i in $(seq {RUN_LEN}); do printf w; done; printf 'WEND%%s\\n' RUN\r"
    );
    core.shell_input(&server, &shell, cmd.into_bytes()).await?;

    let until = tokio::time::Instant::now() + Duration::from_secs(12);
    let mut live = String::new();
    while !live.contains("WENDRUN") {
        let chunk = tokio::select! {
            c = rx.recv() => c,
            _ = tokio::time::sleep_until(until) => break,
        };
        let Some(chunk) = chunk else { break };
        live.push_str(&String::from_utf8_lossy(&chunk));
    }

    // Roam to a narrower window.
    core.detach_shell(&server, &shell).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (tx2, _rx2) = mpsc::channel(256);
    let info = core.attach_shell(&server, &shell, 60, 20, tx2).await?;
    let snap = String::from_utf8_lossy(&info.snapshot).into_owned();
    println!("re-attached at 60x20: snapshot {} bytes", info.snapshot.len());

    let _ = core.terminate_shell(&server, &shell).await;

    let mut failed = false;

    if snap.contains("38;2;255;100;0") {
        println!("PASS truecolor: snapshot keeps rgb(255,100,0) in semicolon form");
    } else if snap.contains("38:2:255:100:0") {
        println!("FAIL truecolor: ambiguous colon form — orange will render dark red");
        failed = true;
    } else {
        println!("FAIL truecolor: no RGB colour in snapshot at all");
        failed = true;
    }

    // The dump uses REP for runs, so count what the sequence actually paints
    // rather than looking for a literal run of 'w'.
    let painted = painted_w(&snap);
    if painted == RUN_LEN {
        println!("PASS reflow: all {RUN_LEN} characters survive the narrowing");
    } else {
        println!("FAIL reflow: snapshot paints {painted} of {RUN_LEN} characters");
        failed = true;
    }

    if failed {
        println!("--- snapshot ---\n{snap:?}");
        std::process::exit(1);
    }
    Ok(())
}

/// Count 'w' cells a snapshot paints, expanding `CSI <n> b` (REP), which
/// repeats the preceding character n more times.
fn painted_w(snap: &str) -> usize {
    let bytes: Vec<char> = snap.chars().collect();
    let mut count = 0usize;
    let mut last: Option<char> = None;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == '\u{1b}' && i + 1 < bytes.len() && bytes[i + 1] == '[' {
            let mut j = i + 2;
            let mut digits = String::new();
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                digits.push(bytes[j]);
                j += 1;
            }
            if j < bytes.len() && bytes[j] == 'b' {
                if last == Some('w') {
                    count += digits.parse::<usize>().unwrap_or(0);
                }
                i = j + 1;
                continue;
            }
            // Any other escape sequence: skip to its final byte.
            while j < bytes.len() && !bytes[j].is_ascii_alphabetic() {
                j += 1;
            }
            i = j + 1;
            last = None;
            continue;
        }
        if bytes[i] == 'w' {
            count += 1;
        }
        last = Some(bytes[i]);
        i += 1;
    }
    count
}

fn expand(p: &str) -> String {
    match p.strip_prefix("~/") {
        Some(rest) => format!("{}/{rest}", std::env::var("HOME").unwrap_or_default()),
        None => p.to_string(),
    }
}
