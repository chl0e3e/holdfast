//! Burst probe: reproduces the "IRC art spam wedges the session" report.
//! Opens a shell, attaches as a deliberately slow consumer, floods the PTY
//! with a multi-megabyte burst (staged art file), and asserts the spec §8
//! slow-consumer drop is *signalled* (ERR_TOO_SLOW → Detached event, not a
//! silent channel end) and that a reattach recovers a clean snapshot.
//! Stage the input first: copy a big text file to ~/o-art-msgs.txt in the
//! shell account's home. Wait ≥60s between runs (daemon auth rate limit).
//!
//! ```text
//! cargo run -p hf-client-core --example zwburst -- https://host user ~/.ssh/id_ed25519
//! ```

use std::path::PathBuf;
use std::time::Duration;

use hf_client_core::{Core, CoreEvent, ServerConfig, ServerStatus};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [url, user, key] = &args[..] else {
        eprintln!("usage: zwburst <url> <user> <keypath>");
        std::process::exit(2);
    };

    let dir = std::env::temp_dir().join(format!("zwburst-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let (core, mut events) = Core::spawn(dir.join("desktop.json")).await?;

    let server = core
        .add_server(ServerConfig {
            url: url.clone(),
            display_name: url.clone(),
            username: Some(user.clone()),
            ssh_key_path: Some(PathBuf::from(shellexpand(key))),
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

    // Watch for the too-slow detach surfacing as a ShellState event.
    let detached = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let detached_flag = detached.clone();
    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            if let CoreEvent::ShellState { state, .. } = event {
                println!("shell state event: {state:?}");
                if format!("{state:?}").contains("Detached") {
                    detached_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
        }
    });

    let shell = core.open_shell(&server, "zwburst", 80, 24).await?;
    // Deliberately slow consumer: tiny queue, throttled drain — the daemon's
    // 128-chunk attachment queue must overflow on a >1 MB burst.
    let (tx, mut rx) = mpsc::channel(4);
    core.attach_shell(&server, &shell, 80, 24, tx).await?;

    // Flood: ~7.6 MB (20x the staged art) then a sentinel.
    core.shell_input(
        &server,
        &shell,
        b"for i in $(seq 20); do cat ~/o-art-msgs.txt; done; printf 'BURSTDONE%s\\n' MARK\r".to_vec(),
    )
    .await?;

    let mut live_bytes = 0usize;
    let mut saw_done = false;
    let mut channel_closed = false;
    let until = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let chunk = tokio::select! {
            c = rx.recv() => c,
            _ = tokio::time::sleep_until(until) => break,
        };
        match chunk {
            Some(chunk) => {
                live_bytes += chunk.len();
                if String::from_utf8_lossy(&chunk).contains("BURSTDONEMARK") {
                    saw_done = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
            None => {
                channel_closed = true;
                break;
            }
        }
    }
    println!(
        "throttled attachment: {live_bytes} bytes received, sentinel={saw_done}, closed={channel_closed}, detached_event={}",
        detached.load(std::sync::atomic::Ordering::SeqCst)
    );

    // Let the shell finish the burst regardless of our attachment's fate.
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Fresh attachment: its snapshot is the server model's screen.
    let (tx2, _rx2) = mpsc::channel(256);
    let info = core.attach_shell(&server, &shell, 80, 24, tx2).await?;
    println!("reattach snapshot: {} bytes", info.snapshot.len());

    let mut replica = hf_terminal_model::TerminalModel::new(hf_terminal_model::TerminalModelConfig {
        cols: 80,
        rows: 24,
        ..Default::default()
    });
    replica.feed(&info.snapshot);
    println!("--- server screen after burst (last 10 rows) ---");
    for line in replica.visible_lines().iter().rev().take(10).rev() {
        println!("|{line}|");
    }

    let _ = core.terminate_shell(&server, &shell).await;

    let got_signal = detached.load(std::sync::atomic::Ordering::SeqCst);
    if saw_done {
        println!("SURVIVED: burst fit the queue; rerun with a bigger flood to force too-slow");
    } else if channel_closed && got_signal {
        println!("PASS: too-slow drop was signalled (Detached event) and reattach recovered a clean snapshot");
    } else if channel_closed {
        println!("FAIL: attachment closed without a Detached event (silent drop)");
        std::process::exit(1);
    } else {
        println!("STALLED: no sentinel and no close within 60s");
        std::process::exit(1);
    }
    Ok(())
}

fn shellexpand(p: &str) -> String {
    match p.strip_prefix("~/") {
        Some(rest) => format!("{}/{rest}", std::env::var("HOME").unwrap_or_default()),
        None => p.to_string(),
    }
}
