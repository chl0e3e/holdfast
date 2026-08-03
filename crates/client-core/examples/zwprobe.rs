//! Deployment probe for the zero-width snapshot fix: opens a shell on a live
//! server, prints a 60-glyph run of e+U+0301 (60 real columns; 120 columns
//! under the pre-fix model), detaches, re-attaches, and checks whether the
//! attach snapshot keeps the run and the trailing X on one 80-column line.
//!
//! ```text
//! cargo run -p hf-client-core --example zwprobe -- https://host user ~/.ssh/id_ed25519
//! ```

use std::path::PathBuf;
use std::time::Duration;

use hf_client_core::{Core, CoreEvent, ServerConfig, ServerStatus};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [url, user, key] = &args[..] else {
        eprintln!("usage: zwprobe <url> <user> <keypath>");
        std::process::exit(2);
    };

    let dir = std::env::temp_dir().join(format!("zwprobe-{}", std::process::id()));
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

    let shell = core.open_shell(&server, "zwprobe", 80, 24).await?;
    let (tx, mut rx) = mpsc::channel(256);
    core.attach_shell(&server, &shell, 80, 24, tx).await?;

    // Have the shell CONSTRUCT 60 e+U+0301 pairs (60 real display columns;
    // 120 under the pre-fix model, forcing a bogus wrap on an 80-col row).
    // The typed command stays ASCII and under 80 columns so readline's echo
    // can't wrap, and the "XENDOUT" sentinel is contiguous only in output.
    let cmd = "echo; for i in $(seq 60); do printf 'e\\xcc\\x81'; done; printf 'XEND%s\\n' OUT\r";
    core.shell_input(&server, &shell, cmd.as_bytes().to_vec())
        .await?;

    // Drain live output until the constructed line appears (or 10s).
    let until = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut live = String::new();
    while !live.contains("XENDOUT") {
        let chunk = tokio::select! {
            c = rx.recv() => c,
            _ = tokio::time::sleep_until(until) => break,
        };
        let Some(chunk) = chunk else { break };
        live.push_str(&String::from_utf8_lossy(&chunk));
    }
    let run = "e\u{0301}".repeat(60);

    println!("live tail: {:?}", &live[live.len().saturating_sub(200)..]);

    // Roam: detach, then re-attach; the first bytes of the new attachment
    // replay the server model's snapshot.
    core.detach_shell(&server, &shell).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let (tx2, _rx2) = mpsc::channel(256);
    let info = core.attach_shell(&server, &shell, 80, 24, tx2).await?;
    let snap = String::from_utf8_lossy(&info.snapshot).into_owned();
    println!("re-attached: snapshot {} bytes", info.snapshot.len());

    let _ = core.terminate_shell(&server, &shell).await;

    let intact = format!("{run}XENDOUT");
    if snap.contains(&intact) {
        println!("PASS: snapshot keeps the 60-column zero-width run and X on one line");
        Ok(())
    } else if snap.contains(&run.repeat(1)[..run.len() / 2]) {
        println!("FAIL: snapshot contains the run but split/sheared (pre-fix daemon?)");
        println!("--- snapshot ---\n{snap:?}");
        std::process::exit(1);
    } else {
        println!("INCONCLUSIVE: run not found in snapshot");
        println!("--- snapshot ---\n{snap:?}");
        std::process::exit(1);
    }
}

fn shellexpand(p: &str) -> String {
    match p.strip_prefix("~/") {
        Some(rest) => format!("{}/{rest}", std::env::var("HOME").unwrap_or_default()),
        None => p.to_string(),
    }
}
