//! Deployment probe for the shell-locale fix: opens a shell on a live server
//! and checks that it runs under a UTF-8 locale. Pre-fix, `setpriv
//! --reset-env` left privilege-dropped shells in the POSIX/ASCII locale, so
//! screen/ncurses rendered every non-ASCII char as `?`.
//!
//! ```text
//! cargo run -p hf-client-core --example localeprobe -- https://host user ~/.ssh/id_ed25519
//! ```

use std::path::PathBuf;
use std::time::Duration;

use hf_client_core::{Core, CoreEvent, ServerConfig, ServerStatus};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [url, user, key] = &args[..] else {
        eprintln!("usage: localeprobe <url> <user> <keypath>");
        std::process::exit(2);
    };

    let dir = std::env::temp_dir().join(format!("localeprobe-{}", std::process::id()));
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

    let shell = core.open_shell(&server, "localeprobe", 80, 24).await?;
    let (tx, mut rx) = mpsc::channel(256);
    core.attach_shell(&server, &shell, 80, 24, tx).await?;

    // charmap is the decisive answer: UTF-8 vs ANSI_X3.4-1968 (= ASCII). The
    // sentinel is constructed so it is contiguous only in real output, never
    // in the echoed command line.
    let cmd = "printf 'CS=%s LANG=%s\\n' \"$(locale charmap)\" \"$LANG\"; printf 'LPROBE-%s\\n' END\r";
    core.shell_input(&server, &shell, cmd.as_bytes().to_vec())
        .await?;

    let until = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut out = String::new();
    while !out.contains("LPROBE-END") {
        let chunk = tokio::select! {
            c = rx.recv() => c,
            _ = tokio::time::sleep_until(until) => break,
        };
        let Some(chunk) = chunk else { break };
        out.push_str(&String::from_utf8_lossy(&chunk));
    }
    let _ = core.terminate_shell(&server, &shell).await;

    // The echoed command also contains "CS=" and the output line may carry
    // escape-sequence prefixes — take the last occurrence and slice from it;
    // real output always follows the echo.
    let report = out
        .lines()
        .filter_map(|l| l.rfind("CS=").map(|i| l[i..].trim_end_matches('\r').to_string()))
        .next_back()
        .unwrap_or_default();
    println!("shell reports: {report}");

    if report.contains("UTF-8") {
        println!("PASS: shell runs under a UTF-8 locale");
        Ok(())
    } else {
        println!("FAIL: no UTF-8 locale in the spawned shell (pre-fix daemon?)");
        println!("--- raw output ---\n{out:?}");
        std::process::exit(1);
    }
}

fn shellexpand(p: &str) -> String {
    match p.strip_prefix("~/") {
        Some(rest) => format!("{}/{rest}", std::env::var("HOME").unwrap_or_default()),
        None => p.to_string(),
    }
}
