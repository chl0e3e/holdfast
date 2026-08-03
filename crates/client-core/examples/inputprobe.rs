//! End-to-end input-path test through the desktop core: connect, open a
//! shell, attach it, send bytes via shell_input, and report what comes back.
//!
//! cargo run -p hf-client-core --example inputprobe -- <store> <url> <user> <password>

use std::path::PathBuf;
use std::time::Duration;

use hf_client_core::{Core, CoreEvent, ServerConfig};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let store = args.next().expect("store path");
    let url = args.next().expect("url");
    let username = args.next().expect("username");
    let password = args.next().expect("password");

    let (core, mut events) = Core::spawn(PathBuf::from(store)).await?;
    let key = core
        .add_server(ServerConfig {
            url,
            display_name: "inputprobe".into(),
            username: Some(username),
            ssh_key_path: None,
        })
        .await?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(40);
    let mut sent_login = false;
    loop {
        let event = tokio::select! {
            e = events.recv() => e,
            _ = tokio::time::sleep_until(deadline) => anyhow::bail!("timeout waiting for connect"),
        };
        let Some(event) = event else { anyhow::bail!("events closed") };
        if let CoreEvent::ServerStatus { server, status, detail } = &event {
            if *server != key {
                continue;
            }
            let s = serde_json::to_string(status)?;
            println!("status {s} detail={detail:?}");
            if s == "\"auth-required\"" {
                anyhow::ensure!(!sent_login, "login rejected");
                core.login(&key, password.clone()).await?;
                sent_login = true;
            } else if s == "\"connected\"" {
                break;
            }
        }
    }

    let shell = core.open_shell(&key, "inputprobe", 80, 24).await?;
    println!("opened shell {shell}");

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
    let info = core.attach_shell(&key, &shell, 80, 24, tx).await?;
    println!(
        "attached: snapshot={}B history {}..{}",
        info.snapshot.len(),
        info.oldest_history_line_id,
        info.newest_history_line_id
    );

    core.shell_input(&key, &shell, b"touch /tmp/hf-linux-input; echo MARKER-$((40+2))\n".to_vec())
        .await?;
    println!("input sent");

    let mut received = Vec::new();
    let stop = tokio::time::Instant::now() + Duration::from_secs(6);
    loop {
        tokio::select! {
            chunk = rx.recv() => {
                let Some(chunk) = chunk else { break };
                received.extend_from_slice(&chunk);
                if String::from_utf8_lossy(&received).contains("MARKER-42") { break; }
            }
            _ = tokio::time::sleep_until(stop) => break,
        }
    }
    println!("received {}B: {:?}", received.len(), String::from_utf8_lossy(&received).chars().take(200).collect::<String>());
    let _ = core.terminate_shell(&key, &shell).await;
    println!("file exists: {}", std::path::Path::new("/tmp/hf-linux-input").exists());
    Ok(())
}
