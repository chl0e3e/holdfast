//! Headless reproduction of the desktop password-login flow.
//!
//! ```text
//! cargo run -p hf-client-core --example authprobe -- <url> <username> <password>
//! ```
//!
//! Adds the server exactly like the desktop's add-server form (username, no
//! key = password auth), waits for `auth-required`, submits the password
//! once, then reports every status event and finally attempts an open.

use std::path::PathBuf;
use std::time::Duration;

use hf_client_core::{Core, CoreEvent, ServerConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let url = args.next().expect("usage: authprobe <url> <username> <password>");
    let username = args.next().expect("username");
    let password = args.next().expect("password");

    let dir = std::env::temp_dir().join(format!("authprobe-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let (core, mut events) = Core::spawn(PathBuf::from(dir.join("desktop.json"))).await?;

    let key = core
        .add_server(ServerConfig {
            url: url.clone(),
            display_name: "probe".into(),
            username: Some(username),
            ssh_key_path: None,
        })
        .await?;
    println!("server added, key={key}");

    let mut sent_login = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let event = tokio::select! {
            e = events.recv() => e,
            _ = tokio::time::sleep_until(deadline) => {
                println!("TIMEOUT waiting for events");
                break;
            }
        };
        let Some(event) = event else { break };
        match &event {
            CoreEvent::ServerStatus { server, status, detail } => {
                println!(
                    "status[{}{}]: {} detail={:?}",
                    server,
                    if *server == key { " (ours)" } else { "" },
                    serde_json::to_string(status)?,
                    detail
                );
                if *server != key {
                    continue;
                }
                let s = serde_json::to_string(status)?;
                if s == "\"auth-required\"" {
                    if sent_login {
                        println!("RESULT: login attempt REJECTED (detail above)");
                        break;
                    }
                    println!("submitting password...");
                    core.login(&key, password.clone()).await?;
                    sent_login = true;
                } else if s == "\"connected\"" {
                    println!("RESULT: login attempt ACCEPTED — trying open_shell");
                    match core.open_shell(&key, "probe", 80, 24).await {
                        Ok(id) => {
                            println!("open_shell OK: {id} — terminating it again");
                            let _ = core.terminate_shell(&key, &id).await;
                        }
                        Err(e) => println!("open_shell FAILED: {e}"),
                    }
                    break;
                }
            }
            CoreEvent::StoreWarning { message } => println!("warning: {message}"),
            _ => {}
        }
    }
    Ok(())
}
