//! One-off: log in with a password, open a shell, leave it RUNNING and the
//! store persisted — used to pre-seed a desktop.json for smoke tests.
//!
//! cargo run -p hf-client-core --example seedstore -- <store> <url> <user> <password>

use std::path::PathBuf;
use std::time::Duration;

use hf_client_core::{Core, CoreEvent, ServerConfig};

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
            display_name: "probe".into(),
            username: Some(username),
            ssh_key_path: None,
        })
        .await?;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut sent_login = false;
    loop {
        let event = tokio::select! {
            e = events.recv() => e,
            _ = tokio::time::sleep_until(deadline) => anyhow::bail!("timeout"),
        };
        let Some(event) = event else { anyhow::bail!("events closed") };
        if let CoreEvent::ServerStatus { server, status, .. } = &event {
            if *server != key {
                continue;
            }
            let s = serde_json::to_string(status)?;
            if s == "\"auth-required\"" {
                anyhow::ensure!(!sent_login, "login rejected");
                core.login(&key, password.clone()).await?;
                sent_login = true;
            } else if s == "\"connected\"" {
                let shell = core.open_shell(&key, "probe shell", 80, 24).await?;
                println!("SEEDED server={key} shell={shell}");
                // Exit without terminating: the shell stays alive on the
                // daemon, the store keeps the resume token.
                return Ok(());
            }
        }
    }
}
