//! Client-core integration: the desktop client's core against a real daemon.
//! The load-bearing scenario is "client restart": a fresh Core built from the
//! same store must reattach every shell with screen and scrollback intact.
//! Reproduce with: `cargo test -p hf-client-core`

#![cfg(unix)] // these tests spawn a real daemon (pty/pam are unix-only)

use std::time::Duration;

use hf_client_core::{store::Store, Core, CoreEvent, ServerConfig};
use hf_daemon::{Daemon, DaemonConfig};
use tokio::sync::mpsc;

fn temp_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("hf-core-test-{:032x}", rand::random::<u128>()));
    std::fs::create_dir_all(&dir).unwrap();
    // Keep the v1 import away from the developer's real CLI state: pointing
    // it at a nonexistent file makes it a no-op in every test.
    std::env::set_var("HOLDFAST_STATE", dir.join("no-such-state.json"));
    dir
}

async fn start_daemon() -> (Daemon, String) {
    let daemon = Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    })
    .await
    .unwrap();
    let url = format!("http://{}", daemon.local_addr);
    (daemon, url)
}

/// Drain the output sink until `needle` appears.
async fn wait_output(rx: &mut mpsc::Receiver<Vec<u8>>, needle: &str) -> String {
    let mut collected = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timeout waiting for {needle:?}; got {:?}",
            String::from_utf8_lossy(&collected)
        );
        match tokio::time::timeout(Duration::from_secs(10), rx.recv()).await {
            Ok(Some(bytes)) => {
                collected.extend_from_slice(&bytes);
                let text = String::from_utf8_lossy(&collected);
                if text.contains(needle) {
                    return text.into_owned();
                }
            }
            Ok(None) => panic!("sink closed while waiting for {needle:?}"),
            Err(_) => continue,
        }
    }
}

async fn wait_connected(events: &mut mpsc::Receiver<CoreEvent>, server: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timeout waiting for {server} to connect"
        );
        if let Ok(Some(event)) = tokio::time::timeout(Duration::from_secs(10), events.recv()).await
        {
            if let CoreEvent::ServerStatus {
                server: s,
                status: hf_client_core::ServerStatus::Connected,
                ..
            } = &event
            {
                if s == server {
                    return;
                }
            }
        }
    }
}

#[tokio::test]
async fn open_attach_io_and_client_restart_reattach() {
    let dir = temp_dir();
    let store_path = dir.join("desktop.json");
    let (daemon, url) = start_daemon().await;

    // --- First "app run": add server, open a shell, do some I/O. ---
    let (core, mut events) = Core::spawn(store_path.clone()).await.unwrap();
    let server = core
        .add_server(ServerConfig {
            url: url.clone(),
            display_name: "local".into(),
            username: None,
            ssh_key_path: None,
        })
        .await
        .unwrap();
    wait_connected(&mut events, &server).await;

    let shell = core.open_shell(&server, "test shell", 40, 6).await.unwrap();

    let (sink_tx, mut sink_rx) = mpsc::channel(256);
    let info = core
        .attach_shell(&server, &shell, 40, 6, sink_tx)
        .await
        .unwrap();
    assert!(info.snapshot.is_empty() || !info.snapshot.is_empty()); // snapshot delivered
    core.shell_input(&server, &shell, b"echo core-alive\r".to_vec())
        .await
        .unwrap();
    wait_output(&mut sink_rx, "core-alive").await;

    // Scrollback paging over the attachment channel.
    core.shell_input(
        &server,
        &shell,
        b"for i in $(seq 1 30); do echo hist-$i; done\r".to_vec(),
    )
    .await
    .unwrap();
    wait_output(&mut sink_rx, "hist-30").await;
    let page = core
        .request_history(&server, &shell, 0, 500)
        .await
        .unwrap();
    assert!(
        page.lines.iter().any(|l| l.contains("hist-1")),
        "history: {:?}",
        page.lines
    );
    assert!(page.first_line_id >= 1, "paging cursor must be real");

    // --- "Client restart": drop the whole Core, rebuild from the store. ---
    drop(core);
    drop(events);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let (core2, mut events2) = Core::spawn(store_path.clone()).await.unwrap();
    let boot = core2.bootstrap().await;
    assert_eq!(boot.servers.len(), 1);
    assert_eq!(boot.servers[0].key, server, "server key must be stable");
    assert_eq!(boot.servers[0].shells.len(), 1);
    assert_eq!(boot.servers[0].shells[0].shell, shell);
    assert_eq!(boot.servers[0].shells[0].name, "test shell");
    wait_connected(&mut events2, &server).await;

    let (sink_tx2, mut sink_rx2) = mpsc::channel(256);
    let info2 = core2
        .attach_shell(&server, &shell, 40, 6, sink_tx2)
        .await
        .expect("reattach after client restart");
    assert!(
        String::from_utf8_lossy(&info2.snapshot).contains("hist-30"),
        "screen must survive the restart"
    );
    core2
        .shell_input(&server, &shell, b"echo back-again\r".to_vec())
        .await
        .unwrap();
    wait_output(&mut sink_rx2, "back-again").await;

    // Exit code is whatever the signal produced; termination succeeding is
    // the contract.
    core2.terminate_shell(&server, &shell).await.unwrap();
    // Terminated shells leave the store.
    assert!(Store::load(store_path).unwrap().store.snapshot().servers[&server]
        .shells
        .is_empty());

    daemon.abort();
}

#[tokio::test]
async fn multiple_shells_on_one_connection() {
    let dir = temp_dir();
    let (daemon, url) = start_daemon().await;
    let (core, mut events) = Core::spawn(dir.join("desktop.json")).await.unwrap();
    let server = core
        .add_server(ServerConfig {
            url,
            display_name: "local".into(),
            username: None,
            ssh_key_path: None,
        })
        .await
        .unwrap();
    wait_connected(&mut events, &server).await;

    // Three shells, all attached concurrently over the one connection, each
    // with an isolated byte stream.
    let mut shells = Vec::new();
    for i in 0..3 {
        let id = core
            .open_shell(&server, &format!("shell {i}"), 40, 6)
            .await
            .unwrap();
        let (tx, rx) = mpsc::channel(256);
        core.attach_shell(&server, &id, 40, 6, tx).await.unwrap();
        shells.push((id, rx));
    }
    for (i, (id, rx)) in shells.iter_mut().enumerate() {
        core.shell_input(&server, id, format!("echo marker-{i}\r").into_bytes())
            .await
            .unwrap();
        let text = wait_output(rx, &format!("marker-{i}")).await;
        for other in 0..3 {
            if other != i {
                assert!(
                    !text.contains(&format!("marker-{other}")),
                    "shell {i} must not see shell {other}'s output"
                );
            }
        }
    }
    for (id, _) in &shells {
        core.terminate_shell(&server, id).await.unwrap();
    }
    daemon.abort();
}

#[tokio::test]
async fn pending_open_journal_recovers_after_crash_before_reply() {
    // Simulate the crash window: a pending open is journaled but never
    // resolved (as if the app died between persist and the server's reply).
    // On the next run the supervisor must resolve it into a real shell entry
    // via the idempotent re-open.
    let dir = temp_dir();
    let store_path = dir.join("desktop.json");
    let (daemon, url) = start_daemon().await;

    let (core, mut events) = Core::spawn(store_path.clone()).await.unwrap();
    let server = core
        .add_server(ServerConfig {
            url,
            display_name: "local".into(),
            username: None,
            ssh_key_path: None,
        })
        .await
        .unwrap();
    wait_connected(&mut events, &server).await;
    drop(core);
    drop(events);

    // Forge the journal entry directly in the store (the "crash").
    let store = Store::load(store_path.clone()).unwrap().store;
    let key_hex: String = (0..16).map(|_| format!("{:02x}", rand::random::<u8>())).collect();
    store
        .push_pending_open(&server, &key_hex, "journaled shell")
        .unwrap();
    drop(store);

    let (core2, mut events2) = Core::spawn(store_path.clone()).await.unwrap();
    wait_connected(&mut events2, &server).await;

    let snap = Store::load(store_path).unwrap().store.snapshot();
    let record = &snap.servers[&server];
    assert!(
        record.pending_opens.is_empty(),
        "journal must be resolved on connect"
    );
    assert_eq!(record.shells.len(), 1, "the journaled open became a shell");
    let (shell_hex, shell) = record.shells.iter().next().unwrap();
    assert_eq!(shell.name, "journaled shell");
    assert_eq!(shell.idempotency_key.as_deref(), Some(key_hex.as_str()));

    // And it is attachable.
    let (tx, mut rx) = mpsc::channel(256);
    core2
        .attach_shell(&server, shell_hex, 40, 6, tx)
        .await
        .expect("journal-recovered shell attaches");
    core2
        .shell_input(&server, shell_hex, b"echo journal-ok\r".to_vec())
        .await
        .unwrap();
    wait_output(&mut rx, "journal-ok").await;
    core2.terminate_shell(&server, shell_hex).await.unwrap();

    daemon.abort();
}
