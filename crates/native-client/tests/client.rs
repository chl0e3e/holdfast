//! Phase 5 exit-criterion test: "the native client can list, open, attach
//! and detach shells and survive a network transition or perform
//! application-level resume." Runs the client library against a real daemon
//! over WebTransport/QUIC. Reproduce with: `cargo test -p hf-native-client`

use std::time::Duration;

use hf_daemon::{Daemon, DaemonConfig};
use hf_native_client::{connect, ShellEvent};

async fn wait_output(shell: &mut hf_native_client::AttachedShell, needle: &str) {
    let mut collected = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(tokio::time::Instant::now() < deadline, "timeout waiting for {needle:?}");
        match tokio::time::timeout(Duration::from_secs(10), shell.next_event())
            .await
            .expect("event timeout")
            .expect("transport alive")
        {
            ShellEvent::Output(data) => {
                collected.extend_from_slice(&data);
                if String::from_utf8_lossy(&collected).contains(needle) {
                    return;
                }
            }
            ShellEvent::Exited(code) => panic!("shell exited early: {code}"),
        }
    }
}

#[tokio::test]
async fn list_open_attach_detach_and_network_transition_resume() {
    let daemon = Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    })
    .await
    .unwrap();
    let url = format!("http://{}", daemon.local_addr);

    // --- Connect (info fetch + cert pinning + hello + auth) and list. ---
    let mut conn = connect(&url).await.expect("connect");
    assert!(conn.list_shells().await.unwrap().is_empty());

    // --- Open and attach. ---
    let (shell_id, token) = conn
        .open_shell(Some("bash"), 40, 6, rand::random())
        .await
        .expect("open shell");
    let mut shell = conn.attach(&shell_id, &token, 40, 6).await.expect("attach");
    let rotated_1 = shell.rotated_token.clone();

    shell
        .input(b"for i in $(seq 1 40); do echo native-$i; done\r")
        .await
        .unwrap();
    wait_output(&mut shell, "native-40").await;

    // --- Explicit detach: the shell keeps running. ---
    shell.detach().await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let listed = conn.list_shells().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].state, 2, "detached shell must still be running");

    // --- Network transition: drop the whole connection/endpoint and come
    // back from a fresh UDP source address; resume with the rotated token. ---
    drop(conn);
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut conn2 = connect(&url).await.expect("reconnect after transition");
    let mut shell2 = conn2
        .attach(&shell_id, &rotated_1, 40, 6)
        .await
        .expect("resume attach");
    assert!(
        String::from_utf8_lossy(&shell2.snapshot).contains("native-40"),
        "screen must survive the transition"
    );

    // Scrollback survives too.
    let lines = shell2.history(0, 1000).await.unwrap();
    let joined = lines.join("\n");
    assert!(joined.contains("native-1") && joined.contains("native-30"), "history: {joined}");

    // Still interactive, then terminate (distinct from detach).
    shell2.input(b"echo resumed-after-transition\r").await.unwrap();
    wait_output(&mut shell2, "resumed-after-transition").await;

    conn2.terminate(&shell_id).await.expect("terminate");
    let listed = conn2.list_shells().await.unwrap();
    assert_eq!(listed[0].state, 3, "terminated shell must be exited");

    daemon.abort();
}

#[tokio::test]
async fn stale_token_fails_and_reports_cleanly() {
    let daemon = Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    })
    .await
    .unwrap();
    let url = format!("http://{}", daemon.local_addr);

    let mut conn = connect(&url).await.unwrap();
    let (shell_id, token) = conn.open_shell(Some("bash"), 40, 6, rand::random()).await.unwrap();
    let _shell = conn.attach(&shell_id, &token, 40, 6).await.unwrap();

    // The original token was rotated away by the successful attach.
    let err = match conn.attach(&shell_id, &token, 40, 6).await {
        Ok(_) => panic!("stale token must be rejected"),
        Err(e) => e,
    };
    assert!(err.to_string().contains("attach failed"), "got: {err}");

    daemon.abort();
}
