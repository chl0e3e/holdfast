//! Phase 5 exit-criterion test: "the native client can list, open, attach
//! and detach shells and survive a network transition or perform
//! application-level resume." Runs the client library against a real daemon
//! over WebTransport/QUIC. Reproduce with: `cargo test -p hf-native-client`

#![cfg(unix)] // these tests spawn a real daemon (pty/pam are unix-only)

use std::time::Duration;

use hf_daemon::{Daemon, DaemonConfig};
use hf_native_client::{
    connect, upload_file, AttachError, ShellEvent, UploadCancellation, UploadPhase,
};
use hf_protocol::pb;

async fn wait_output(shell: &mut hf_native_client::AttachedShell, needle: &str) {
    let mut collected = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timeout waiting for {needle:?}"
        );
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
            ShellEvent::Ping(_) => {}
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
    assert!(
        joined.contains("native-1") && joined.contains("native-30"),
        "history: {joined}"
    );

    // Still interactive, then terminate (distinct from detach).
    shell2
        .input(b"echo resumed-after-transition\r")
        .await
        .unwrap();
    wait_output(&mut shell2, "resumed-after-transition").await;

    conn2.terminate(&shell_id).await.expect("terminate");
    let listed = conn2.list_shells().await.unwrap();
    assert_eq!(listed[0].state, 3, "terminated shell must be exited");

    daemon.abort();
}

#[tokio::test]
async fn upload_streams_a_file_and_cancellation_removes_the_partial() {
    use sha2::{Digest, Sha256};

    let temp = std::env::temp_dir().join(format!(
        "hf-native-upload-test-{:032x}",
        rand::random::<u128>()
    ));
    let upload_root = temp.join("remote");
    std::fs::create_dir_all(&temp).unwrap();
    let daemon = Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        upload_root: Some(upload_root.clone()),
        ..Default::default()
    })
    .await
    .unwrap();
    let url = format!("http://{}", daemon.local_addr);
    let mut conn = connect(&url).await.unwrap();
    assert!(conn
        .hello
        .capabilities
        .contains(&(pb::Capability::FileTransfer as i32)));
    let (shell_id, _) = conn
        .open_shell(Some("bash"), 40, 6, rand::random())
        .await
        .unwrap();

    let content = (0..(hf_protocol::UPLOAD_CHUNK_BYTES_MAX * 2 + 17))
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let source = temp.join("native payload.bin");
    std::fs::write(&source, &content).unwrap();
    let symlink = temp.join("source-link.bin");
    std::os::unix::fs::symlink(&source, &symlink).unwrap();
    let symlink_error = upload_file(
        &conn.connection,
        &shell_id,
        &symlink,
        UploadCancellation::default(),
        |_| {},
    )
    .await
    .expect_err("native source symlinks must be refused");
    assert!(symlink_error.to_string().contains("non-symlink regular file"));
    assert_eq!(std::fs::read_dir(&upload_root).unwrap().count(), 0);
    let mut progress_events = Vec::new();
    let result = upload_file(
        &conn.connection,
        &shell_id,
        &source,
        UploadCancellation::default(),
        |progress| progress_events.push(progress),
    )
    .await
    .unwrap();
    assert_eq!(std::fs::read(&result.remote_path).unwrap(), content);
    assert_eq!(result.bytes_written, content.len() as u64);
    assert_eq!(result.sha256, Sha256::digest(&content).as_slice());
    assert!(progress_events
        .iter()
        .any(|progress| progress.phase == UploadPhase::Hashing));
    assert_eq!(progress_events.last().unwrap().bytes, content.len() as u64);

    let cancelled_source = temp.join("cancel.bin");
    std::fs::write(&cancelled_source, vec![0x7a; 256 * 1024]).unwrap();
    let cancellation = UploadCancellation::default();
    let trigger = cancellation.clone();
    let error = upload_file(
        &conn.connection,
        &shell_id,
        &cancelled_source,
        cancellation,
        move |progress| {
            if progress.phase == UploadPhase::Uploading && progress.bytes > 0 {
                trigger.cancel();
            }
        },
    )
    .await
    .expect_err("cancelled upload must fail without hidden resumption");
    assert!(error.to_string().contains("cancelled"));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(std::fs::read_dir(&upload_root).unwrap().count(), 1);

    daemon.abort();
    std::fs::remove_dir_all(temp).unwrap();
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
    let (shell_id, token) = conn
        .open_shell(Some("bash"), 40, 6, rand::random())
        .await
        .unwrap();
    let _shell = conn.attach(&shell_id, &token, 40, 6).await.unwrap();

    // The original token was rotated away by the successful attach: the
    // rejection must carry the distinct replay code (spec §12), not a
    // generic failure, so clients can pick the recovery path.
    let err = match conn.attach(&shell_id, &token, 40, 6).await {
        Ok(_) => panic!("stale token must be rejected"),
        Err(e) => e,
    };
    match &err {
        AttachError::Rejected { code, .. } => {
            assert_eq!(*code, pb::ErrorCode::ErrTokenReplayed, "got: {err}")
        }
        AttachError::Transport(_) => panic!("expected a server rejection, got: {err}"),
    }

    daemon.abort();
}

#[tokio::test]
async fn lost_token_recovers_via_idempotency_key_with_scrollback_intact() {
    // The client-crash scenario (ADR 0018): the rotated token is lost, only
    // the pre-rotation token and the open-time idempotency key survive.
    let daemon = Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    })
    .await
    .unwrap();
    let url = format!("http://{}", daemon.local_addr);

    let mut conn = connect(&url).await.unwrap();
    let idempotency_key: [u8; 16] = rand::random();
    let (shell_id, token) = conn
        .open_shell(Some("bash"), 40, 6, idempotency_key)
        .await
        .unwrap();
    let mut shell = conn.attach(&shell_id, &token, 40, 6).await.unwrap();
    shell.input(b"echo survives-the-crash\r").await.unwrap();
    wait_output(&mut shell, "survives-the-crash").await;
    drop(shell); // crash: the rotated token is never persisted

    // The stale token is rejected as replayed…
    match conn.attach(&shell_id, &token, 40, 6).await {
        Ok(_) => panic!("stale token must be rejected"),
        Err(e) => assert!(matches!(
            e,
            AttachError::Rejected {
                code: pb::ErrorCode::ErrTokenReplayed,
                ..
            }
        )),
    }

    // …but re-opening with the same idempotency key returns the SAME shell
    // with a fresh token (spec §9), and everything is still there.
    let (recovered_id, fresh_token) = conn.open_shell(None, 40, 6, idempotency_key).await.unwrap();
    assert_eq!(
        recovered_id, shell_id,
        "same key must return the same shell"
    );
    let mut shell = conn
        .attach(&shell_id, &fresh_token, 40, 6)
        .await
        .expect("recovered token must attach");
    assert!(
        String::from_utf8_lossy(&shell.snapshot).contains("survives-the-crash"),
        "screen must survive recovery"
    );
    shell.input(b"echo alive-again\r").await.unwrap();
    wait_output(&mut shell, "alive-again").await;

    conn.terminate(&shell_id).await.unwrap();
    daemon.abort();
}
