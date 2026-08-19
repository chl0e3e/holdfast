//! Phase 2 exit-criterion test over a real WebSocket connection:
//! "refreshing the browser reattaches to two still-running shells and
//! restores the correct current screen plus scrollback."
//!
//! Reproduce with: `cargo test -p hf-daemon`

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hf_daemon::wire;
use hf_daemon::{Daemon, DaemonConfig};
use hf_protocol::pb::{self, envelope::Message as Msg, Envelope};
use hf_protocol::{FRAME_BYTES_DEFAULT, PROTOCOL_MAJOR, PROTOCOL_MINOR, UPLOAD_FILE_BYTES_DEFAULT};
use tokio_tungstenite::tungstenite::Message as WsMessage;

const T: Duration = Duration::from_secs(10);

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

struct Client {
    ws: WsStream,
    next_request: u64,
}

impl Client {
    async fn connect(addr: std::net::SocketAddr) -> Client {
        let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/terminal/ws"))
            .await
            .expect("ws connect");
        Client {
            ws,
            next_request: 1,
        }
    }

    async fn send(&mut self, channel: u64, mut envelope: Envelope) -> u64 {
        let request_id = self.next_request;
        self.next_request += 1;
        envelope.request_id = request_id;
        let bytes = wire::encode_message(channel, &envelope, FRAME_BYTES_DEFAULT).unwrap();
        self.ws
            .send(WsMessage::Binary(bytes.into()))
            .await
            .expect("ws send");
        request_id
    }

    async fn recv(&mut self) -> (u64, Envelope) {
        loop {
            let msg = tokio::time::timeout(T, self.ws.next())
                .await
                .expect("recv timeout")
                .expect("stream open")
                .expect("ws error");
            if let WsMessage::Binary(data) = msg {
                return wire::decode_message(&data, FRAME_BYTES_DEFAULT).expect("decode");
            }
        }
    }

    /// Receive until `pred` matches, failing on timeout.
    async fn recv_until<F, R>(&mut self, mut pred: F) -> R
    where
        F: FnMut(u64, &Envelope) -> Option<R>,
    {
        let deadline = tokio::time::Instant::now() + T;
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for message"
            );
            let (ch, env) = self.recv().await;
            if let Some(r) = pred(ch, &env) {
                return r;
            }
        }
    }

    async fn hello_and_auth(&mut self) {
        self.send(
            0,
            plain(Msg::ClientHello(pb::ClientHello {
                protocol_major: PROTOCOL_MAJOR,
                protocol_minor: PROTOCOL_MINOR,
                client_kind: pb::ClientKind::BrowserWebsocket as i32,
                client_build: "ws-test".into(),
                capabilities: vec![pb::Capability::FileTransfer as i32],
                max_frame_bytes: FRAME_BYTES_DEFAULT,
                max_datagram_bytes: 0,
                encodings: vec![pb::Encoding::Utf8 as i32],
            })),
        )
        .await;
        self.recv_until(|ch, env| {
            matches!((ch, &env.message), (0, Some(Msg::ServerHello(_)))).then_some(())
        })
        .await;

        self.send(
            0,
            plain(Msg::Authenticate(pb::Authenticate {
                method: Some(pb::authenticate::Method::ConnectionGrant(vec![])),
            })),
        )
        .await;
        let ok = self
            .recv_until(|ch, env| match (ch, &env.message) {
                (0, Some(Msg::AuthenticationResult(r))) => Some(r.ok),
                _ => None,
            })
            .await;
        assert!(ok, "dev auth must accept");
    }

    async fn open_shell(&mut self, key: u8) -> (Vec<u8>, Vec<u8>) {
        self.send(
            0,
            plain(Msg::OpenShell(pb::OpenShell {
                unix_account: String::new(),
                command: "bash".into(),
                initial_cols: 40,
                initial_rows: 6,
                idempotency_key: vec![key; 16],
            })),
        )
        .await;
        self.recv_until(|ch, env| match (ch, &env.message) {
            (0, Some(Msg::ShellOpened(o))) => Some((env.shell_id.clone(), o.resume_token.clone())),
            _ => None,
        })
        .await
    }

    /// Attach on `channel`; returns (snapshot, rotated_token, newest_line_id).
    async fn attach(
        &mut self,
        channel: u64,
        shell_id: &[u8],
        token: &[u8],
    ) -> (Vec<u8>, Vec<u8>, u64) {
        let mut env = plain(Msg::AttachShell(pb::AttachShell {
            resume_token: token.to_vec(),
            cols: 40,
            rows: 6,
            last_seen_revision: 0,
            last_history_line_id: 0,
        }));
        env.shell_id = shell_id.to_vec();
        self.send(channel, env).await;
        self.recv_until(|ch, env| match (ch, &env.message) {
            (c, Some(Msg::ShellAttached(a))) if c == channel => Some((
                a.screen_snapshot.clone(),
                a.rotated_resume_token.clone(),
                a.newest_history_line_id,
            )),
            (c, Some(Msg::Error(e))) if c == channel => panic!("attach failed: {e:?}"),
            _ => None,
        })
        .await
    }

    async fn input(&mut self, channel: u64, data: &[u8]) {
        self.send(
            channel,
            plain(Msg::TerminalInput(pb::TerminalInput {
                data: data.to_vec(),
            })),
        )
        .await;
    }

    async fn wait_output(&mut self, channel: u64, needle: &str) {
        let mut collected = Vec::new();
        self.recv_until(|ch, env| match (ch, &env.message) {
            (c, Some(Msg::TerminalOutput(out))) if c == channel => {
                collected.extend_from_slice(&out.data);
                String::from_utf8_lossy(&collected)
                    .contains(needle)
                    .then_some(())
            }
            _ => None,
        })
        .await;
    }
}

fn plain(message: Msg) -> Envelope {
    Envelope {
        request_id: 0,
        server_id: vec![],
        shell_id: vec![],
        message: Some(message),
    }
}

#[tokio::test]
async fn browser_reload_reattaches_two_shells_with_screen_and_scrollback() {
    let daemon = Daemon::start(DaemonConfig {
        enable_websocket: true,
        bind: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    })
    .await
    .unwrap();

    // --- Session 1: open two shells, produce screen + scrollback state. ---
    let mut c1 = Client::connect(daemon.local_addr).await;
    c1.hello_and_auth().await;

    let (shell_a, token_a) = c1.open_shell(1).await;
    let (shell_b, token_b) = c1.open_shell(2).await;
    assert_ne!(shell_a, shell_b);

    let (_, token_a2, _) = c1.attach(1, &shell_a, &token_a).await;
    let (_, token_b2, _) = c1.attach(3, &shell_b, &token_b).await;

    c1.input(1, b"echo marker-shell-A\r").await;
    c1.wait_output(1, "marker-shell-A").await;
    // Shell B: enough output to scroll well past the 6-row screen.
    c1.input(3, b"for i in $(seq 1 40); do echo scroll-B-$i; done\r")
        .await;
    c1.wait_output(3, "scroll-B-40").await;

    // --- Browser reload: drop the whole connection without detaching. ---
    drop(c1);
    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- Session 2: reattach both shells with the rotated tokens. ---
    let mut c2 = Client::connect(daemon.local_addr).await;
    c2.hello_and_auth().await;

    // Both shells survived the disconnect.
    c2.send(0, plain(Msg::ListShells(pb::ListShells {}))).await;
    let states = c2
        .recv_until(|ch, env| match (ch, &env.message) {
            (0, Some(Msg::ShellList(list))) => {
                Some(list.shells.iter().map(|s| s.state).collect::<Vec<_>>())
            }
            _ => None,
        })
        .await;
    assert_eq!(states.len(), 2);
    assert!(states.iter().all(|s| *s == pb::ShellState::Running as i32));

    let (snapshot_a, _token_a3, _) = c2.attach(1, &shell_a, &token_a2).await;
    assert!(
        String::from_utf8_lossy(&snapshot_a).contains("marker-shell-A"),
        "shell A snapshot must restore the current screen"
    );

    let (snapshot_b, _token_b3, newest_b) = c2.attach(3, &shell_b, &token_b2).await;
    let visible_b = String::from_utf8_lossy(&snapshot_b);
    assert!(
        visible_b.contains("scroll-B-40"),
        "shell B snapshot shows latest output"
    );
    assert!(newest_b > 0, "shell B has retained scrollback");

    // Scrollback that scrolled off the screen is retrievable via history.
    let req = c2
        .send(
            3,
            plain(Msg::RequestHistory(pb::RequestHistory {
                before_line_id: 0,
                maximum_lines: 1000,
                maximum_bytes: 1 << 20,
            })),
        )
        .await;
    let lines = c2
        .recv_until(|ch, env| match (ch, &env.message) {
            (3, Some(Msg::HistoryChunk(chunk))) if env.request_id == req => {
                Some(chunk.lines.clone())
            }
            _ => None,
        })
        .await;
    let joined = lines.join("\n");
    assert!(
        joined.contains("scroll-B-1") && joined.contains("scroll-B-30"),
        "history must contain scrolled-off lines: {joined}"
    );
    c2.recv_until(|ch, env| {
        matches!((ch, &env.message), (3, Some(Msg::HistoryEnd(_)))).then_some(())
    })
    .await;

    // Shells remain interactive after reattach.
    c2.input(1, b"echo alive-after-reload\r").await;
    c2.wait_output(1, "alive-after-reload").await;

    // --- Detach vs terminate are distinct. ---
    c2.send(1, plain(Msg::DetachShell(pb::DetachShell {})))
        .await;
    let mut env = plain(Msg::TerminateShell(pb::TerminateShell {}));
    env.shell_id = shell_b.clone();
    c2.send(0, env).await;
    c2.recv_until(|ch, env| {
        matches!((ch, &env.message), (0, Some(Msg::ShellExited(_)))).then_some(())
    })
    .await;

    c2.send(0, plain(Msg::ListShells(pb::ListShells {}))).await;
    let by_shell = c2
        .recv_until(|ch, env| match (ch, &env.message) {
            (0, Some(Msg::ShellList(list))) => Some(
                list.shells
                    .iter()
                    .map(|s| (s.shell_id.clone(), s.state))
                    .collect::<Vec<_>>(),
            ),
            _ => None,
        })
        .await;
    for (id, state) in by_shell {
        if id == shell_a {
            assert_eq!(
                state,
                pb::ShellState::Running as i32,
                "detached shell keeps running"
            );
        } else {
            assert_eq!(
                state,
                pb::ShellState::Exited as i32,
                "terminated shell exits"
            );
        }
    }

    daemon.abort();
}

#[tokio::test]
async fn websocket_upload_commits_and_abort_cleans_the_partial() {
    use sha2::{Digest, Sha256};

    let temp = tempfile::tempdir().unwrap();
    let upload_root = temp.path().join("uploads");
    let daemon = Daemon::start(DaemonConfig {
        enable_websocket: true,
        bind: "127.0.0.1:0".parse().unwrap(),
        upload_root: Some(upload_root.clone()),
        ..Default::default()
    })
    .await
    .unwrap();
    let mut client = Client::connect(daemon.local_addr).await;
    client.hello_and_auth().await;
    let (shell_id, _) = client.open_shell(91).await;

    // Reject an oversized declaration before creating an upload directory.
    let mut oversized = plain(Msg::BeginUpload(pb::BeginUpload {
        original_name: "too-large.bin".into(),
        total_bytes: UPLOAD_FILE_BYTES_DEFAULT + 1,
        sha256: vec![0; 32],
    }));
    oversized.shell_id = shell_id.clone();
    client.send(3, oversized).await;
    let declaration_error = client
        .recv_until(|channel, envelope| match (channel, &envelope.message) {
            (3, Some(Msg::Error(error))) => Some(error.clone()),
            _ => None,
        })
        .await;
    assert_eq!(
        declaration_error.code,
        pb::ErrorCode::ErrLimitExceeded as i32
    );
    assert_eq!(std::fs::read_dir(&upload_root).unwrap().count(), 0);

    let content = b"file bytes over the reliable upload channel";
    let mut begin = plain(Msg::BeginUpload(pb::BeginUpload {
        original_name: "../../demo payload.txt".into(),
        total_bytes: content.len() as u64,
        sha256: Sha256::digest(content).to_vec(),
    }));
    begin.shell_id = shell_id.clone();
    client.send(5, begin).await;
    let accepted = client
        .recv_until(|channel, envelope| match (channel, &envelope.message) {
            (5, Some(Msg::UploadAccepted(accepted))) => Some(accepted.clone()),
            (5, Some(Msg::Error(error))) => panic!("upload rejected: {error:?}"),
            _ => None,
        })
        .await;
    assert!(accepted.maximum_chunk_bytes > 0);
    client
        .send(
            5,
            plain(Msg::UploadChunk(pb::UploadChunk {
                upload_id: accepted.upload_id.clone(),
                offset: 0,
                data: content.to_vec(),
            })),
        )
        .await;
    client
        .send(
            5,
            plain(Msg::FinishUpload(pb::FinishUpload {
                upload_id: accepted.upload_id,
            })),
        )
        .await;
    let finished = client
        .recv_until(|channel, envelope| match (channel, &envelope.message) {
            (5, Some(Msg::UploadFinished(finished))) => Some(finished.clone()),
            (5, Some(Msg::Error(error))) => panic!("upload failed: {error:?}"),
            _ => None,
        })
        .await;
    assert_eq!(std::fs::read(&finished.remote_path).unwrap(), content);
    assert_eq!(finished.bytes_written, content.len() as u64);
    assert_eq!(finished.sha256, Sha256::digest(content).as_slice());
    assert!(finished.remote_path.ends_with("demo_payload.txt"));

    let partial = b"will be cancelled";
    let mut begin = plain(Msg::BeginUpload(pb::BeginUpload {
        original_name: "cancel.txt".into(),
        total_bytes: partial.len() as u64,
        sha256: Sha256::digest(partial).to_vec(),
    }));
    begin.shell_id = shell_id.clone();
    client.send(7, begin).await;
    let accepted = client
        .recv_until(|channel, envelope| match (channel, &envelope.message) {
            (7, Some(Msg::UploadAccepted(accepted))) => Some(accepted.clone()),
            _ => None,
        })
        .await;
    client
        .send(
            7,
            plain(Msg::AbortUpload(pb::AbortUpload {
                upload_id: accepted.upload_id,
                reason: "test cancellation".into(),
            })),
        )
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(std::fs::read_dir(&upload_root).unwrap().count(), 1);

    // A chunk larger than the server-selected bound is rejected by the
    // upload actor before any of its bytes reach the partial file.
    let too_large_chunk = vec![0x5a; hf_protocol::UPLOAD_CHUNK_BYTES_MAX + 1];
    let mut begin = plain(Msg::BeginUpload(pb::BeginUpload {
        original_name: "oversized-chunk.bin".into(),
        total_bytes: too_large_chunk.len() as u64,
        sha256: Sha256::digest(&too_large_chunk).to_vec(),
    }));
    begin.shell_id = shell_id.clone();
    client.send(8, begin).await;
    let accepted = client
        .recv_until(|channel, envelope| match (channel, &envelope.message) {
            (8, Some(Msg::UploadAccepted(accepted))) => Some(accepted.clone()),
            _ => None,
        })
        .await;
    assert!(too_large_chunk.len() > accepted.maximum_chunk_bytes as usize);
    client
        .send(
            8,
            plain(Msg::UploadChunk(pb::UploadChunk {
                upload_id: accepted.upload_id,
                offset: 0,
                data: too_large_chunk,
            })),
        )
        .await;
    let chunk_error = client
        .recv_until(|channel, envelope| match (channel, &envelope.message) {
            (8, Some(Msg::Error(error))) => Some(error.clone()),
            _ => None,
        })
        .await;
    assert_eq!(chunk_error.code, pb::ErrorCode::ErrInvalidArgument as i32);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(std::fs::read_dir(&upload_root).unwrap().count(), 1);

    // The connection bound is two live upload actors. A third declaration is
    // rejected without opening another destination; abort releases both.
    let mut live_uploads = Vec::new();
    for channel in [9, 11] {
        let mut begin = plain(Msg::BeginUpload(pb::BeginUpload {
            original_name: format!("pending-{channel}.bin"),
            total_bytes: 1,
            sha256: Sha256::digest([channel as u8]).to_vec(),
        }));
        begin.shell_id = shell_id.clone();
        client.send(channel, begin).await;
        let accepted = client
            .recv_until(
                |reply_channel, envelope| match (reply_channel, &envelope.message) {
                    (c, Some(Msg::UploadAccepted(accepted))) if c == channel => {
                        Some(accepted.clone())
                    }
                    _ => None,
                },
            )
            .await;
        live_uploads.push((channel, accepted.upload_id));
    }
    let mut third = plain(Msg::BeginUpload(pb::BeginUpload {
        original_name: "third.bin".into(),
        total_bytes: 1,
        sha256: Sha256::digest([13u8]).to_vec(),
    }));
    third.shell_id = shell_id.clone();
    client.send(13, third).await;
    let concurrency_error = client
        .recv_until(|channel, envelope| match (channel, &envelope.message) {
            (13, Some(Msg::Error(error))) => Some(error.clone()),
            _ => None,
        })
        .await;
    assert_eq!(
        concurrency_error.code,
        pb::ErrorCode::ErrLimitExceeded as i32
    );
    for (channel, upload_id) in live_uploads {
        client
            .send(
                channel,
                plain(Msg::AbortUpload(pb::AbortUpload {
                    upload_id,
                    reason: "test cleanup".into(),
                })),
            )
            .await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(std::fs::read_dir(&upload_root).unwrap().count(), 1);

    // Losing the transport drops the bounded sender and removes its partial.
    let mut disconnect = plain(Msg::BeginUpload(pb::BeginUpload {
        original_name: "disconnect.bin".into(),
        total_bytes: 1,
        sha256: Sha256::digest([1u8]).to_vec(),
    }));
    disconnect.shell_id = shell_id;
    client.send(15, disconnect).await;
    client
        .recv_until(|channel, envelope| {
            matches!(
                (channel, &envelope.message),
                (15, Some(Msg::UploadAccepted(_)))
            )
            .then_some(())
        })
        .await;
    drop(client);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(std::fs::read_dir(&upload_root).unwrap().count(), 1);
    let metrics = daemon.metrics();
    assert_eq!(metrics.uploads_completed, 1);
    assert_eq!(metrics.uploads_cancelled, 4);
    assert_eq!(metrics.uploads_failed, 1);
    assert_eq!(metrics.uploads_rejected, 2);
    assert_eq!(metrics.uploads_active, 0);
    daemon.abort();
}

#[tokio::test]
async fn upload_capability_stays_disabled_without_an_explicit_root() {
    use sha2::{Digest, Sha256};

    let daemon = Daemon::start(DaemonConfig {
        enable_websocket: true,
        bind: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    })
    .await
    .unwrap();
    let mut client = Client::connect(daemon.local_addr).await;
    client.hello_and_auth().await;
    let (shell_id, _) = client.open_shell(92).await;
    let mut begin = plain(Msg::BeginUpload(pb::BeginUpload {
        original_name: "disabled.txt".into(),
        total_bytes: 0,
        sha256: Sha256::digest([]).to_vec(),
    }));
    begin.shell_id = shell_id;
    client.send(5, begin).await;
    let error = client
        .recv_until(|channel, envelope| match (channel, &envelope.message) {
            (5, Some(Msg::Error(error))) => Some(error.clone()),
            _ => None,
        })
        .await;
    assert_eq!(error.code, pb::ErrorCode::ErrUnknownMessage as i32);
    assert_eq!(daemon.metrics().uploads_active, 0);
    daemon.abort();
}

#[tokio::test]
async fn upload_root_symlink_is_rejected_without_chmodding_its_target() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    std::fs::create_dir(&target).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
    let link = temp.path().join("upload-link");
    symlink(&target, &link).unwrap();
    let result = Daemon::start(DaemonConfig {
        enable_websocket: true,
        bind: "127.0.0.1:0".parse().unwrap(),
        webtransport_bind: None,
        upload_root: Some(link),
        ..Default::default()
    })
    .await;
    assert!(result.is_err());
    assert_eq!(
        std::fs::metadata(target).unwrap().permissions().mode() & 0o777,
        0o755
    );
}

#[tokio::test]
async fn stale_resume_token_is_rejected() {
    let daemon = Daemon::start(DaemonConfig {
        enable_websocket: true,
        bind: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    })
    .await
    .unwrap();

    let mut c = Client::connect(daemon.local_addr).await;
    c.hello_and_auth().await;
    let (shell, token) = c.open_shell(9).await;
    let (_, _rotated, _) = c.attach(1, &shell, &token).await;

    // The original token was rotated away; replaying it must fail with the
    // distinct possible-theft code (spec §12), not generic expiry.
    let mut env = plain(Msg::AttachShell(pb::AttachShell {
        resume_token: token,
        cols: 40,
        rows: 6,
        last_seen_revision: 0,
        last_history_line_id: 0,
    }));
    env.shell_id = shell;
    c.send(5, env).await;
    let code = c
        .recv_until(|ch, env| match (ch, &env.message) {
            (5, Some(Msg::Error(e))) => Some(e.code),
            _ => None,
        })
        .await;
    assert_eq!(code, pb::ErrorCode::ErrTokenReplayed as i32);
    daemon.abort();
}

#[tokio::test]
async fn requests_before_auth_are_rejected() {
    let daemon = Daemon::start(DaemonConfig {
        enable_websocket: true,
        bind: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    })
    .await
    .unwrap();

    let mut c = Client::connect(daemon.local_addr).await;
    c.send(0, plain(Msg::ListShells(pb::ListShells {}))).await;
    let code = c
        .recv_until(|ch, env| match (ch, &env.message) {
            (0, Some(Msg::Error(e))) => Some(e.code),
            _ => None,
        })
        .await;
    assert_eq!(code, pb::ErrorCode::ErrUnauthenticated as i32);
    daemon.abort();
}

#[tokio::test]
async fn dev_auth_refuses_non_loopback_bind() {
    let result = Daemon::start(DaemonConfig {
        enable_websocket: true,
        bind: "0.0.0.0:0".parse().unwrap(),
        ..Default::default()
    })
    .await;
    assert!(result.is_err(), "dev auth must not listen beyond loopback");
}
