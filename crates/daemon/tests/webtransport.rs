//! Phase 3 tests: the same protocol over real WebTransport/QUIC (UDP), plus
//! the exit-criterion resume path — the client's address changes between
//! connections and the shell + retained history survive — and cross-transport
//! semantics (shell opened over WebTransport, reattached over WebSocket).
//!
//! Reproduce with: `cargo test -p hf-daemon`

use std::time::Duration;

use hf_daemon::{Daemon, DaemonConfig};
use hf_protocol::framing::{encode_frame, FrameDecoder};
use hf_protocol::pb::{self, envelope::Message as Msg, Envelope};
use hf_protocol::{FRAME_BYTES_DEFAULT, PROTOCOL_MAJOR, PROTOCOL_MINOR};
use wtransport::endpoint::endpoint_side::Client;
use wtransport::tls::Sha256Digest;
use wtransport::{ClientConfig, Connection, Endpoint, RecvStream, SendStream};

const T: Duration = Duration::from_secs(10);

fn plain(message: Msg) -> Envelope {
    Envelope {
        request_id: 0,
        server_id: vec![],
        shell_id: vec![],
        message: Some(message),
    }
}

struct Chan {
    send: SendStream,
    recv: RecvStream,
    decoder: FrameDecoder,
    buf: Vec<u8>,
}

impl Chan {
    async fn open(connection: &Connection) -> Chan {
        let (send, recv) = connection.open_bi().await.unwrap().await.unwrap();
        Chan {
            send,
            recv,
            decoder: FrameDecoder::new(FRAME_BYTES_DEFAULT),
            buf: vec![0; 16 * 1024],
        }
    }

    async fn send_env(&mut self, envelope: Envelope) {
        let bytes = encode_frame(&envelope, FRAME_BYTES_DEFAULT).unwrap();
        self.send.write_all(&bytes).await.unwrap();
    }

    async fn recv_env(&mut self) -> Envelope {
        loop {
            if let Some(envelope) = self.decoder.next_frame().unwrap() {
                return envelope;
            }
            let n = tokio::time::timeout(T, self.recv.read(&mut self.buf))
                .await
                .expect("recv timeout")
                .unwrap()
                .expect("stream closed");
            self.decoder.extend(&self.buf[..n]).unwrap();
        }
    }

    async fn recv_until<F, R>(&mut self, mut pred: F) -> R
    where
        F: FnMut(&Envelope) -> Option<R>,
    {
        loop {
            let envelope = self.recv_env().await;
            if let Some(r) = pred(&envelope) {
                return r;
            }
        }
    }
}

/// Connection + hello only (no auth), returning the pinned cert hash so a test
/// can drive the auth exchange itself (e.g. SSH with a channel binding).
async fn wt_hello(daemon: &Daemon) -> (Endpoint<Client>, Connection, Chan, [u8; 32]) {
    let hash_bytes: [u8; 32] = {
        let b64 = daemon.webtransport_cert_hash_base64.as_ref().unwrap();
        let mut decoded = Vec::new();
        let table: Vec<i32> = (0..=255)
            .map(|c| {
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                    .find(c as u8 as char)
                    .map(|i| i as i32)
                    .unwrap_or(-1)
            })
            .collect();
        let chars: Vec<i32> = b64
            .bytes()
            .filter(|b| *b != b'=')
            .map(|b| table[b as usize])
            .collect();
        for chunk in chars.chunks(4) {
            let mut n = 0u32;
            for (i, c) in chunk.iter().enumerate() {
                n |= (*c as u32) << (18 - 6 * i);
            }
            decoded.push((n >> 16) as u8);
            if chunk.len() > 2 {
                decoded.push((n >> 8) as u8);
            }
            if chunk.len() > 3 {
                decoded.push(n as u8);
            }
        }
        decoded.try_into().unwrap()
    };

    let endpoint = Endpoint::client(
        ClientConfig::builder()
            .with_bind_default()
            .with_server_certificate_hashes([Sha256Digest::new(hash_bytes)])
            .build(),
    )
    .unwrap();
    let connection = endpoint
        .connect(format!(
            "https://127.0.0.1:{}/",
            daemon.webtransport_addr.unwrap().port()
        ))
        .await
        .expect("webtransport session");
    let mut control = Chan::open(&connection).await;

    // Hello + dev auth on the control stream (channel 0).
    control
        .send_env(plain(Msg::ClientHello(pb::ClientHello {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            client_kind: pb::ClientKind::NativeQuic as i32,
            client_build: "wt-test".into(),
            capabilities: vec![],
            max_frame_bytes: FRAME_BYTES_DEFAULT,
            max_datagram_bytes: 1200,
            encodings: vec![pb::Encoding::Utf8 as i32],
        })))
        .await;
    control
        .recv_until(|env| matches!(&env.message, Some(Msg::ServerHello(_))).then_some(()))
        .await;
    (endpoint, connection, control, hash_bytes)
}

async fn wt_connect(daemon: &Daemon) -> (Endpoint<Client>, Connection, Chan) {
    let (endpoint, connection, mut control, _hash) = wt_hello(daemon).await;
    control
        .send_env(plain(Msg::Authenticate(pb::Authenticate {
            method: Some(pb::authenticate::Method::ConnectionGrant(vec![])),
        })))
        .await;
    let ok = control
        .recv_until(|env| match &env.message {
            Some(Msg::AuthenticationResult(r)) => Some(r.ok),
            _ => None,
        })
        .await;
    assert!(ok);

    (endpoint, connection, control)
}

async fn open_shell(control: &mut Chan, key: u8) -> (Vec<u8>, Vec<u8>) {
    control
        .send_env(plain(Msg::OpenShell(pb::OpenShell {
            unix_account: String::new(),
            command: "bash".into(),
            initial_cols: 40,
            initial_rows: 6,
            idempotency_key: vec![key; 16],
        })))
        .await;
    control
        .recv_until(|env| match &env.message {
            Some(Msg::ShellOpened(o)) => Some((env.shell_id.clone(), o.resume_token.clone())),
            _ => None,
        })
        .await
}

async fn attach(
    connection: &Connection,
    shell_id: &[u8],
    token: &[u8],
) -> (Chan, Vec<u8>, Vec<u8>) {
    let mut chan = Chan::open(connection).await;
    let mut env = plain(Msg::AttachShell(pb::AttachShell {
        resume_token: token.to_vec(),
        cols: 40,
        rows: 6,
        last_seen_revision: 0,
        last_history_line_id: 0,
    }));
    env.shell_id = shell_id.to_vec();
    chan.send_env(env).await;
    let (snapshot, rotated) = chan
        .recv_until(|env| match &env.message {
            Some(Msg::ShellAttached(a)) => {
                Some((a.screen_snapshot.clone(), a.rotated_resume_token.clone()))
            }
            Some(Msg::Error(e)) => panic!("attach failed: {e:?}"),
            _ => None,
        })
        .await;
    (chan, snapshot, rotated)
}

async fn wait_output(chan: &mut Chan, needle: &str) {
    let mut collected = Vec::new();
    chan.recv_until(|env| match &env.message {
        Some(Msg::TerminalOutput(out)) => {
            collected.extend_from_slice(&out.data);
            String::from_utf8_lossy(&collected)
                .contains(needle)
                .then_some(())
        }
        _ => None,
    })
    .await;
}

/// Phase 3 exit criterion (application-level resume clause): the client's
/// network address changes between connections — a brand-new UDP endpoint —
/// and the logical shell plus retained history survive.
#[tokio::test]
async fn address_change_resume_over_webtransport() {
    let daemon = Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    })
    .await
    .unwrap();

    // Connection 1 (first UDP source address).
    let (_ep1, conn1, mut control1) = wt_connect(&daemon).await;
    let (shell, token) = open_shell(&mut control1, 1).await;
    let (mut chan, _, rotated) = attach(&conn1, &shell, &token).await;
    chan.send_env(plain(Msg::TerminalInput(pb::TerminalInput {
        data: b"for i in $(seq 1 40); do echo wt-scroll-$i; done\r".to_vec(),
    })))
    .await;
    wait_output(&mut chan, "wt-scroll-40").await;

    // Hard-drop the connection and the entire client endpoint: the second
    // connection comes from a different local UDP address.
    conn1.close(0u32.into(), b"network change");
    drop(chan);
    drop(control1);
    drop(_ep1);
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Connection 2 (new address): resume with the rotated token.
    let (_ep2, conn2, _control2) = wt_connect(&daemon).await;
    let (mut chan2, snapshot, _) = attach(&conn2, &shell, &rotated).await;
    assert!(
        String::from_utf8_lossy(&snapshot).contains("wt-scroll-40"),
        "screen must survive the address change"
    );

    // History retained across the migration-equivalent event.
    chan2
        .send_env(plain(Msg::RequestHistory(pb::RequestHistory {
            before_line_id: 0,
            maximum_lines: 1000,
            maximum_bytes: 1 << 20,
        })))
        .await;
    let lines = chan2
        .recv_until(|env| match &env.message {
            Some(Msg::HistoryChunk(c)) => Some(c.lines.clone()),
            _ => None,
        })
        .await;
    let joined = lines.join("\n");
    assert!(joined.contains("wt-scroll-1") && joined.contains("wt-scroll-30"));

    // Still interactive.
    chan2
        .send_env(plain(Msg::TerminalInput(pb::TerminalInput {
            data: b"echo survived-migration\r".to_vec(),
        })))
        .await;
    wait_output(&mut chan2, "survived-migration").await;

    daemon.abort();
}

/// A shell opened over WebTransport must be reattachable over the (test-only,
/// config-gated) WebSocket transport — the session layer is transport-neutral
/// (spec §2), even though the product itself is HTTP/3-only (ADR 0014).
#[tokio::test]
async fn webtransport_shell_reattaches_over_websocket() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    let daemon = Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        enable_websocket: true,
        ..Default::default()
    })
    .await
    .unwrap();

    // Open + use the shell over WebTransport.
    let (_ep, conn, mut control) = wt_connect(&daemon).await;
    let (shell, token) = open_shell(&mut control, 7).await;
    let (mut chan, _, rotated) = attach(&conn, &shell, &token).await;
    chan.send_env(plain(Msg::TerminalInput(pb::TerminalInput {
        data: b"echo cross-transport-marker\r".to_vec(),
    })))
    .await;
    wait_output(&mut chan, "cross-transport-marker").await;
    conn.close(0u32.into(), b"switching transports");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Reattach over WebSocket.
    let (mut ws, _) =
        tokio_tungstenite::connect_async(format!("ws://{}/terminal/ws", daemon.local_addr))
            .await
            .unwrap();
    async fn ws_send(
        ws: &mut (impl SinkExt<WsMessage, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
        channel: u64,
        env: Envelope,
    ) {
        let bytes = hf_daemon::wire::encode_message(channel, &env, FRAME_BYTES_DEFAULT).unwrap();
        ws.send(WsMessage::Binary(bytes.into())).await.unwrap();
    }
    async fn ws_recv_until<R>(
        ws: &mut (impl StreamExt<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
                  + Unpin),
        mut pred: impl FnMut(u64, &Envelope) -> Option<R>,
    ) -> R {
        loop {
            let msg = tokio::time::timeout(T, ws.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            if let WsMessage::Binary(data) = msg {
                let (ch, env) =
                    hf_daemon::wire::decode_message(&data, FRAME_BYTES_DEFAULT).unwrap();
                if let Some(r) = pred(ch, &env) {
                    return r;
                }
            }
        }
    }

    ws_send(
        &mut ws,
        0,
        plain(Msg::ClientHello(pb::ClientHello {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            client_kind: pb::ClientKind::BrowserWebsocket as i32,
            client_build: "cross-test".into(),
            capabilities: vec![],
            max_frame_bytes: FRAME_BYTES_DEFAULT,
            max_datagram_bytes: 0,
            encodings: vec![pb::Encoding::Utf8 as i32],
        })),
    )
    .await;
    ws_recv_until(&mut ws, |ch, env| {
        matches!((ch, &env.message), (0, Some(Msg::ServerHello(_)))).then_some(())
    })
    .await;
    ws_send(
        &mut ws,
        0,
        plain(Msg::Authenticate(pb::Authenticate {
            method: Some(pb::authenticate::Method::ConnectionGrant(vec![])),
        })),
    )
    .await;
    ws_recv_until(&mut ws, |ch, env| match (ch, &env.message) {
        (0, Some(Msg::AuthenticationResult(r))) => Some(assert!(r.ok)),
        _ => None,
    })
    .await;

    let mut env = plain(Msg::AttachShell(pb::AttachShell {
        resume_token: rotated,
        cols: 40,
        rows: 6,
        last_seen_revision: 0,
        last_history_line_id: 0,
    }));
    env.shell_id = shell.clone();
    ws_send(&mut ws, 1, env).await;
    let snapshot = ws_recv_until(&mut ws, |ch, env| match (ch, &env.message) {
        (1, Some(Msg::ShellAttached(a))) => Some(a.screen_snapshot.clone()),
        (1, Some(Msg::Error(e))) => panic!("ws reattach failed: {e:?}"),
        _ => None,
    })
    .await;
    assert!(
        String::from_utf8_lossy(&snapshot).contains("cross-transport-marker"),
        "WebSocket reattach must restore the screen produced over WebTransport"
    );

    daemon.abort();
}

/// Concurrent bidirectional streams per connection are bounded to a value the
/// daemon owns (not quinn's default), so one connection cannot spawn unbounded
/// per-stream read tasks/buffers. Opening streams past the cap blocks rather
/// than being granted.
#[tokio::test]
async fn concurrent_bidi_streams_are_capped() {
    let daemon = Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    })
    .await
    .unwrap();

    let (_ep, conn, _control) = wt_connect(&daemon).await;

    // Hold every opened stream so it stays counted against the cap. Open until
    // the next open blocks (times out) — that point is the enforced ceiling.
    let mut held = Vec::new();
    loop {
        let opened = tokio::time::timeout(Duration::from_millis(500), async {
            let opening = conn.open_bi().await.ok()?;
            opening.await.ok()
        })
        .await;
        match opened {
            Ok(Some(pair)) => held.push(pair),
            _ => break, // blocked by the cap, or errored — either way saturated
        }
        if held.len() > 500 {
            panic!("stream cap not enforced: opened {} streams", held.len());
        }
    }

    // The daemon sets max_concurrent_bidi_streams = 64; the WebTransport session
    // consumes a little of that, so the reachable app total is at or just below
    // it. Assert it is genuinely bounded and not pathologically tight.
    assert!(
        held.len() <= 64,
        "concurrent bidi streams must be capped, got {}",
        held.len()
    );
    assert!(
        held.len() >= 32,
        "cap unexpectedly tight, got {}",
        held.len()
    );

    daemon.abort();
}

/// SSH auth over WebTransport binds the signature to the server's certificate
/// hash (ADR 0008). A signature made against a *different* channel binding — as
/// a relay forwarding to the real server would produce — is rejected, while the
/// correct binding authenticates.
#[tokio::test]
async fn ssh_channel_binding_is_enforced_over_webtransport() {
    use ssh_key::rand_core::OsRng;
    use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey};

    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let public_line = key.public_key().to_openssh().unwrap();
    let mut users = std::collections::BTreeMap::new();
    users.insert("alice".to_string(), format!("{public_line}\n"));
    let daemon = Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        auth: hf_daemon::AuthConfig::SshKeys { users },
        ..Default::default()
    })
    .await
    .unwrap();

    // The real channel binding is the certificate hash the client pins.
    let (_e, _c, _ctrl, cert_hash) = wt_hello(&daemon).await;

    // Over a fresh connection, run the SSH exchange signing `binding || nonce`;
    // return whether the daemon accepted.
    async fn attempt(daemon: &Daemon, key: &PrivateKey, binding: &[u8]) -> bool {
        let (_ep, _conn, mut control, _hash) = wt_hello(daemon).await;
        let public_line = key.public_key().to_openssh().unwrap();
        control
            .send_env(plain(Msg::Authenticate(pb::Authenticate {
                method: Some(pb::authenticate::Method::SshChallengeRequest(
                    pb::SshChallengeRequest {
                        username: "alice".into(),
                        public_key: public_line.into_bytes(),
                    },
                )),
            })))
            .await;
        let challenge = control
            .recv_until(|env| match &env.message {
                Some(Msg::AuthenticationResult(r)) => Some(r.challenge.clone()),
                _ => None,
            })
            .await;
        assert!(
            !challenge.is_empty(),
            "authorized key must receive a challenge"
        );
        let message = hf_auth::ssh::channel_bound_message(binding, &challenge);
        let sig = key
            .sign(hf_auth::SSH_NAMESPACE, HashAlg::Sha512, &message)
            .unwrap();
        let pem = sig.to_pem(LineEnding::LF).unwrap();
        control
            .send_env(plain(Msg::Authenticate(pb::Authenticate {
                method: Some(pb::authenticate::Method::SshChallengeResponse(
                    pb::SshChallengeResponse {
                        challenge,
                        signature: pem.into_bytes(),
                    },
                )),
            })))
            .await;
        control
            .recv_until(|env| match &env.message {
                Some(Msg::AuthenticationResult(r)) => Some(r.ok),
                _ => None,
            })
            .await
    }

    assert!(
        attempt(&daemon, &key, &cert_hash).await,
        "the correct channel binding must authenticate"
    );
    assert!(
        !attempt(&daemon, &key, &[0u8; 32]).await,
        "a relayed signature (wrong channel binding) must be rejected"
    );

    daemon.abort();
}
