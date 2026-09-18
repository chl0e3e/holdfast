use futures_util::{SinkExt, StreamExt};
use hf_daemon::{wire, Daemon, DaemonConfig};
use hf_protocol::{
    pb::{self, envelope::Message as Msg, Envelope},
    FRAME_BYTES_DEFAULT,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{timeout, Duration},
};
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};
type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;
async fn send(ws: &mut Ws, ch: u64, id: u64, msg: Msg) {
    let env = Envelope {
        request_id: id,
        message: Some(msg),
        ..Default::default()
    };
    ws.send(Message::Binary(
        wire::encode_message(ch, &env, FRAME_BYTES_DEFAULT)
            .unwrap()
            .into(),
    ))
    .await
    .unwrap();
}
async fn recv(ws: &mut Ws) -> (u64, Msg) {
    loop {
        let next = timeout(Duration::from_secs(3), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        if let Message::Binary(bytes) = next {
            let (ch, env) = wire::decode_message(&bytes, FRAME_BYTES_DEFAULT).unwrap();
            return (ch, env.message.unwrap());
        }
    }
}
async fn client(daemon: &Daemon, auth: bool, minor: u32) -> (Ws, pb::ServerHello) {
    let (mut ws, _) =
        tokio_tungstenite::connect_async(format!("ws://{}/terminal/ws", daemon.local_addr))
            .await
            .unwrap();
    send(
        &mut ws,
        0,
        1,
        Msg::ClientHello(pb::ClientHello {
            protocol_minor: minor,
            max_frame_bytes: FRAME_BYTES_DEFAULT,
            capabilities: vec![pb::Capability::TcpForward as i32],
            encodings: vec![pb::Encoding::Utf8 as i32],
            ..Default::default()
        }),
    )
    .await;
    let (_, Msg::ServerHello(hello)) = recv(&mut ws).await else {
        panic!("hello")
    };
    if auth {
        send(
            &mut ws,
            0,
            2,
            Msg::Authenticate(pb::Authenticate {
                method: Some(pb::authenticate::Method::ConnectionGrant(vec![])),
            }),
        )
        .await;
        assert!(matches!(
            recv(&mut ws).await,
            (
                0,
                Msg::AuthenticationResult(pb::AuthenticationResult { ok: true, .. })
            )
        ));
    }
    (ws, hello)
}
fn config(users: &[&str]) -> DaemonConfig {
    DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        webtransport_bind: None,
        enable_websocket: true,
        tcp_forward_users: users.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}
fn open(port: u16) -> Msg {
    Msg::OpenTcpForward(pb::OpenTcpForward {
        host: "127.0.0.1".into(),
        port: port.into(),
    })
}

#[tokio::test]
async fn forwarding_requires_capability_auth_and_allowlist_before_tcp() {
    for (users, auth, minor, code) in [
        (vec![], true, 3, pb::ErrorCode::ErrUnknownMessage),
        (vec!["dev"], false, 3, pb::ErrorCode::ErrUnauthenticated),
        (vec!["other"], true, 3, pb::ErrorCode::ErrForbidden),
        (vec!["dev"], true, 2, pb::ErrorCode::ErrUnknownMessage),
    ] {
        let daemon = Daemon::start(config(&users)).await.unwrap();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (mut ws, hello) = client(&daemon, auth, minor).await;
        assert_eq!(
            hello
                .capabilities
                .contains(&(pb::Capability::TcpForward as i32)),
            !users.is_empty() && minor >= 3
        );
        send(&mut ws, 1, 3, open(target.local_addr().unwrap().port())).await;
        let (1, Msg::Error(error)) = recv(&mut ws).await else {
            panic!("expected refusal")
        };
        assert_eq!(error.code, code as i32);
        assert!(timeout(Duration::from_millis(30), target.accept())
            .await
            .is_err());
        daemon.abort();
    }
}

#[tokio::test]
async fn forwarding_preserves_half_close_and_control_and_rejects_oversize() {
    let daemon = Daemon::start(config(&["dev"])).await.unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut ws, _) = client(&daemon, true, 3).await;
    send(&mut ws, 1, 3, open(target.local_addr().unwrap().port())).await;
    let (mut tcp, _) = target.accept().await.unwrap();
    assert!(matches!(recv(&mut ws).await, (1, Msg::TcpForwardOpened(_))));
    send(
        &mut ws,
        1,
        0,
        Msg::TcpForwardData(pb::TcpForwardData {
            data: b"request".to_vec(),
        }),
    )
    .await;
    assert!(matches!(recv(&mut ws).await, (1, Msg::TcpForwardAck(_))));
    send(&mut ws, 1, 0, Msg::TcpForwardEof(pb::TcpForwardEof {})).await;
    assert!(matches!(recv(&mut ws).await, (1, Msg::TcpForwardAck(_))));
    let mut buffer = [0; 7];
    tcp.read_exact(&mut buffer).await.unwrap();
    assert_eq!(&buffer, b"request");
    assert_eq!(tcp.read(&mut buffer).await.unwrap(), 0);
    tcp.write_all(b"response").await.unwrap();
    let (1, Msg::TcpForwardData(data)) = recv(&mut ws).await else {
        panic!("data")
    };
    assert_eq!(data.data, b"response");
    send(&mut ws, 1, 0, Msg::TcpForwardAck(pb::TcpForwardAck {})).await;
    tcp.shutdown().await.unwrap();
    assert!(matches!(recv(&mut ws).await, (1, Msg::TcpForwardEof(_))));
    send(&mut ws, 1, 0, Msg::TcpForwardAck(pb::TcpForwardAck {})).await;

    send(&mut ws, 3, 4, open(target.local_addr().unwrap().port())).await;
    let (mut tcp, _) = target.accept().await.unwrap();
    assert!(matches!(recv(&mut ws).await, (3, Msg::TcpForwardOpened(_))));
    send(
        &mut ws,
        3,
        0,
        Msg::TcpForwardData(pb::TcpForwardData {
            data: vec![0; 8193],
        }),
    )
    .await;
    assert!(matches!(recv(&mut ws).await, (3, Msg::Error(_))));
    assert_eq!(
        timeout(Duration::from_secs(2), tcp.read(&mut buffer))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    send(&mut ws, 0, 5, Msg::Ping(pb::Ping { nonce: 42 })).await;
    assert!(matches!(
        recv(&mut ws).await,
        (0, Msg::Pong(pb::Pong { nonce: 42 }))
    ));
    daemon.abort();
}

#[tokio::test]
async fn a_list_only_grant_cannot_forward_even_for_an_allowlisted_user() {
    let key = [7; 32];
    let daemon = Daemon::start(DaemonConfig {
        auth: hf_daemon::AuthConfig::SshKeys {
            users: Default::default(),
        },
        grant_signing_key: Some(key),
        ..config(&["alice"])
    })
    .await
    .unwrap();
    let grant = hf_auth::GrantSigner::from_bytes(&key).issue(&hf_auth::GrantClaims {
        sub: "alice".into(),
        aud: daemon.server_id.to_string(),
        servers: vec![],
        ops: vec!["list".into()],
        iat_ms: 0,
        exp_ms: 4_102_444_800_000,
        jti: "forward-scope-test".into(),
    });
    let (mut ws, _) = client(&daemon, false, 3).await;
    send(
        &mut ws,
        0,
        2,
        Msg::Authenticate(pb::Authenticate {
            method: Some(pb::authenticate::Method::ConnectionGrant(
                grant.0.into_bytes(),
            )),
        }),
    )
    .await;
    assert!(matches!(
        recv(&mut ws).await,
        (
            0,
            Msg::AuthenticationResult(pb::AuthenticationResult { ok: true, .. })
        )
    ));
    send(&mut ws, 1, 3, open(80)).await;
    let (1, Msg::Error(error)) = recv(&mut ws).await else {
        panic!("expected scope refusal")
    };
    assert_eq!(error.code, pb::ErrorCode::ErrForbidden as i32);
    daemon.abort();
}

#[tokio::test]
async fn forwarding_connection_limit_does_not_block_control() {
    let daemon = Daemon::start(config(&["dev"])).await.unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut ws, _) = client(&daemon, true, 3).await;
    let mut peers = Vec::with_capacity(32);
    for index in 0..32 {
        send(
            &mut ws,
            1 + index * 2,
            3 + index,
            open(target.local_addr().unwrap().port()),
        )
        .await;
        peers.push(target.accept().await.unwrap().0);
        assert!(matches!(recv(&mut ws).await, (_, Msg::TcpForwardOpened(_))));
    }
    send(&mut ws, 65, 40, open(target.local_addr().unwrap().port())).await;
    let (65, Msg::Error(error)) = recv(&mut ws).await else {
        panic!("limit")
    };
    assert_eq!(error.code, pb::ErrorCode::ErrLimitExceeded as i32);
    peers[0].write_all(&[42; 8192]).await.unwrap();
    assert!(matches!(recv(&mut ws).await, (1, Msg::TcpForwardData(_))));
    // Withhold its ack: a slow proxy must not stall terminal control.
    send(&mut ws, 0, 31, Msg::Ping(pb::Ping { nonce: 43 })).await;
    assert!(matches!(
        recv(&mut ws).await,
        (0, Msg::Pong(pb::Pong { nonce: 43 }))
    ));
    drop(ws);
    let mut byte = [0];
    assert_eq!(
        timeout(Duration::from_secs(2), peers[0].read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    daemon.abort();
}
