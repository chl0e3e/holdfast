//! ADR 0030 integration: exact dockerwm H3 bridge bytes reach the real
//! Holdfast connection handler, including ADR 0008 certificate channel binding.

use std::{collections::BTreeMap, net::SocketAddr, time::Duration};

use hf_daemon::{AuthConfig, Daemon, DaemonConfig, FrontdoorBridgeConfig};
use hf_protocol::{
    framing::{encode_frame, FrameDecoder},
    pb::{self, envelope::Message as Msg, Envelope},
    FRAME_BYTES_DEFAULT, PROTOCOL_MAJOR, PROTOCOL_MINOR,
};
use ssh_key::{rand_core::OsRng, Algorithm, HashAlg, LineEnding, PrivateKey};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::UnixStream,
};

const HEADER_MAGIC: &[u8; 8] = b"DWMH3B02";
const ACK_MAGIC: &[u8; 8] = b"DWMH3A02";
const HOSTNAME: &str = "holdfast.example";
const SSH_NAMESPACE: &str = "holdfast-auth@v0";
const TIMEOUT: Duration = Duration::from_secs(10);

fn plain(message: Msg) -> Envelope {
    Envelope {
        request_id: 1,
        server_id: vec![],
        shell_id: vec![],
        message: Some(message),
    }
}

fn bridge_header(
    kind: u8,
    session_id: [u8; 32],
    stream_id: u64,
    channel_binding: [u8; 32],
) -> Vec<u8> {
    let remote: SocketAddr = "127.0.0.1:4242".parse().expect("remote address");
    let mut bytes = Vec::with_capacity(105 + HOSTNAME.len());
    bytes.extend_from_slice(HEADER_MAGIC);
    bytes.push(kind);
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(&session_id);
    bytes.extend_from_slice(&stream_id.to_be_bytes());
    bytes.push(4);
    match remote.ip() {
        std::net::IpAddr::V4(address) => {
            bytes.extend_from_slice(&address.octets());
            bytes.extend_from_slice(&[0; 12]);
        }
        std::net::IpAddr::V6(_) => unreachable!(),
    }
    bytes.extend_from_slice(&remote.port().to_be_bytes());
    bytes.extend_from_slice(&(HOSTNAME.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&channel_binding);
    bytes.extend_from_slice(HOSTNAME.as_bytes());
    bytes
}

async fn bridge_connect(socket: &std::path::Path, header: Vec<u8>) -> anyhow::Result<UnixStream> {
    let mut stream = UnixStream::connect(socket).await?;
    stream.write_all(&header).await?;
    let mut acknowledgement = [0_u8; 8];
    tokio::time::timeout(TIMEOUT, stream.read_exact(&mut acknowledgement)).await??;
    anyhow::ensure!(
        &acknowledgement == ACK_MAGIC,
        "wrong bridge acknowledgement"
    );
    Ok(stream)
}

async fn bridge_rejected(socket: &std::path::Path, header: Vec<u8>) {
    let mut stream = UnixStream::connect(socket).await.expect("connect bridge");
    stream
        .write_all(&header)
        .await
        .expect("write bridge header");
    let mut acknowledgement = [0_u8; 8];
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut acknowledgement))
        .await
        .expect("rejected bridge connection must close promptly");
    match result {
        Ok(0) | Err(_) => {}
        Ok(count) => panic!("rejected bridge connection returned {count} acknowledgement bytes"),
    }
}

struct Channel {
    stream: UnixStream,
    decoder: FrameDecoder,
    buffer: Vec<u8>,
}

impl Channel {
    async fn send(&mut self, envelope: Envelope) {
        let frame = encode_frame(&envelope, FRAME_BYTES_DEFAULT).expect("encode frame");
        self.stream.write_all(&frame).await.expect("send frame");
    }

    async fn receive(&mut self) -> Envelope {
        loop {
            if let Some(envelope) = self.decoder.next_frame().expect("decode frame") {
                return envelope;
            }
            let count = tokio::time::timeout(TIMEOUT, self.stream.read(&mut self.buffer))
                .await
                .expect("receive timeout")
                .expect("read frame");
            assert_ne!(count, 0, "bridge stream closed before reply");
            self.decoder
                .extend(&self.buffer[..count])
                .expect("bounded frame");
        }
    }

    async fn receive_auth_result(&mut self) -> pb::AuthenticationResult {
        loop {
            if let Some(Msg::AuthenticationResult(result)) = self.receive().await.message {
                return result;
            }
        }
    }
}

async fn request_challenge(channel: &mut Channel, key: &PrivateKey) -> Vec<u8> {
    channel
        .send(plain(Msg::Authenticate(pb::Authenticate {
            method: Some(pb::authenticate::Method::SshChallengeRequest(
                pb::SshChallengeRequest {
                    username: "alice".into(),
                    public_key: key
                        .public_key()
                        .to_openssh()
                        .expect("public key")
                        .into_bytes(),
                },
            )),
        })))
        .await;
    let result = channel.receive_auth_result().await;
    assert!(
        !result.challenge.is_empty(),
        "authorized key gets a challenge"
    );
    result.challenge
}

async fn answer_challenge(
    channel: &mut Channel,
    key: &PrivateKey,
    challenge: Vec<u8>,
    binding: &[u8],
) -> pb::AuthenticationResult {
    let message = hf_auth::ssh::channel_bound_message(binding, &challenge);
    let signature = key
        .sign(SSH_NAMESPACE, HashAlg::Sha512, &message)
        .expect("sign challenge")
        .to_pem(LineEnding::LF)
        .expect("encode signature");
    channel
        .send(plain(Msg::Authenticate(pb::Authenticate {
            method: Some(pb::authenticate::Method::SshChallengeResponse(
                pb::SshChallengeResponse {
                    challenge,
                    signature: signature.into_bytes(),
                },
            )),
        })))
        .await;
    channel.receive_auth_result().await
}

#[tokio::test]
async fn exact_bridge_reaches_holdfast_and_preserves_certificate_binding() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let socket = temporary.path().join("holdfast-h3.sock");
    let (probe, _) = UnixStream::pair().expect("credential probe");
    let uid = probe.peer_cred().expect("peer credentials").uid();
    assert_ne!(uid, 0, "front-door integration test must run unprivileged");

    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).expect("SSH key");
    let mut users = BTreeMap::new();
    users.insert(
        "alice".into(),
        format!("{}\n", key.public_key().to_openssh().expect("public key")),
    );
    let daemon = Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().expect("TCP bind"),
        webtransport_bind: None,
        h3_frontdoor: Some(FrontdoorBridgeConfig {
            socket_path: socket.clone(),
            frontdoor_uid: uid,
            hostname: HOSTNAME.into(),
            public_port: 443,
            maximum_sessions: 4,
            maximum_streams_per_session: 4,
        }),
        auth: AuthConfig::SshKeys { users },
        ..Default::default()
    })
    .await
    .expect("start bridged daemon");
    assert_eq!(daemon.webtransport_addr, None);
    assert_eq!(
        daemon.webtransport_certificate_mode,
        Some(hf_daemon::WebTransportCertificateMode::WebPki)
    );

    let session_id = [0x31; 32];
    let binding = [0x42; 32];
    let _control = bridge_connect(&socket, bridge_header(1, session_id, 0, binding))
        .await
        .expect("open bridge session");

    let mut wrong_hostname = bridge_header(2, session_id, 1, binding);
    wrong_hostname[105..].copy_from_slice(b"attacker.example");
    bridge_rejected(&socket, wrong_hostname).await;

    let mut wrong_address = bridge_header(2, session_id, 1, binding);
    wrong_address[53] ^= 1;
    bridge_rejected(&socket, wrong_address).await;

    bridge_rejected(&socket, bridge_header(2, session_id, 1, [0x99; 32])).await;
    bridge_rejected(&socket, bridge_header(2, session_id, 2, binding)).await;

    let stream = bridge_connect(&socket, bridge_header(2, session_id, 1, binding))
        .await
        .expect("open bridge stream");
    let mut channel = Channel {
        stream,
        decoder: FrameDecoder::new(FRAME_BYTES_DEFAULT),
        buffer: vec![0; 16 * 1024],
    };

    channel
        .send(plain(Msg::ClientHello(pb::ClientHello {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            client_kind: pb::ClientKind::BrowserWebtransport as i32,
            client_build: "frontdoor-bridge-test".into(),
            capabilities: vec![],
            max_frame_bytes: FRAME_BYTES_DEFAULT,
            max_datagram_bytes: 0,
            encodings: vec![pb::Encoding::Utf8 as i32],
        })))
        .await;
    loop {
        if matches!(channel.receive().await.message, Some(Msg::ServerHello(_))) {
            break;
        }
    }

    let challenge = request_challenge(&mut channel, &key).await;
    let rejected = answer_challenge(&mut channel, &key, challenge, &[0x99; 32]).await;
    assert!(
        !rejected.ok,
        "a signature bound to another certificate must fail"
    );

    let challenge = request_challenge(&mut channel, &key).await;
    let accepted = answer_challenge(&mut channel, &key, challenge, &binding).await;
    assert!(accepted.ok, "the routed public leaf hash must authenticate");
    assert_eq!(accepted.user_id, "alice");

    daemon.abort();
}

#[tokio::test]
async fn shared_public_frontdoor_refuses_dev_auth_and_direct_tls() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let (probe, _) = UnixStream::pair().expect("credential probe");
    let uid = probe.peer_cred().expect("peer credentials").uid();
    assert_ne!(uid, 0, "front-door integration test must run unprivileged");
    let bridge = FrontdoorBridgeConfig {
        socket_path: temporary.path().join("holdfast-h3.sock"),
        frontdoor_uid: uid,
        hostname: HOSTNAME.into(),
        public_port: 443,
        maximum_sessions: 4,
        maximum_streams_per_session: 4,
    };

    let dev_error = match Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().expect("TCP bind"),
        webtransport_bind: None,
        h3_frontdoor: Some(bridge.clone()),
        ..Default::default()
    })
    .await
    {
        Ok(_) => panic!("dev auth must not be public through the shared front door"),
        Err(error) => error,
    };
    assert!(dev_error.to_string().contains("refusing dev-auth"));

    let direct_error = match Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().expect("TCP bind"),
        webtransport_bind: Some("127.0.0.1:0".parse().expect("UDP bind")),
        h3_frontdoor: Some(bridge),
        auth: AuthConfig::SshKeys {
            users: BTreeMap::new(),
        },
        ..Default::default()
    })
    .await
    {
        Ok(_) => panic!("direct and bridged QUIC listeners must be exclusive"),
        Err(error) => error,
    };
    assert!(direct_error.to_string().contains("mutually exclusive"));
}
