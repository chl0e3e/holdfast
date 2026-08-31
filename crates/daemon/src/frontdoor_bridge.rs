//! Least-authority backend for a shared HTTP/3/WebTransport front door.
//!
//! This module implements the version-2 `DWMH3B02` Unix bridge documented by
//! ADR 0030. It carries only routed-session metadata and raw bidirectional
//! stream bytes. Holdfast protocol parsing remains in `webtransport`/`Conn`.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use anyhow::{bail, Context as _, Result};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{unix::OwnedWriteHalf, UnixListener, UnixStream},
    sync::{mpsc, watch, Mutex, Semaphore},
    task::JoinHandle,
};

const HEADER_MAGIC: &[u8; 8] = b"DWMH3B02";
const ACK_MAGIC: &[u8; 8] = b"DWMH3A02";
const HEADER_FIXED_BYTES: usize = 105;
const HOSTNAME_BYTES_MAX: usize = 253;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECTION_HANDSHAKES_MAX: usize = 512;
const SESSIONS_MAX: usize = 4096;
const STREAMS_PER_SESSION_MAX: usize = 64;

const KIND_SESSION: u8 = 1;
const KIND_STREAM: u8 = 2;

#[derive(Clone, Debug)]
pub struct FrontdoorBridgeConfig {
    pub socket_path: PathBuf,
    pub frontdoor_uid: u32,
    pub hostname: String,
    pub public_port: u16,
    pub maximum_sessions: usize,
    pub maximum_streams_per_session: usize,
}

impl FrontdoorBridgeConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.socket_path.is_absolute()
            || self.socket_path == Path::new("/")
            || self.socket_path.file_name().is_none()
            || self
                .socket_path
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            bail!("shared H3 front-door socket must be an absolute non-root path");
        }
        validate_hostname(&self.hostname)?;
        if self.frontdoor_uid == 0
            || self.public_port == 0
            || self.maximum_sessions == 0
            || self.maximum_sessions > SESSIONS_MAX
            || self.maximum_streams_per_session == 0
            || self.maximum_streams_per_session > STREAMS_PER_SESSION_MAX
        {
            bail!("shared H3 front-door identity, port or limits are invalid");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BridgeHeader {
    kind: u8,
    session_id: [u8; 32],
    stream_id: u64,
    remote_address: SocketAddr,
    hostname: String,
    channel_binding: [u8; 32],
}

impl BridgeHeader {
    async fn read(stream: &mut UnixStream) -> Result<Self> {
        let mut fixed = [0_u8; HEADER_FIXED_BYTES];
        stream
            .read_exact(&mut fixed)
            .await
            .context("read shared H3 bridge header")?;
        if &fixed[..8] != HEADER_MAGIC || fixed[9..12] != [0; 3] {
            bail!("shared H3 bridge magic or reserved bytes are invalid");
        }
        let kind = fixed[8];
        let session_id = fixed[12..44]
            .try_into()
            .expect("fixed session identity width");
        let stream_id = u64::from_be_bytes(fixed[44..52].try_into().expect("fixed stream width"));
        let address_bytes: [u8; 16] = fixed[53..69].try_into().expect("fixed address width");
        let address = match fixed[52] {
            4 if address_bytes[4..] == [0; 12] => {
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&address_bytes[..4])?))
            }
            6 => IpAddr::V6(Ipv6Addr::from(address_bytes)),
            _ => bail!("shared H3 bridge address family is invalid"),
        };
        let port = u16::from_be_bytes(fixed[69..71].try_into().expect("fixed port width"));
        let hostname_length = usize::from(u16::from_be_bytes(
            fixed[71..73].try_into().expect("fixed hostname width"),
        ));
        let channel_binding = fixed[73..105]
            .try_into()
            .expect("fixed channel-binding width");
        if hostname_length == 0 || hostname_length > HOSTNAME_BYTES_MAX {
            bail!("shared H3 bridge hostname length is invalid");
        }
        let mut hostname = vec![0_u8; hostname_length];
        stream
            .read_exact(&mut hostname)
            .await
            .context("read shared H3 bridge hostname")?;
        let header = Self {
            kind,
            session_id,
            stream_id,
            remote_address: SocketAddr::new(address, port),
            hostname: String::from_utf8(hostname).context("bridge hostname is not UTF-8")?,
            channel_binding,
        };
        header.validate()?;
        Ok(header)
    }

    fn validate(&self) -> Result<()> {
        validate_hostname(&self.hostname)?;
        if self.session_id == [0; 32]
            || self.channel_binding == [0; 32]
            || (self.kind == KIND_SESSION && self.stream_id != 0)
            || (self.kind == KIND_STREAM && self.stream_id == 0)
            || !matches!(self.kind, KIND_SESSION | KIND_STREAM)
            || self.remote_address.port() == 0
        {
            bail!("shared H3 bridge header is invalid");
        }
        Ok(())
    }
}

struct SessionEntry {
    header: BridgeHeader,
    streams: mpsc::Sender<UnixStream>,
    next_stream_id: u64,
}

pub struct FrontdoorBridge {
    sessions: Mutex<mpsc::Receiver<BridgeSession>>,
    accept_task: JoinHandle<()>,
    socket: SocketGuard,
    pub public_port: u16,
}

impl FrontdoorBridge {
    pub fn bind(config: FrontdoorBridgeConfig) -> Result<Self> {
        config.validate()?;
        validate_socket_parent(&config.socket_path)?;
        let listener = UnixListener::bind(&config.socket_path).with_context(|| {
            format!(
                "bind shared H3 front-door socket {}",
                config.socket_path.display()
            )
        })?;
        std::fs::set_permissions(&config.socket_path, std::fs::Permissions::from_mode(0o660))
            .context("protect shared H3 front-door socket")?;
        let socket = SocketGuard::new(config.socket_path.clone())?;
        let (sessions_tx, sessions_rx) = mpsc::channel(config.maximum_sessions);
        let entries = Arc::new(StdMutex::new(HashMap::new()));
        let handshakes = Arc::new(Semaphore::new(CONNECTION_HANDSHAKES_MAX));
        let frontdoor_uid = config.frontdoor_uid;
        let hostname = config.hostname;
        let maximum_sessions = config.maximum_sessions;
        let maximum_streams = config.maximum_streams_per_session;
        let accept_task = tokio::spawn(async move {
            accept_connections(
                listener,
                frontdoor_uid,
                hostname,
                maximum_sessions,
                maximum_streams,
                entries,
                handshakes,
                sessions_tx,
            )
            .await;
        });
        Ok(Self {
            sessions: Mutex::new(sessions_rx),
            accept_task,
            socket,
            public_port: config.public_port,
        })
    }

    pub async fn accept(&self) -> Result<BridgeSession> {
        self.sessions
            .lock()
            .await
            .recv()
            .await
            .context("shared H3 front-door backend stopped")
    }

    pub fn spawn_accept_loop(self: Arc<Self>, state: Arc<crate::AppState>) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                match self.accept().await {
                    Ok(session) => {
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            if let Err(error) =
                                crate::webtransport::handle_bridge_session(session, state).await
                            {
                                tracing::debug!("shared H3 front-door session ended: {error:#}");
                            }
                        });
                    }
                    Err(error) => {
                        tracing::error!("shared H3 front-door backend stopped: {error:#}");
                        return;
                    }
                }
            }
        })
    }
}

impl Drop for FrontdoorBridge {
    fn drop(&mut self) {
        self.accept_task.abort();
        // Keep the guard alive through accept-task cancellation. Its own Drop
        // removes only the inode created by this process.
        let _ = &self.socket;
    }
}

pub struct BridgeSession {
    remote_address: SocketAddr,
    channel_binding: [u8; 32],
    streams: Mutex<mpsc::Receiver<UnixStream>>,
    closed: watch::Receiver<bool>,
    _control: OwnedWriteHalf,
}

impl BridgeSession {
    pub const fn remote_address(&self) -> SocketAddr {
        self.remote_address
    }

    pub const fn channel_binding(&self) -> &[u8; 32] {
        &self.channel_binding
    }

    pub async fn accept_bi(&self) -> Result<UnixStream> {
        let mut streams = self.streams.lock().await;
        let mut closed = self.closed.clone();
        tokio::select! {
            stream = streams.recv() => stream.context("shared H3 bridge session closed"),
            changed = closed.changed() => {
                let _ = changed;
                bail!("shared H3 bridge control connection closed")
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn accept_connections(
    listener: UnixListener,
    frontdoor_uid: u32,
    hostname: String,
    maximum_sessions: usize,
    maximum_streams: usize,
    entries: Arc<StdMutex<HashMap<[u8; 32], SessionEntry>>>,
    handshakes: Arc<Semaphore>,
    sessions: mpsc::Sender<BridgeSession>,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(permit) = Arc::clone(&handshakes).try_acquire_owned() else {
            continue;
        };
        let entries = Arc::clone(&entries);
        let sessions = sessions.clone();
        let hostname = hostname.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = tokio::time::timeout(
                HANDSHAKE_TIMEOUT,
                accept_connection(
                    stream,
                    frontdoor_uid,
                    &hostname,
                    maximum_sessions,
                    maximum_streams,
                    entries,
                    sessions,
                ),
            )
            .await;
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn accept_connection(
    mut stream: UnixStream,
    frontdoor_uid: u32,
    expected_hostname: &str,
    maximum_sessions: usize,
    maximum_streams: usize,
    entries: Arc<StdMutex<HashMap<[u8; 32], SessionEntry>>>,
    sessions: mpsc::Sender<BridgeSession>,
) -> Result<()> {
    let credentials = stream
        .peer_cred()
        .context("read shared H3 front-door peer credentials")?;
    if credentials.uid() != frontdoor_uid {
        bail!("shared H3 front-door UID is not authorized");
    }
    let header = BridgeHeader::read(&mut stream).await?;
    if header.hostname != expected_hostname {
        bail!("shared H3 bridge hostname is not authorized");
    }
    if header.kind == KIND_SESSION {
        let session_permit = sessions
            .try_reserve()
            .map_err(|_| anyhow::anyhow!("shared H3 bridge session queue is full"))?;
        let (streams_tx, streams_rx) = mpsc::channel(maximum_streams);
        {
            let mut entries = entries.lock().expect("bridge entries lock");
            if entries.len() >= maximum_sessions || entries.contains_key(&header.session_id) {
                bail!("shared H3 bridge session capacity or identity is invalid");
            }
            entries.insert(
                header.session_id,
                SessionEntry {
                    header: header.clone(),
                    streams: streams_tx,
                    next_stream_id: 1,
                },
            );
        }
        if let Err(error) = stream.write_all(ACK_MAGIC).await {
            entries
                .lock()
                .expect("bridge entries lock")
                .remove(&header.session_id);
            return Err(error).context("acknowledge shared H3 bridge session");
        }
        let (mut control_read, control_write) = stream.into_split();
        let (closed_tx, closed_rx) = watch::channel(false);
        session_permit.send(BridgeSession {
            remote_address: header.remote_address,
            channel_binding: header.channel_binding,
            streams: Mutex::new(streams_rx),
            closed: closed_rx,
            _control: control_write,
        });
        tokio::spawn(async move {
            let mut unexpected = [0_u8; 1];
            let _ = control_read.read(&mut unexpected).await;
            entries
                .lock()
                .expect("bridge entries lock")
                .remove(&header.session_id);
            let _ = closed_tx.send(true);
        });
        return Ok(());
    }

    let sender = {
        let mut entries = entries.lock().expect("bridge entries lock");
        let entry = entries
            .get_mut(&header.session_id)
            .context("shared H3 bridge stream names no live session")?;
        if entry.header.hostname != header.hostname
            || entry.header.remote_address != header.remote_address
            || entry.header.channel_binding != header.channel_binding
            || header.stream_id != entry.next_stream_id
        {
            bail!("shared H3 bridge stream metadata does not match its session");
        }
        entry.next_stream_id = entry
            .next_stream_id
            .checked_add(1)
            .context("shared H3 bridge stream identity exhausted")?;
        entry.streams.clone()
    };
    let permit = sender
        .try_reserve_owned()
        .map_err(|_| anyhow::anyhow!("shared H3 bridge stream capacity is exhausted"))?;
    stream
        .write_all(ACK_MAGIC)
        .await
        .context("acknowledge shared H3 bridge stream")?;
    permit.send(stream);
    Ok(())
}

fn validate_socket_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .context("shared H3 front-door socket has no parent")?;
    let metadata = std::fs::symlink_metadata(parent)
        .with_context(|| format!("inspect bridge socket directory {}", parent.display()))?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o022 != 0
    {
        bail!("shared H3 front-door socket directory must be protected and non-symlinked");
    }
    Ok(())
}

fn validate_hostname(hostname: &str) -> Result<()> {
    if hostname.is_empty()
        || hostname.len() > HOSTNAME_BYTES_MAX
        || hostname.ends_with('.')
        || hostname.parse::<IpAddr>().is_ok()
        || hostname.bytes().any(|byte| byte.is_ascii_uppercase())
        || !hostname.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        bail!("shared H3 front-door hostname must be canonical lowercase DNS");
    }
    Ok(())
}

struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl SocketGuard {
    fn new(path: PathBuf) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(&path).context("inspect bound bridge socket")?;
        if !metadata.file_type().is_socket() {
            bail!("shared H3 front-door path is not a Unix socket");
        }
        Ok(Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if let Ok(metadata) = std::fs::symlink_metadata(&self.path) {
            if metadata.file_type().is_socket()
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
            {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded_header(header: &BridgeHeader) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_FIXED_BYTES + header.hostname.len());
        bytes.extend_from_slice(HEADER_MAGIC);
        bytes.push(header.kind);
        bytes.extend_from_slice(&[0; 3]);
        bytes.extend_from_slice(&header.session_id);
        bytes.extend_from_slice(&header.stream_id.to_be_bytes());
        match header.remote_address.ip() {
            IpAddr::V4(address) => {
                bytes.push(4);
                bytes.extend_from_slice(&address.octets());
                bytes.extend_from_slice(&[0; 12]);
            }
            IpAddr::V6(address) => {
                bytes.push(6);
                bytes.extend_from_slice(&address.octets());
            }
        }
        bytes.extend_from_slice(&header.remote_address.port().to_be_bytes());
        bytes.extend_from_slice(&(header.hostname.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&header.channel_binding);
        bytes.extend_from_slice(header.hostname.as_bytes());
        bytes
    }

    fn valid_header() -> BridgeHeader {
        BridgeHeader {
            kind: KIND_SESSION,
            session_id: [0x31; 32],
            stream_id: 0,
            remote_address: "127.0.0.1:4242".parse().expect("remote address"),
            hostname: "holdfast.example".into(),
            channel_binding: [0x42; 32],
        }
    }

    async fn decode(bytes: &[u8]) -> Result<BridgeHeader> {
        let (mut writer, mut reader) = UnixStream::pair().expect("Unix stream pair");
        writer.write_all(bytes).await.expect("write bridge header");
        writer.shutdown().await.expect("finish bridge header");
        BridgeHeader::read(&mut reader).await
    }

    #[test]
    fn configuration_bounds_and_hostname_are_explicit() {
        let valid = FrontdoorBridgeConfig {
            socket_path: "/run/holdfast/h3-bridge.sock".into(),
            frontdoor_uid: 973,
            hostname: "holdfast.example".into(),
            public_port: 443,
            maximum_sessions: 128,
            maximum_streams_per_session: 64,
        };
        valid.validate().expect("valid configuration");

        for invalid in [
            FrontdoorBridgeConfig {
                hostname: "Holdfast.example".into(),
                ..valid.clone()
            },
            FrontdoorBridgeConfig {
                frontdoor_uid: 0,
                ..valid.clone()
            },
            FrontdoorBridgeConfig {
                public_port: 0,
                ..valid.clone()
            },
            FrontdoorBridgeConfig {
                maximum_streams_per_session: 65,
                ..valid.clone()
            },
            FrontdoorBridgeConfig {
                socket_path: "/run/holdfast/../other/h3-bridge.sock".into(),
                ..valid.clone()
            },
        ] {
            assert!(invalid.validate().is_err());
        }
    }

    #[tokio::test]
    async fn exact_header_round_trips_and_malformed_wire_is_rejected() {
        let header = valid_header();
        assert_eq!(
            decode(&encoded_header(&header))
                .await
                .expect("valid header"),
            header
        );

        let valid = encoded_header(&valid_header());
        for (label, malformed) in [
            ("magic", {
                let mut bytes = valid.clone();
                bytes[0] ^= 1;
                bytes
            }),
            ("reserved", {
                let mut bytes = valid.clone();
                bytes[9] = 1;
                bytes
            }),
            ("address family", {
                let mut bytes = valid.clone();
                bytes[52] = 5;
                bytes
            }),
            ("noncanonical IPv4", {
                let mut bytes = valid.clone();
                bytes[57] = 1;
                bytes
            }),
            ("zero identity", {
                let mut bytes = valid.clone();
                bytes[12..44].fill(0);
                bytes
            }),
            ("zero binding", {
                let mut bytes = valid.clone();
                bytes[73..105].fill(0);
                bytes
            }),
            ("invalid kind", {
                let mut bytes = valid.clone();
                bytes[8] = 3;
                bytes
            }),
            ("session stream identity", {
                let mut bytes = valid.clone();
                bytes[44..52].copy_from_slice(&1_u64.to_be_bytes());
                bytes
            }),
            ("uppercase hostname", {
                let mut bytes = valid.clone();
                bytes[HEADER_FIXED_BYTES] = b'H';
                bytes
            }),
        ] {
            assert!(decode(&malformed).await.is_err(), "accepted {label}");
        }
    }

    #[tokio::test]
    async fn unauthorized_peer_uid_is_rejected_before_header_admission() {
        let (server, _client) = UnixStream::pair().expect("Unix stream pair");
        let uid = server.peer_cred().expect("peer credentials").uid();
        let entries = Arc::new(StdMutex::new(HashMap::new()));
        let (sessions, _receiver) = mpsc::channel(1);
        let error = accept_connection(
            server,
            uid.saturating_add(1),
            "holdfast.example",
            1,
            1,
            entries,
            sessions,
        )
        .await
        .expect_err("wrong peer UID must fail");
        assert!(error.to_string().contains("UID is not authorized"));
    }
}
