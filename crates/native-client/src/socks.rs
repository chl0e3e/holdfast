//! Loopback SOCKS5 CONNECT, using the existing authenticated QUIC connection.
use crate::{plain, Chan, Connection};
use anyhow::{anyhow, bail, ensure, Result};
use hf_protocol::{
    forward::valid_destination,
    framing::{encode_frame, FrameDecoder},
    pb::{self, envelope::Message as Msg},
    FORWARD_DATA_BYTES_MAX, FRAME_BYTES_DEFAULT,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
    task::JoinSet,
    time::timeout,
};

const HANDSHAKE: Duration = Duration::from_secs(10);
const IO: Duration = Duration::from_secs(30);
const IDLE: Duration = Duration::from_secs(300);
const MAX_CONNECTIONS: usize = 32;
const ACCEPT_BACKLOG: u32 = 16;

/// Dropping this handle closes the listener and every accepted TCP connection.
pub struct SocksProxy {
    pub address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for SocksProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl SocksProxy {
    pub async fn stop(mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
    /// Caller must first check negotiated TCP_FORWARD. Never binds outside loopback.
    pub async fn start(connection: Connection, address: SocketAddr) -> Result<Self> {
        ensure!(
            address.ip().is_loopback(),
            "SOCKS listener must bind to loopback"
        );
        let socket = if address.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        // Unix TIME_WAIT must not prevent an explicit Stop → Start. Windows
        // SO_REUSEADDR has different listener-sharing semantics; never set it.
        #[cfg(unix)]
        socket.set_reuseaddr(true)?;
        socket.bind(address)?;
        let listener = socket.listen(ACCEPT_BACKLOG)?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let mut clients = JoinSet::new();
            loop {
                tokio::select! {
                    // Reap completed tasks first. At capacity leave connections
                    // in the bounded TCP backlog rather than accepting and
                    // silently closing a browser's next request.
                    biased;
                    _ = clients.join_next(), if !clients.is_empty() => {}
                    accepted = listener.accept(), if clients.len() < MAX_CONNECTIONS => {
                        let Ok((socket, peer)) = accepted else { break };
                        if !peer.ip().is_loopback() { continue; }
                        let connection = connection.clone();
                        clients.spawn(async move { let _ = serve(socket, &connection).await; });
                    }
                }
            }
            // JoinSet drop aborts children; they must never outlive the listener.
        });
        Ok(Self { address, task })
    }
}

async fn reply(socket: &mut TcpStream, code: u8, bound: SocketAddr) -> Result<()> {
    let mut bytes = Vec::with_capacity(22);
    bytes.extend_from_slice(&[5, code, 0]);
    match bound.ip() {
        IpAddr::V4(ip) => {
            bytes.push(1);
            bytes.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            bytes.push(4);
            bytes.extend_from_slice(&ip.octets());
        }
    }
    bytes.extend_from_slice(&bound.port().to_be_bytes());
    timeout(IO, socket.write_all(&bytes)).await??;
    Ok(())
}
async fn reject(socket: &mut TcpStream, code: u8) -> Result<()> {
    reply(socket, code, SocketAddr::from(([0, 0, 0, 0], 0))).await
}

async fn request(socket: &mut TcpStream) -> Result<(String, u16)> {
    let mut greeting = [0; 2];
    socket.read_exact(&mut greeting).await?;
    ensure!(greeting[0] == 5 && greeting[1] > 0, "SOCKS5 required");
    let mut methods = [0; 255];
    socket
        .read_exact(&mut methods[..greeting[1] as usize])
        .await?;
    let accepted = methods[..greeting[1] as usize].contains(&0);
    socket
        .write_all(&[5, if accepted { 0 } else { 255 }])
        .await?;
    ensure!(accepted, "no supported SOCKS authentication method");
    let mut header = [0; 4];
    socket.read_exact(&mut header).await?;
    if header[0] != 5 || header[2] != 0 {
        reject(socket, 1).await?;
        bail!("invalid SOCKS request");
    }
    if header[1] != 1 {
        reject(socket, 7).await?;
        bail!("only SOCKS CONNECT is supported");
    }
    let host = match header[3] {
        1 => {
            let mut ip = [0; 4];
            socket.read_exact(&mut ip).await?;
            Ipv4Addr::from(ip).to_string()
        }
        4 => {
            let mut ip = [0; 16];
            socket.read_exact(&mut ip).await?;
            Ipv6Addr::from(ip).to_string()
        }
        3 => {
            let len = socket.read_u8().await? as usize;
            let mut host = [0; 255];
            socket.read_exact(&mut host[..len]).await?;
            String::from_utf8(host[..len].to_vec()).unwrap_or_default()
        }
        _ => {
            reject(socket, 8).await?;
            bail!("unsupported SOCKS address type");
        }
    };
    let port = socket.read_u16().await?;
    if !valid_destination(&host, port.into()) {
        reject(socket, 8).await?;
        bail!("invalid SOCKS destination");
    }
    Ok((host, port))
}

async fn serve(mut socket: TcpStream, connection: &Connection) -> Result<()> {
    let (host, port) = timeout(HANDSHAKE, request(&mut socket)).await??;
    let opened: Result<_> = timeout(IO, async {
        let mut chan = Chan::open(connection).await?;
        let mut env = plain(Msg::OpenTcpForward(pb::OpenTcpForward {
            host,
            port: port.into(),
        }));
        env.request_id = 1;
        chan.send_env(env).await?;
        let env = chan.recv_env().await?;
        ensure!(env.request_id == 1, "wrong TCP forwarding response");
        match env.message {
            Some(Msg::TcpForwardOpened(open)) => {
                let port = u16::try_from(open.bound_port)?;
                ensure!(port > 0, "invalid bound port");
                Ok((chan, SocketAddr::new(open.bound_ip.parse()?, port)))
            }
            Some(Msg::Error(error)) => Err(anyhow!("forward rejected: {}", error.code)),
            _ => bail!("unexpected TCP forwarding response"),
        }
    })
    .await
    .map_err(anyhow::Error::from)
    .and_then(|result| result);
    let (chan, bound) = match opened {
        Ok(opened) => opened,
        Err(e) => {
            reject(&mut socket, 1).await?;
            return Err(e);
        }
    };
    reply(&mut socket, 0, bound).await?;
    relay(socket, chan).await
}

async fn relay(mut socket: TcpStream, chan: Chan) -> Result<()> {
    let Chan {
        mut send,
        mut recv,
        mut decoder,
        mut buf,
    } = chan;
    let mut outgoing = [0; FORWARD_DATA_BYTES_MAX];
    let mut waiting_ack = false;
    let mut local_eof = false;
    let mut remote_eof = false;
    let mut ack_deadline = tokio::time::Instant::now() + IO;
    loop {
        if local_eof && remote_eof && !waiting_ack {
            // Flush the final EOF acknowledgement before releasing the stream.
            timeout(IO, send.finish()).await??;
            return Ok(());
        }
        tokio::select! {
            data = socket.read(&mut outgoing), if !local_eof && !waiting_ack => {
                let n = data?;
                let message = if n == 0 { local_eof = true; Msg::TcpForwardEof(pb::TcpForwardEof {}) }
                    else { Msg::TcpForwardData(pb::TcpForwardData { data: outgoing[..n].to_vec() }) };
                timeout(IO, send.write_all(&encode_frame(&plain(message), FRAME_BYTES_DEFAULT)?)).await??;
                waiting_ack = true;
                ack_deadline = tokio::time::Instant::now() + IO;
            }
            env = receive(&mut recv, &mut decoder, &mut buf) => {
                let env = env?;
                ensure!(env.request_id == 0 && env.server_id.is_empty() && env.shell_id.is_empty(), "invalid forward frame identity");
                match env.message {
                    Some(Msg::TcpForwardAck(_)) if waiting_ack => { waiting_ack = false; }
                    Some(Msg::TcpForwardData(data)) if !remote_eof && !data.data.is_empty() && data.data.len() <= FORWARD_DATA_BYTES_MAX => {
                        timeout(IO, socket.write_all(&data.data)).await??;
                        timeout(IO, send.write_all(&encode_frame(&plain(Msg::TcpForwardAck(pb::TcpForwardAck {})), FRAME_BYTES_DEFAULT)?)).await??;
                    }
                    Some(Msg::TcpForwardEof(_)) if !remote_eof => {
                        remote_eof = true;
                        timeout(IO, socket.shutdown()).await??;
                        timeout(IO, send.write_all(&encode_frame(&plain(Msg::TcpForwardAck(pb::TcpForwardAck {})), FRAME_BYTES_DEFAULT)?)).await??;
                    }
                    _ => bail!("invalid or failed TCP forwarding channel"),
                }
            }
            _ = tokio::time::sleep_until(ack_deadline), if waiting_ack => bail!("TCP forward acknowledgement timed out"),
            _ = tokio::time::sleep(IDLE) => bail!("TCP forward idle timeout"),
        }
    }
}
async fn receive(
    recv: &mut crate::transport::RecvStream,
    decoder: &mut FrameDecoder,
    buf: &mut [u8],
) -> Result<pb::Envelope> {
    loop {
        if let Some(env) = decoder.next_frame()? {
            return Ok(env);
        }
        let n = recv
            .read(buf)
            .await?
            .ok_or_else(|| anyhow!("forward stream closed"))?;
        decoder.extend(&buf[..n])?;
    }
}
