//! Bounded TCP forwarding actors. No terminal or control-plane bytes.
use anyhow::{anyhow, bail, Result};
use hf_protocol::{
    pb::{self, envelope::Message as Msg, Envelope},
    FORWARD_DATA_BYTES_MAX,
};
use std::{
    collections::{BTreeSet, HashMap},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{mpsc, watch},
};

const IO_TIMEOUT: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
pub(crate) const MAX_PER_CONNECTION: usize = 32;

pub(crate) struct ForwardService {
    users: BTreeSet<String>,
    active: Mutex<HashMap<String, usize>>,
}

impl ForwardService {
    pub fn new(users: BTreeSet<String>) -> Result<Self> {
        if users.len() > 256 || users.iter().any(|u| u.is_empty() || u.len() > 128) {
            bail!("TCP forwarding permits at most 256 usernames of 1..128 bytes");
        }
        Ok(Self {
            users,
            active: Mutex::new(HashMap::new()),
        })
    }
    pub fn enabled(&self) -> bool {
        !self.users.is_empty()
    }
    pub fn permits(&self, user: &str) -> bool {
        self.users.contains(user)
    }
    pub fn acquire(self: &Arc<Self>, user: &str) -> Option<Permit> {
        let mut active = self.active.lock().unwrap();
        if active.values().sum::<usize>() >= 256 || active.get(user).copied().unwrap_or(0) >= 64 {
            return None;
        }
        *active.entry(user.into()).or_default() += 1;
        Some(Permit {
            service: self.clone(),
            user: user.into(),
        })
    }
}
pub(crate) struct Permit {
    service: Arc<ForwardService>,
    user: String,
}
impl Drop for Permit {
    fn drop(&mut self) {
        let mut active = self.service.active.lock().unwrap();
        if let Some(n) = active.get_mut(&self.user) {
            *n -= 1;
            if *n == 0 {
                active.remove(&self.user);
            }
        }
    }
}

pub(crate) struct ForwardBinding {
    input: mpsc::Sender<Option<Vec<u8>>>,
    acks: mpsc::Sender<()>,
    task: tokio::task::JoinHandle<()>,
    input_ready: Arc<AtomicBool>,
    ack_expected: Arc<AtomicBool>,
}
impl Drop for ForwardBinding {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl ForwardBinding {
    pub fn abort(&self) {
        self.task.abort();
    }
    pub fn message(&self, env: Envelope) -> bool {
        if env.request_id != 0 || !env.server_id.is_empty() || !env.shell_id.is_empty() {
            return false;
        }
        match env.message {
            Some(Msg::TcpForwardData(data))
                if !data.data.is_empty() && data.data.len() <= FORWARD_DATA_BYTES_MAX =>
            {
                self.input_ready.swap(false, Ordering::SeqCst)
                    && self.input.try_send(Some(data.data)).is_ok()
            }
            Some(Msg::TcpForwardEof(_)) => {
                self.input_ready.swap(false, Ordering::SeqCst) && self.input.try_send(None).is_ok()
            }
            Some(Msg::TcpForwardAck(_)) => {
                self.ack_expected.swap(false, Ordering::SeqCst) && self.acks.try_send(()).is_ok()
            }
            _ => false,
        }
    }
}

async fn send(
    out: &mpsc::Sender<(u64, Envelope)>,
    channel: u64,
    request_id: u64,
    message: Msg,
) -> Result<()> {
    tokio::time::timeout(
        IO_TIMEOUT,
        out.send((
            channel,
            Envelope {
                request_id,
                message: Some(message),
                ..Default::default()
            },
        )),
    )
    .await??;
    Ok(())
}

pub(crate) fn spawn(
    host: String,
    port: u16,
    channel: u64,
    request_id: u64,
    out: mpsc::Sender<(u64, Envelope)>,
    permit: Permit,
) -> ForwardBinding {
    let (input, mut input_rx) = mpsc::channel::<Option<Vec<u8>>>(1);
    let (acks, mut ack_rx) = mpsc::channel(1);
    let input_ready = Arc::new(AtomicBool::new(false));
    let ack_expected = Arc::new(AtomicBool::new(false));
    let ready = input_ready.clone();
    let expected = ack_expected.clone();
    let task = tokio::spawn(async move {
        let _permit = permit;
        let result: Result<()> = async {
            let socket = tokio::time::timeout(
                Duration::from_secs(10),
                TcpStream::connect((host.as_str(), port)),
            )
            .await??;
            let bound = socket.local_addr()?;
            ready.store(true, Ordering::SeqCst);
            send(
                &out,
                channel,
                request_id,
                Msg::TcpForwardOpened(pb::TcpForwardOpened {
                    bound_ip: bound.ip().to_string(),
                    bound_port: bound.port().into(),
                }),
            )
            .await?;
            let (mut read, mut write) = socket.into_split();
            let (activity, mut activity_rx) = watch::channel(tokio::time::Instant::now());
            let upstream = async {
                loop {
                    let data = input_rx
                        .recv()
                        .await
                        .ok_or_else(|| anyhow!("forward closed"))?;
                    activity.send_replace(tokio::time::Instant::now());
                    let eof = data.is_none();
                    match data {
                        Some(data) => {
                            tokio::time::timeout(IO_TIMEOUT, write.write_all(&data)).await??
                        }
                        None => tokio::time::timeout(IO_TIMEOUT, write.shutdown()).await??,
                    }
                    if !eof {
                        ready.store(true, Ordering::SeqCst);
                    }
                    send(&out, channel, 0, Msg::TcpForwardAck(pb::TcpForwardAck {})).await?;
                    if eof {
                        // A post-EOF frame is invalid even while reverse data continues.
                        input_rx.close();
                        if !input_rx.is_empty() {
                            bail!("data after EOF");
                        }
                        return Ok::<_, anyhow::Error>(());
                    }
                }
            };
            let downstream = async {
                let mut buffer = [0; FORWARD_DATA_BYTES_MAX];
                loop {
                    // No peer ack is legal before sending the next frame.
                    let n = tokio::select! {
                        n = read.read(&mut buffer) => n?,
                        _ = ack_rx.recv() => bail!("unsolicited forward acknowledgement"),
                    };
                    activity.send_replace(tokio::time::Instant::now());
                    let message = if n == 0 {
                        Msg::TcpForwardEof(pb::TcpForwardEof {})
                    } else {
                        Msg::TcpForwardData(pb::TcpForwardData {
                            data: buffer[..n].to_vec(),
                        })
                    };
                    expected.store(true, Ordering::SeqCst);
                    send(&out, channel, 0, message).await?;
                    tokio::time::timeout(IO_TIMEOUT, ack_rx.recv())
                        .await?
                        .ok_or_else(|| anyhow!("forward closed"))?;
                    if n == 0 {
                        ack_rx.close();
                        return Ok::<_, anyhow::Error>(());
                    }
                }
            };
            let idle = async {
                loop {
                    let deadline = *activity_rx.borrow_and_update() + IDLE_TIMEOUT;
                    tokio::select! {
                        _ = tokio::time::sleep_until(deadline) => break,
                        _ = activity_rx.changed() => {}
                    }
                }
            };
            tokio::select! {
                result = async { tokio::try_join!(upstream, downstream) } => { result?; Ok(()) }
                _ = idle => Err(anyhow!("TCP forward idle timeout")),
            }
        }
        .await;
        if result.is_err() {
            // Never disclose DNS or destination details through logs/errors.
            let _ = send(
                &out,
                channel,
                request_id,
                Msg::Error(pb::Error {
                    code: pb::ErrorCode::ErrServerUnavailable as i32,
                    human_message: "TCP forwarding failed or timed out".into(),
                    retryable: false,
                }),
            )
            .await;
        }
    });
    ForwardBinding {
        input,
        acks,
        task,
        input_ready,
        ack_expected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn user_and_global_limits_release_on_drop() {
        let service = Arc::new(ForwardService::new(["alice".into()].into()).unwrap());
        assert!(service.permits("alice"));
        assert!(!service.permits("bob"));
        let mut permits: Vec<_> = (0..64).map(|_| service.acquire("alice").unwrap()).collect();
        assert!(service.acquire("alice").is_none());
        permits.pop();
        assert!(service.acquire("alice").is_some());
        drop(permits);
        assert!(service.active.lock().unwrap().is_empty());
        let permits: Vec<_> = (0..256)
            .map(|i| service.acquire(&format!("user-{}", i / 64)).unwrap())
            .collect();
        assert!(service.acquire("next-user").is_none());
        drop(permits);
        assert!(service.acquire("next-user").is_some());
    }
}
