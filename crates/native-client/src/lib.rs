//! Native client library: WebTransport sessions against a holdfastd
//! (ADR 0005 — native clients share the browser's WebTransport endpoint).
//!
//! `connect` fetches `/webtransport-info` from the daemon's HTTP listener,
//! pins the certificate hash, establishes the QUIC session and performs
//! hello + authentication. Shell operations mirror the wire protocol; resume
//! tokens rotate on every attach and must be re-persisted by the caller
//! (see [`state`]).

pub mod state;

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use hf_protocol::framing::{encode_frame, FrameDecoder};
use hf_protocol::pb::{self, envelope::Message as Msg, Envelope};
use hf_protocol::{FRAME_BYTES_DEFAULT, PROTOCOL_MAJOR, PROTOCOL_MINOR};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wtransport::tls::Sha256Digest;
use wtransport::{ClientConfig, Connection, Endpoint, RecvStream, SendStream};

const T: Duration = Duration::from_secs(10);

pub fn plain(message: Msg) -> Envelope {
    Envelope { request_id: 0, server_id: vec![], shell_id: vec![], message: Some(message) }
}

/// One protocol channel: a bidirectional stream carrying §3 frames.
pub struct Chan {
    send: SendStream,
    recv: RecvStream,
    decoder: FrameDecoder,
    buf: Vec<u8>,
}

impl Chan {
    async fn open(connection: &Connection) -> Result<Chan> {
        let (send, recv) = connection.open_bi().await?.await?;
        Ok(Chan {
            send,
            recv,
            decoder: FrameDecoder::new(FRAME_BYTES_DEFAULT),
            buf: vec![0; 16 * 1024],
        })
    }

    pub async fn send_env(&mut self, envelope: Envelope) -> Result<()> {
        let bytes = encode_frame(&envelope, FRAME_BYTES_DEFAULT)?;
        self.send.write_all(&bytes).await?;
        Ok(())
    }

    pub async fn recv_env(&mut self) -> Result<Envelope> {
        loop {
            if let Some(envelope) = self.decoder.next_frame()? {
                return Ok(envelope);
            }
            let n = self
                .recv
                .read(&mut self.buf)
                .await?
                .ok_or_else(|| anyhow!("stream closed"))?;
            self.decoder.extend(&self.buf[..n])?;
        }
    }

    async fn recv_until<F, R>(&mut self, mut pred: F) -> Result<R>
    where
        F: FnMut(&Envelope) -> Option<R>,
    {
        loop {
            let envelope = tokio::time::timeout(T, self.recv_env())
                .await
                .context("timed out waiting for server response")??;
            if let Some(r) = pred(&envelope) {
                return Ok(r);
            }
        }
    }
}

/// Minimal HTTP/1.1 GET for the daemon's dev info endpoint (loopback use).
async fn http_get(base: &str, path: &str) -> Result<String> {
    let host_port = base
        .strip_prefix("http://")
        .ok_or_else(|| anyhow!("--url must be http://host:port (got {base})"))?
        .trim_end_matches('/');
    let mut stream = tokio::net::TcpStream::connect(host_port)
        .await
        .with_context(|| format!("connect {host_port}"))?;
    let host = host_port.split(':').next().unwrap_or(host_port);
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let text = String::from_utf8_lossy(&response);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow!("malformed HTTP response"))?;
    if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
        bail!("GET {path}: {}", head.lines().next().unwrap_or("unknown status"));
    }
    Ok(body.to_string())
}

pub struct ServerConn {
    pub connection: Connection,
    pub control: Chan,
    /// Grant handed back by the daemon on successful auth; persist and reuse
    /// for later reconnects (spec §5). Empty in dev mode.
    pub grant: Vec<u8>,
    next_request: u64,
}

/// How to authenticate to the daemon (spec §5).
pub enum AuthMethod {
    /// Dev mode: present an empty connection grant (loopback daemons only).
    Dev,
    /// Present a previously issued connection grant.
    Grant(Vec<u8>),
    /// SSH public-key challenge/response with an OpenSSH private key file.
    SshKey { username: String, private_key_path: std::path::PathBuf },
}

/// Connect, negotiate and authenticate (dev grant) against a daemon.
pub async fn connect(http_base: &str) -> Result<ServerConn> {
    connect_with(http_base, AuthMethod::Dev).await
}

/// Connect and authenticate with an explicit method.
pub async fn connect_with(http_base: &str, auth: AuthMethod) -> Result<ServerConn> {
    let info: serde_json::Value = serde_json::from_str(
        &http_get(http_base, "/webtransport-info").await?,
    )
    .context("parse /webtransport-info")?;
    let port = info["port"].as_u64().ok_or_else(|| anyhow!("info missing port"))? as u16;
    let hash_b64 =
        info["certHashBase64"].as_str().ok_or_else(|| anyhow!("info missing certHashBase64"))?;
    let hash: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(hash_b64)?
        .try_into()
        .map_err(|_| anyhow!("cert hash must be 32 bytes"))?;

    let host = http_base
        .strip_prefix("http://")
        .unwrap_or(http_base)
        .split(':')
        .next()
        .unwrap_or("127.0.0.1")
        .to_string();

    let endpoint = Endpoint::client(
        ClientConfig::builder()
            .with_bind_default()
            .with_server_certificate_hashes([Sha256Digest::new(hash)])
            .build(),
    )?;
    let connection = endpoint
        .connect(format!("https://{host}:{port}/"))
        .await
        .context("webtransport connect")?;

    let mut control = Chan::open(&connection).await?;
    control
        .send_env(plain(Msg::ClientHello(pb::ClientHello {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            client_kind: pb::ClientKind::NativeQuic as i32,
            client_build: format!("hf {}", env!("CARGO_PKG_VERSION")),
            capabilities: vec![],
            max_frame_bytes: FRAME_BYTES_DEFAULT,
            max_datagram_bytes: 1200,
            encodings: vec![pb::Encoding::Utf8 as i32],
        })))
        .await?;
    control
        .recv_until(|env| matches!(&env.message, Some(Msg::ServerHello(_))).then_some(()))
        .await?;

    let grant = authenticate(&mut control, auth).await?;
    Ok(ServerConn { connection, control, grant, next_request: 1 })
}

/// Run the authentication exchange; returns the grant the daemon issues
/// (empty in dev mode).
async fn authenticate(control: &mut Chan, auth: AuthMethod) -> Result<Vec<u8>> {
    match auth {
        AuthMethod::Dev => {
            let result = send_auth(control, pb::authenticate::Method::ConnectionGrant(vec![])).await?;
            ensure_ok(&result)?;
            Ok(result.challenge) // empty in dev
        }
        AuthMethod::Grant(grant) => {
            let result =
                send_auth(control, pb::authenticate::Method::ConnectionGrant(grant.clone())).await?;
            ensure_ok(&result)?;
            Ok(if result.challenge.is_empty() { grant } else { result.challenge })
        }
        AuthMethod::SshKey { username, private_key_path } => {
            let key = ssh_key::PrivateKey::read_openssh_file(&private_key_path)
                .with_context(|| format!("read private key {}", private_key_path.display()))?;
            if key.is_encrypted() {
                bail!("passphrase-protected keys are not yet supported; use an unencrypted key");
            }
            let public_line = key
                .public_key()
                .to_openssh()
                .context("serialize public key")?;

            // Step 1–3: offer the key, receive a challenge.
            let challenge_result = send_auth(
                control,
                pb::authenticate::Method::SshChallengeRequest(pb::SshChallengeRequest {
                    username,
                    public_key: public_line.into_bytes(),
                }),
            )
            .await?;
            if challenge_result.challenge.is_empty() {
                bail!("authentication failed (key not authorized)");
            }

            // Step 4–5: sign the challenge and prove possession.
            let sig = key
                .sign(hf_auth::SSH_NAMESPACE, ssh_key::HashAlg::Sha512, &challenge_result.challenge)
                .context("sign challenge")?;
            let pem = sig.to_pem(ssh_key::LineEnding::LF).context("encode signature")?;
            let result = send_auth(
                control,
                pb::authenticate::Method::SshChallengeResponse(pb::SshChallengeResponse {
                    challenge: challenge_result.challenge,
                    signature: pem.into_bytes(),
                }),
            )
            .await?;
            ensure_ok(&result)?;
            Ok(result.challenge) // the issued grant
        }
    }
}

async fn send_auth(
    control: &mut Chan,
    method: pb::authenticate::Method,
) -> Result<pb::AuthenticationResult> {
    control
        .send_env(plain(Msg::Authenticate(pb::Authenticate { method: Some(method) })))
        .await?;
    control
        .recv_until(|env| match &env.message {
            Some(Msg::AuthenticationResult(r)) => Some(r.clone()),
            _ => None,
        })
        .await
}

fn ensure_ok(result: &pb::AuthenticationResult) -> Result<()> {
    if result.ok {
        Ok(())
    } else {
        bail!("authentication failed: {}", result.error_message);
    }
}

impl ServerConn {
    fn request_id(&mut self) -> u64 {
        let id = self.next_request;
        self.next_request += 1;
        id
    }

    pub async fn list_shells(&mut self) -> Result<Vec<pb::ShellInfo>> {
        let request_id = self.request_id();
        let mut env = plain(Msg::ListShells(pb::ListShells {}));
        env.request_id = request_id;
        self.control.send_env(env).await?;
        self.control
            .recv_until(|env| match &env.message {
                Some(Msg::ShellList(list)) if env.request_id == request_id => {
                    Some(list.shells.clone())
                }
                _ => None,
            })
            .await
    }

    /// Returns (shell_id wire bytes, resume token).
    pub async fn open_shell(
        &mut self,
        command: Option<&str>,
        cols: u16,
        rows: u16,
        idempotency_key: [u8; 16],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let request_id = self.request_id();
        let mut env = plain(Msg::OpenShell(pb::OpenShell {
            unix_account: String::new(),
            command: command.unwrap_or("").to_string(),
            initial_cols: cols as u32,
            initial_rows: rows as u32,
            idempotency_key: idempotency_key.to_vec(),
        }));
        env.request_id = request_id;
        self.control.send_env(env).await?;
        self.control
            .recv_until(|env| match &env.message {
                Some(Msg::ShellOpened(o)) if env.request_id == request_id => {
                    Some(Ok((env.shell_id.clone(), o.resume_token.clone())))
                }
                Some(Msg::Error(e)) if env.request_id == request_id => {
                    Some(Err(anyhow!("open failed: {}", e.human_message)))
                }
                _ => None,
            })
            .await?
    }

    pub async fn terminate(&mut self, shell_id: &[u8]) -> Result<i32> {
        let request_id = self.request_id();
        let mut env = plain(Msg::TerminateShell(pb::TerminateShell {}));
        env.request_id = request_id;
        env.shell_id = shell_id.to_vec();
        self.control.send_env(env).await?;
        self.control
            .recv_until(|env| match &env.message {
                Some(Msg::ShellExited(e)) if env.request_id == request_id => Some(Ok(e.exit_code)),
                Some(Msg::Error(e)) if env.request_id == request_id => {
                    Some(Err(anyhow!("terminate failed: {}", e.human_message)))
                }
                _ => None,
            })
            .await?
    }

    /// Attach; the returned shell carries the redraw snapshot, freshly
    /// rotated token (persist it!), and the live event stream.
    pub async fn attach(
        &self,
        shell_id: &[u8],
        token: &[u8],
        cols: u16,
        rows: u16,
    ) -> Result<AttachedShell> {
        let mut chan = Chan::open(&self.connection).await?;
        let mut env = plain(Msg::AttachShell(pb::AttachShell {
            resume_token: token.to_vec(),
            cols: cols as u32,
            rows: rows as u32,
            last_seen_revision: 0,
            last_history_line_id: 0,
        }));
        env.shell_id = shell_id.to_vec();
        chan.send_env(env).await?;
        let attached = chan
            .recv_until(|env| match &env.message {
                Some(Msg::ShellAttached(a)) => Some(Ok(a.clone())),
                Some(Msg::Error(e)) => {
                    Some(Err(anyhow!("attach failed ({}): {}", e.code, e.human_message)))
                }
                _ => None,
            })
            .await??;
        Ok(AttachedShell {
            chan,
            shell_id: shell_id.to_vec(),
            snapshot: attached.screen_snapshot,
            rotated_token: attached.rotated_resume_token,
            oldest_history_line_id: attached.oldest_history_line_id,
            newest_history_line_id: attached.newest_history_line_id,
        })
    }
}

#[derive(Debug)]
pub enum ShellEvent {
    Output(Vec<u8>),
    Exited(i32),
}

pub struct AttachedShell {
    chan: Chan,
    pub shell_id: Vec<u8>,
    pub snapshot: Vec<u8>,
    pub rotated_token: Vec<u8>,
    pub oldest_history_line_id: u64,
    pub newest_history_line_id: u64,
}

impl AttachedShell {
    pub async fn input(&mut self, data: &[u8]) -> Result<()> {
        self.chan
            .send_env(plain(Msg::TerminalInput(pb::TerminalInput { data: data.to_vec() })))
            .await
    }

    pub async fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        self.chan
            .send_env(plain(Msg::TerminalResize(pb::TerminalResize {
                cols: cols as u32,
                rows: rows as u32,
            })))
            .await
    }

    /// Fetch up to `max_lines` of history ending before `before` (0=newest).
    pub async fn history(&mut self, before: u64, max_lines: u32) -> Result<Vec<String>> {
        self.chan
            .send_env(plain(Msg::RequestHistory(pb::RequestHistory {
                before_line_id: before,
                maximum_lines: max_lines,
                maximum_bytes: 128 * 1024,
            })))
            .await?;
        self.chan
            .recv_until(|env| match &env.message {
                Some(Msg::HistoryChunk(c)) => Some(c.lines.clone()),
                _ => None,
            })
            .await
    }

    /// Next live event; errors indicate the transport died (resume upstream).
    pub async fn next_event(&mut self) -> Result<ShellEvent> {
        loop {
            let envelope = self.chan.recv_env().await?;
            match envelope.message {
                Some(Msg::TerminalOutput(out)) => return Ok(ShellEvent::Output(out.data)),
                Some(Msg::ShellExited(e)) => return Ok(ShellEvent::Exited(e.exit_code)),
                _ => continue,
            }
        }
    }

    /// Graceful detach: the shell keeps running server-side.
    pub async fn detach(mut self) -> Result<()> {
        self.chan
            .send_env(plain(Msg::DetachShell(pb::DetachShell {})))
            .await
    }
}
