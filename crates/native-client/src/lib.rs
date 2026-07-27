//! Native client library: WebTransport sessions against a holdfastd
//! (ADR 0005 — native clients share the browser's WebTransport endpoint).
//!
//! `connect` fetches `/webtransport-info` from the daemon's HTTP listener,
//! pins the certificate hash, establishes the QUIC session and performs
//! hello + authentication. Shell operations mirror the wire protocol; resume
//! tokens rotate on every attach and must be re-persisted by the caller
//! (see [`state`]).

pub mod state;

use std::io::Read;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use hf_protocol::framing::{encode_frame, FrameDecoder};
use hf_protocol::pb::{self, envelope::Message as Msg, Envelope};
use hf_protocol::{FRAME_BYTES_DEFAULT, PROTOCOL_MAJOR, PROTOCOL_MINOR};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wtransport::tls::Sha256Digest;
use wtransport::{ClientConfig, Endpoint, RecvStream, SendStream};
// Re-exported so drivers built on [`ServerConn::into_parts`]/[`attach_shell`]
// need no direct wtransport dependency.
pub use wtransport::Connection;

const T: Duration = Duration::from_secs(10);
const SSH_PRIVATE_KEY_MAX_BYTES: u64 = 64 * 1024;

pub fn plain(message: Msg) -> Envelope {
    Envelope {
        request_id: 0,
        server_id: vec![],
        shell_id: vec![],
        message: Some(message),
    }
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
        .ok_or_else(|| anyhow!("server URL must start with https:// or http:// (got {base})"))?
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
        bail!(
            "GET {path}: {}",
            head.lines().next().unwrap_or("unknown status")
        );
    }
    Ok(body.to_string())
}

pub struct ServerConn {
    pub connection: Connection,
    pub control: Chan,
    /// Grant handed back by the daemon on successful auth; persist and reuse
    /// for later reconnects (spec §5). Empty in dev mode.
    pub grant: Vec<u8>,
    /// The negotiated `ServerHello` (frame bounds, capabilities, keepalive).
    pub hello: pb::ServerHello,
    next_request: u64,
}

/// Structured attach failure. Retry policy depends on telling a server
/// rejection — and its exact code — apart from transport loss: forgetting a
/// resume token on a transient error permanently orphans the shell.
#[derive(Debug, thiserror::Error)]
pub enum AttachError {
    /// The transport (stream open, send, receive, timeout) failed; the token
    /// was never judged. Always safe to retry with the same token.
    #[error("transport: {0}")]
    Transport(#[source] anyhow::Error),
    /// The server answered with an `Error` message.
    #[error("attach rejected ({code:?}): {message}")]
    Rejected {
        code: pb::ErrorCode,
        retryable: bool,
        message: String,
    },
}

/// How to authenticate to the daemon (spec §5).
#[derive(Clone)]
pub enum AuthMethod {
    /// Dev mode: present an empty connection grant (loopback daemons only).
    Dev,
    /// Present a previously issued connection grant.
    Grant(Vec<u8>),
    /// SSH public-key challenge/response with an OpenSSH private key file.
    SshKey {
        username: String,
        private_key_path: std::path::PathBuf,
    },
    /// Opt-in password login (ADR 0016): one round trip, only ever sent over
    /// the encrypted transport, never persisted by any client.
    Password { username: String, password: String },
}

/// Connect, negotiate and authenticate (dev grant) against a daemon.
pub async fn connect(http_base: &str) -> Result<ServerConn> {
    connect_with(http_base, AuthMethod::Dev).await
}

/// Connect and authenticate with an explicit method.
///
/// Two URL forms (ADR 0014):
/// - `http://host:port` — development bootstrap: fetch `/webtransport-info`
///   from the daemon's TCP listener and pin the self-signed certificate hash.
/// - `https://host[:port]` — production: connect WebTransport directly to the
///   HTTP/3 endpoint (default port 443) and validate the certificate through
///   WebPKI, exactly like a browser. No bootstrap request is needed.
pub async fn connect_with(http_base: &str, auth: AuthMethod) -> Result<ServerConn> {
    let (connection, hash) = if let Some(rest) = http_base.strip_prefix("https://") {
        let rest = rest.trim_end_matches('/');
        let url = match rest.rsplit_once(':') {
            Some((_, port)) if port.chars().all(|c| c.is_ascii_digit()) => {
                format!("https://{rest}/")
            }
            _ => format!("https://{rest}:443/"),
        };
        let endpoint = Endpoint::client(
            ClientConfig::builder()
                .with_bind_default()
                .with_native_certs()
                .build(),
        )?;
        let connection = endpoint
            .connect(&url)
            .await
            .context("webtransport connect")?;
        // Channel binding (ADR 0008): hash of the leaf certificate WebPKI
        // validation just authenticated.
        let digest = connection
            .peer_identity()
            .and_then(|chain| chain.as_slice().first().map(|c| c.hash()))
            .ok_or_else(|| anyhow!("server presented no certificate"))?;
        (connection, *digest.as_ref())
    } else {
        let info: serde_json::Value =
            serde_json::from_str(&http_get(http_base, "/webtransport-info").await?)
                .context("parse /webtransport-info")?;
        let port = info["port"]
            .as_u64()
            .ok_or_else(|| anyhow!("info missing port"))? as u16;
        let hash_b64 = info["certHashBase64"]
            .as_str()
            .ok_or_else(|| anyhow!("info missing certHashBase64"))?;
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
        (connection, hash)
    };

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
    let hello = control
        .recv_until(|env| match &env.message {
            Some(Msg::ServerHello(h)) => Some(h.clone()),
            _ => None,
        })
        .await?;

    // SSH-auth channel binding (ADR 0008): the certificate hash we pinned above.
    // Mixed into the signed challenge so a relay forwarding to a different
    // server — whose certificate differs — cannot reuse our signature.
    let grant = authenticate(&mut control, auth, &hash).await?;
    Ok(ServerConn {
        connection,
        control,
        grant,
        hello,
        next_request: 1,
    })
}

/// Run the authentication exchange; returns the grant the daemon issues
/// (empty in dev mode). `channel_binding` is the pinned server certificate hash
/// (ADR 0008), folded into the SSH challenge signature.
async fn authenticate(
    control: &mut Chan,
    auth: AuthMethod,
    channel_binding: &[u8],
) -> Result<Vec<u8>> {
    match auth {
        AuthMethod::Dev => {
            let result =
                send_auth(control, pb::authenticate::Method::ConnectionGrant(vec![])).await?;
            ensure_ok(&result)?;
            Ok(result.challenge) // empty in dev
        }
        AuthMethod::Grant(grant) => {
            let result = send_auth(
                control,
                pb::authenticate::Method::ConnectionGrant(grant.clone()),
            )
            .await?;
            ensure_ok(&result)?;
            Ok(if result.challenge.is_empty() {
                grant
            } else {
                result.challenge
            })
        }
        AuthMethod::SshKey {
            username,
            private_key_path,
        } => {
            let key = read_private_key(&private_key_path)?;
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

            // Step 4–5: sign the channel-bound challenge and prove possession.
            let message =
                hf_auth::ssh::channel_bound_message(channel_binding, &challenge_result.challenge);
            let sig = key
                .sign(hf_auth::SSH_NAMESPACE, ssh_key::HashAlg::Sha512, &message)
                .context("sign challenge")?;
            let pem = sig
                .to_pem(ssh_key::LineEnding::LF)
                .context("encode signature")?;
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
        AuthMethod::Password { username, password } => {
            let result = send_auth(
                control,
                pb::authenticate::Method::PasswordRequest(pb::PasswordRequest {
                    username,
                    password,
                }),
            )
            .await?;
            ensure_ok(&result)?;
            if result.challenge.is_empty() {
                bail!("authentication succeeded but no grant was issued");
            }
            Ok(result.challenge) // the issued grant
        }
    }
}

fn read_private_key(path: &std::path::Path) -> Result<ssh_key::PrivateKey> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("open private key {}", path.display()))?;
    let metadata = file.metadata()?;
    if metadata.len() > SSH_PRIVATE_KEY_MAX_BYTES {
        bail!("private key exceeds {SSH_PRIVATE_KEY_MAX_BYTES} bytes");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(SSH_PRIVATE_KEY_MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > SSH_PRIVATE_KEY_MAX_BYTES {
        bail!("private key exceeds {SSH_PRIVATE_KEY_MAX_BYTES} bytes");
    }
    ssh_key::PrivateKey::from_openssh(&bytes)
        .with_context(|| format!("parse private key {}", path.display()))
}

async fn send_auth(
    control: &mut Chan,
    method: pb::authenticate::Method,
) -> Result<pb::AuthenticationResult> {
    control
        .send_env(plain(Msg::Authenticate(pb::Authenticate {
            method: Some(method),
        })))
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
    ) -> Result<AttachedShell, AttachError> {
        attach_shell(&self.connection, shell_id, token, cols, rows).await
    }

    /// Negotiated keepalive interval, if the server advertised one (spec §14).
    pub fn keepalive_interval(&self) -> Option<Duration> {
        (self.hello.keepalive_interval_ms > 0)
            .then(|| Duration::from_millis(self.hello.keepalive_interval_ms as u64))
    }

    /// Decompose into raw parts so a driver (e.g. the desktop client's
    /// control-channel actor) can own the control channel while keeping the
    /// connection for further [`attach_shell`] stream opens.
    pub fn into_parts(self) -> (Connection, Chan, Vec<u8>, pb::ServerHello) {
        (self.connection, self.control, self.grant, self.hello)
    }
}

/// What to do when an attach fails (ADR 0018). Kept pure for unit testing:
/// the one thing a client must never get wrong is forgetting a resume token —
/// the only credential for the shell — on a *transient* failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureAction {
    /// Transient (transport, server backpressure): retry with the same token.
    Retry,
    /// Token definitively superseded, but the stored idempotency key can
    /// recover the same shell with a fresh token (spec §9).
    RecoverViaIdempotency,
    /// The shell is gone (or unrecoverable): drop the stored entry.
    ForgetAndExit,
    /// Rejected for a reason unrelated to the token (auth, permissions):
    /// give up for now, but the token stays valid and stored.
    ExitKeepToken,
}

/// The retry policy every client shares (ADR 0018).
pub fn attach_failure_action(error: &AttachError, have_idempotency_key: bool) -> FailureAction {
    use pb::ErrorCode;
    match error {
        AttachError::Transport(_) => FailureAction::Retry,
        AttachError::Rejected {
            code, retryable, ..
        } => match code {
            ErrorCode::ErrTokenExpired | ErrorCode::ErrTokenReplayed => {
                if have_idempotency_key {
                    FailureAction::RecoverViaIdempotency
                } else {
                    FailureAction::ForgetAndExit
                }
            }
            ErrorCode::ErrNotFound => FailureAction::ForgetAndExit,
            _ if *retryable => FailureAction::Retry,
            _ => FailureAction::ExitKeepToken,
        },
    }
}

/// Attach on an existing authenticated connection (each attachment is its own
/// bidi stream, spec §2). Free function so callers holding only the
/// [`Connection`] half from [`ServerConn::into_parts`] can attach too.
pub async fn attach_shell(
    connection: &Connection,
    shell_id: &[u8],
    token: &[u8],
    cols: u16,
    rows: u16,
) -> Result<AttachedShell, AttachError> {
    let mut chan = Chan::open(connection).await.map_err(AttachError::Transport)?;
    let mut env = plain(Msg::AttachShell(pb::AttachShell {
        resume_token: token.to_vec(),
        cols: cols as u32,
        rows: rows as u32,
        last_seen_revision: 0,
        last_history_line_id: 0,
    }));
    env.shell_id = shell_id.to_vec();
    chan.send_env(env).await.map_err(AttachError::Transport)?;
    let outcome = chan
        .recv_until(|env| match &env.message {
            Some(Msg::ShellAttached(a)) => Some(Ok(a.clone())),
            Some(Msg::Error(e)) => Some(Err((e.code, e.retryable, e.human_message.clone()))),
            _ => None,
        })
        .await
        .map_err(AttachError::Transport)?;
    let attached = match outcome {
        Ok(a) => a,
        Err((code, retryable, message)) => {
            return Err(AttachError::Rejected {
                // Unknown codes (newer server) collapse to ERR_INTERNAL but
                // keep the server's retryable hint and message.
                code: pb::ErrorCode::try_from(code).unwrap_or(pb::ErrorCode::ErrInternal),
                retryable,
                message,
            })
        }
    };
    Ok(AttachedShell {
        chan,
        shell_id: shell_id.to_vec(),
        snapshot: attached.screen_snapshot,
        rotated_token: attached.rotated_resume_token,
        oldest_history_line_id: attached.oldest_history_line_id,
        newest_history_line_id: attached.newest_history_line_id,
    })
}

#[derive(Debug)]
pub enum ShellEvent {
    Output(Vec<u8>),
    Exited(i32),
    /// Server liveness probe on this channel (spec §14): answer with
    /// [`AttachedShell::pong`] / [`AttachmentWriter::pong`], or the server
    /// counts a miss and eventually detaches this attachment.
    Ping(u64),
}

pub struct AttachedShell {
    chan: Chan,
    pub shell_id: Vec<u8>,
    pub snapshot: Vec<u8>,
    pub rotated_token: Vec<u8>,
    pub oldest_history_line_id: u64,
    pub newest_history_line_id: u64,
}

/// Write half of an attachment, used by adapters that must receive terminal
/// output while independently forwarding local input. Both halves retain the
/// same bounded protocol framing as [`AttachedShell`].
pub struct AttachmentWriter {
    send: SendStream,
}

/// Read half of an attachment.
pub struct AttachmentReader {
    recv: RecvStream,
    decoder: FrameDecoder,
    buf: Vec<u8>,
}

impl AttachedShell {
    pub fn split(self) -> (AttachmentWriter, AttachmentReader) {
        let Chan {
            send,
            recv,
            decoder,
            buf,
        } = self.chan;
        (
            AttachmentWriter { send },
            AttachmentReader { recv, decoder, buf },
        )
    }

    pub async fn input(&mut self, data: &[u8]) -> Result<()> {
        self.chan
            .send_env(plain(Msg::TerminalInput(pb::TerminalInput {
                data: data.to_vec(),
            })))
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
                Some(Msg::Ping(p)) => return Ok(ShellEvent::Ping(p.nonce)),
                _ => continue,
            }
        }
    }

    /// Answer a server [`ShellEvent::Ping`] on this attachment channel.
    pub async fn pong(&mut self, nonce: u64) -> Result<()> {
        self.chan
            .send_env(plain(Msg::Pong(pb::Pong { nonce })))
            .await
    }

    /// Graceful detach: the shell keeps running server-side.
    pub async fn detach(mut self) -> Result<()> {
        self.chan
            .send_env(plain(Msg::DetachShell(pb::DetachShell {})))
            .await
    }
}

impl AttachmentWriter {
    async fn send_env(&mut self, envelope: Envelope) -> Result<()> {
        let bytes = encode_frame(&envelope, FRAME_BYTES_DEFAULT)?;
        self.send.write_all(&bytes).await?;
        Ok(())
    }

    pub async fn input(&mut self, data: &[u8]) -> Result<()> {
        self.send_env(plain(Msg::TerminalInput(pb::TerminalInput {
            data: data.to_vec(),
        })))
        .await
    }

    pub async fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        self.send_env(plain(Msg::TerminalResize(pb::TerminalResize {
            cols: cols as u32,
            rows: rows as u32,
        })))
        .await
    }

    /// Answer a server [`ShellEvent::Ping`] surfaced by the paired reader.
    pub async fn pong(&mut self, nonce: u64) -> Result<()> {
        self.send_env(plain(Msg::Pong(pb::Pong { nonce }))).await
    }

    /// Request scrollback (spec §10); the `HistoryChunk`/`HistoryEnd` replies
    /// arrive on the paired [`AttachmentReader`]'s envelope stream.
    pub async fn request_history(&mut self, before_line_id: u64, maximum_lines: u32) -> Result<()> {
        self.send_env(plain(Msg::RequestHistory(pb::RequestHistory {
            before_line_id,
            maximum_lines,
            maximum_bytes: 128 * 1024,
        })))
        .await
    }

    pub async fn detach(mut self) -> Result<()> {
        self.send_env(plain(Msg::DetachShell(pb::DetachShell {})))
            .await
    }
}

impl AttachmentReader {
    /// Next raw envelope. Most callers want [`next_event`](Self::next_event);
    /// drivers that also consume `HistoryChunk`/`HistoryEnd` (the desktop
    /// client's pump) need the unfiltered stream.
    pub async fn next_envelope(&mut self) -> Result<Envelope> {
        self.recv_env().await
    }

    async fn recv_env(&mut self) -> Result<Envelope> {
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

    pub async fn next_event(&mut self) -> Result<ShellEvent> {
        loop {
            let envelope = self.recv_env().await?;
            match envelope.message {
                Some(Msg::TerminalOutput(out)) => return Ok(ShellEvent::Output(out.data)),
                Some(Msg::ShellExited(e)) => return Ok(ShellEvent::Exited(e.exit_code)),
                Some(Msg::Ping(p)) => return Ok(ShellEvent::Ping(p.nonce)),
                _ => continue,
            }
        }
    }
}
