//! Loopback-only OpenSSH compatibility adapter (ADR 0013).
//!
//! This crate terminates a deliberately small SSH server and translates one
//! interactive PTY shell channel into one Holdfast shell attachment. It is not
//! imported by `holdfastd` and does not implement exec, subsystems or forwarding.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::{fs::File, fs::Metadata, io::Read};

use anyhow::{bail, Context, Result};
use hf_auth::ssh::SshVerifier;
use hf_native_client::{connect_with, AuthMethod, ServerConn, ShellEvent};
use russh::server::{Auth, ChannelOpenHandle, Config as SshConfig, Handle, Msg, Session};
use russh::{Channel, ChannelId, Pty};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch, Semaphore};

#[cfg(unix)]
pub use hf_auth::pam;
pub use hf_auth::password::{PasswordVerifier, MAX_PASSWORD_BYTES};

pub const DEFAULT_LISTEN: &str = "127.0.0.1:2222";
pub const DEFAULT_MAX_CONNECTIONS: usize = 16;
pub const MAX_CONNECTIONS: usize = 256;
pub const MAX_AUTHORIZED_KEYS_BYTES: u64 = 256 * 1024;
pub const MAX_HOST_KEY_BYTES: u64 = 64 * 1024;
pub const SSH_PACKET_BYTES: u32 = 32 * 1024;
pub const SSH_WINDOW_BYTES: u32 = 512 * 1024;
pub const SSH_CHANNEL_MESSAGES: usize = 16;
pub const SSH_EVENT_MESSAGES: usize = 16;
pub const INPUT_MESSAGES: usize = 64;
pub const MAX_TERMINAL_DIMENSION: u32 = 4096;
pub const MAX_TERM_BYTES: usize = 64;
pub const MAX_LOCAL_USER_BYTES: usize = 128;
/// Constant time-to-rejection for every failed authentication attempt
/// (russh's `auth_rejection_time`), so password and public-key failures are
/// indistinguishable by timing and brute force pays it on each try.
pub const AUTH_REJECTION_DELAY: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TerminalSize {
    cols: u16,
    rows: u16,
}

/// Fully validated adapter configuration. Key material is supplied by the
/// caller so tests can generate it without creating production key files.
pub struct AdapterConfig {
    pub listen: SocketAddr,
    pub remote_url: String,
    pub remote_auth: AuthMethod,
    pub local_user: String,
    pub authorized_keys: Arc<SshVerifier>,
    /// Off (`None`) by default: public-key only, per ADR 0013. Set to enable
    /// SSH password authentication for `local_user` (ADR 0015).
    pub password_auth: Option<Arc<dyn PasswordVerifier>>,
    pub host_key: russh::keys::PrivateKey,
    pub max_connections: usize,
}

impl AdapterConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.listen.ip().is_loopback() {
            bail!("SSH compatibility listener must use a loopback address");
        }
        if self.remote_url.len() > 2048 || !self.remote_url.starts_with("http://") {
            bail!("remote URL must be a bounded http:// URL");
        }
        if self.local_user.is_empty() || self.local_user.len() > MAX_LOCAL_USER_BYTES {
            bail!("local username must be 1..={MAX_LOCAL_USER_BYTES} bytes");
        }
        if self.max_connections == 0 || self.max_connections > MAX_CONNECTIONS {
            bail!("max connections must be 1..={MAX_CONNECTIONS}");
        }
        Ok(())
    }
}

/// Read a bounded authorized_keys file. Option-bearing entries fail closed in
/// `SshVerifier`; see ADR 0013 and the verifier's documentation.
pub fn load_authorized_keys(path: &Path) -> Result<Arc<SshVerifier>> {
    let (_, bytes) = read_bounded(path, MAX_AUTHORIZED_KEYS_BYTES, "authorized_keys")?;
    let text = std::str::from_utf8(&bytes).context("authorized_keys is not UTF-8")?;
    Ok(Arc::new(
        SshVerifier::from_authorized_keys(text).context("no usable unrestricted authorized key")?,
    ))
}

/// Read a bounded, unencrypted OpenSSH host private key. On Unix, group/other
/// permission bits are rejected before key contents are read.
pub fn load_host_key(path: &Path) -> Result<russh::keys::PrivateKey> {
    let (file, metadata) = open_bounded(path, MAX_HOST_KEY_BYTES, "host key")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!(
                "host key {} must not be accessible by group or others",
                path.display()
            );
        }
    }
    let bytes = read_opened_bounded(file, &metadata, path, MAX_HOST_KEY_BYTES, "host key")?;
    let key = russh::keys::PrivateKey::from_openssh(&bytes)
        .with_context(|| format!("parse host key {}", path.display()))?;
    if key.is_encrypted() {
        bail!("encrypted SSH host keys are not supported");
    }
    Ok(key)
}

fn read_bounded(path: &Path, maximum: u64, kind: &str) -> Result<(Metadata, Vec<u8>)> {
    let (file, metadata) = open_bounded(path, maximum, kind)?;
    let bytes = read_opened_bounded(file, &metadata, path, maximum, kind)?;
    Ok((metadata, bytes))
}

fn open_bounded(path: &Path, maximum: u64, kind: &str) -> Result<(File, Metadata)> {
    let file = File::open(path).with_context(|| format!("open {kind} {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("stat {kind} {}", path.display()))?;
    if metadata.len() > maximum {
        bail!("{kind} exceeds {maximum} bytes");
    }
    Ok((file, metadata))
}

fn read_opened_bounded(
    file: File,
    metadata: &Metadata,
    path: &Path,
    maximum: u64,
    kind: &str,
) -> Result<Vec<u8>> {
    // `take(maximum + 1)` preserves the bound if the file grows after the
    // metadata check. The extra byte distinguishes exactly-full from oversized.
    let mut bytes = Vec::with_capacity(metadata.len().min(maximum) as usize);
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {kind} {}", path.display()))?;
    if bytes.len() as u64 > maximum {
        bail!("{kind} exceeds {maximum} bytes");
    }
    Ok(bytes)
}

/// Bind and serve until the task is cancelled.
pub async fn serve(config: AdapterConfig) -> Result<()> {
    config.validate()?;
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind SSH adapter {}", config.listen))?;
    serve_on(listener, config).await
}

/// Serve an already-bound listener. Binding separately makes the real OpenSSH
/// integration tests race-free while retaining the same validation.
pub async fn serve_on(listener: TcpListener, config: AdapterConfig) -> Result<()> {
    config.validate()?;
    let local = listener.local_addr().context("read SSH listener address")?;
    if !local.ip().is_loopback() {
        bail!("bound SSH compatibility listener is not loopback");
    }

    let mut methods = russh::MethodSet::empty();
    methods.push(russh::MethodKind::PublicKey);
    if config.password_auth.is_some() {
        methods.push(russh::MethodKind::Password);
    }
    let ssh_config = Arc::new(SshConfig {
        methods,
        auth_rejection_time: AUTH_REJECTION_DELAY,
        keys: vec![config.host_key.clone()],
        window_size: SSH_WINDOW_BYTES,
        maximum_packet_size: SSH_PACKET_BYTES,
        channel_buffer_size: SSH_CHANNEL_MESSAGES,
        event_buffer_size: SSH_EVENT_MESSAGES,
        max_auth_attempts: 3,
        inactivity_timeout: Some(Duration::from_secs(60 * 60)),
        keepalive_interval: Some(Duration::from_secs(30)),
        keepalive_max: 3,
        nodelay: true,
        ..SshConfig::default()
    });
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let shared = Arc::new(Shared {
        remote_url: config.remote_url,
        remote_auth: config.remote_auth,
        local_user: config.local_user,
        authorized_keys: config.authorized_keys,
        password_auth: config.password_auth,
    });

    loop {
        // Acquire before accept so the number of live TCP sockets and handler
        // tasks can never exceed the configured bound.
        let permit = permits
            .clone()
            .acquire_owned()
            .await
            .context("connection semaphore closed")?;
        let (stream, peer) = listener.accept().await.context("accept SSH connection")?;
        let handler = AdapterHandler::new(shared.clone());
        let ssh_config = ssh_config.clone();
        tokio::spawn(async move {
            let result = async {
                let running = russh::server::run_stream(ssh_config, stream, handler).await?;
                running.await
            }
            .await;
            if let Err(error) = result {
                tracing::debug!(%peer, %error, "SSH compatibility connection closed with error");
            }
            drop(permit);
        });
    }
}

struct Shared {
    remote_url: String,
    remote_auth: AuthMethod,
    local_user: String,
    authorized_keys: Arc<SshVerifier>,
    password_auth: Option<Arc<dyn PasswordVerifier>>,
}

struct ChannelState {
    id: ChannelId,
    size: TerminalSize,
    pty_accepted: bool,
    shell_started: bool,
    input: Option<mpsc::Sender<Vec<u8>>>,
    resize: Option<watch::Sender<TerminalSize>>,
    cancel: Option<watch::Sender<bool>>,
}

struct AdapterHandler {
    shared: Arc<Shared>,
    channel: Option<ChannelState>,
}

impl AdapterHandler {
    fn new(shared: Arc<Shared>) -> Self {
        Self {
            shared,
            channel: None,
        }
    }

    fn authorized(&self, user: &str, key: &russh::keys::ssh_key::PublicKey) -> bool {
        if user != self.shared.local_user {
            return false;
        }
        key.to_openssh()
            .ok()
            .and_then(|line| self.shared.authorized_keys.is_authorized(&line).ok())
            .is_some()
    }

    fn cancel_channel(&mut self, id: ChannelId) {
        if let Some(channel) = self.channel.as_mut().filter(|state| state.id == id) {
            if let Some(cancel) = channel.cancel.take() {
                let _ = cancel.send(true);
            }
            channel.input.take();
            channel.resize.take();
        }
    }
}

impl Drop for AdapterHandler {
    fn drop(&mut self) {
        if let Some(channel) = self.channel.as_mut() {
            if let Some(cancel) = channel.cancel.take() {
                let _ = cancel.send(true);
            }
        }
    }
}

impl russh::server::Handler for AdapterHandler {
    type Error = anyhow::Error;

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth> {
        Ok(if self.authorized(user, key) {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth> {
        Ok(if self.authorized(user, key) {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth> {
        // Bounds and the username check run before the verifier so an
        // attacker cannot spend PAM (or other backend) work with an oversized
        // password or a foreign username. russh's constant
        // `auth_rejection_time` masks which check failed.
        let verifier = self.shared.password_auth.clone().filter(|_| {
            user == self.shared.local_user
                && !password.is_empty()
                && password.len() <= MAX_PASSWORD_BYTES
        });
        let accepted = match verifier {
            Some(verifier) => {
                let user = user.to_owned();
                let password = password.to_owned();
                tokio::task::spawn_blocking(move || verifier.verify(&user, &password))
                    .await
                    .unwrap_or(false)
            }
            None => false,
        };
        Ok(if accepted {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<()> {
        if self.channel.is_some() {
            return Ok(()); // dropping reply rejects the second channel
        }
        self.channel = Some(ChannelState {
            id: channel.id(),
            size: TerminalSize { cols: 80, rows: 24 },
            pty_accepted: false,
            shell_started: false,
            input: None,
            resize: None,
            cancel: None,
        });
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        id: ChannelId,
        term: &str,
        cols: u32,
        rows: u32,
        _pixel_width: u32,
        _pixel_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<()> {
        let Some(channel) = self.channel.as_mut().filter(|state| state.id == id) else {
            session.channel_failure(id)?;
            return Ok(());
        };
        if channel.shell_started
            || term.len() > MAX_TERM_BYTES
            || cols > MAX_TERMINAL_DIMENSION
            || rows > MAX_TERMINAL_DIMENSION
        {
            session.channel_failure(id)?;
            return Ok(());
        }
        // OpenSSH reports zero dimensions when `-tt` forces a PTY while its
        // own stdin is a pipe. Use the documented terminal default rather
        // than creating a zero-sized remote PTY.
        channel.size = TerminalSize {
            cols: if cols == 0 { 80 } else { cols as u16 },
            rows: if rows == 0 { 24 } else { rows as u16 },
        };
        channel.pty_accepted = true;
        session.channel_success(id)?;
        Ok(())
    }

    async fn shell_request(&mut self, id: ChannelId, session: &mut Session) -> Result<()> {
        let Some(channel) = self.channel.as_mut().filter(|state| state.id == id) else {
            session.channel_failure(id)?;
            return Ok(());
        };
        if !channel.pty_accepted || channel.shell_started {
            session.channel_failure(id)?;
            return Ok(());
        }
        channel.shell_started = true;
        let size = channel.size;

        let opened = open_remote(&self.shared, size).await;
        let (connection, shell_id, attached) = match opened {
            Ok(opened) => opened,
            Err(error) => {
                tracing::warn!(%error, "failed to open Holdfast shell for SSH client");
                session.channel_failure(id)?;
                return Ok(());
            }
        };
        let snapshot = attached.snapshot.clone();
        let (input_tx, input_rx) = mpsc::channel(INPUT_MESSAGES);
        let (resize_tx, resize_rx) = watch::channel(size);
        let (cancel_tx, cancel_rx) = watch::channel(false);
        channel.input = Some(input_tx);
        channel.resize = Some(resize_tx);
        channel.cancel = Some(cancel_tx);

        let handle = session.handle();
        tokio::spawn(bridge_shell(
            connection, shell_id, attached, snapshot, input_rx, resize_rx, cancel_rx, handle, id,
        ));
        session.channel_success(id)?;
        Ok(())
    }

    async fn data(&mut self, id: ChannelId, data: &[u8], session: &mut Session) -> Result<()> {
        let Some(input) = self
            .channel
            .as_ref()
            .filter(|state| state.id == id && state.shell_started)
            .and_then(|state| state.input.clone())
        else {
            session.close(id)?;
            return Ok(());
        };
        if data.len() > SSH_PACKET_BYTES as usize || input.send(data.to_vec()).await.is_err() {
            session.close(id)?;
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        id: ChannelId,
        cols: u32,
        rows: u32,
        _pixel_width: u32,
        _pixel_height: u32,
        session: &mut Session,
    ) -> Result<()> {
        let valid = cols > 0
            && rows > 0
            && cols <= MAX_TERMINAL_DIMENSION
            && rows <= MAX_TERMINAL_DIMENSION;
        let Some(channel) = self
            .channel
            .as_mut()
            .filter(|state| state.id == id && valid)
        else {
            session.channel_failure(id)?;
            return Ok(());
        };
        let size = TerminalSize {
            cols: cols as u16,
            rows: rows as u16,
        };
        channel.size = size;
        if let Some(resize) = &channel.resize {
            let _ = resize.send(size); // watch coalesces rapid resize bursts to one bounded value
        }
        session.channel_success(id)?;
        Ok(())
    }

    async fn channel_close(&mut self, id: ChannelId, _session: &mut Session) -> Result<()> {
        self.cancel_channel(id);
        Ok(())
    }

    async fn channel_eof(&mut self, _id: ChannelId, _session: &mut Session) -> Result<()> {
        // EOF means the client will send no more stdin. It does not mean that
        // already-buffered PTY input and output should be discarded; an
        // OpenSSH client with piped stdin sends EOF immediately after `exit`.
        Ok(())
    }

    async fn exec_request(
        &mut self,
        id: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<()> {
        session.channel_failure(id)?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<()> {
        session.channel_failure(id)?;
        Ok(())
    }

    async fn env_request(
        &mut self,
        id: ChannelId,
        _name: &str,
        _value: &str,
        session: &mut Session,
    ) -> Result<()> {
        session.channel_failure(id)?;
        Ok(())
    }

    async fn x11_request(
        &mut self,
        id: ChannelId,
        _single: bool,
        _protocol: &str,
        _cookie: &str,
        _screen: u32,
        session: &mut Session,
    ) -> Result<()> {
        session.channel_failure(id)?;
        Ok(())
    }

    async fn agent_request(&mut self, id: ChannelId, session: &mut Session) -> Result<bool> {
        session.channel_failure(id)?;
        Ok(false)
    }
}

async fn open_remote(
    shared: &Shared,
    size: TerminalSize,
) -> Result<(ServerConn, Vec<u8>, hf_native_client::AttachedShell)> {
    let mut connection = connect_with(&shared.remote_url, shared.remote_auth.clone()).await?;
    let (shell_id, token) = connection
        .open_shell(None, size.cols, size.rows, rand_10::random())
        .await?;
    match connection
        .attach(&shell_id, &token, size.cols, size.rows)
        .await
    {
        Ok(attached) => Ok((connection, shell_id, attached)),
        Err(error) => {
            let _ = connection.terminate(&shell_id).await;
            Err(error.into())
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn bridge_shell(
    mut connection: ServerConn,
    shell_id: Vec<u8>,
    attached: hf_native_client::AttachedShell,
    snapshot: Vec<u8>,
    mut input: mpsc::Receiver<Vec<u8>>,
    mut resize: watch::Receiver<TerminalSize>,
    mut cancel: watch::Receiver<bool>,
    ssh: Handle,
    channel: ChannelId,
) {
    let (mut writer, mut reader) = attached.split();
    let mut clean_exit = false;
    if !snapshot.is_empty() && ssh.data(channel, snapshot).await.is_err() {
        let _ = connection.terminate(&shell_id).await;
        return;
    }

    loop {
        tokio::select! {
            biased;
            changed = cancel.changed() => {
                if changed.is_err() || *cancel.borrow() {
                    break;
                }
            }
            value = input.recv() => {
                match value {
                    Some(bytes) if writer.input(&bytes).await.is_ok() => {}
                    _ => break,
                }
            }
            changed = resize.changed() => {
                if changed.is_err() {
                    break;
                }
                let size = *resize.borrow_and_update();
                if writer.resize(size.cols, size.rows).await.is_err() {
                    break;
                }
            }
            event = reader.next_event() => {
                match event {
                    Ok(ShellEvent::Output(bytes)) => {
                        if ssh.data(channel, bytes).await.is_err() {
                            break;
                        }
                    }
                    Ok(ShellEvent::Exited(code)) => {
                        let status = if code < 0 { 255 } else { code as u32 };
                        let _ = ssh.exit_status_request(channel, status).await;
                        let _ = ssh.eof(channel).await;
                        let _ = ssh.close(channel).await;
                        clean_exit = true;
                        break;
                    }
                    Ok(ShellEvent::Ping(nonce)) => {
                        // Liveness probe (spec §14): answer through the write
                        // half or the daemon eventually detaches us.
                        if writer.pong(nonce).await.is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        tracing::debug!(%error, "Holdfast attachment ended");
                        break;
                    }
                }
            }
        }
    }

    if !clean_exit {
        let _ = tokio::time::timeout(Duration::from_secs(5), connection.terminate(&shell_id)).await;
        let _ = ssh.exit_status_request(channel, 255).await;
        let _ = ssh.eof(channel).await;
        let _ = ssh.close(channel).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "holdfast-adapter-{name}-{}-{}",
            std::process::id(),
            rand_10::random::<u64>()
        ))
    }

    #[test]
    fn rejects_non_loopback_and_unbounded_connection_counts() {
        let verifier = SshVerifier::from_authorized_keys(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICyA4HLtsYpDxEz/pbI5Ey0RZQxQ5qDlYTV5s++MFVJv",
        )
        .unwrap();
        let key = russh::keys::PrivateKey::random(
            &mut rand_10::rng(),
            russh::keys::ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let mut config = AdapterConfig {
            listen: "0.0.0.0:2222".parse().unwrap(),
            remote_url: "http://127.0.0.1:8080".into(),
            remote_auth: AuthMethod::Dev,
            local_user: "adapter".into(),
            authorized_keys: Arc::new(verifier),
            password_auth: None,
            host_key: key,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        };
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("loopback"));
        config.listen = DEFAULT_LISTEN.parse().unwrap();
        config.max_connections = 0;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("max connections"));
        config.max_connections = MAX_CONNECTIONS + 1;
        assert!(config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("max connections"));
    }

    #[test]
    fn bounds_are_finite_and_packet_queue_is_bounded() {
        assert!(SSH_PACKET_BYTES > 0);
        assert!(SSH_WINDOW_BYTES >= SSH_PACKET_BYTES);
        assert!(SSH_CHANNEL_MESSAGES > 0);
        assert!(SSH_EVENT_MESSAGES > 0);
        assert!(INPUT_MESSAGES > 0);
        assert!(MAX_AUTHORIZED_KEYS_BYTES < u64::MAX);
        assert!(MAX_HOST_KEY_BYTES < u64::MAX);
        assert!(MAX_PASSWORD_BYTES > 0 && MAX_PASSWORD_BYTES <= SSH_PACKET_BYTES as usize);
        assert!(AUTH_REJECTION_DELAY > Duration::ZERO);
    }

    #[test]
    fn authorized_keys_reader_enforces_its_byte_ceiling() {
        let path = temp_path("oversized-authorized-keys");
        std::fs::write(&path, vec![b'x'; MAX_AUTHORIZED_KEYS_BYTES as usize + 1]).unwrap();
        let error = match load_authorized_keys(&path) {
            Ok(_) => panic!("oversized authorized_keys unexpectedly loaded"),
            Err(error) => error,
        };
        let _ = std::fs::remove_file(path);
        assert!(error.to_string().contains("exceeds"));
    }

    #[cfg(unix)]
    #[test]
    fn host_key_loader_requires_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_path("host-key");
        let key = russh::keys::PrivateKey::random(
            &mut rand_10::rng(),
            russh::keys::ssh_key::Algorithm::Ed25519,
        )
        .unwrap();
        let pem = key
            .to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap();
        std::fs::write(&path, pem.as_bytes()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = match load_host_key(&path) {
            Ok(_) => panic!("publicly readable host key unexpectedly loaded"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("group or others"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        load_host_key(&path).unwrap();
        let _ = std::fs::remove_file(path);
    }
}
