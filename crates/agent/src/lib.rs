//! Outbound managed-server registration for the optional administration overlay.
//!
//! Standalone daemon builds do not depend on this crate. Feature-gated agent
//! mode composes the outbound link with the same local shell core while keeping
//! shell ownership independent from every temporary gateway connection.

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use hf_auth::{ConnectionGrant, GrantError, GrantVerifier};
use hf_protocol::{
    framing::{checked_payload_len, decode_agent_payload, encode_agent_frame, FrameError},
    ids::ServerId,
    pb::{
        agent_envelope, AgentEnvelope, AgentPing, AgentPong, AgentRegister, AgentRegistration,
        AgentShellAttached, AgentShellOpened, Error as ProtocolError, ErrorCode, HistoryChunk,
        HistoryEnd, ShellExited, TerminalOutput,
    },
    AGENT_ALPN, AGENT_ATTACHMENT_FRAME_BYTES_MAX, AGENT_ATTACHMENT_OUTPUT_QUEUE_MESSAGES,
    AGENT_ATTACHMENT_STREAMS_MAX, AGENT_AUDIENCE_BYTES_MAX, AGENT_BUILD_BYTES_MAX,
    AGENT_COMMAND_BYTES_MAX, AGENT_CONNECTION_FLOW_WINDOW_BYTES, AGENT_CONTROL_FRAME_BYTES_MAX,
    AGENT_CONTROL_FRAME_BYTES_MIN, AGENT_GRANT_BYTES_MAX, AGENT_HISTORY_LINES_MAX,
    AGENT_TERMINAL_INPUT_BYTES_MAX, AGENT_TERMINAL_OUTPUT_BYTES_MAX, AGENT_UNIX_ACCOUNT_BYTES_MAX,
    AGENT_USER_ID_BYTES_MAX, PROTOCOL_MAJOR, PROTOCOL_MINOR,
};
use hf_session_core::{AttachmentEvent, OpenShellRequest, SessionError, ShellManager};
use quinn::{
    crypto::rustls::QuicClientConfig, ClientConfig, Connection, Endpoint, RecvStream, SendStream,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub type AgentClientConfig = ClientConfig;

/// Immutable identity and metadata sent on every reconnect.
#[derive(Clone, Debug)]
pub struct RegistrationRequest {
    server_id: ServerId,
    agent_build: String,
    max_frame_bytes: u32,
}

impl RegistrationRequest {
    pub fn new(server_id: ServerId, agent_build: impl Into<String>) -> Result<Self, AgentError> {
        let agent_build = agent_build.into();
        if agent_build.len() > AGENT_BUILD_BYTES_MAX {
            return Err(AgentError::BuildTooLong(agent_build.len()));
        }
        Ok(Self {
            server_id,
            agent_build,
            max_frame_bytes: AGENT_CONTROL_FRAME_BYTES_MAX,
        })
    }
}

/// Reusable outbound endpoint. Reusing it permits reconnect without changing
/// any local shell owner or shell state.
pub struct AgentConnector {
    endpoint: Endpoint,
    client_config: ClientConfig,
    gateway_addr: SocketAddr,
    gateway_name: String,
    request: RegistrationRequest,
}

#[derive(Debug, Clone, Copy)]
pub struct ReconnectPolicy {
    pub initial_delay: Duration,
    pub maximum_delay: Duration,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(250),
            maximum_delay: Duration::from_secs(10),
        }
    }
}

impl ReconnectPolicy {
    fn validate(self) -> Result<Self, AgentError> {
        if self.initial_delay.is_zero()
            || self.maximum_delay.is_zero()
            || self.initial_delay > self.maximum_delay
        {
            return Err(AgentError::InvalidReconnectPolicy);
        }
        Ok(self)
    }
}

#[derive(Default)]
struct SupervisorState {
    connected: AtomicBool,
    registrations: AtomicU64,
}

#[derive(Clone, Default)]
pub struct AgentStatus {
    state: Arc<SupervisorState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentStatusSnapshot {
    pub connected: bool,
    pub registrations: u64,
}

impl AgentStatus {
    pub fn snapshot(&self) -> AgentStatusSnapshot {
        AgentStatusSnapshot {
            connected: self.state.connected.load(Ordering::Acquire),
            registrations: self.state.registrations.load(Ordering::Acquire),
        }
    }
}

/// Owns only the temporary gateway link. The shell manager is shared and
/// deliberately outlives every connect/serve iteration.
pub struct AgentSupervisor {
    connector: AgentConnector,
    manager: Arc<ShellManager>,
    policy: ReconnectPolicy,
    grant_verifier: GrantVerifier,
    grant_audience: String,
    status: AgentStatus,
}

impl AgentSupervisor {
    pub fn new(
        connector: AgentConnector,
        manager: Arc<ShellManager>,
        policy: ReconnectPolicy,
        grant_verifier: GrantVerifier,
        grant_audience: impl Into<String>,
    ) -> Result<Self, AgentError> {
        let grant_audience = grant_audience.into();
        if grant_audience.is_empty() || grant_audience.len() > AGENT_AUDIENCE_BYTES_MAX {
            return Err(AgentError::InvalidGrantAudience);
        }
        Ok(Self {
            connector,
            manager,
            policy: policy.validate()?,
            grant_verifier,
            grant_audience,
            status: AgentStatus::default(),
        })
    }

    pub fn status(&self) -> AgentStatus {
        self.status.clone()
    }

    /// Reconnect forever until the containing task is cancelled. A successful
    /// registration resets exponential backoff; link failure never touches
    /// local shells or scrollback.
    pub async fn run(self) {
        let mut delay = self.policy.initial_delay;
        loop {
            match self.connector.connect().await {
                Ok(mut link) => {
                    self.status.state.connected.store(true, Ordering::Release);
                    self.status
                        .state
                        .registrations
                        .fetch_add(1, Ordering::AcqRel);
                    tracing::info!(server_id = %link.server_id(), "agent registered with gateway");
                    delay = self.policy.initial_delay;
                    let _ = link
                        .serve(
                            Arc::clone(&self.manager),
                            self.grant_verifier.clone(),
                            self.grant_audience.clone(),
                        )
                        .await;
                    self.status.state.connected.store(false, Ordering::Release);
                    tracing::warn!("agent gateway link lost; reconnecting");
                }
                Err(_) => {
                    self.status.state.connected.store(false, Ordering::Release);
                    tracing::warn!("agent gateway registration failed; reconnecting");
                }
            }
            tokio::time::sleep(delay).await;
            delay = delay.saturating_mul(2).min(self.policy.maximum_delay);
        }
    }
}

impl AgentConnector {
    pub fn bind(
        bind_addr: SocketAddr,
        gateway_addr: SocketAddr,
        gateway_name: impl Into<String>,
        client_config: ClientConfig,
        request: RegistrationRequest,
    ) -> Result<Self, AgentError> {
        Ok(Self {
            endpoint: Endpoint::client(bind_addr)?,
            client_config,
            gateway_addr,
            gateway_name: gateway_name.into(),
            request,
        })
    }

    /// Establish mTLS, register the certificate-bound server identity, and
    /// retain the control stream for later keepalive/routing work.
    pub async fn connect(&self) -> Result<RegisteredLink, AgentError> {
        let connection = self
            .endpoint
            .connect_with(
                self.client_config.clone(),
                self.gateway_addr,
                &self.gateway_name,
            )?
            .await?;
        let (mut send, mut recv) = connection.open_bi().await?;
        let request = AgentEnvelope {
            request_id: 0,
            server_id: self.request.server_id.to_wire(),
            shell_id: Vec::new(),
            message: Some(agent_envelope::Message::AgentRegister(AgentRegister {
                protocol_major: PROTOCOL_MAJOR,
                protocol_minor: PROTOCOL_MINOR,
                server_id: self.request.server_id.to_wire(),
                agent_build: self.request.agent_build.clone(),
                max_frame_bytes: self.request.max_frame_bytes,
            })),
        };
        write_envelope(&mut send, &request, AGENT_CONTROL_FRAME_BYTES_MAX).await?;

        let response = read_envelope(&mut recv, AGENT_CONTROL_FRAME_BYTES_MAX).await?;
        let Some(agent_envelope::Message::AgentRegistration(registration)) = response.message
        else {
            connection.close(1u32.into(), b"invalid registration response");
            return Err(AgentError::UnexpectedResponse);
        };
        validate_registration(self.request.server_id, &response.server_id, &registration)?;

        Ok(RegisteredLink {
            connection,
            send,
            recv,
            server_id: self.request.server_id,
            max_frame_bytes: registration.max_frame_bytes,
            keepalive_interval_ms: registration.keepalive_interval_ms,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.endpoint.local_addr()
    }
}

/// Live, authenticated agent control link. Dropping it does not own or end any
/// local shell; it only drops this temporary gateway connection.
pub struct RegisteredLink {
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
    server_id: ServerId,
    max_frame_bytes: u32,
    keepalive_interval_ms: u32,
}

impl RegisteredLink {
    pub fn server_id(&self) -> ServerId {
        self.server_id
    }

    pub fn max_frame_bytes(&self) -> u32 {
        self.max_frame_bytes
    }

    pub fn keepalive_interval_ms(&self) -> u32 {
        self.keepalive_interval_ms
    }

    /// Send one bounded application-level keepalive and require the matching
    /// nonce. The eventual supervisor schedules this at the negotiated interval.
    pub async fn ping(&mut self, nonce: u64) -> Result<(), AgentError> {
        let request = AgentEnvelope {
            request_id: 0,
            server_id: self.server_id.to_wire(),
            shell_id: Vec::new(),
            message: Some(agent_envelope::Message::AgentPing(AgentPing { nonce })),
        };
        write_envelope(&mut self.send, &request, self.max_frame_bytes).await?;
        let response = read_envelope(&mut self.recv, self.max_frame_bytes).await?;
        if matches!(
            response.message,
            Some(agent_envelope::Message::AgentPong(ref pong)) if pong.nonce == nonce
        ) {
            Ok(())
        } else {
            Err(AgentError::UnexpectedResponse)
        }
    }

    /// Serve the control stream and all gateway-opened attachment streams
    /// concurrently. The QUIC transport caps attachment streams at 64; the
    /// local manager applies the tighter per-shell attachment limit.
    pub async fn serve(
        &mut self,
        manager: Arc<ShellManager>,
        grant_verifier: GrantVerifier,
        grant_audience: String,
    ) -> Result<(), AgentError> {
        let connection = self.connection.clone();
        let mut attachments = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                control = self.serve_next(&manager, &grant_verifier, &grant_audience) => {
                    control?;
                }
                incoming = connection.accept_bi(),
                    if attachments.len() < AGENT_ATTACHMENT_STREAMS_MAX as usize => {
                    let (send, recv) = incoming?;
                    let manager = Arc::clone(&manager);
                    let verifier = grant_verifier.clone();
                    let audience = grant_audience.clone();
                    let server_id = self.server_id;
                    attachments.spawn(async move {
                        if serve_attachment(
                            send,
                            recv,
                            server_id,
                            manager,
                            verifier,
                            audience,
                        )
                        .await
                        .is_err()
                        {
                            tracing::warn!(server_id = %server_id, "agent attachment stream closed with error");
                        }
                    });
                }
                completed = attachments.join_next(), if !attachments.is_empty() => {
                    if completed.is_some_and(|result| result.is_err()) {
                        tracing::warn!(server_id = %self.server_id, "agent attachment task failed");
                    }
                }
            }
        }
    }

    /// Process one gateway control operation. Shell creation always flows
    /// through the supplied local manager, so its AccessPolicy, launcher and
    /// resource limits remain authoritative regardless of gateway behavior.
    pub async fn serve_next(
        &mut self,
        manager: &ShellManager,
        grant_verifier: &GrantVerifier,
        grant_audience: &str,
    ) -> Result<AgentAction, AgentError> {
        let request = read_envelope(&mut self.recv, self.max_frame_bytes).await?;
        let scoped_server = ServerId::from_wire(&request.server_id)
            .map_err(|_| AgentError::ServerIdentityMismatch)?;
        if scoped_server != self.server_id {
            let _ = self
                .send_protocol_error(
                    request.request_id,
                    ErrorCode::ErrForbidden,
                    "server identity mismatch",
                    false,
                )
                .await;
            return Err(AgentError::ServerIdentityMismatch);
        }

        match request.message {
            Some(agent_envelope::Message::AgentPing(ping)) => {
                let response = AgentEnvelope {
                    request_id: request.request_id,
                    server_id: self.server_id.to_wire(),
                    shell_id: Vec::new(),
                    message: Some(agent_envelope::Message::AgentPong(AgentPong {
                        nonce: ping.nonce,
                    })),
                };
                write_envelope(&mut self.send, &response, self.max_frame_bytes).await?;
                Ok(AgentAction::Ping(ping.nonce))
            }
            Some(agent_envelope::Message::AgentOpenShell(open)) => {
                let local_request = match validate_open_request(
                    open,
                    grant_verifier,
                    grant_audience,
                    self.server_id,
                ) {
                    Ok(request) => request,
                    Err(error) => {
                        let (code, message) = map_open_validation_error(error);
                        self.send_protocol_error(request.request_id, code, message, false)
                            .await?;
                        return Ok(AgentAction::ShellRejected { code });
                    }
                };
                match manager.open_shell(&local_request) {
                    Ok(opened) => {
                        let response = AgentEnvelope {
                            request_id: request.request_id,
                            server_id: self.server_id.to_wire(),
                            shell_id: Vec::new(),
                            message: Some(agent_envelope::Message::AgentShellOpened(
                                AgentShellOpened {
                                    shell_id: opened.shell_id.to_wire(),
                                    reused: opened.reused,
                                },
                            )),
                        };
                        write_envelope(&mut self.send, &response, self.max_frame_bytes).await?;
                        Ok(AgentAction::ShellOpened {
                            shell_id: opened.shell_id,
                            reused: opened.reused,
                        })
                    }
                    Err(error) => {
                        let (code, message, retryable) = map_session_error(&error);
                        self.send_protocol_error(request.request_id, code, message, retryable)
                            .await?;
                        Ok(AgentAction::ShellRejected { code })
                    }
                }
            }
            _ => {
                self.send_protocol_error(
                    request.request_id,
                    ErrorCode::ErrUnknownMessage,
                    "unexpected agent control message",
                    false,
                )
                .await?;
                Ok(AgentAction::UnknownRejected)
            }
        }
    }

    async fn send_protocol_error(
        &mut self,
        request_id: u64,
        code: ErrorCode,
        message: &'static str,
        retryable: bool,
    ) -> Result<(), AgentError> {
        let response = AgentEnvelope {
            request_id,
            server_id: self.server_id.to_wire(),
            shell_id: Vec::new(),
            message: Some(agent_envelope::Message::AgentError(ProtocolError {
                code: code as i32,
                human_message: message.to_owned(),
                retryable,
            })),
        };
        write_envelope(&mut self.send, &response, self.max_frame_bytes).await
    }

    pub fn close(&self) {
        self.connection.close(0u32.into(), b"agent link closed");
    }
}

struct AttachmentLease {
    manager: Arc<ShellManager>,
    shell_id: hf_protocol::ids::ShellId,
    attachment_id: u64,
}

impl Drop for AttachmentLease {
    fn drop(&mut self) {
        let _ = self.manager.detach(&self.shell_id, self.attachment_id);
    }
}

async fn serve_attachment(
    mut send: SendStream,
    mut recv: RecvStream,
    server_id: ServerId,
    manager: Arc<ShellManager>,
    verifier: GrantVerifier,
    audience: String,
) -> Result<(), AgentError> {
    let first = read_envelope(&mut recv, AGENT_ATTACHMENT_FRAME_BYTES_MAX).await?;
    let shell_id = validate_attachment_scope(&first, server_id)?;
    let Some(agent_envelope::Message::AgentAttachShell(request)) = first.message else {
        send_attachment_error(
            &mut send,
            server_id,
            shell_id,
            first.request_id,
            ErrorCode::ErrUnknownMessage,
            "attachment stream must begin with attach",
            false,
        )
        .await?;
        return Err(AgentError::UnexpectedAttachmentMessage);
    };
    let authorization = match validate_attach_request(request, &verifier, &audience, server_id) {
        Ok(authorization) => authorization,
        Err(error) => {
            let (code, message) = map_open_validation_error(error);
            send_attachment_error(
                &mut send,
                server_id,
                shell_id,
                first.request_id,
                code,
                message,
                false,
            )
            .await?;
            return Ok(());
        }
    };

    let attachment = match manager.attach_authorized(
        &authorization.user_id,
        &shell_id,
        authorization.cols,
        authorization.rows,
    ) {
        Ok(attachment) => attachment,
        Err(error) => {
            let (code, message, retryable) = map_attachment_session_error(&error);
            send_attachment_error(
                &mut send,
                server_id,
                shell_id,
                first.request_id,
                code,
                message,
                retryable,
            )
            .await?;
            return Ok(());
        }
    };

    let _lease = AttachmentLease {
        manager: Arc::clone(&manager),
        shell_id,
        attachment_id: attachment.attachment_id,
    };
    let attached = AgentEnvelope {
        request_id: first.request_id,
        server_id: server_id.to_wire(),
        shell_id: shell_id.to_wire(),
        message: Some(agent_envelope::Message::AgentShellAttached(
            AgentShellAttached {
                screen_snapshot: attachment.snapshot.clone(),
                screen_revision: attachment.screen_revision,
                oldest_history_line_id: attachment.oldest_history_line_id,
                newest_history_line_id: attachment.newest_history_line_id,
            },
        )),
    };
    write_envelope(&mut send, &attached, AGENT_ATTACHMENT_FRAME_BYTES_MAX).await?;
    let (event_tx, mut event_rx) =
        tokio::sync::mpsc::channel(AGENT_ATTACHMENT_OUTPUT_QUEUE_MESSAGES);
    std::thread::Builder::new()
        .name("hf-agent-attach-output".into())
        .spawn(move || {
            for event in attachment.events.iter() {
                if event_tx.blocking_send(event).is_err() {
                    break;
                }
            }
        })
        .map_err(AgentError::AttachmentForwarder)?;

    let remaining_ms = authorization.expires_at_ms.saturating_sub(unix_time_ms());
    let expiry = tokio::time::sleep(Duration::from_millis(remaining_ms.max(0) as u64));
    tokio::pin!(expiry);

    loop {
        tokio::select! {
            incoming = read_envelope(&mut recv, AGENT_ATTACHMENT_FRAME_BYTES_MAX) => {
                let envelope = incoming?;
                if validate_attachment_scope(&envelope, server_id)? != shell_id {
                    return Err(AgentError::AttachmentIdentityMismatch);
                }
                match envelope.message {
                    Some(agent_envelope::Message::TerminalInput(input)) => {
                        if input.data.len() > AGENT_TERMINAL_INPUT_BYTES_MAX {
                            send_attachment_error(
                                &mut send, server_id, shell_id, envelope.request_id,
                                ErrorCode::ErrInputOverflow, "terminal input frame too large", false,
                            ).await?;
                            return Ok(());
                        }
                        if let Err(error) = manager.write_input(&shell_id, &input.data) {
                            let (code, message, retryable) = map_attachment_session_error(&error);
                            send_attachment_error(
                                &mut send, server_id, shell_id, envelope.request_id,
                                code, message, retryable,
                            ).await?;
                            return Ok(());
                        }
                    }
                    Some(agent_envelope::Message::TerminalResize(resize)) => {
                        if resize.cols > u16::MAX as u32 || resize.rows > u16::MAX as u32 {
                            send_attachment_error(
                                &mut send, server_id, shell_id, envelope.request_id,
                                ErrorCode::ErrUnknownMessage, "invalid terminal dimensions", false,
                            ).await?;
                            return Ok(());
                        }
                        if let Err(error) = manager.resize(
                            &shell_id,
                            resize.cols as u16,
                            resize.rows as u16,
                        ) {
                            let (code, message, retryable) = map_attachment_session_error(&error);
                            send_attachment_error(
                                &mut send, server_id, shell_id, envelope.request_id,
                                code, message, retryable,
                            ).await?;
                            return Ok(());
                        }
                    }
                    Some(agent_envelope::Message::RequestHistory(request)) => {
                        let maximum_bytes = request
                            .maximum_bytes
                            .min(AGENT_ATTACHMENT_FRAME_BYTES_MAX / 2);
                        match manager.history(
                            &shell_id,
                            request.before_line_id,
                            request.maximum_lines.min(AGENT_HISTORY_LINES_MAX),
                            maximum_bytes,
                        ) {
                            Ok(range) => {
                                let chunk = AgentEnvelope {
                                    request_id: envelope.request_id,
                                    server_id: server_id.to_wire(),
                                    shell_id: shell_id.to_wire(),
                                    message: Some(agent_envelope::Message::HistoryChunk(HistoryChunk {
                                        first_line_id: range.first_line_id,
                                        lines: range.lines,
                                        truncated_by_eviction: range.truncated_by_eviction,
                                    })),
                                };
                                write_envelope(&mut send, &chunk, AGENT_ATTACHMENT_FRAME_BYTES_MAX).await?;
                                let oldest = manager
                                    .history_bounds(&shell_id)
                                    .map(|(oldest, _)| oldest)
                                    .unwrap_or(0);
                                let end = AgentEnvelope {
                                    request_id: envelope.request_id,
                                    server_id: server_id.to_wire(),
                                    shell_id: shell_id.to_wire(),
                                    message: Some(agent_envelope::Message::HistoryEnd(HistoryEnd {
                                        oldest_available_line_id: oldest,
                                    })),
                                };
                                write_envelope(&mut send, &end, AGENT_ATTACHMENT_FRAME_BYTES_MAX).await?;
                            }
                            Err(error) => {
                                let (code, message, retryable) = map_attachment_session_error(&error);
                                send_attachment_error(
                                    &mut send, server_id, shell_id, envelope.request_id,
                                    code, message, retryable,
                                ).await?;
                            }
                        }
                    }
                    Some(agent_envelope::Message::DetachShell(_)) => return Ok(()),
                    _ => {
                        send_attachment_error(
                            &mut send, server_id, shell_id, envelope.request_id,
                            ErrorCode::ErrUnknownMessage, "unexpected attachment message", false,
                        ).await?;
                        return Ok(());
                    }
                }
            }
            event = event_rx.recv() => {
                match event {
                    Some(AttachmentEvent::Output(data)) => {
                        if data.len() > AGENT_TERMINAL_OUTPUT_BYTES_MAX {
                            return Err(AgentError::OversizedTerminalOutput(data.len()));
                        }
                        let output = AgentEnvelope {
                            request_id: 0,
                            server_id: server_id.to_wire(),
                            shell_id: shell_id.to_wire(),
                            message: Some(agent_envelope::Message::TerminalOutput(TerminalOutput { data })),
                        };
                        write_envelope(&mut send, &output, AGENT_ATTACHMENT_FRAME_BYTES_MAX).await?;
                    }
                    Some(AttachmentEvent::Exited(exit)) => {
                        let exited = AgentEnvelope {
                            request_id: 0,
                            server_id: server_id.to_wire(),
                            shell_id: shell_id.to_wire(),
                            message: Some(agent_envelope::Message::ShellExited(ShellExited {
                                exit_code: exit.exit_code as i32,
                                signaled: !exit.success && exit.exit_code == 0,
                                signal: String::new(),
                            })),
                        };
                        write_envelope(&mut send, &exited, AGENT_ATTACHMENT_FRAME_BYTES_MAX).await?;
                        return Ok(());
                    }
                    None => {
                        send_attachment_error(
                            &mut send, server_id, shell_id, 0,
                            ErrorCode::ErrTooSlow, "attachment output queue exceeded", true,
                        ).await?;
                        return Ok(());
                    }
                }
            }
            _ = &mut expiry => {
                send_attachment_error(
                    &mut send, server_id, shell_id, 0,
                    ErrorCode::ErrTokenExpired, "connection grant expired", true,
                ).await?;
                return Ok(());
            }
        }
    }
}

fn validate_attachment_scope(
    envelope: &AgentEnvelope,
    server_id: ServerId,
) -> Result<hf_protocol::ids::ShellId, AgentError> {
    if ServerId::from_wire(&envelope.server_id).ok() != Some(server_id) {
        return Err(AgentError::ServerIdentityMismatch);
    }
    hf_protocol::ids::ShellId::from_wire(&envelope.shell_id)
        .map_err(|_| AgentError::AttachmentIdentityMismatch)
}

async fn send_attachment_error(
    send: &mut SendStream,
    server_id: ServerId,
    shell_id: hf_protocol::ids::ShellId,
    request_id: u64,
    code: ErrorCode,
    message: &'static str,
    retryable: bool,
) -> Result<(), AgentError> {
    write_envelope(
        send,
        &AgentEnvelope {
            request_id,
            server_id: server_id.to_wire(),
            shell_id: shell_id.to_wire(),
            message: Some(agent_envelope::Message::AgentError(ProtocolError {
                code: code as i32,
                human_message: message.to_owned(),
                retryable,
            })),
        },
        AGENT_ATTACHMENT_FRAME_BYTES_MAX,
    )
    .await
}

/// Build a QUIC configuration that authenticates the gateway CA and always
/// presents the agent certificate. DER is used directly so PEM parsing stays
/// at the eventual CLI/configuration boundary.
pub fn mtls_client_config(
    gateway_roots: rustls::RootCertStore,
    agent_chain: Vec<CertificateDer<'static>>,
    agent_key: PrivateKeyDer<'static>,
) -> Result<ClientConfig, AgentError> {
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(gateway_roots)
        .with_client_auth_cert(agent_chain, agent_key)?;
    tls.alpn_protocols = vec![AGENT_ALPN.to_vec()];
    let crypto =
        QuicClientConfig::try_from(tls).map_err(|error| AgentError::Tls(error.to_string()))?;
    let mut config = ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(AGENT_ATTACHMENT_STREAMS_MAX.into());
    transport.max_concurrent_uni_streams(0u8.into());
    transport.stream_receive_window(AGENT_ATTACHMENT_FRAME_BYTES_MAX.into());
    transport.receive_window(
        AGENT_CONNECTION_FLOW_WINDOW_BYTES
            .try_into()
            .expect("agent flow window fits QUIC varint"),
    );
    transport.send_window(AGENT_CONNECTION_FLOW_WINDOW_BYTES);
    config.transport_config(Arc::new(transport));
    Ok(config)
}

async fn write_envelope(
    send: &mut SendStream,
    envelope: &AgentEnvelope,
    maximum: u32,
) -> Result<(), AgentError> {
    let frame = encode_agent_frame(envelope, maximum)?;
    send.write_all(&frame).await?;
    Ok(())
}

async fn read_envelope(recv: &mut RecvStream, maximum: u32) -> Result<AgentEnvelope, AgentError> {
    let mut header = [0u8; 4];
    recv.read_exact(&mut header).await?;
    let len = checked_payload_len(header, maximum)?;
    let mut payload = vec![0u8; len];
    recv.read_exact(&mut payload).await?;
    Ok(decode_agent_payload(&payload)?)
}

fn validate_registration(
    expected_server_id: ServerId,
    envelope_server_id: &[u8],
    registration: &AgentRegistration,
) -> Result<(), AgentError> {
    if !registration.accepted {
        return Err(AgentError::Rejected(registration.rejection_reason.clone()));
    }
    let returned =
        ServerId::from_wire(&registration.server_id).map_err(|_| AgentError::UnexpectedResponse)?;
    let scoped =
        ServerId::from_wire(envelope_server_id).map_err(|_| AgentError::UnexpectedResponse)?;
    if returned != expected_server_id
        || scoped != expected_server_id
        || registration.max_frame_bytes < AGENT_CONTROL_FRAME_BYTES_MIN
        || registration.max_frame_bytes > AGENT_CONTROL_FRAME_BYTES_MAX
        || registration.keepalive_interval_ms == 0
    {
        return Err(AgentError::UnexpectedResponse);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentAction {
    Ping(u64),
    ShellOpened {
        shell_id: hf_protocol::ids::ShellId,
        reused: bool,
    },
    ShellRejected {
        code: ErrorCode,
    },
    UnknownRejected,
}

fn validate_open_request(
    open: hf_protocol::pb::AgentOpenShell,
    verifier: &GrantVerifier,
    expected_audience: &str,
    server_id: ServerId,
) -> Result<OpenShellRequest, OpenValidationError> {
    if open.user_id.is_empty()
        || open.user_id.len() > AGENT_USER_ID_BYTES_MAX
        || open.unix_account.len() > AGENT_UNIX_ACCOUNT_BYTES_MAX
        || open.command.len() > AGENT_COMMAND_BYTES_MAX
        || open.connection_grant.is_empty()
        || open.connection_grant.len() > AGENT_GRANT_BYTES_MAX
        || open.idempotency_key.len() != 16
        || open.initial_cols > u16::MAX as u32
        || open.initial_rows > u16::MAX as u32
    {
        return Err(OpenValidationError::Invalid);
    }
    let idempotency_key: [u8; 16] = open
        .idempotency_key
        .try_into()
        .map_err(|_| OpenValidationError::Invalid)?;
    let grant = ConnectionGrant::from_wire(&open.connection_grant)
        .map_err(|_| OpenValidationError::Unauthenticated)?;
    let claims = verifier
        .verify(&grant, expected_audience, unix_time_ms())
        .map_err(|error| match error {
            GrantError::WrongAudience { .. } => OpenValidationError::Forbidden,
            _ => OpenValidationError::Unauthenticated,
        })?;
    if claims.sub != open.user_id
        || !claims.permits("open")
        || !claims
            .servers
            .iter()
            .any(|allowed| allowed == &server_id.to_string())
    {
        return Err(OpenValidationError::Forbidden);
    }
    Ok(OpenShellRequest {
        user: open.user_id,
        requested_account: (!open.unix_account.is_empty()).then_some(open.unix_account),
        command: (!open.command.is_empty()).then_some(open.command),
        args: Vec::new(),
        cols: open.initial_cols as u16,
        rows: open.initial_rows as u16,
        idempotency_key,
    })
}

struct AttachmentAuthorization {
    user_id: String,
    cols: u16,
    rows: u16,
    expires_at_ms: i64,
}

fn validate_attach_request(
    attach: hf_protocol::pb::AgentAttachShell,
    verifier: &GrantVerifier,
    expected_audience: &str,
    server_id: ServerId,
) -> Result<AttachmentAuthorization, OpenValidationError> {
    if attach.user_id.is_empty()
        || attach.user_id.len() > AGENT_USER_ID_BYTES_MAX
        || attach.connection_grant.is_empty()
        || attach.connection_grant.len() > AGENT_GRANT_BYTES_MAX
        || attach.cols > u16::MAX as u32
        || attach.rows > u16::MAX as u32
    {
        return Err(OpenValidationError::Invalid);
    }
    let grant = ConnectionGrant::from_wire(&attach.connection_grant)
        .map_err(|_| OpenValidationError::Unauthenticated)?;
    let claims = verifier
        .verify(&grant, expected_audience, unix_time_ms())
        .map_err(|error| match error {
            GrantError::WrongAudience { .. } => OpenValidationError::Forbidden,
            _ => OpenValidationError::Unauthenticated,
        })?;
    if claims.sub != attach.user_id
        || !claims.permits("attach")
        || !claims
            .servers
            .iter()
            .any(|allowed| allowed == &server_id.to_string())
    {
        return Err(OpenValidationError::Forbidden);
    }
    Ok(AttachmentAuthorization {
        user_id: attach.user_id,
        cols: attach.cols as u16,
        rows: attach.rows as u16,
        expires_at_ms: claims.exp_ms,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenValidationError {
    Invalid,
    Unauthenticated,
    Forbidden,
}

fn map_open_validation_error(error: OpenValidationError) -> (ErrorCode, &'static str) {
    match error {
        OpenValidationError::Invalid => (ErrorCode::ErrUnknownMessage, "invalid shell request"),
        OpenValidationError::Unauthenticated => {
            (ErrorCode::ErrUnauthenticated, "invalid connection grant")
        }
        OpenValidationError::Forbidden => (ErrorCode::ErrForbidden, "grant scope denied shell"),
    }
}

fn unix_time_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn map_session_error(error: &SessionError) -> (ErrorCode, &'static str, bool) {
    match error {
        SessionError::Forbidden => (
            ErrorCode::ErrForbidden,
            "local access policy denied shell",
            false,
        ),
        SessionError::LimitExceeded(_) => (
            ErrorCode::ErrLimitExceeded,
            "local shell limit exceeded",
            true,
        ),
        SessionError::Pty(_) => (ErrorCode::ErrInternal, "local PTY launch failed", true),
        SessionError::Internal(_) => (ErrorCode::ErrInternal, "invalid shell request", false),
        // Token variants are unreachable in agent mode (the gateway never
        // holds local resume tokens — attach_authorized), grouped anyway.
        SessionError::ShellNotFound
        | SessionError::NotRunning
        | SessionError::InvalidToken
        | SessionError::TokenReplayed => (ErrorCode::ErrInternal, "invalid shell state", false),
    }
}

fn map_attachment_session_error(error: &SessionError) -> (ErrorCode, &'static str, bool) {
    match error {
        // Ownership mismatch and unknown IDs intentionally have the same
        // authorization shape so the gateway cannot use this as an oracle.
        // Token variants are unreachable here (attach_authorized), grouped
        // into the same shape anyway.
        SessionError::ShellNotFound
        | SessionError::Forbidden
        | SessionError::InvalidToken
        | SessionError::TokenReplayed => (ErrorCode::ErrForbidden, "shell attachment denied", false),
        SessionError::NotRunning => (ErrorCode::ErrNotReady, "shell is not running", false),
        SessionError::LimitExceeded(_) => (
            ErrorCode::ErrLimitExceeded,
            "local attachment limit exceeded",
            true,
        ),
        SessionError::Pty(_) => (ErrorCode::ErrInternal, "local PTY operation failed", true),
        SessionError::Internal(_) => (ErrorCode::ErrInternal, "invalid shell state", false),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("agent build metadata is {0} bytes; maximum is {AGENT_BUILD_BYTES_MAX}")]
    BuildTooLong(usize),
    #[error("failed to bind the outbound QUIC endpoint: {0}")]
    Bind(#[from] std::io::Error),
    #[error("invalid gateway address or server name: {0}")]
    ConnectStart(#[from] quinn::ConnectError),
    #[error("agent QUIC connection failed: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("agent control stream write failed: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("agent control stream read failed: {0}")]
    Read(#[from] quinn::ReadExactError),
    #[error("agent control frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("TLS configuration failed: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("QUIC TLS configuration failed: {0}")]
    Tls(String),
    #[error("gateway rejected registration: {0}")]
    Rejected(String),
    #[error("gateway returned an invalid registration response")]
    UnexpectedResponse,
    #[error("gateway message is scoped to a different server identity")]
    ServerIdentityMismatch,
    #[error("reconnect delays must be non-zero and initial must not exceed maximum")]
    InvalidReconnectPolicy,
    #[error("grant audience must contain 1 to {AGENT_AUDIENCE_BYTES_MAX} encoded bytes")]
    InvalidGrantAudience,
    #[error("agent mode requires an explicit local account policy")]
    MissingAccountPolicy,
    #[error("gateway opened an invalid attachment stream")]
    UnexpectedAttachmentMessage,
    #[error("attachment frame is scoped to a different shell identity")]
    AttachmentIdentityMismatch,
    #[error("failed to start bounded attachment output forwarder: {0}")]
    AttachmentForwarder(std::io::Error),
    #[error("local PTY emitted an oversized {0}-byte output chunk")]
    OversizedTerminalOutput(usize),
}

#[cfg(test)]
mod tests {
    use super::*;
    use hf_auth::{GrantClaims, GrantSigner};

    #[test]
    fn build_metadata_is_bounded_in_encoded_bytes() {
        assert!(RegistrationRequest::new(ServerId([1; 16]), "x".repeat(128)).is_ok());
        assert!(matches!(
            RegistrationRequest::new(ServerId([1; 16]), "é".repeat(65)),
            Err(AgentError::BuildTooLong(130))
        ));
    }

    #[test]
    fn shell_open_requires_signed_subject_operation_and_server_scope() {
        let signer = GrantSigner::generate();
        let server_id = ServerId([9; 16]);
        let now = unix_time_ms();
        let issue = |sub: &str, servers: Vec<String>, ops: Vec<String>| {
            signer.issue(&GrantClaims {
                sub: sub.to_owned(),
                aud: "gateway-audience".to_owned(),
                servers,
                ops,
                iat_ms: now - 1_000,
                exp_ms: now + 60_000,
                jti: "test-jti".to_owned(),
            })
        };
        let request = |user: &str, grant: ConnectionGrant| hf_protocol::pb::AgentOpenShell {
            user_id: user.to_owned(),
            unix_account: "allowed".to_owned(),
            command: String::new(),
            initial_cols: 80,
            initial_rows: 24,
            idempotency_key: vec![1; 16],
            connection_grant: grant.as_bytes().to_vec(),
        };

        let valid = request(
            "alice",
            issue(
                "alice",
                vec![server_id.to_string()],
                vec!["open".to_owned()],
            ),
        );
        assert!(
            validate_open_request(valid, &signer.verifier(), "gateway-audience", server_id).is_ok()
        );

        let wrong_subject = request(
            "bob",
            issue(
                "alice",
                vec![server_id.to_string()],
                vec!["open".to_owned()],
            ),
        );
        assert!(matches!(
            validate_open_request(
                wrong_subject,
                &signer.verifier(),
                "gateway-audience",
                server_id
            ),
            Err(OpenValidationError::Forbidden)
        ));

        let wrong_server = request(
            "alice",
            issue(
                "alice",
                vec![ServerId([8; 16]).to_string()],
                vec!["open".to_owned()],
            ),
        );
        assert!(matches!(
            validate_open_request(
                wrong_server,
                &signer.verifier(),
                "gateway-audience",
                server_id
            ),
            Err(OpenValidationError::Forbidden)
        ));

        let wrong_operation = request(
            "alice",
            issue(
                "alice",
                vec![server_id.to_string()],
                vec!["list".to_owned()],
            ),
        );
        assert!(matches!(
            validate_open_request(
                wrong_operation,
                &signer.verifier(),
                "gateway-audience",
                server_id
            ),
            Err(OpenValidationError::Forbidden)
        ));
    }

    #[test]
    fn attachment_requires_attach_scoped_signed_grant() {
        let signer = GrantSigner::generate();
        let server_id = ServerId([10; 16]);
        let now = unix_time_ms();
        let issue = |sub: &str, operation: &str| {
            signer.issue(&GrantClaims {
                sub: sub.to_owned(),
                aud: "gateway-audience".to_owned(),
                servers: vec![server_id.to_string()],
                ops: vec![operation.to_owned()],
                iat_ms: now - 1_000,
                exp_ms: now + 60_000,
                jti: "attach-jti".to_owned(),
            })
        };
        let request = |user: &str, grant: ConnectionGrant| hf_protocol::pb::AgentAttachShell {
            user_id: user.to_owned(),
            connection_grant: grant.as_bytes().to_vec(),
            cols: 80,
            rows: 24,
        };

        let valid = validate_attach_request(
            request("alice", issue("alice", "attach")),
            &signer.verifier(),
            "gateway-audience",
            server_id,
        )
        .unwrap();
        assert_eq!(valid.user_id, "alice");

        assert!(matches!(
            validate_attach_request(
                request("alice", issue("alice", "open")),
                &signer.verifier(),
                "gateway-audience",
                server_id,
            ),
            Err(OpenValidationError::Forbidden)
        ));
        assert!(matches!(
            validate_attach_request(
                request("bob", issue("alice", "attach")),
                &signer.verifier(),
                "gateway-audience",
                server_id,
            ),
            Err(OpenValidationError::Forbidden)
        ));
    }
}
