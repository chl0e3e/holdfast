//! Gateway-side managed-server mTLS registration.
//!
//! The current Phase 6 surface establishes the bounded agent identity boundary,
//! authorized shell creation, and per-attachment terminal streams. A future
//! client-facing gateway maps browser/native attachments onto this backend API.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

use hf_protocol::{
    framing::{checked_payload_len, decode_agent_payload, encode_agent_frame, FrameError},
    ids::{ServerId, ShellId},
    pb::{
        agent_envelope, AgentAttachShell, AgentEnvelope, AgentOpenShell, AgentRegistration,
        DetachShell, HistoryChunk, HistoryEnd, RequestHistory, ShellExited, TerminalInput,
        TerminalResize,
    },
    AGENT_ALPN, AGENT_ATTACHMENT_FRAME_BYTES_MAX, AGENT_BUILD_BYTES_MAX, AGENT_COMMAND_BYTES_MAX,
    AGENT_CONNECTION_FLOW_WINDOW_BYTES, AGENT_CONTROL_FRAME_BYTES_MAX,
    AGENT_CONTROL_FRAME_BYTES_MIN, AGENT_GRANT_BYTES_MAX, AGENT_HISTORY_LINES_MAX,
    AGENT_KEEP_ALIVE_INTERVAL_MS, AGENT_MAX_IDLE_TIMEOUT_MS, AGENT_TERMINAL_INPUT_BYTES_MAX,
    AGENT_UNIX_ACCOUNT_BYTES_MAX, AGENT_USER_ID_BYTES_MAX, PROTOCOL_MAJOR,
};
use quinn::{crypto::rustls::QuicServerConfig, Connection, Endpoint, RecvStream, SendStream};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};

const DEFAULT_KEEPALIVE_INTERVAL_MS: u32 = 10_000;
const DEFAULT_REGISTRATION_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CertificateFingerprint([u8; 32]);

impl CertificateFingerprint {
    pub fn from_leaf_der(leaf_der: &[u8]) -> Self {
        Self(Sha256::digest(leaf_der).into())
    }
}

/// Bounded certificate authorization and active-agent state. Rotation may map
/// multiple fingerprints to one server, but a fingerprint can never be rebound
/// to a different server identity.
pub struct CertificateRegistry {
    identities: RwLock<HashMap<CertificateFingerprint, ServerId>>,
    active: Mutex<HashSet<ServerId>>,
    max_identities: usize,
    max_active_agents: usize,
}

impl CertificateRegistry {
    pub fn new(max_identities: usize, max_active_agents: usize) -> Result<Self, RegistryError> {
        if max_identities == 0 || max_active_agents == 0 {
            return Err(RegistryError::ZeroLimit);
        }
        Ok(Self {
            identities: RwLock::new(HashMap::new()),
            active: Mutex::new(HashSet::new()),
            max_identities,
            max_active_agents,
        })
    }

    pub fn authorize_leaf(
        &self,
        server_id: ServerId,
        leaf_der: &[u8],
    ) -> Result<CertificateFingerprint, RegistryError> {
        let fingerprint = CertificateFingerprint::from_leaf_der(leaf_der);
        let mut identities = self
            .identities
            .write()
            .map_err(|_| RegistryError::Poisoned)?;
        if let Some(existing) = identities.get(&fingerprint) {
            return if *existing == server_id {
                Ok(fingerprint)
            } else {
                Err(RegistryError::FingerprintRebind)
            };
        }
        if identities.len() >= self.max_identities {
            return Err(RegistryError::IdentityLimit(self.max_identities));
        }
        identities.insert(fingerprint, server_id);
        Ok(fingerprint)
    }

    pub fn revoke(&self, fingerprint: CertificateFingerprint) -> Result<bool, RegistryError> {
        Ok(self
            .identities
            .write()
            .map_err(|_| RegistryError::Poisoned)?
            .remove(&fingerprint)
            .is_some())
    }

    fn resolve(
        &self,
        fingerprint: CertificateFingerprint,
    ) -> Result<Option<ServerId>, RegistryError> {
        Ok(self
            .identities
            .read()
            .map_err(|_| RegistryError::Poisoned)?
            .get(&fingerprint)
            .copied())
    }

    fn claim(self: &Arc<Self>, server_id: ServerId) -> Result<ActiveAgentLease, RegistryError> {
        let mut active = self.active.lock().map_err(|_| RegistryError::Poisoned)?;
        if active.contains(&server_id) {
            return Err(RegistryError::AlreadyActive(server_id));
        }
        if active.len() >= self.max_active_agents {
            return Err(RegistryError::ActiveLimit(self.max_active_agents));
        }
        active.insert(server_id);
        Ok(ActiveAgentLease {
            registry: Arc::clone(self),
            server_id,
        })
    }

    pub fn identity_count(&self) -> Result<usize, RegistryError> {
        Ok(self
            .identities
            .read()
            .map_err(|_| RegistryError::Poisoned)?
            .len())
    }

    pub fn active_count(&self) -> Result<usize, RegistryError> {
        Ok(self
            .active
            .lock()
            .map_err(|_| RegistryError::Poisoned)?
            .len())
    }
}

struct ActiveAgentLease {
    registry: Arc<CertificateRegistry>,
    server_id: ServerId,
}

impl Drop for ActiveAgentLease {
    fn drop(&mut self) {
        if let Ok(mut active) = self.registry.active.lock() {
            active.remove(&self.server_id);
        }
    }
}

pub struct AgentGateway {
    endpoint: Endpoint,
    registry: Arc<CertificateRegistry>,
    registration_timeout: Duration,
    keepalive_interval_ms: u32,
}

impl AgentGateway {
    pub fn bind(
        bind_addr: SocketAddr,
        server_config: quinn::ServerConfig,
        registry: Arc<CertificateRegistry>,
    ) -> Result<Self, GatewayError> {
        Ok(Self {
            endpoint: Endpoint::server(server_config, bind_addr)?,
            registry,
            registration_timeout: DEFAULT_REGISTRATION_TIMEOUT,
            keepalive_interval_ms: DEFAULT_KEEPALIVE_INTERVAL_MS,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.endpoint.local_addr()
    }

    /// Accept and authenticate one connection. Callers may schedule multiple
    /// accepts, while the registry independently enforces the active bound.
    pub async fn accept_registration(&self) -> Result<RegisteredAgent, GatewayError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or(GatewayError::EndpointClosed)?;
        let connection = tokio::time::timeout(self.registration_timeout, incoming)
            .await
            .map_err(|_| GatewayError::RegistrationTimeout)??;
        let fingerprint = peer_leaf_fingerprint(&connection)?;
        let expected_server_id = self.registry.resolve(fingerprint)?;

        let (mut send, mut recv) =
            tokio::time::timeout(self.registration_timeout, connection.accept_bi())
                .await
                .map_err(|_| GatewayError::RegistrationTimeout)??;
        let envelope = tokio::time::timeout(
            self.registration_timeout,
            read_envelope(&mut recv, AGENT_CONTROL_FRAME_BYTES_MAX),
        )
        .await
        .map_err(|_| GatewayError::RegistrationTimeout)??;

        let envelope_server_id = envelope.server_id.clone();
        let Some(agent_envelope::Message::AgentRegister(register)) = envelope.message else {
            return reject(connection, send, "invalid registration message").await;
        };
        if register.protocol_major != PROTOCOL_MAJOR {
            return reject(connection, send, "incompatible agent protocol").await;
        }
        if register.agent_build.len() > AGENT_BUILD_BYTES_MAX {
            return reject(connection, send, "invalid agent metadata").await;
        }
        let claimed = match ServerId::from_wire(&register.server_id) {
            Ok(server_id) => server_id,
            Err(_) => return reject(connection, send, "invalid server identity").await,
        };
        let scoped = ServerId::from_wire(&envelope_server_id).ok();
        if expected_server_id != Some(claimed) || scoped != Some(claimed) {
            return reject(connection, send, "certificate identity mismatch").await;
        }
        if register.max_frame_bytes < AGENT_CONTROL_FRAME_BYTES_MIN {
            return reject(connection, send, "invalid frame limit").await;
        }
        let lease = match self.registry.claim(claimed) {
            Ok(lease) => lease,
            Err(RegistryError::AlreadyActive(_)) => {
                return reject(connection, send, "server already connected").await
            }
            Err(error) => return Err(error.into()),
        };
        let negotiated_max = register.max_frame_bytes.min(AGENT_CONTROL_FRAME_BYTES_MAX);
        let response = AgentEnvelope {
            request_id: 0,
            server_id: claimed.to_wire(),
            shell_id: Vec::new(),
            message: Some(agent_envelope::Message::AgentRegistration(
                AgentRegistration {
                    accepted: true,
                    server_id: claimed.to_wire(),
                    max_frame_bytes: negotiated_max,
                    keepalive_interval_ms: self.keepalive_interval_ms,
                    rejection_reason: String::new(),
                },
            )),
        };
        write_envelope(&mut send, &response, negotiated_max).await?;

        Ok(RegisteredAgent {
            connection,
            send,
            recv,
            server_id: claimed,
            max_frame_bytes: negotiated_max,
            next_request_id: 1,
            _lease: lease,
        })
    }
}

pub struct RegisteredAgent {
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
    server_id: ServerId,
    max_frame_bytes: u32,
    next_request_id: u64,
    _lease: ActiveAgentLease,
}

impl RegisteredAgent {
    pub fn server_id(&self) -> ServerId {
        self.server_id
    }

    pub fn max_frame_bytes(&self) -> u32 {
        self.max_frame_bytes
    }

    /// Read and answer one bounded application-level keepalive.
    pub async fn answer_ping(&mut self) -> Result<u64, GatewayError> {
        let request = read_envelope(&mut self.recv, self.max_frame_bytes).await?;
        let Some(agent_envelope::Message::AgentPing(ping)) = request.message else {
            return Err(GatewayError::UnexpectedControlMessage);
        };
        if ServerId::from_wire(&request.server_id).ok() != Some(self.server_id) {
            return Err(GatewayError::ServerIdentityMismatch);
        }
        let response = AgentEnvelope {
            request_id: request.request_id,
            server_id: self.server_id.to_wire(),
            shell_id: Vec::new(),
            message: Some(agent_envelope::Message::AgentPong(
                hf_protocol::pb::AgentPong { nonce: ping.nonce },
            )),
        };
        write_envelope(&mut self.send, &response, self.max_frame_bytes).await?;
        Ok(ping.nonce)
    }

    /// Request a shell through the managed server's local policy and launcher.
    pub async fn open_shell(
        &mut self,
        request: &AgentShellRequest,
    ) -> Result<AgentOpenedShell, GatewayError> {
        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.checked_add(1).unwrap_or(1);
        let envelope = AgentEnvelope {
            request_id,
            server_id: self.server_id.to_wire(),
            shell_id: Vec::new(),
            message: Some(agent_envelope::Message::AgentOpenShell(AgentOpenShell {
                user_id: request.user_id.clone(),
                unix_account: request.unix_account.clone().unwrap_or_default(),
                command: request.command.clone().unwrap_or_default(),
                initial_cols: request.cols as u32,
                initial_rows: request.rows as u32,
                idempotency_key: request.idempotency_key.to_vec(),
                connection_grant: request.connection_grant.clone(),
            })),
        };
        write_envelope(&mut self.send, &envelope, self.max_frame_bytes).await?;
        let response = read_envelope(&mut self.recv, self.max_frame_bytes).await?;
        if response.request_id != request_id
            || ServerId::from_wire(&response.server_id).ok() != Some(self.server_id)
        {
            return Err(GatewayError::ServerIdentityMismatch);
        }
        match response.message {
            Some(agent_envelope::Message::AgentShellOpened(opened)) => Ok(AgentOpenedShell {
                shell_id: ShellId::from_wire(&opened.shell_id)
                    .map_err(|_| GatewayError::UnexpectedControlMessage)?,
                reused: opened.reused,
            }),
            Some(agent_envelope::Message::AgentError(error)) => Err(GatewayError::Remote {
                code: error.code,
                message: error.human_message,
                retryable: error.retryable,
            }),
            _ => Err(GatewayError::UnexpectedControlMessage),
        }
    }

    /// Open one independently bounded terminal attachment stream. The agent
    /// re-verifies the signed grant and local shell ownership before returning
    /// the coherent screen snapshot.
    pub async fn attach_shell(
        &self,
        shell_id: ShellId,
        request: &AgentAttachmentRequest,
    ) -> Result<AgentAttachment, GatewayError> {
        let (mut send, mut recv) = self.connection.open_bi().await?;
        let request_id = 1;
        let envelope = AgentEnvelope {
            request_id,
            server_id: self.server_id.to_wire(),
            shell_id: shell_id.to_wire(),
            message: Some(agent_envelope::Message::AgentAttachShell(
                AgentAttachShell {
                    user_id: request.user_id.clone(),
                    connection_grant: request.connection_grant.clone(),
                    cols: request.cols as u32,
                    rows: request.rows as u32,
                },
            )),
        };
        write_envelope(&mut send, &envelope, AGENT_ATTACHMENT_FRAME_BYTES_MAX).await?;
        let response = read_envelope(&mut recv, AGENT_ATTACHMENT_FRAME_BYTES_MAX).await?;
        validate_attachment_scope(&response, self.server_id, shell_id, request_id)?;
        match response.message {
            Some(agent_envelope::Message::AgentShellAttached(attached)) => Ok(AgentAttachment {
                attached: AgentAttachedShell {
                    screen_snapshot: attached.screen_snapshot,
                    screen_revision: attached.screen_revision,
                    oldest_history_line_id: attached.oldest_history_line_id,
                    newest_history_line_id: attached.newest_history_line_id,
                },
                sender: AgentAttachmentSender {
                    send,
                    server_id: self.server_id,
                    shell_id,
                    next_request_id: 2,
                },
                receiver: AgentAttachmentReceiver {
                    recv,
                    server_id: self.server_id,
                    shell_id,
                },
            }),
            Some(agent_envelope::Message::AgentError(error)) => Err(GatewayError::Remote {
                code: error.code,
                message: error.human_message,
                retryable: error.retryable,
            }),
            _ => Err(GatewayError::UnexpectedAttachmentMessage),
        }
    }

    pub fn close(&self) {
        self.connection.close(0u32.into(), b"gateway link closed");
    }
}

#[derive(Clone)]
pub struct AgentAttachmentRequest {
    user_id: String,
    connection_grant: Vec<u8>,
    cols: u16,
    rows: u16,
}

impl std::fmt::Debug for AgentAttachmentRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentAttachmentRequest")
            .field("user_id", &"[REDACTED]")
            .field("connection_grant", &"[REDACTED]")
            .field("cols", &self.cols)
            .field("rows", &self.rows)
            .finish()
    }
}

impl AgentAttachmentRequest {
    pub fn new(
        user_id: impl Into<String>,
        connection_grant: Vec<u8>,
        cols: u16,
        rows: u16,
    ) -> Result<Self, GatewayError> {
        let user_id = user_id.into();
        if user_id.is_empty()
            || user_id.len() > AGENT_USER_ID_BYTES_MAX
            || connection_grant.is_empty()
            || connection_grant.len() > AGENT_GRANT_BYTES_MAX
        {
            return Err(GatewayError::InvalidAttachmentRequest);
        }
        Ok(Self {
            user_id,
            connection_grant,
            cols,
            rows,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAttachedShell {
    pub screen_snapshot: Vec<u8>,
    pub screen_revision: u64,
    pub oldest_history_line_id: u64,
    pub newest_history_line_id: u64,
}

pub struct AgentAttachment {
    pub attached: AgentAttachedShell,
    sender: AgentAttachmentSender,
    receiver: AgentAttachmentReceiver,
}

impl AgentAttachment {
    pub async fn send_input(&mut self, data: &[u8]) -> Result<u64, GatewayError> {
        self.sender.send_input(data).await
    }

    pub async fn resize(&mut self, cols: u16, rows: u16) -> Result<u64, GatewayError> {
        self.sender.resize(cols, rows).await
    }

    pub async fn request_history(
        &mut self,
        before_line_id: u64,
        maximum_lines: u32,
        maximum_bytes: u32,
    ) -> Result<u64, GatewayError> {
        self.sender
            .request_history(before_line_id, maximum_lines, maximum_bytes)
            .await
    }

    pub async fn next_event(&mut self) -> Result<AgentAttachmentEvent, GatewayError> {
        self.receiver.next_event().await
    }

    pub async fn detach(mut self) -> Result<(), GatewayError> {
        self.sender.detach().await
    }

    pub fn split(self) -> (AgentAttachmentSender, AgentAttachmentReceiver) {
        (self.sender, self.receiver)
    }
}

pub struct AgentAttachmentSender {
    send: SendStream,
    server_id: ServerId,
    shell_id: ShellId,
    next_request_id: u64,
}

impl AgentAttachmentSender {
    fn request_id(&mut self) -> u64 {
        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.checked_add(1).unwrap_or(1);
        request_id
    }

    pub async fn send_input(&mut self, data: &[u8]) -> Result<u64, GatewayError> {
        if data.len() > AGENT_TERMINAL_INPUT_BYTES_MAX {
            return Err(GatewayError::InputTooLarge(data.len()));
        }
        let request_id = self.request_id();
        self.write(
            request_id,
            agent_envelope::Message::TerminalInput(TerminalInput {
                data: data.to_vec(),
            }),
        )
        .await?;
        Ok(request_id)
    }

    pub async fn resize(&mut self, cols: u16, rows: u16) -> Result<u64, GatewayError> {
        let request_id = self.request_id();
        self.write(
            request_id,
            agent_envelope::Message::TerminalResize(TerminalResize {
                cols: cols as u32,
                rows: rows as u32,
            }),
        )
        .await?;
        Ok(request_id)
    }

    pub async fn request_history(
        &mut self,
        before_line_id: u64,
        maximum_lines: u32,
        maximum_bytes: u32,
    ) -> Result<u64, GatewayError> {
        let request_id = self.request_id();
        self.write(
            request_id,
            agent_envelope::Message::RequestHistory(RequestHistory {
                before_line_id,
                maximum_lines: maximum_lines.min(AGENT_HISTORY_LINES_MAX),
                maximum_bytes: maximum_bytes.min(AGENT_ATTACHMENT_FRAME_BYTES_MAX / 2),
            }),
        )
        .await?;
        Ok(request_id)
    }

    pub async fn detach(&mut self) -> Result<(), GatewayError> {
        let request_id = self.request_id();
        self.write(
            request_id,
            agent_envelope::Message::DetachShell(DetachShell {}),
        )
        .await?;
        let _ = self.send.finish();
        Ok(())
    }

    async fn write(
        &mut self,
        request_id: u64,
        message: agent_envelope::Message,
    ) -> Result<(), GatewayError> {
        write_envelope(
            &mut self.send,
            &AgentEnvelope {
                request_id,
                server_id: self.server_id.to_wire(),
                shell_id: self.shell_id.to_wire(),
                message: Some(message),
            },
            AGENT_ATTACHMENT_FRAME_BYTES_MAX,
        )
        .await
    }
}

pub struct AgentAttachmentReceiver {
    recv: RecvStream,
    server_id: ServerId,
    shell_id: ShellId,
}

impl AgentAttachmentReceiver {
    pub async fn next_event(&mut self) -> Result<AgentAttachmentEvent, GatewayError> {
        let envelope = read_envelope(&mut self.recv, AGENT_ATTACHMENT_FRAME_BYTES_MAX).await?;
        validate_attachment_scope(
            &envelope,
            self.server_id,
            self.shell_id,
            envelope.request_id,
        )?;
        match envelope.message {
            Some(agent_envelope::Message::TerminalOutput(output)) => {
                Ok(AgentAttachmentEvent::Output(output.data))
            }
            Some(agent_envelope::Message::HistoryChunk(chunk)) => {
                Ok(AgentAttachmentEvent::HistoryChunk {
                    request_id: envelope.request_id,
                    chunk,
                })
            }
            Some(agent_envelope::Message::HistoryEnd(end)) => {
                Ok(AgentAttachmentEvent::HistoryEnd {
                    request_id: envelope.request_id,
                    end,
                })
            }
            Some(agent_envelope::Message::ShellExited(exit)) => {
                Ok(AgentAttachmentEvent::ShellExited(exit))
            }
            Some(agent_envelope::Message::AgentError(error)) => Err(GatewayError::Remote {
                code: error.code,
                message: error.human_message,
                retryable: error.retryable,
            }),
            _ => Err(GatewayError::UnexpectedAttachmentMessage),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentAttachmentEvent {
    Output(Vec<u8>),
    HistoryChunk {
        request_id: u64,
        chunk: HistoryChunk,
    },
    HistoryEnd {
        request_id: u64,
        end: HistoryEnd,
    },
    ShellExited(ShellExited),
}

fn validate_attachment_scope(
    envelope: &AgentEnvelope,
    server_id: ServerId,
    shell_id: ShellId,
    request_id: u64,
) -> Result<(), GatewayError> {
    if envelope.request_id != request_id
        || ServerId::from_wire(&envelope.server_id).ok() != Some(server_id)
        || ShellId::from_wire(&envelope.shell_id).ok() != Some(shell_id)
    {
        return Err(GatewayError::AttachmentIdentityMismatch);
    }
    Ok(())
}

#[derive(Clone)]
pub struct AgentShellRequest {
    user_id: String,
    connection_grant: Vec<u8>,
    unix_account: Option<String>,
    command: Option<String>,
    cols: u16,
    rows: u16,
    idempotency_key: [u8; 16],
}

impl std::fmt::Debug for AgentShellRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentShellRequest")
            .field("user_id", &"[REDACTED]")
            .field("connection_grant", &"[REDACTED]")
            .field("unix_account", &"[REDACTED]")
            .field("command", &"[REDACTED]")
            .field("cols", &self.cols)
            .field("rows", &self.rows)
            .field("idempotency_key", &"[REDACTED]")
            .finish()
    }
}

impl AgentShellRequest {
    pub fn new(
        user_id: impl Into<String>,
        connection_grant: Vec<u8>,
        unix_account: Option<String>,
        command: Option<String>,
        cols: u16,
        rows: u16,
        idempotency_key: [u8; 16],
    ) -> Result<Self, GatewayError> {
        let user_id = user_id.into();
        if user_id.is_empty()
            || user_id.len() > AGENT_USER_ID_BYTES_MAX
            || connection_grant.is_empty()
            || connection_grant.len() > AGENT_GRANT_BYTES_MAX
            || unix_account
                .as_ref()
                .is_some_and(|value| value.len() > AGENT_UNIX_ACCOUNT_BYTES_MAX)
            || command
                .as_ref()
                .is_some_and(|value| value.len() > AGENT_COMMAND_BYTES_MAX)
        {
            return Err(GatewayError::InvalidShellRequest);
        }
        Ok(Self {
            user_id,
            connection_grant,
            unix_account,
            command,
            cols,
            rows,
            idempotency_key,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentOpenedShell {
    pub shell_id: ShellId,
    pub reused: bool,
}

/// Build a server configuration that requires a certificate chained to the
/// agent CA. Registry authorization is applied after this PKI check.
pub fn mtls_server_config(
    agent_roots: rustls::RootCertStore,
    gateway_chain: Vec<CertificateDer<'static>>,
    gateway_key: PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig, GatewayError> {
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(agent_roots)).build()?;
    let mut tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(gateway_chain, gateway_key)?;
    tls.alpn_protocols = vec![AGENT_ALPN.to_vec()];
    let crypto =
        QuicServerConfig::try_from(tls).map_err(|error| GatewayError::Tls(error.to_string()))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let transport = Arc::get_mut(&mut config.transport).expect("new server config owns transport");
    transport.max_concurrent_bidi_streams(1u8.into());
    transport.max_concurrent_uni_streams(0u8.into());
    transport.stream_receive_window(AGENT_ATTACHMENT_FRAME_BYTES_MAX.into());
    transport.receive_window(
        AGENT_CONNECTION_FLOW_WINDOW_BYTES
            .try_into()
            .expect("agent flow window fits QUIC varint"),
    );
    transport.send_window(AGENT_CONNECTION_FLOW_WINDOW_BYTES);
    // The idle limit is the lower of the two peers', so the gateway has to
    // raise its own or the agent's keepalive would be pacing against a 30s
    // ceiling here. Keepalive on this side too, so an agent built before the
    // client-side change still holds its link up.
    transport.max_idle_timeout(Some(quinn::VarInt::from_u32(AGENT_MAX_IDLE_TIMEOUT_MS).into()));
    transport.keep_alive_interval(Some(Duration::from_millis(AGENT_KEEP_ALIVE_INTERVAL_MS)));
    Ok(config)
}

fn peer_leaf_fingerprint(connection: &Connection) -> Result<CertificateFingerprint, GatewayError> {
    let identity = connection
        .peer_identity()
        .ok_or(GatewayError::MissingPeerIdentity)?;
    let chain = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| GatewayError::InvalidPeerIdentity)?;
    let leaf = chain.first().ok_or(GatewayError::MissingPeerIdentity)?;
    Ok(CertificateFingerprint::from_leaf_der(leaf.as_ref()))
}

async fn reject(
    connection: Connection,
    mut send: SendStream,
    reason: &'static str,
) -> Result<RegisteredAgent, GatewayError> {
    let response = AgentEnvelope {
        request_id: 0,
        server_id: Vec::new(),
        shell_id: Vec::new(),
        message: Some(agent_envelope::Message::AgentRegistration(
            AgentRegistration {
                accepted: false,
                server_id: Vec::new(),
                max_frame_bytes: 0,
                keepalive_interval_ms: 0,
                rejection_reason: reason.to_owned(),
            },
        )),
    };
    let _ = write_envelope(&mut send, &response, AGENT_CONTROL_FRAME_BYTES_MAX).await;
    let _ = send.finish();
    // Let QUIC acknowledge the bounded rejection frame before closing the
    // connection; otherwise an immediate CONNECTION_CLOSE may race it and the
    // agent sees only a generic transport error.
    let _ = tokio::time::timeout(Duration::from_secs(1), send.stopped()).await;
    connection.close(1u32.into(), b"registration rejected");
    Err(GatewayError::Rejected(reason))
}

async fn write_envelope(
    send: &mut SendStream,
    envelope: &AgentEnvelope,
    maximum: u32,
) -> Result<(), GatewayError> {
    let frame = encode_agent_frame(envelope, maximum)?;
    send.write_all(&frame).await?;
    Ok(())
}

async fn read_envelope(recv: &mut RecvStream, maximum: u32) -> Result<AgentEnvelope, GatewayError> {
    let mut header = [0u8; 4];
    recv.read_exact(&mut header).await?;
    let len = checked_payload_len(header, maximum)?;
    let mut payload = vec![0u8; len];
    recv.read_exact(&mut payload).await?;
    Ok(decode_agent_payload(&payload)?)
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("registry limits must be non-zero")]
    ZeroLimit,
    #[error("certificate identity capacity {0} reached")]
    IdentityLimit(usize),
    #[error("active agent capacity {0} reached")]
    ActiveLimit(usize),
    #[error("certificate fingerprint is already bound to another server")]
    FingerprintRebind,
    #[error("server {0} already has an active agent")]
    AlreadyActive(ServerId),
    #[error("certificate registry lock was poisoned")]
    Poisoned,
}

#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("failed to bind gateway QUIC endpoint: {0}")]
    Bind(#[from] std::io::Error),
    #[error("gateway endpoint is closed")]
    EndpointClosed,
    #[error("agent registration timed out")]
    RegistrationTimeout,
    #[error("agent QUIC connection failed: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("agent control stream write failed: {0}")]
    Write(#[from] quinn::WriteError),
    #[error("agent control stream read failed: {0}")]
    Read(#[from] quinn::ReadExactError),
    #[error("agent control frame failed: {0}")]
    Frame(#[from] FrameError),
    #[error("agent did not present a certificate")]
    MissingPeerIdentity,
    #[error("QUIC returned an unexpected peer identity type")]
    InvalidPeerIdentity,
    #[error("agent registration rejected: {0}")]
    Rejected(&'static str),
    #[error("unexpected agent control message")]
    UnexpectedControlMessage,
    #[error("unexpected agent attachment message")]
    UnexpectedAttachmentMessage,
    #[error("agent response is scoped to a different server identity or request")]
    ServerIdentityMismatch,
    #[error("agent attachment response is scoped to a different server, shell or request")]
    AttachmentIdentityMismatch,
    #[error("agent shell request exceeds a fixed metadata bound")]
    InvalidShellRequest,
    #[error("agent attachment request exceeds a fixed metadata bound")]
    InvalidAttachmentRequest,
    #[error("terminal input is {0} bytes; maximum is {AGENT_TERMINAL_INPUT_BYTES_MAX}")]
    InputTooLarge(usize),
    #[error("managed server rejected the operation with code {code}: {message}")]
    Remote {
        code: i32,
        message: String,
        retryable: bool,
    },
    #[error("certificate registry failed: {0}")]
    Registry(#[from] RegistryError),
    #[error("TLS configuration failed: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("client certificate verifier failed: {0}")]
    Verifier(#[from] rustls::server::VerifierBuilderError),
    #[error("QUIC TLS configuration failed: {0}")]
    Tls(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_bounded_and_prevents_rebinding() {
        let registry = CertificateRegistry::new(1, 1).unwrap();
        let first = ServerId([1; 16]);
        let second = ServerId([2; 16]);
        registry.authorize_leaf(first, b"first cert").unwrap();
        assert!(matches!(
            registry.authorize_leaf(second, b"first cert"),
            Err(RegistryError::FingerprintRebind)
        ));
        assert!(matches!(
            registry.authorize_leaf(second, b"second cert"),
            Err(RegistryError::IdentityLimit(1))
        ));
    }

    #[test]
    fn active_agent_state_is_bounded_and_released() {
        let registry = Arc::new(CertificateRegistry::new(2, 1).unwrap());
        let first = ServerId([1; 16]);
        let second = ServerId([2; 16]);
        let lease = registry.claim(first).unwrap();
        assert!(matches!(
            registry.claim(first),
            Err(RegistryError::AlreadyActive(id)) if id == first
        ));
        assert!(matches!(
            registry.claim(second),
            Err(RegistryError::ActiveLimit(1))
        ));
        drop(lease);
        assert!(registry.claim(second).is_ok());
    }

    #[test]
    fn shell_request_debug_redacts_grant_and_command() {
        let request = AgentShellRequest::new(
            "alice",
            b"secret-grant".to_vec(),
            Some("root".to_owned()),
            Some("secret-command".to_owned()),
            80,
            24,
            [7; 16],
        )
        .unwrap();
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("secret-grant"));
        assert!(!rendered.contains("secret-command"));
        assert!(!rendered.contains("alice"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn attachment_request_is_bounded_and_redacted() {
        let request =
            AgentAttachmentRequest::new("alice", b"secret-attach-grant".to_vec(), 80, 24).unwrap();
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("alice"));
        assert!(!rendered.contains("secret-attach-grant"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(matches!(
            AgentAttachmentRequest::new("alice", vec![0; AGENT_GRANT_BYTES_MAX + 1], 80, 24,),
            Err(GatewayError::InvalidAttachmentRequest)
        ));
    }
}
