//! Transport-neutral per-session protocol handling: control channel (0) plus
//! client-opened attachment channels. On WebSocket a channel is a varint
//! prefix (spec §2); on WebTransport/QUIC a channel is a bidirectional
//! stream. One session = one authenticated connection with any number of
//! shell attachments; dropping the connection detaches everything but kills
//! nothing (spec §11).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use hf_auth::ConnectionGrant;
use hf_protocol::ids::ShellId;
use hf_protocol::negotiate::{negotiate_server, server_hello, Negotiated};
use hf_protocol::pb::{self, envelope::Message as Msg, Envelope};
use hf_protocol::FRAME_BYTES_DEFAULT;
use hf_session_core::{AttachmentEvent, OpenShellRequest, ResumeToken, SessionError, ShellState};

use crate::auth::AuthMode;
use crate::observability::{AuditEvent, AuthMethod, RejectReason, ShellOperation};
use crate::AppState;

pub(crate) const KEEPALIVE_INTERVAL_MS: u32 = 15_000;
/// Outgoing queue bound (messages) per connection — spec §8: no unbounded
/// queues. Attachment fan-out upstream is already bounded per attachment.
pub(crate) const OUTGOING_QUEUE: usize = 512;

pub(crate) struct Conn {
    state: Arc<AppState>,
    peer_ip: IpAddr,
    negotiated: Option<Negotiated>,
    authenticated: bool,
    /// Authenticated user id, set on successful auth; the account authorizer
    /// keys on this (threat model T12). Empty in dev mode.
    user_id: String,
    /// Operations this connection may perform. `None` = unrestricted (dev, SSH
    /// key auth, or a grant with empty `ops`); `Some(list)` restricts to the
    /// grant's scoped operations (threat model T4 — a scoped grant must not be
    /// silently upgraded to full access).
    op_scope: Option<Vec<String>>,
    /// TLS channel binding for SSH auth (ADR 0008): the server's WebTransport
    /// certificate hash on that transport, empty on WebSocket (nginx-terminated,
    /// no binding available). Mixed into the signed challenge so a relayed
    /// signature — made against a different server's channel — fails.
    channel_binding: Vec<u8>,
    /// Username + pending SSH challenge nonce, set after a challenge request
    /// and consumed by the matching response (spec §5).
    pending_challenge: Option<(String, Vec<u8>)>,
    /// Whether the underlying transport supports unreliable datagrams
    /// (spec §4: DATAGRAMS capability is stripped when it does not).
    transport_datagrams: bool,
    /// channel_id → attachment binding.
    attachments: HashMap<u64, Binding>,
    out: tokio::sync::mpsc::Sender<(u64, Envelope)>,
}

struct Binding {
    shell_id: ShellId,
    attachment_id: u64,
}

impl Conn {
    pub(crate) fn new(
        state: Arc<AppState>,
        peer_ip: IpAddr,
        out: tokio::sync::mpsc::Sender<(u64, Envelope)>,
        transport_datagrams: bool,
        channel_binding: Vec<u8>,
    ) -> Conn {
        Conn {
            state,
            peer_ip,
            negotiated: None,
            authenticated: false,
            user_id: String::new(),
            op_scope: None,
            channel_binding,
            pending_challenge: None,
            transport_datagrams,
            attachments: HashMap::new(),
            out,
        }
    }

    pub(crate) fn max_frame_bytes(&self) -> u32 {
        self.negotiated
            .as_ref()
            .map(|n| n.max_frame_bytes)
            .unwrap_or(FRAME_BYTES_DEFAULT)
    }

    /// Whether this connection's grant scope permits `op` ("open", "attach",
    /// "terminate", "list"). Unrestricted connections permit everything.
    fn permits(&self, op: &str) -> bool {
        self.op_scope
            .as_ref()
            .map_or(true, |ops| ops.iter().any(|o| o == op))
    }

    /// The transport saw a channel/stream close: drop its attachment, if any.
    pub(crate) fn channel_closed(&mut self, channel: u64) {
        if let Some(binding) = self.attachments.remove(&channel) {
            let _ = self
                .state
                .manager
                .detach(&binding.shell_id, binding.attachment_id);
            self.state.observability.record(AuditEvent::ShellDetached {
                user: self.user_id.clone(),
                shell_id: binding.shell_id,
            });
        }
    }

    /// Connection gone (reload, network loss, close): detach everything;
    /// shells keep running (spec §11).
    pub(crate) fn detach_all(&mut self) {
        for (_, binding) in self.attachments.drain() {
            let _ = self
                .state
                .manager
                .detach(&binding.shell_id, binding.attachment_id);
            self.state.observability.record(AuditEvent::ShellDetached {
                user: self.user_id.clone(),
                shell_id: binding.shell_id,
            });
        }
    }

    async fn send(&self, channel: u64, envelope: Envelope) -> bool {
        self.out.send((channel, envelope)).await.is_ok()
    }

    pub(crate) async fn send_error(&self, channel: u64, code: pb::ErrorCode, text: &str) -> bool {
        self.send(channel, error_envelope(0, code, text, false))
            .await
    }

    /// Authentication (spec §5). Rate-limited by source address. Handles the
    /// dev accept-all mode, connection-grant verification, and the SSH
    /// challenge/response sub-negotiation.
    async fn handle_authenticate(&mut self, request_id: u64, auth: pb::Authenticate) -> bool {
        let now = Instant::now();
        if !self.state.auth.rate_limiter.check(self.peer_ip, now) {
            self.state
                .observability
                .record(AuditEvent::AuthenticationFailed {
                    source_ip: self.peer_ip,
                    reason: RejectReason::RateLimited,
                });
            return self
                .send(
                    0,
                    auth_failure(
                        request_id,
                        pb::ErrorCode::ErrLimitExceeded,
                        "too many attempts",
                    ),
                )
                .await;
        }

        // Dev mode: accept anything (loopback-only, enforced at startup).
        if matches!(self.state.auth.mode, AuthMode::DevInsecure) {
            self.authenticated = true;
            self.user_id = "dev".into();
            self.state.auth.rate_limiter.record_success(self.peer_ip);
            self.state
                .observability
                .record(AuditEvent::AuthenticationSucceeded {
                    user: self.user_id.clone(),
                    source_ip: self.peer_ip,
                    method: AuthMethod::Development,
                });
            return self.send(0, auth_ok(request_id, "dev", 0)).await;
        }

        match auth.method {
            // Present a previously issued grant.
            Some(pb::authenticate::Method::ConnectionGrant(bytes)) => {
                let grant = match ConnectionGrant::from_wire(&bytes) {
                    Ok(g) => g,
                    Err(_) => return self.fail_auth(request_id, "malformed grant").await,
                };
                match self.state.auth.grant_verifier.verify(
                    &grant,
                    &self.state.auth.audience,
                    now_ms(),
                ) {
                    Ok(claims) => {
                        self.authenticated = true;
                        self.user_id = claims.sub.clone();
                        // Honor the grant's operation scope (empty = all).
                        self.op_scope = (!claims.ops.is_empty()).then(|| claims.ops.clone());
                        self.state.auth.rate_limiter.record_success(self.peer_ip);
                        self.state
                            .observability
                            .record(AuditEvent::AuthenticationSucceeded {
                                user: claims.sub.clone(),
                                source_ip: self.peer_ip,
                                method: AuthMethod::ConnectionGrant,
                            });
                        self.send(0, auth_ok(request_id, &claims.sub, claims.exp_ms))
                            .await
                    }
                    Err(_) => self.fail_auth(request_id, "invalid grant").await,
                }
            }

            // Step 1–3: offer a key, receive a challenge.
            Some(pb::authenticate::Method::SshChallengeRequest(req)) => {
                let offered = String::from_utf8_lossy(&req.public_key).to_string();
                let authorized = self
                    .state
                    .auth
                    .ssh_verifier(&req.username)
                    .map(|v| v.is_authorized(&offered).is_ok())
                    .unwrap_or(false);
                if !authorized {
                    // Do not reveal whether the user or the key was unknown.
                    return self.fail_auth(request_id, "authentication failed").await;
                }
                let challenge = hf_auth::ssh::new_challenge().to_vec();
                self.pending_challenge = Some((req.username.clone(), challenge.clone()));
                // ok=false + challenge present = "sign this and resend".
                let result = pb::AuthenticationResult {
                    ok: false,
                    user_id: String::new(),
                    expires_at_ms: 0,
                    error_code: 0,
                    error_message: String::new(),
                    challenge,
                };
                self.send(0, respond(request_id, Msg::AuthenticationResult(result)))
                    .await
            }

            // Step 4–5: prove possession of the key.
            Some(pb::authenticate::Method::SshChallengeResponse(resp)) => {
                let Some((username, expected)) = self.pending_challenge.take() else {
                    return self.fail_auth(request_id, "no challenge in progress").await;
                };
                if resp.challenge != expected {
                    return self.fail_auth(request_id, "challenge mismatch").await;
                }
                let verified = self.state.auth.ssh_verifier(&username).and_then(|v| {
                    v.verify_response(&self.channel_binding, &expected, &resp.signature)
                        .ok()
                });
                match verified {
                    Some(identity) => {
                        // Whether a touch-proving hardware key was used is
                        // worth having in the audit trail (threat model T10);
                        // the fingerprint alone does not say.
                        tracing::info!(
                            user = %username,
                            key = %identity.fingerprint,
                            security_key = identity.security_key.is_some(),
                            user_verified = identity
                                .security_key
                                .as_ref()
                                .is_some_and(|sk| sk.user_verified),
                            "authenticated"
                        );
                        self.succeed_issuing_grant(request_id, username, AuthMethod::SshKey)
                            .await
                    }
                    None => self.fail_auth(request_id, "authentication failed").await,
                }
            }

            // Opt-in local password login (ADR 0016): single round trip, same
            // issued grant as the SSH challenge path.
            Some(pb::authenticate::Method::PasswordRequest(req)) => {
                // Bounds and the allowlist run before the verifier so no
                // backend (PAM) work is spent on oversized or foreign input;
                // all failures collapse into the same reply.
                let verifier = self
                    .state
                    .auth
                    .password_verifier(&req.username)
                    .filter(|_| {
                        !req.username.is_empty()
                            && req.username.len() <= hf_auth::MAX_USERNAME_BYTES
                            && !req.password.is_empty()
                            && req.password.len() <= hf_auth::MAX_PASSWORD_BYTES
                    });
                let accepted = match verifier {
                    Some(verifier) => {
                        let username = req.username.clone();
                        let password = req.password;
                        tokio::task::spawn_blocking(move || verifier.verify(&username, &password))
                            .await
                            .unwrap_or(false)
                    }
                    None => false,
                };
                if accepted {
                    tracing::info!(user = %req.username, "authenticated by password");
                    self.succeed_issuing_grant(request_id, req.username, AuthMethod::Password)
                        .await
                } else {
                    self.fail_auth(request_id, "authentication failed").await
                }
            }

            None => self.fail_auth(request_id, "no authentication method").await,
        }
    }

    /// Shared success tail for the credential-proving methods (SSH challenge,
    /// password): mark authenticated, audit, and answer with a session grant.
    async fn succeed_issuing_grant(
        &mut self,
        request_id: u64,
        username: String,
        method: AuthMethod,
    ) -> bool {
        self.authenticated = true;
        self.user_id = username.clone();
        self.state.auth.rate_limiter.record_success(self.peer_ip);
        self.state
            .observability
            .record(AuditEvent::AuthenticationSucceeded {
                user: username.clone(),
                source_ip: self.peer_ip,
                method,
            });
        // Issue a grant for this session (audience-bound).
        let claims = hf_auth::GrantClaims {
            sub: username.clone(),
            aud: self.state.auth.audience.clone(),
            servers: vec![],
            ops: vec![],
            iat_ms: now_ms(),
            exp_ms: now_ms().saturating_add(12 * 3600 * 1000),
            jti: hex16(&rand::random::<[u8; 16]>()),
        };
        let grant = self.state.auth.grant_signer.issue(&claims);
        let mut result = auth_ok(request_id, &username, claims.exp_ms);
        if let Some(Msg::AuthenticationResult(r)) = &mut result.message {
            // Reuse the challenge field to hand back the grant
            // (opaque bytes; the client stores it for resume).
            r.challenge = grant.as_bytes().to_vec();
        }
        self.send(0, result).await
    }

    async fn fail_auth(&self, request_id: u64, message: &str) -> bool {
        self.state
            .auth
            .rate_limiter
            .record_failure(self.peer_ip, Instant::now());
        self.state
            .observability
            .record(AuditEvent::AuthenticationFailed {
                source_ip: self.peer_ip,
                reason: RejectReason::InvalidRequest,
            });
        self.send(
            0,
            auth_failure(request_id, pb::ErrorCode::ErrUnauthenticated, message),
        )
        .await
    }

    /// Returns false when the connection must close.
    pub(crate) async fn dispatch(&mut self, channel: u64, envelope: Envelope) -> bool {
        let request_id = envelope.request_id;
        let Some(message) = envelope.message.clone() else {
            return self
                .send(
                    channel,
                    error_envelope(
                        request_id,
                        pb::ErrorCode::ErrUnknownMessage,
                        "empty envelope",
                        false,
                    ),
                )
                .await
                && false;
        };

        // Pre-auth allowlist (spec §4).
        if !self.authenticated
            && !matches!(
                message,
                Msg::ClientHello(_)
                    | Msg::Authenticate(_)
                    | Msg::Ping(_)
                    | Msg::Pong(_)
                    | Msg::Close(_)
            )
        {
            return self
                .send(
                    channel,
                    error_envelope(
                        request_id,
                        pb::ErrorCode::ErrUnauthenticated,
                        "authenticate first",
                        false,
                    ),
                )
                .await;
        }

        match (channel, message) {
            (0, Msg::ClientHello(hello)) => {
                match negotiate_server(
                    &hello,
                    &[],
                    FRAME_BYTES_DEFAULT,
                    1200,
                    self.transport_datagrams,
                ) {
                    Ok(negotiated) => {
                        let reply = server_hello(&negotiated, KEEPALIVE_INTERVAL_MS);
                        self.negotiated = Some(negotiated);
                        self.send(0, respond(request_id, Msg::ServerHello(reply)))
                            .await
                    }
                    Err(e) => {
                        let _ = self
                            .send(
                                0,
                                error_envelope(
                                    request_id,
                                    pb::ErrorCode::ErrVersion,
                                    &e.to_string(),
                                    false,
                                ),
                            )
                            .await;
                        false
                    }
                }
            }
            (0, Msg::Authenticate(auth)) => {
                if self.negotiated.is_none() {
                    return self
                        .send(
                            0,
                            error_envelope(
                                request_id,
                                pb::ErrorCode::ErrUnknownMessage,
                                "hello first",
                                false,
                            ),
                        )
                        .await;
                }
                self.handle_authenticate(request_id, auth).await
            }
            (_, Msg::Ping(ping)) => {
                self.send(
                    channel,
                    respond(request_id, Msg::Pong(pb::Pong { nonce: ping.nonce })),
                )
                .await
            }
            (0, Msg::Close(_)) => false,
            (0, Msg::ListServers(_)) => {
                let list = pb::ServerList {
                    servers: vec![pb::ServerInfo {
                        server_id: self.state.server_id.to_wire(),
                        display_name: "local".into(),
                        healthy: true,
                    }],
                };
                self.send(0, respond(request_id, Msg::ServerList(list)))
                    .await
            }
            (0, Msg::ListShells(_)) => {
                if !self.permits("list") {
                    return self
                        .send(
                            0,
                            error_envelope(
                                request_id,
                                pb::ErrorCode::ErrForbidden,
                                "grant does not permit list",
                                false,
                            ),
                        )
                        .await;
                }
                let shells = self
                    .state
                    .manager
                    .list_shells()
                    .into_iter()
                    // Per-user isolation (threat model T12): a client only sees
                    // shells it owns, so it cannot enumerate or act on other
                    // users' shell ids. In dev/single-user mode every shell
                    // shares the one user id, so this is a no-op there.
                    .filter(|info| info.owner == self.user_id)
                    .map(|info| pb::ShellInfo {
                        server_id: self.state.server_id.to_wire(),
                        shell_id: info.shell_id.to_wire(),
                        state: shell_state_pb(info.state) as i32,
                        title: String::new(),
                        created_at_ms: info.created_at_ms,
                        last_attached_at_ms: info.last_attached_at_ms,
                    })
                    .collect();
                self.send(
                    0,
                    respond(request_id, Msg::ShellList(pb::ShellList { shells })),
                )
                .await
            }
            (0, Msg::OpenShell(open)) => {
                if !self.permits("open") {
                    self.state
                        .observability
                        .record(AuditEvent::ShellOperationRejected {
                            user: self.user_id.clone(),
                            shell_id: None,
                            operation: ShellOperation::Open,
                            reason: RejectReason::Forbidden,
                        });
                    return self
                        .send(
                            0,
                            error_envelope(
                                request_id,
                                pb::ErrorCode::ErrForbidden,
                                "grant does not permit open",
                                false,
                            ),
                        )
                        .await;
                }
                let Ok(idempotency_key) = <[u8; 16]>::try_from(open.idempotency_key.as_slice())
                else {
                    return self
                        .send(
                            0,
                            error_envelope(
                                request_id,
                                pb::ErrorCode::ErrUnknownMessage,
                                "idempotency_key must be 16 bytes",
                                false,
                            ),
                        )
                        .await;
                };
                let manager_state = Arc::clone(&self.state);
                let audit_account =
                    (!open.unix_account.is_empty()).then(|| open.unix_account.clone());
                let req = OpenShellRequest {
                    user: self.user_id.clone(),
                    requested_account: (!open.unix_account.is_empty())
                        .then(|| open.unix_account.clone()),
                    command: (!open.command.is_empty()).then(|| open.command.clone()),
                    args: vec![],
                    cols: open.initial_cols as u16,
                    rows: open.initial_rows as u16,
                    idempotency_key,
                };
                let result =
                    tokio::task::spawn_blocking(move || manager_state.manager.open_shell(&req))
                        .await
                        .unwrap_or_else(|e| Err(SessionError::Internal(e.to_string())));
                match result {
                    Ok(opened) => {
                        self.state.observability.record(AuditEvent::ShellOpened {
                            user: self.user_id.clone(),
                            shell_id: opened.shell_id,
                            account: audit_account,
                            reused: opened.reused,
                        });
                        let mut env = respond(
                            request_id,
                            Msg::ShellOpened(pb::ShellOpened {
                                resume_token: opened.resume_token.to_wire(),
                                expires_at_ms: 0,
                            }),
                        );
                        env.server_id = self.state.server_id.to_wire();
                        env.shell_id = opened.shell_id.to_wire();
                        self.send(0, env).await
                    }
                    Err(e) => {
                        self.state
                            .observability
                            .record(AuditEvent::ShellOperationRejected {
                                user: self.user_id.clone(),
                                shell_id: None,
                                operation: ShellOperation::Open,
                                reason: reject_reason(&e),
                            });
                        self.send(0, session_error(request_id, &e)).await
                    }
                }
            }
            (0, Msg::TerminateShell(_)) => {
                if !self.permits("terminate") {
                    self.state
                        .observability
                        .record(AuditEvent::ShellOperationRejected {
                            user: self.user_id.clone(),
                            shell_id: None,
                            operation: ShellOperation::Terminate,
                            reason: RejectReason::Forbidden,
                        });
                    return self
                        .send(
                            0,
                            error_envelope(
                                request_id,
                                pb::ErrorCode::ErrForbidden,
                                "grant does not permit terminate",
                                false,
                            ),
                        )
                        .await;
                }
                let Ok(shell_id) = ShellId::from_wire(&envelope.shell_id) else {
                    return self
                        .send(
                            0,
                            error_envelope(
                                request_id,
                                pb::ErrorCode::ErrNotFound,
                                "bad shell id",
                                false,
                            ),
                        )
                        .await;
                };
                // Per-user isolation (threat model T12): only the shell's owner
                // may terminate it. A shell owned by someone else is reported as
                // not-found, so a client cannot even probe for the existence of
                // another user's shell by id. Owner is immutable (set at open),
                // so there is no check/act race.
                match self.state.manager.shell_info(&shell_id) {
                    Ok(info) if info.owner == self.user_id => {}
                    _ => {
                        self.state
                            .observability
                            .record(AuditEvent::ShellOperationRejected {
                                user: self.user_id.clone(),
                                shell_id: Some(shell_id),
                                operation: ShellOperation::Terminate,
                                reason: RejectReason::NotFound,
                            });
                        return self
                            .send(
                                0,
                                error_envelope(
                                    request_id,
                                    pb::ErrorCode::ErrNotFound,
                                    "no such shell",
                                    false,
                                ),
                            )
                            .await;
                    }
                }
                let manager_state = Arc::clone(&self.state);
                let result =
                    tokio::task::spawn_blocking(move || manager_state.manager.terminate(&shell_id))
                        .await
                        .unwrap_or_else(|e| Err(SessionError::Internal(e.to_string())));
                match result {
                    Ok(exit) => {
                        self.state
                            .observability
                            .record(AuditEvent::ShellTerminated {
                                user: self.user_id.clone(),
                                shell_id,
                                exit_code: exit.exit_code,
                            });
                        let mut env = respond(
                            request_id,
                            Msg::ShellExited(pb::ShellExited {
                                exit_code: exit.exit_code as i32,
                                signaled: !exit.success && exit.exit_code == 0,
                                signal: String::new(),
                            }),
                        );
                        env.shell_id = envelope.shell_id.clone();
                        self.send(0, env).await
                    }
                    Err(e) => {
                        self.state
                            .observability
                            .record(AuditEvent::ShellOperationRejected {
                                user: self.user_id.clone(),
                                shell_id: Some(shell_id),
                                operation: ShellOperation::Terminate,
                                reason: reject_reason(&e),
                            });
                        self.send(0, session_error(request_id, &e)).await
                    }
                }
            }
            // ---- Attachment channels (client-opened, odd IDs) ----
            (ch, Msg::AttachShell(attach)) if ch != 0 => self.attach(ch, &envelope, attach).await,
            (ch, Msg::TerminalInput(input)) if ch != 0 => {
                if let Some(b) = self.attachments.get(&ch) {
                    if let Err(e) = self.state.manager.write_input(&b.shell_id, &input.data) {
                        return self.send(ch, session_error(request_id, &e)).await;
                    }
                }
                true
            }
            (ch, Msg::TerminalResize(resize)) if ch != 0 => {
                if let Some(b) = self.attachments.get(&ch) {
                    // Newest size wins; errors on exited shells are benign.
                    let _ = self.state.manager.resize(
                        &b.shell_id,
                        resize.cols as u16,
                        resize.rows as u16,
                    );
                }
                true
            }
            (ch, Msg::RequestHistory(req)) if ch != 0 => {
                let Some(b) = self.attachments.get(&ch) else {
                    return self
                        .send(
                            ch,
                            error_envelope(
                                request_id,
                                pb::ErrorCode::ErrNotFound,
                                "no attachment on channel",
                                false,
                            ),
                        )
                        .await;
                };
                match self.state.manager.history(
                    &b.shell_id,
                    req.before_line_id,
                    req.maximum_lines.min(10_000),
                    // Cap to half the *negotiated* frame size (not the default),
                    // so the HistoryChunk always fits within what this client
                    // agreed to receive, leaving room for envelope overhead.
                    req.maximum_bytes.min(self.max_frame_bytes() / 2),
                ) {
                    Ok(range) => {
                        let chunk = respond(
                            request_id,
                            Msg::HistoryChunk(pb::HistoryChunk {
                                first_line_id: range.first_line_id,
                                lines: range.lines,
                                truncated_by_eviction: range.truncated_by_eviction,
                            }),
                        );
                        if !self.send(ch, chunk).await {
                            return false;
                        }
                        let oldest = self
                            .state
                            .manager
                            .history_bounds(&b.shell_id)
                            .map(|(oldest, _)| oldest)
                            .unwrap_or(0);
                        self.send(
                            ch,
                            respond(
                                request_id,
                                Msg::HistoryEnd(pb::HistoryEnd {
                                    oldest_available_line_id: oldest,
                                }),
                            ),
                        )
                        .await
                    }
                    Err(e) => self.send(ch, session_error(request_id, &e)).await,
                }
            }
            (ch, Msg::DetachShell(_)) if ch != 0 => {
                if let Some(b) = self.attachments.remove(&ch) {
                    let _ = self.state.manager.detach(&b.shell_id, b.attachment_id);
                    self.state.observability.record(AuditEvent::ShellDetached {
                        user: self.user_id.clone(),
                        shell_id: b.shell_id,
                    });
                }
                true
            }
            (_, _) => {
                self.send(
                    channel,
                    error_envelope(
                        request_id,
                        pb::ErrorCode::ErrUnknownMessage,
                        "unexpected message for this channel",
                        false,
                    ),
                )
                .await
            }
        }
    }

    async fn attach(&mut self, channel: u64, envelope: &Envelope, attach: pb::AttachShell) -> bool {
        let request_id = envelope.request_id;
        if !self.permits("attach") {
            self.state
                .observability
                .record(AuditEvent::ShellOperationRejected {
                    user: self.user_id.clone(),
                    shell_id: None,
                    operation: ShellOperation::Attach,
                    reason: RejectReason::Forbidden,
                });
            return self
                .send(
                    channel,
                    error_envelope(
                        request_id,
                        pb::ErrorCode::ErrForbidden,
                        "grant does not permit attach",
                        false,
                    ),
                )
                .await;
        }
        if self.attachments.contains_key(&channel) {
            return self
                .send(
                    channel,
                    error_envelope(
                        request_id,
                        pb::ErrorCode::ErrUnknownMessage,
                        "channel already attached",
                        false,
                    ),
                )
                .await;
        }
        let Ok(shell_id) = ShellId::from_wire(&envelope.shell_id) else {
            return self
                .send(
                    channel,
                    error_envelope(
                        request_id,
                        pb::ErrorCode::ErrNotFound,
                        "bad shell id",
                        false,
                    ),
                )
                .await;
        };
        let Some(token) = ResumeToken::from_wire(&attach.resume_token) else {
            return self
                .send(
                    channel,
                    error_envelope(
                        request_id,
                        pb::ErrorCode::ErrTokenExpired,
                        "malformed resume token",
                        false,
                    ),
                )
                .await;
        };

        match self.state.manager.attach(
            &self.user_id,
            &shell_id,
            &token,
            attach.cols as u16,
            attach.rows as u16,
        ) {
            Ok(attachment) => {
                self.state.observability.record(AuditEvent::ShellAttached {
                    user: self.user_id.clone(),
                    shell_id,
                });
                self.attachments.insert(
                    channel,
                    Binding {
                        shell_id,
                        attachment_id: attachment.attachment_id,
                    },
                );

                let mut reply = respond(
                    request_id,
                    Msg::ShellAttached(pb::ShellAttached {
                        screen_snapshot: attachment.snapshot.clone(),
                        screen_revision: attachment.screen_revision,
                        rotated_resume_token: attachment.rotated_resume_token.to_wire(),
                        oldest_history_line_id: attachment.oldest_history_line_id,
                        newest_history_line_id: attachment.newest_history_line_id,
                    }),
                );
                reply.server_id = self.state.server_id.to_wire();
                reply.shell_id = envelope.shell_id.clone();
                if !self.send(channel, reply).await {
                    return false;
                }

                // Forward live events from the sync attachment channel to the
                // async writer. Bounded on both sides; a full outgoing queue
                // eventually backs up the attachment queue, whose overflow
                // detaches this attachment upstream (spec §8).
                let out = self.out.clone();
                let events = attachment.events;
                std::thread::Builder::new()
                    .name("hf-attach-forward".into())
                    .spawn(move || {
                        let mut exited = false;
                        for event in events.iter() {
                            let envelope = match event {
                                AttachmentEvent::Output(data) => Envelope {
                                    request_id: 0,
                                    server_id: vec![],
                                    shell_id: vec![],
                                    message: Some(Msg::TerminalOutput(pb::TerminalOutput { data })),
                                },
                                AttachmentEvent::Exited(exit) => {
                                    exited = true;
                                    Envelope {
                                        request_id: 0,
                                        server_id: vec![],
                                        shell_id: vec![],
                                        message: Some(Msg::ShellExited(pb::ShellExited {
                                            exit_code: exit.exit_code as i32,
                                            signaled: !exit.success,
                                            signal: String::new(),
                                        })),
                                    }
                                }
                            };
                            if out.blocking_send((channel, envelope)).is_err() {
                                return;
                            }
                        }
                        // Event channel closed without an exit: session-core
                        // force-detached this attachment (slow consumer, spec
                        // §8) or it was torn down on another path. Say so on
                        // the wire (ERR_TOO_SLOW, spec §13) so the client can
                        // reattach for a fresh snapshot instead of wedging on
                        // a stale frame. Clients that detached deliberately
                        // no longer route this channel, so the frame is inert
                        // for them.
                        if !exited {
                            let envelope = error_envelope(
                                0,
                                pb::ErrorCode::ErrTooSlow,
                                "attachment dropped: output overran the slow-consumer bound",
                                true,
                            );
                            let _ = out.blocking_send((channel, envelope));
                        }
                    })
                    .expect("spawn forwarder");
                true
            }
            Err(e) => {
                self.state
                    .observability
                    .record(AuditEvent::ShellOperationRejected {
                        user: self.user_id.clone(),
                        shell_id: Some(shell_id),
                        operation: ShellOperation::Attach,
                        reason: reject_reason(&e),
                    });
                self.send(channel, session_error(request_id, &e)).await
            }
        }
    }
}

fn reject_reason(error: &SessionError) -> RejectReason {
    match error {
        SessionError::ShellNotFound => RejectReason::NotFound,
        SessionError::NotRunning => RejectReason::NotRunning,
        SessionError::LimitExceeded(_) => RejectReason::LimitExceeded,
        SessionError::Forbidden => RejectReason::Forbidden,
        SessionError::InvalidToken => RejectReason::InvalidToken,
        SessionError::TokenReplayed => RejectReason::TokenReplayed,
        SessionError::Pty(_) | SessionError::Internal(_) => RejectReason::Internal,
    }
}

fn respond(request_id: u64, message: Msg) -> Envelope {
    Envelope {
        request_id,
        server_id: vec![],
        shell_id: vec![],
        message: Some(message),
    }
}

fn auth_ok(request_id: u64, user_id: &str, expires_at_ms: i64) -> Envelope {
    respond(
        request_id,
        Msg::AuthenticationResult(pb::AuthenticationResult {
            ok: true,
            user_id: user_id.to_string(),
            expires_at_ms,
            error_code: 0,
            error_message: String::new(),
            challenge: vec![],
        }),
    )
}

fn auth_failure(request_id: u64, code: pb::ErrorCode, message: &str) -> Envelope {
    respond(
        request_id,
        Msg::AuthenticationResult(pb::AuthenticationResult {
            ok: false,
            user_id: String::new(),
            expires_at_ms: 0,
            error_code: code as i32,
            error_message: message.to_string(),
            challenge: vec![],
        }),
    )
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn hex16(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn error_envelope(request_id: u64, code: pb::ErrorCode, text: &str, retryable: bool) -> Envelope {
    respond(
        request_id,
        Msg::Error(pb::Error {
            code: code as i32,
            human_message: text.into(),
            retryable,
        }),
    )
}

fn session_error(request_id: u64, e: &SessionError) -> Envelope {
    let (code, retryable) = match e {
        SessionError::ShellNotFound => (pb::ErrorCode::ErrNotFound, false),
        SessionError::NotRunning => (pb::ErrorCode::ErrNotFound, false),
        SessionError::LimitExceeded(_) => (pb::ErrorCode::ErrLimitExceeded, true),
        SessionError::Forbidden => (pb::ErrorCode::ErrForbidden, false),
        SessionError::InvalidToken => (pb::ErrorCode::ErrTokenExpired, false),
        // Distinct from expiry: a superseded-but-once-valid token is a theft
        // signal (spec §12) and must reach the client as code 11 so it can
        // tell "recover via idempotency key" from "token was garbage".
        SessionError::TokenReplayed => (pb::ErrorCode::ErrTokenReplayed, false),
        SessionError::Pty(_) | SessionError::Internal(_) => (pb::ErrorCode::ErrInternal, true),
    };
    error_envelope(request_id, code, &e.to_string(), retryable)
}

fn shell_state_pb(state: ShellState) -> pb::ShellState {
    match state {
        ShellState::Running => pb::ShellState::Running,
        ShellState::Terminating => pb::ShellState::Terminating,
        ShellState::Exited => pb::ShellState::Exited,
    }
}
