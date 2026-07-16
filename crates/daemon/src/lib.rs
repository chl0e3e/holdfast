//! holdfastd library: the standalone Holdfast daemon.
//!
//! Transports (identical protocol semantics, spec §2):
//! - **WebTransport over QUIC** (UDP) — primary, Phase 3.
//! - **WebSocket** (TCP, via the HTTP listener) — fallback, Phase 2.
//!
//! The HTTP listener also serves the browser client and
//! `/webtransport-info` (WebTransport port + certificate hash for
//! `serverCertificateHashes` pinning during development).
//!
//! Authentication: explicit dev mode — any `Authenticate` is accepted, and
//! the daemon refuses to start dev mode on non-loopback binds. The real local
//! issuer (SSH challenge/response, spec §5) replaces this before anything
//! listens beyond localhost.

pub mod wire;

pub mod auth;
mod conn;
mod webtransport;
mod ws;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::Router;
use hf_protocol::ids::ServerId;
use hf_session_core::{SessionCoreConfig, ShellManager};

use crate::auth::{AuthMode, AuthState};

/// How the daemon authenticates clients (Clone/Debug-safe config; built into
/// [`AuthState`] at startup).
#[derive(Debug, Clone)]
pub enum AuthConfig {
    /// Accept any client. Permitted only on loopback binds (dev/tests).
    DevInsecure,
    /// SSH public-key challenge/response: username → authorized_keys text.
    SshKeys { users: BTreeMap<String, String> },
}

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// HTTP/WebSocket listener (TCP).
    pub bind: SocketAddr,
    /// WebTransport listener (UDP); `None` disables WebTransport.
    pub webtransport_bind: Option<SocketAddr>,
    /// Directory of built browser-client assets to serve at `/`.
    pub web_root: Option<PathBuf>,
    pub auth: AuthConfig,
    /// Allowed browser `Origin` values for the WebSocket endpoint (threat
    /// model T7). `None` allows any origin (development); `Some(list)` rejects
    /// WebSocket upgrades whose Origin is not listed. Requests without an
    /// Origin header (native/non-browser clients) are always allowed.
    pub allowed_origins: Option<Vec<String>>,
    /// Per-user allowed Unix accounts (threat model T12, authorization half).
    /// `None` = permissive (dev). `Some(map)` enforces the allowlist; the
    /// first account listed for a user is their default. The uid/gid switch
    /// itself is a deployment concern (ADR 0007).
    pub account_policy: Option<BTreeMap<String, Vec<String>>>,
    /// ed25519 seed for the connection-grant signing key. `None` generates a
    /// fresh random key on every start, which invalidates all previously issued
    /// grants across a restart; set this (from a persisted secret) so grants —
    /// and therefore client reconnects — survive a daemon restart.
    pub grant_signing_key: Option<[u8; 32]>,
    pub session: SessionCoreConfig,
}

impl Default for DaemonConfig {
    fn default() -> DaemonConfig {
        DaemonConfig {
            bind: "127.0.0.1:8080".parse().unwrap(),
            webtransport_bind: Some("127.0.0.1:0".parse().unwrap()),
            web_root: None,
            auth: AuthConfig::DevInsecure,
            allowed_origins: None,
            account_policy: None,
            grant_signing_key: None,
            session: SessionCoreConfig::default(),
        }
    }
}

pub struct AppState {
    pub manager: ShellManager,
    pub server_id: ServerId,
    pub auth: AuthState,
    pub allowed_origins: Option<Vec<String>>,
    /// (UDP port, cert hash base64) when WebTransport is enabled.
    pub webtransport_info: Option<(u16, String)>,
}

impl AppState {
    /// Origin check for browser endpoints (threat model T7). No Origin header
    /// (native clients) is allowed; an allowlist rejects unknown origins.
    fn origin_allowed(&self, origin: Option<&str>) -> bool {
        match (&self.allowed_origins, origin) {
            (None, _) => true,        // dev: any origin
            (Some(_), None) => true,  // non-browser client
            (Some(list), Some(o)) => list.iter().any(|a| a == o),
        }
    }
}

/// A bound, running daemon (used directly by integration tests).
pub struct Daemon {
    pub local_addr: SocketAddr,
    pub webtransport_addr: Option<SocketAddr>,
    pub webtransport_cert_hash_base64: Option<String>,
    pub server_id: ServerId,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl Daemon {
    /// Bind and start serving. Bind addresses may use port 0.
    pub async fn start(config: DaemonConfig) -> anyhow::Result<Daemon> {
        if matches!(config.auth, AuthConfig::DevInsecure) {
            let mut binds = vec![config.bind];
            binds.extend(config.webtransport_bind);
            for bind in binds {
                if !bind.ip().is_loopback() {
                    anyhow::bail!(
                        "refusing dev-auth on non-loopback bind {bind} (threat model T7/T4)"
                    );
                }
            }
        }

        let server_id = ServerId(rand::random());
        let mut handles = Vec::new();

        // Build the auth state; audience binds grants to this server id.
        let audience = server_id.to_string();
        let auth_mode = match &config.auth {
            AuthConfig::DevInsecure => AuthMode::DevInsecure,
            AuthConfig::SshKeys { users } => {
                let mut verifiers = std::collections::HashMap::new();
                for (username, keys) in users {
                    let verifier = hf_auth::SshVerifier::from_authorized_keys(keys)
                        .map_err(|e| anyhow::anyhow!("authorized_keys for {username}: {e}"))?;
                    verifiers.insert(username.clone(), verifier);
                }
                AuthMode::SshKeys { users: verifiers }
            }
        };
        let auth = AuthState::new(auth_mode, audience, config.grant_signing_key);

        let wt_listener = config
            .webtransport_bind
            .map(webtransport::WtListener::bind)
            .transpose()?;
        let webtransport_info = wt_listener
            .as_ref()
            .map(|l| (l.local_addr.port(), l.cert_hash_base64.clone()));

        let manager = match &config.account_policy {
            Some(map) => {
                let allowed: std::collections::HashMap<String, Vec<String>> =
                    map.iter().map(|(u, a)| (u.clone(), a.clone())).collect();
                ShellManager::with_policy(
                    config.session.clone(),
                    Arc::new(hf_session_core::StaticPolicy::new(allowed)),
                )
            }
            None => ShellManager::new(config.session.clone()),
        };
        let state = Arc::new(AppState {
            manager,
            server_id,
            auth,
            allowed_origins: config.allowed_origins.clone(),
            webtransport_info: webtransport_info.clone(),
        });

        if let Some(listener) = &wt_listener {
            handles.push(listener.spawn_accept_loop(Arc::clone(&state)));
        }

        let mut router = Router::new()
            .route("/terminal/ws", any(ws_handler))
            .route("/webtransport-info", get(wt_info_handler))
            .with_state(Arc::clone(&state));
        if let Some(root) = &config.web_root {
            router = router.fallback_service(tower_http::services::ServeDir::new(root));
        }

        let listener = tokio::net::TcpListener::bind(config.bind).await?;
        let local_addr = listener.local_addr()?;
        tracing::info!(
            %local_addr,
            webtransport = ?wt_listener.as_ref().map(|l| l.local_addr),
            server_id = %server_id,
            "holdfastd listening"
        );

        handles.push(tokio::spawn(async move {
            let service = router.into_make_service_with_connect_info::<SocketAddr>();
            if let Err(e) = axum::serve(listener, service).await {
                tracing::error!("server error: {e}");
            }
        }));

        Ok(Daemon {
            local_addr,
            webtransport_addr: wt_listener.as_ref().map(|l| l.local_addr),
            webtransport_cert_hash_base64: wt_listener.map(|l| l.cert_hash_base64),
            server_id,
            handles,
        })
    }

    pub fn abort(&self) {
        for handle in &self.handles {
            handle.abort();
        }
    }
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Response {
    let origin = headers.get(axum::http::header::ORIGIN).and_then(|v| v.to_str().ok());
    if !state.origin_allowed(origin) {
        tracing::warn!(?origin, "rejected WebSocket upgrade: origin not allowed");
        return (axum::http::StatusCode::FORBIDDEN, "origin not allowed").into_response();
    }
    ws.on_upgrade(move |socket| ws::handle_connection(socket, state, peer.ip()))
}

async fn wt_info_handler(State(state): State<Arc<AppState>>) -> Response {
    match &state.webtransport_info {
        Some((port, hash)) => (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            format!(r#"{{"port":{port},"certHashBase64":"{hash}"}}"#),
        )
            .into_response(),
        None => (axum::http::StatusCode::NOT_FOUND, "webtransport disabled").into_response(),
    }
}
