//! holdfastd library: the standalone Holdfast daemon.
//!
//! Transport (spec §2, ADR 0014): **WebTransport over HTTP/3/QUIC** (UDP),
//! only. The same QUIC endpoint serves the browser client page over plain
//! HTTP/3 GET. The TCP listener is a bootstrap: in production (WebPKI
//! certificate) it serves a "QUIC required" interstitial with an `Alt-Svc`
//! upgrade; in development it serves the app plus `/webtransport-info`
//! (WebTransport port + certificate hash for `serverCertificateHashes`
//! pinning). A legacy WebSocket transport survives behind a test-only config
//! gate (`enable_websocket`, default off) to keep the session layer's
//! transport-neutrality tested.
//!
//! Authentication: explicit dev mode — any `Authenticate` is accepted, and
//! the daemon refuses to start dev mode on non-loopback binds. The real local
//! issuer (SSH challenge/response, spec §5) replaces this before anything
//! listens beyond localhost.

pub mod wire;

pub mod observability;

#[cfg(feature = "agent-mode")]
pub mod agent_mode;
pub mod auth;
mod conn;
mod uploads;
mod webtransport;
mod ws;

use std::collections::{BTreeMap, BTreeSet};
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

use crate::observability::{AuditRecord, MetricsSnapshot, Observability, DEFAULT_AUDIT_CAPACITY};

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

/// Opt-in local password login (ADR 0016): allowlisted usernames plus the
/// verifier (PAM in production via `hf_auth::pam`, fakes in tests). Requires
/// a real [`AuthConfig`] mode; refused alongside `DevInsecure`.
#[derive(Clone)]
pub struct PasswordAuthConfig {
    pub users: BTreeSet<String>,
    pub verifier: Arc<dyn hf_auth::PasswordVerifier>,
}

impl std::fmt::Debug for PasswordAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The verifier is opaque (and must never expose secrets); show users.
        f.debug_struct("PasswordAuthConfig")
            .field("users", &self.users)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// HTTP/WebSocket listener (TCP).
    pub bind: SocketAddr,
    /// WebTransport listener (UDP); `None` disables WebTransport.
    pub webtransport_bind: Option<SocketAddr>,
    /// PEM certificate chain for production WebTransport/WebPKI. Must be set
    /// together with `webtransport_private_key`; absent means a short-lived
    /// self-signed development identity, allowed only on loopback.
    pub webtransport_certificate: Option<PathBuf>,
    /// PEM private key paired with `webtransport_certificate`.
    pub webtransport_private_key: Option<PathBuf>,
    /// Directory of built browser-client assets to serve at `/`.
    pub web_root: Option<PathBuf>,
    pub auth: AuthConfig,
    /// Password login for allowlisted users; `None` = key-only (the default).
    pub password_auth: Option<PasswordAuthConfig>,
    /// Allowed browser `Origin` values (threat model T7), enforced on the
    /// WebTransport CONNECT request (and the WebSocket upgrade when that
    /// endpoint is enabled). `None` allows any origin (development);
    /// `Some(list)` rejects browser requests whose Origin is not listed.
    /// Requests without an Origin header (native clients) are always allowed.
    pub allowed_origins: Option<Vec<String>>,
    /// Serve the legacy `/terminal/ws` WebSocket transport. Off by default:
    /// the product is HTTP/3-only (ADR 0014) and the shipped binary never
    /// enables this; it exists so protocol tests can exercise the
    /// transport-neutral session layer over a second transport.
    pub enable_websocket: bool,
    /// Per-user allowed Unix accounts (threat model T12, authorization half).
    /// `None` = permissive (dev). `Some(map)` enforces the allowlist; the
    /// first account listed for a user is their default. The uid/gid switch
    /// itself is a deployment concern (ADR 0007).
    pub account_policy: Option<BTreeMap<String, Vec<String>>>,
    /// ed25519 seed for the connection-grant signing key. `None` generates a
    /// fresh random key on every start, which invalidates all previously issued
    /// grants across a restart; set this (from a persisted secret) so grants —
    /// and therefore client reconnects — survive a daemon restart. When set,
    /// the standalone server identity is derived from this key's public half
    /// unless `server_id` overrides it (ADR 0017): grants are audience-bound
    /// to the server id, so a persisted key without a persisted identity would
    /// still fail verification after a restart.
    pub grant_signing_key: Option<[u8; 32]>,
    /// Explicit stable server identity. `None`: derived from
    /// `grant_signing_key` when that is set, else random per start (dev).
    pub server_id: Option<ServerId>,
    /// Absolute temporary upload root. `None` keeps file transfer disabled and
    /// unadvertised. See ADR 0028.
    pub upload_root: Option<PathBuf>,
    pub upload_max_file_bytes: u64,
    pub upload_retention: std::time::Duration,
    pub session: SessionCoreConfig,
}

impl Default for DaemonConfig {
    fn default() -> DaemonConfig {
        DaemonConfig {
            bind: "127.0.0.1:8080".parse().unwrap(),
            webtransport_bind: Some("127.0.0.1:0".parse().unwrap()),
            webtransport_certificate: None,
            webtransport_private_key: None,
            web_root: None,
            auth: AuthConfig::DevInsecure,
            password_auth: None,
            allowed_origins: None,
            enable_websocket: false,
            account_policy: None,
            grant_signing_key: None,
            server_id: None,
            upload_root: None,
            upload_max_file_bytes: hf_protocol::UPLOAD_FILE_BYTES_DEFAULT,
            upload_retention: std::time::Duration::from_secs(24 * 60 * 60),
            session: SessionCoreConfig::default(),
        }
    }
}

/// Stable server identity from the grant signing key's *public* half:
/// SHA-256("holdfast-server-id-v1" || ed25519 public key), truncated to the
/// 16-byte id (ADR 0017). Deriving from public material keeps the seed out of
/// anything that ends up in logs or wire ids.
fn derive_server_id(seed: &[u8; 32]) -> ServerId {
    use sha2::{Digest, Sha256};
    let public = hf_auth::GrantSigner::from_bytes(seed)
        .verifier()
        .public_bytes();
    let mut hasher = Sha256::new();
    hasher.update(b"holdfast-server-id-v1");
    hasher.update(public);
    let digest = hasher.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    ServerId(id)
}

pub struct AppState {
    pub manager: ShellManager,
    pub server_id: ServerId,
    pub auth: AuthState,
    pub allowed_origins: Option<Vec<String>>,
    /// (UDP port, cert hash base64) when WebTransport is enabled.
    pub webtransport_info: Option<(u16, String, WebTransportCertificateMode)>,
    /// Raw certificate SHA-256, the SSH-auth channel binding for WebTransport
    /// connections (ADR 0008). `None` when WebTransport is disabled.
    pub webtransport_cert_hash: Option<[u8; 32]>,
    pub observability: Observability,
    pub(crate) uploads: Option<Arc<uploads::UploadService>>,
}

impl AppState {
    /// Origin check for browser endpoints (threat model T7). No Origin header
    /// (native clients) is allowed; an allowlist rejects unknown origins.
    fn origin_allowed(&self, origin: Option<&str>) -> bool {
        match (&self.allowed_origins, origin) {
            (None, _) => true,       // dev: any origin
            (Some(_), None) => true, // non-browser client
            (Some(list), Some(o)) => list.iter().any(|a| a == o),
        }
    }
}

/// A bound, running daemon (used directly by integration tests).
pub struct Daemon {
    pub local_addr: SocketAddr,
    pub webtransport_addr: Option<SocketAddr>,
    pub webtransport_cert_hash_base64: Option<String>,
    pub webtransport_certificate_mode: Option<WebTransportCertificateMode>,
    pub server_id: ServerId,
    observability: Observability,
    handles: Vec<tokio::task::JoinHandle<()>>,
}

/// How browser clients authenticate the WebTransport certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebTransportCertificateMode {
    /// Short-lived self-signed development certificate pinned by SHA-256.
    DevelopmentHashPin,
    /// Operator-configured certificate validated through browser WebPKI.
    WebPki,
}

impl WebTransportCertificateMode {
    fn as_wire_name(self) -> &'static str {
        match self {
            Self::DevelopmentHashPin => "hash-pin",
            Self::WebPki => "webpki",
        }
    }
}

impl Daemon {
    /// Bind and start serving. Bind addresses may use port 0.
    pub async fn start(config: DaemonConfig) -> anyhow::Result<Daemon> {
        match (
            &config.webtransport_certificate,
            &config.webtransport_private_key,
        ) {
            (Some(_), Some(_)) | (None, None) => {}
            _ => anyhow::bail!("WebTransport TLS requires both certificate and private-key paths"),
        }
        if let Some(bind) = config.webtransport_bind {
            if !bind.ip().is_loopback() && config.webtransport_certificate.is_none() {
                anyhow::bail!(
                    "refusing self-signed WebTransport on non-loopback bind {bind}; configure a public certificate and private key"
                );
            }
        } else if config.webtransport_certificate.is_some() {
            anyhow::bail!("WebTransport certificate configured while WebTransport is disabled");
        }
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
            if config.password_auth.is_some() {
                anyhow::bail!("password auth requires a real auth mode, not dev-auth");
            }
        }
        if let Some(password) = &config.password_auth {
            if password.users.is_empty() {
                anyhow::bail!("password auth enabled with an empty user allowlist");
            }
            for user in &password.users {
                if user.is_empty() || user.len() > hf_auth::MAX_USERNAME_BYTES {
                    anyhow::bail!(
                        "password-auth username must be 1..={} bytes",
                        hf_auth::MAX_USERNAME_BYTES
                    );
                }
            }
        }
        if config.upload_max_file_bytes > hf_protocol::UPLOAD_FILE_BYTES_HARD_MAX {
            anyhow::bail!(
                "upload maximum exceeds the hard {}-byte ceiling",
                hf_protocol::UPLOAD_FILE_BYTES_HARD_MAX
            );
        }
        if let Some(root) = &config.upload_root {
            if !root.is_absolute() {
                anyhow::bail!("upload root must be absolute");
            }
            if root.to_str().is_none() {
                anyhow::bail!("upload root must be valid UTF-8 for the wire path");
            }
            if config.session.privilege_drop && config.session.spawner_socket.is_none() {
                anyhow::bail!(
                    "multi-user uploads require --spawner-socket; refusing daemon-owned output"
                );
            }
        }

        let server_id = match (config.server_id, &config.grant_signing_key) {
            (Some(id), _) => id,
            (None, Some(seed)) => derive_server_id(seed),
            // Dev: ephemeral identity; grants die with the process anyway.
            (None, None) => ServerId(rand::random()),
        };
        let observability = Observability::new(server_id, DEFAULT_AUDIT_CAPACITY);
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
        let password_auth = config.password_auth.as_ref().map(|p| auth::PasswordAuth {
            users: p.users.clone(),
            verifier: p.verifier.clone(),
        });
        let auth = AuthState::new(auth_mode, password_auth, audience, config.grant_signing_key);

        let wt_listener = config
            .webtransport_bind
            .map(|bind| {
                webtransport::WtListener::bind(
                    bind,
                    config.webtransport_certificate.as_deref(),
                    config.webtransport_private_key.as_deref(),
                    config.web_root.clone(),
                )
            })
            .transpose()?;
        let webtransport_info = wt_listener.as_ref().map(|l| {
            (
                l.local_addr.port(),
                l.cert_hash_base64.clone(),
                l.certificate_mode,
            )
        });
        let webtransport_cert_hash = wt_listener.as_ref().map(|l| l.cert_hash);

        let uploads = match &config.upload_root {
            None => None,
            Some(_root) if config.session.privilege_drop => {
                Some(Arc::new(uploads::UploadService::spawner(
                    config
                        .session
                        .spawner_socket
                        .clone()
                        .expect("checked above"),
                    config.upload_max_file_bytes,
                )))
            }
            Some(root) => {
                std::fs::create_dir_all(root)?;
                let metadata = std::fs::symlink_metadata(root)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    anyhow::bail!("upload root must be a non-symlink directory");
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))?;
                }
                Some(Arc::new(uploads::UploadService::same_uid(
                    root.clone(),
                    config.upload_max_file_bytes,
                )?))
            }
        };

        let manager = build_shell_manager(config.session.clone(), &config.account_policy);
        let state = Arc::new(AppState {
            manager,
            server_id,
            auth,
            allowed_origins: config.allowed_origins.clone(),
            webtransport_info: webtransport_info.clone(),
            webtransport_cert_hash,
            observability: observability.clone(),
            uploads: uploads.clone(),
        });

        if let Some(listener) = &wt_listener {
            handles.push(listener.spawn_accept_loop(Arc::clone(&state)));
        }

        // Idle-shell expiry reaper (ADR 0021): operator opt-in — reclaims
        // shells left Running with zero attachments past the TTL, with a
        // distinct audit event so expiry is never mistaken for a terminate.
        if let Some(ttl) = config.session.idle_shell_ttl {
            let reaper_state = Arc::clone(&state);
            handles.push(tokio::spawn(async move {
                let period = (ttl / 4).clamp(
                    std::time::Duration::from_secs(1),
                    std::time::Duration::from_secs(60),
                );
                let mut ticker = tokio::time::interval(period);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    ticker.tick().await;
                    let scan_state = Arc::clone(&reaper_state);
                    // reap_idle blocks on child reaping (condvar); keep it
                    // off the async workers.
                    let reaped =
                        tokio::task::spawn_blocking(move || scan_state.manager.reap_idle(ttl))
                            .await
                            .unwrap_or_default();
                    for (user, shell_id, exit) in reaped {
                        reaper_state.observability.record(
                            crate::observability::AuditEvent::ShellExpired {
                                user,
                                shell_id,
                                exit_code: exit.exit_code,
                            },
                        );
                    }
                }
            }));
        }

        if let Some(uploads) = uploads {
            let retention = config.upload_retention;
            handles.push(tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60 * 60));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    ticker.tick().await;
                    let uploads = Arc::clone(&uploads);
                    let result = tokio::task::spawn_blocking(move || {
                        uploads.reap_expired(std::time::SystemTime::now(), retention)
                    })
                    .await;
                    if let Ok(Err(error)) = result {
                        tracing::warn!("upload retention scan failed: {error}");
                    }
                }
            }));
        }

        // QUIC-first bootstrap (ADR 0014): with an operator certificate, the
        // TCP side serves only an interstitial that waits for the browser to
        // upgrade to HTTP/3 (via Alt-Svc) and states that QUIC is required —
        // the app itself is served exclusively over the QUIC endpoint, with
        // no TCP fallback. Development (hash-pin) mode keeps serving the app
        // over TCP, since browsers never Alt-Svc-upgrade an origin without
        // WebPKI TLS; terminal traffic is WebTransport-only either way.
        let quic_first = matches!(
            webtransport_info,
            Some((_, _, WebTransportCertificateMode::WebPki))
        );

        let mut router = Router::new().route("/webtransport-info", get(wt_info_handler));
        if config.enable_websocket {
            router = router.route("/terminal/ws", any(ws_handler));
        }
        if quic_first {
            router = router.fallback(interstitial_handler);
        }
        let mut router = router.with_state(Arc::clone(&state));
        if !quic_first {
            if let Some(root) = &config.web_root {
                router = router.fallback_service(tower_http::services::ServeDir::new(root));
            }
        }
        if let Some((port, _, WebTransportCertificateMode::WebPki)) = &webtransport_info {
            // Advertise the HTTP/3 endpoint on every TCP response so browsers
            // learn to reach the QUIC side for subsequent requests.
            let alt_svc = axum::http::HeaderValue::from_str(&format!("h3=\":{port}\"; ma=86400"))
                .expect("valid Alt-Svc header");
            router = router.layer(axum::middleware::from_fn(
                move |req: axum::extract::Request, next: axum::middleware::Next| {
                    let alt_svc = alt_svc.clone();
                    async move {
                        let mut response = next.run(req).await;
                        response.headers_mut().insert("alt-svc", alt_svc);
                        response
                    }
                },
            ));
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
            webtransport_certificate_mode: wt_listener.as_ref().map(|l| l.certificate_mode),
            webtransport_cert_hash_base64: wt_listener.map(|l| l.cert_hash_base64),
            server_id,
            observability,
            handles,
        })
    }

    pub fn abort(&self) {
        for handle in &self.handles {
            handle.abort();
        }
    }

    /// Snapshot of the bounded, content-free audit ring (oldest first).
    pub fn audit_events(&self) -> Vec<AuditRecord> {
        self.observability.audit_events()
    }

    /// Monotonic counters with fixed labels only.
    pub fn metrics(&self) -> MetricsSnapshot {
        self.observability.metrics()
    }
}

fn build_shell_manager(
    session: SessionCoreConfig,
    account_policy: &Option<BTreeMap<String, Vec<String>>>,
) -> ShellManager {
    match account_policy {
        Some(map) => {
            let allowed: std::collections::HashMap<String, Vec<String>> =
                map.iter().map(|(u, a)| (u.clone(), a.clone())).collect();
            ShellManager::with_policy(
                session,
                Arc::new(hf_session_core::StaticPolicy::new(allowed)),
            )
        }
        None => ShellManager::new(session),
    }
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    State(state): State<Arc<AppState>>,
) -> Response {
    let origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok());
    if !state.origin_allowed(origin) {
        tracing::warn!(?origin, "rejected WebSocket upgrade: origin not allowed");
        return (axum::http::StatusCode::FORBIDDEN, "origin not allowed").into_response();
    }
    ws.on_upgrade(move |socket| ws::handle_connection(socket, state, peer.ip()))
}

/// Served for every TCP path in QUIC-first mode (ADR 0014): tells the
/// visitor the page is loading over QUIC, retries while the browser adopts
/// the Alt-Svc route (a reload served over HTTP/3 gets the real app from the
/// QUIC endpoint instead of this page), and after a few attempts states that
/// QUIC is required. There is no TCP fallback.
const INTERSTITIAL_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Holdfast — connecting over QUIC</title>
<style>
  body { margin: 0; font: 16px/1.5 system-ui, sans-serif; background: #0d1117;
         color: #c9d1d9; display: grid; place-items: center; min-height: 100vh; }
  main { max-width: 34rem; padding: 2rem; text-align: center; }
  h1 { font-size: 1.3rem; letter-spacing: .04em; }
  .spin { display: inline-block; width: 1rem; height: 1rem; margin-right: .5rem;
          border: 2px solid #58a6ff; border-top-color: transparent; border-radius: 50%;
          animation: r 1s linear infinite; vertical-align: -.15rem; }
  @keyframes r { to { transform: rotate(360deg); } }
  a { color: #58a6ff; }
  #hint { color: #8b949e; }
</style>
</head>
<body>
<main>
<h1>Holdfast</h1>
<p id="status"><span class="spin"></span>Loading over QUIC (HTTP/3)&hellip;</p>
<p id="hint" hidden>This server is QUIC-only: the terminal is served over
HTTP/3 on UDP port __WT_PORT__, and this page loaded over TCP, which usually
means UDP is blocked between you and the server. There is no TCP fallback —
allow UDP/QUIC to this host and reload.</p>
<script>
(function () {
  var nav = performance.getEntriesByType('navigation')[0];
  if (nav && nav.nextHopProtocol === 'h3') {
    // Served over HTTP/3 the daemon returns the app, never this page; seeing
    // it means an intermediary cached it — a hard reload fetches the app.
    location.reload();
    return;
  }
  var tries = Number(sessionStorage.getItem('hf-h3-tries') || '0');
  if (tries < 8) {
    sessionStorage.setItem('hf-h3-tries', String(tries + 1));
    setTimeout(function () { location.reload(); }, 1500);
  } else {
    sessionStorage.removeItem('hf-h3-tries');
    document.getElementById('status').textContent =
      'QUIC (HTTP/3) is required, but this page could only load over TCP.';
    document.getElementById('hint').hidden = false;
  }
})();
</script>
</main>
</body>
</html>
"#;

async fn interstitial_handler(State(state): State<Arc<AppState>>) -> Response {
    let port = state
        .webtransport_info
        .as_ref()
        .map(|(port, _, _)| port.to_string())
        .unwrap_or_default();
    (
        [
            (axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        INTERSTITIAL_HTML.replace("__WT_PORT__", &port),
    )
        .into_response()
}

async fn wt_info_handler(State(state): State<Arc<AppState>>) -> Response {
    match &state.webtransport_info {
        Some((port, hash, mode)) => (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            format!(
                r#"{{"port":{port},"certHashBase64":"{hash}","certificateMode":"{}","passwordAuth":{}}}"#,
                mode.as_wire_name(),
                state.auth.password.is_some()
            ),
        )
            .into_response(),
        None => (axum::http::StatusCode::NOT_FOUND, "webtransport disabled").into_response(),
    }
}
