//! hf-client-core — the desktop client's GUI-free core.
//!
//! One [`Core`] owns the persisted [`store`] and a supervisor task per
//! configured server (`server` module). Each supervisor owns its WebTransport
//! connection: grant-first auth with SSH-key fallback, pending-open recovery,
//! client keepalive (ADR 0020), and per-shell attachment pumps (`shell`
//! module). Everything observable flows out as [`CoreEvent`]s on a bounded
//! channel; terminal output flows through per-attachment bounded sinks the
//! GUI supplies. No queue in this crate is unbounded (AGENTS rule 7).
//!
//! Terminology (spec §1): a *shell* is the persistent server-side PTY; an
//! *attachment* is one temporary stream binding to it.

mod server;
mod shell;
pub mod store;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use tokio::sync::{mpsc, oneshot, Mutex};

use server::{run_supervisor, ServerCmd, SupervisorCtx};
use store::{Store, StoreData};

/// Events the GUI renders. Low-rate; terminal bytes go through the
/// per-attachment output sinks instead.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", tag = "type")]
pub enum CoreEvent {
    ServerStatus {
        server: String,
        status: ServerStatus,
        #[serde(skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    ShellState {
        server: String,
        shell: String,
        state: ShellStateEvent,
        #[serde(skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
    },
    ShellsUpdated {
        server: String,
        shells: Vec<ShellRow>,
    },
    StoreWarning {
        message: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServerStatus {
    Connecting,
    Connected,
    Reconnecting,
    /// Password-auth server with no valid grant: the GUI must call
    /// [`Core::login`]. `detail` carries the failure message after a
    /// rejected attempt.
    AuthRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShellStateEvent {
    Attached,
    Detached,
    Orphaned,
    Exited,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellRow {
    pub shell: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub has_token: bool,
}

/// One page of scrollback (spec §10 paging fields, needed by the GUI to
/// page backwards and know when history is exhausted).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryPage {
    pub lines: Vec<String>,
    pub first_line_id: u64,
    pub truncated_by_eviction: bool,
}

/// Reply to a successful attach. The snapshot must be written to the
/// terminal *before* the output sink is drained (it redraws the screen the
/// following output continues from).
#[derive(Debug)]
pub struct AttachInfo {
    pub snapshot: Vec<u8>,
    pub oldest_history_line_id: u64,
    pub newest_history_line_id: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapView {
    pub servers: Vec<ServerView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerView {
    pub key: String,
    pub url: String,
    pub display_name: String,
    pub shells: Vec<ShellView>,
    /// Present connection status. Status events emitted before the GUI
    /// subscribes (e.g. `auth-required` milliseconds after spawn) are
    /// otherwise lost, leaving a password server with no login prompt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ServerStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellView {
    pub shell: String,
    pub name: String,
}

/// Configuration for a newly added server.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub url: String,
    pub display_name: String,
    pub username: Option<String>,
    pub ssh_key_path: Option<PathBuf>,
}

#[derive(Clone)]
pub struct Core {
    inner: Arc<CoreInner>,
}

struct CoreInner {
    store: Arc<Store>,
    servers: Mutex<HashMap<String, mpsc::Sender<ServerCmd>>>,
    events: mpsc::Sender<CoreEvent>,
    /// Last emitted status per server, snapshotted into [`BootstrapView`] so
    /// a GUI that subscribes after spawn still learns the current state.
    statuses: Arc<std::sync::Mutex<HashMap<String, (ServerStatus, Option<String>)>>>,
}

/// Command queue depth per server supervisor. Commands sent while the
/// supervisor is reconnecting queue here (bounded pending work).
const SERVER_QUEUE: usize = 64;
/// Event channel depth (GUI side must keep draining).
const EVENT_QUEUE: usize = 256;

impl Core {
    /// Load (or create) the store at `store_path`, import the hf CLI's v1
    /// state on first run, and start a supervisor per configured server.
    pub async fn spawn(store_path: PathBuf) -> Result<(Core, mpsc::Receiver<CoreEvent>)> {
        let loaded = Store::load(store_path)?;
        let store = Arc::new(loaded.store);

        // First run: bring over the CLI's servers/tokens/grants (read-only).
        if let Ok(v1) = v1_state_path() {
            let _ = store.import_v1(&v1);
        }

        let (event_tx, event_rx) = mpsc::channel(EVENT_QUEUE);
        if let Some(message) = loaded.warning {
            let _ = event_tx.send(CoreEvent::StoreWarning { message }).await;
        }

        let core = Core {
            inner: Arc::new(CoreInner {
                store,
                servers: Mutex::new(HashMap::new()),
                events: event_tx,
                statuses: Arc::new(std::sync::Mutex::new(HashMap::new())),
            }),
        };
        for key in core.inner.store.snapshot().servers.keys() {
            core.start_supervisor(key.clone()).await;
        }
        Ok((core, event_rx))
    }

    async fn start_supervisor(&self, server_key: String) {
        let (tx, rx) = mpsc::channel(SERVER_QUEUE);
        let ctx = SupervisorCtx {
            server_key: server_key.clone(),
            store: Arc::clone(&self.inner.store),
            events: self.inner.events.clone(),
            statuses: Arc::clone(&self.inner.statuses),
        };
        tokio::spawn(run_supervisor(ctx, rx));
        self.inner.servers.lock().await.insert(server_key, tx);
    }

    /// Everything the GUI needs to build its initial tabs. Live statuses
    /// arrive as events immediately after.
    pub async fn bootstrap(&self) -> BootstrapView {
        let data: StoreData = self.inner.store.snapshot();
        let statuses = self.inner.statuses.lock().unwrap().clone();
        BootstrapView {
            servers: data
                .servers
                .into_iter()
                .map(|(key, record)| {
                    let (status, status_detail) = match statuses.get(&key) {
                        Some((s, d)) => (Some(*s), d.clone()),
                        None => (None, None),
                    };
                    ServerView {
                        key,
                        url: record.url,
                        display_name: record.display_name,
                        shells: record
                            .shells
                            .into_iter()
                            .map(|(shell, s)| ShellView {
                                shell,
                                name: s.name,
                            })
                            .collect(),
                        status,
                        status_detail,
                    }
                })
                .collect(),
        }
    }

    pub async fn add_server(&self, config: ServerConfig) -> Result<String> {
        let key = self.inner.store.add_server(store::ServerRecord {
            url: normalize_url(&config.url),
            display_name: config.display_name,
            username: config.username,
            ssh_key_path: config.ssh_key_path,
            grant: None,
            shells: Default::default(),
            pending_opens: Vec::new(),
        })?;
        self.start_supervisor(key.clone()).await;
        Ok(key)
    }

    /// Dropping the command channel stops the supervisor; the server's
    /// shells keep running server-side unless individually terminated.
    pub async fn remove_server(&self, server_key: &str) -> Result<()> {
        self.inner.servers.lock().await.remove(server_key);
        self.inner.statuses.lock().unwrap().remove(server_key);
        self.inner.store.remove_server(server_key)
    }

    pub async fn open_shell(
        &self,
        server_key: &str,
        name: &str,
        cols: u16,
        rows: u16,
    ) -> Result<String> {
        let (reply, rx) = oneshot::channel();
        self.send(
            server_key,
            ServerCmd::Open {
                name: name.to_string(),
                cols,
                rows,
                reply,
            },
        )
        .await?;
        rx.await.map_err(|_| anyhow!("server task stopped"))?
    }

    /// Attach a stored shell. `output` is the GUI's bounded sink for raw PTY
    /// bytes; write [`AttachInfo::snapshot`] to the terminal before draining
    /// it.
    pub async fn attach_shell(
        &self,
        server_key: &str,
        shell_hex: &str,
        cols: u16,
        rows: u16,
        output: mpsc::Sender<Vec<u8>>,
    ) -> Result<AttachInfo> {
        let (reply, rx) = oneshot::channel();
        self.send(
            server_key,
            ServerCmd::Attach {
                shell_hex: shell_hex.to_string(),
                cols,
                rows,
                output,
                reply,
            },
        )
        .await?;
        rx.await.map_err(|_| anyhow!("server task stopped"))?
    }

    pub async fn shell_input(&self, server_key: &str, shell_hex: &str, bytes: Vec<u8>) -> Result<()> {
        self.send(
            server_key,
            ServerCmd::Input {
                shell_hex: shell_hex.to_string(),
                bytes,
            },
        )
        .await
    }

    pub async fn resize_shell(
        &self,
        server_key: &str,
        shell_hex: &str,
        cols: u16,
        rows: u16,
    ) -> Result<()> {
        self.send(
            server_key,
            ServerCmd::Resize {
                shell_hex: shell_hex.to_string(),
                cols,
                rows,
            },
        )
        .await
    }

    pub async fn detach_shell(&self, server_key: &str, shell_hex: &str) -> Result<()> {
        self.send(
            server_key,
            ServerCmd::Detach {
                shell_hex: shell_hex.to_string(),
            },
        )
        .await
    }

    pub async fn terminate_shell(&self, server_key: &str, shell_hex: &str) -> Result<i32> {
        let (reply, rx) = oneshot::channel();
        self.send(
            server_key,
            ServerCmd::Terminate {
                shell_hex: shell_hex.to_string(),
                reply,
            },
        )
        .await?;
        rx.await.map_err(|_| anyhow!("server task stopped"))?
    }

    pub async fn request_history(
        &self,
        server_key: &str,
        shell_hex: &str,
        before_line_id: u64,
        max_lines: u32,
    ) -> Result<HistoryPage> {
        let (reply, rx) = oneshot::channel();
        self.send(
            server_key,
            ServerCmd::History {
                shell_hex: shell_hex.to_string(),
                before_line_id,
                max_lines,
                reply,
            },
        )
        .await?;
        rx.await.map_err(|_| anyhow!("server task stopped"))?
    }

    /// Supply the password for a password-auth server (username configured,
    /// no SSH key — ADR 0016). Used for exactly one connect attempt and never
    /// persisted; afterwards the refreshed 12 h grant carries reconnects. The
    /// outcome arrives as a `ServerStatus` event (`Connected`, or
    /// `AuthRequired` again with a detail message on rejection).
    pub async fn login(&self, server_key: &str, password: String) -> Result<()> {
        self.send(server_key, ServerCmd::Login { password }).await
    }

    /// Drop a shell entry without terminating the server-side shell (e.g. an
    /// orphan the user gives up on).
    pub async fn forget_shell(&self, server_key: &str, shell_hex: &str) -> Result<()> {
        self.inner.store.remove_shell(server_key, shell_hex)
    }

    pub async fn rename_shell(&self, server_key: &str, shell_hex: &str, name: &str) -> Result<()> {
        self.inner.store.rename_shell(server_key, shell_hex, name)
    }

    async fn send(&self, server_key: &str, cmd: ServerCmd) -> Result<()> {
        let tx = self
            .inner
            .servers
            .lock()
            .await
            .get(server_key)
            .cloned()
            .with_context(|| format!("unknown server {server_key}"))?;
        tx.send(cmd)
            .await
            .map_err(|_| anyhow!("server task stopped"))
    }
}

/// The hf CLI's v1 state file, for the one-time import.
fn v1_state_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("HOLDFAST_STATE") {
        if !path.is_empty() {
            return Ok(PathBuf::from(path));
        }
    }
    let config = dirs::config_dir().context("no per-user config directory")?;
    Ok(config.join("holdfast/state.json"))
}

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// A scheme-less URL from the add-server form ("iliad.example.com") can never
/// connect, but the failure only surfaced as a login error after the user
/// typed a password. Assume https:// — bare hostnames are how people type
/// public servers; loopback dev daemons are spelled http://host:port.
/// Applied both when a server is added and when a stored record connects, so
/// records saved before this normalization heal too.
pub(crate) fn normalize_url(url: &str) -> String {
    let url = url.trim();
    if url.is_empty() || url.contains("://") {
        url.to_string()
    } else {
        format!("https://{url}")
    }
}

#[cfg(test)]
mod view_tests {
    use super::*;

    /// The desktop reads these exact keys/values to decide whether to open
    /// the login dialog at launch; a rename here silently loses the prompt.
    #[test]
    fn bootstrap_json_carries_status_for_the_gui() {
        let view = BootstrapView {
            servers: vec![ServerView {
                key: "abc".into(),
                url: "https://host".into(),
                display_name: "host".into(),
                shells: vec![],
                status: Some(ServerStatus::AuthRequired),
                status_detail: Some("authentication failed".into()),
            }],
        };
        let json = serde_json::to_value(&view).unwrap();
        let server = &json["servers"][0];
        assert_eq!(server["status"], "auth-required");
        assert_eq!(server["statusDetail"], "authentication failed");
        assert_eq!(server["displayName"], "host");

        // Absent status must be omitted, not null: the GUI tests truthiness.
        let view = BootstrapView {
            servers: vec![ServerView {
                key: "abc".into(),
                url: "https://host".into(),
                display_name: "host".into(),
                shells: vec![],
                status: None,
                status_detail: None,
            }],
        };
        let json = serde_json::to_value(&view).unwrap();
        assert!(json["servers"][0].get("status").is_none());
    }
}

#[cfg(test)]
mod url_tests {
    use super::normalize_url;

    #[test]
    fn bare_hostnames_become_https() {
        assert_eq!(normalize_url("iliad.example.com"), "https://iliad.example.com");
        assert_eq!(normalize_url(" host:443 "), "https://host:443");
        assert_eq!(normalize_url("http://127.0.0.1:8080"), "http://127.0.0.1:8080");
        assert_eq!(normalize_url("https://host"), "https://host");
        assert_eq!(normalize_url(""), "");
    }
}
