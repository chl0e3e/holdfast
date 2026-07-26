//! Desktop client persistence (schema v2): per-server config + grants +
//! per-shell resume tokens and idempotency keys, in `holdfast/desktop.json`
//! under the per-user config dir (`HOLDFAST_DESKTOP_STATE` overrides).
//!
//! Deliberately a separate file from the hf CLI's `state.json` so the two
//! clients never clobber each other's tokens (single-use tokens make the
//! last attacher win regardless — that is protocol-correct). The CLI's v1
//! file is imported once on first run.
//!
//! Same write discipline as ADR 0018: atomic tmp+rename created 0600 (unix),
//! corrupt files renamed aside rather than silently replaced, newer schema
//! versions refused.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

pub const STORE_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoreData {
    pub version: u32,
    /// server key (8-byte random hex) → server record
    #[serde(default)]
    pub servers: BTreeMap<String, ServerRecord>,
}

impl Default for StoreData {
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            servers: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerRecord {
    pub url: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_key_path: Option<PathBuf>,
    /// base64 connection grant (12h TTL; refreshed on every auth).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
    /// shell id hex → shell record
    #[serde(default)]
    pub shells: BTreeMap<String, ShellRecord>,
    /// `OpenShell`s whose idempotency key was persisted *before* the request
    /// was sent (crash-safe, ADR 0018): resolved into `shells` on the next
    /// connect by re-opening with the same key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_opens: Vec<PendingOpen>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellRecord {
    /// base64 resume token (latest rotation).
    pub token: String,
    /// hex 16-byte idempotency key (recovery credential, spec §9).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    pub name: String,
    #[serde(default)]
    pub last_attached_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingOpen {
    /// hex 16-byte idempotency key.
    pub idempotency_key: String,
    pub name: String,
}

/// Single-writer handle: every mutation happens under the lock and is
/// persisted atomically before the lock is released.
pub struct Store {
    path: PathBuf,
    data: Mutex<StoreData>,
}

/// Outcome of loading: the data plus a human-readable warning when the
/// previous file had to be moved aside (surfaced as a `store-warning` event).
pub struct Loaded {
    pub store: Store,
    pub warning: Option<String>,
}

pub fn default_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("HOLDFAST_DESKTOP_STATE") {
        if !path.is_empty() {
            return Ok(PathBuf::from(path));
        }
    }
    let config = dirs::config_dir().context("no per-user config directory")?;
    Ok(config.join("holdfast/desktop.json"))
}

impl Store {
    pub fn load(path: PathBuf) -> Result<Loaded> {
        let (data, warning) = match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<StoreData>(&text) {
                Ok(data) if data.version > STORE_VERSION => bail!(
                    "{} is schema v{} but this client only understands v{}; upgrade the client",
                    path.display(),
                    data.version,
                    STORE_VERSION
                ),
                Ok(data) => (data, None),
                Err(parse_err) => {
                    let backup = path.with_file_name(format!(
                        "desktop.json.corrupt-{}",
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_millis())
                            .unwrap_or(0)
                    ));
                    std::fs::rename(&path, &backup)
                        .with_context(|| format!("back up corrupt {}", path.display()))?;
                    let warning = format!(
                        "{} did not parse ({parse_err}); moved to {}",
                        path.display(),
                        backup.display()
                    );
                    (StoreData::default(), Some(warning))
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (StoreData::default(), None),
            Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
        };
        Ok(Loaded {
            store: Store {
                path,
                data: Mutex::new(data),
            },
            warning,
        })
    }

    /// One-time import of the hf CLI's v1 `state.json` (url-keyed) into v2
    /// server records. Only runs when the v2 store has no servers yet; the v1
    /// file is left untouched (the CLI keeps using it).
    pub fn import_v1(&self, v1_path: &Path) -> Result<usize> {
        #[derive(Deserialize)]
        struct V1State {
            #[serde(default)]
            servers: BTreeMap<String, BTreeMap<String, V1Shell>>,
            #[serde(default)]
            grants: BTreeMap<String, String>,
        }
        #[derive(Deserialize)]
        struct V1Shell {
            token: String,
            name: String,
            #[serde(default)]
            idempotency_key: Option<String>,
        }

        let text = match std::fs::read_to_string(v1_path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e).with_context(|| format!("read {}", v1_path.display())),
        };
        let v1: V1State = match serde_json::from_str(&text) {
            Ok(v1) => v1,
            // A corrupt CLI file is the CLI's problem; never block first run.
            Err(_) => return Ok(0),
        };

        let mut data = self.data.lock().unwrap();
        if !data.servers.is_empty() {
            return Ok(0);
        }
        let mut imported = 0;
        let urls: std::collections::BTreeSet<&String> =
            v1.servers.keys().chain(v1.grants.keys()).collect();
        for url in urls {
            let shells = v1
                .servers
                .get(url)
                .map(|m| {
                    m.iter()
                        .map(|(id, s)| {
                            (
                                id.clone(),
                                ShellRecord {
                                    token: s.token.clone(),
                                    idempotency_key: s.idempotency_key.clone(),
                                    name: s.name.clone(),
                                    last_attached_at_ms: 0,
                                },
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();
            data.servers.insert(
                new_server_key(),
                ServerRecord {
                    url: url.clone(),
                    display_name: url.clone(),
                    username: None,
                    ssh_key_path: None,
                    grant: v1.grants.get(url).cloned(),
                    shells,
                    pending_opens: Vec::new(),
                },
            );
            imported += 1;
        }
        if imported > 0 {
            self.save(&data)?;
        }
        Ok(imported)
    }

    pub fn snapshot(&self) -> StoreData {
        self.data.lock().unwrap().clone()
    }

    pub fn server(&self, key: &str) -> Option<ServerRecord> {
        self.data.lock().unwrap().servers.get(key).cloned()
    }

    pub fn add_server(&self, record: ServerRecord) -> Result<String> {
        let mut data = self.data.lock().unwrap();
        let key = new_server_key();
        data.servers.insert(key.clone(), record);
        self.save(&data)?;
        Ok(key)
    }

    pub fn remove_server(&self, key: &str) -> Result<()> {
        let mut data = self.data.lock().unwrap();
        data.servers.remove(key);
        self.save(&data)
    }

    pub fn set_grant(&self, key: &str, grant: &[u8]) -> Result<()> {
        use base64::Engine;
        self.mutate_server(key, |server| {
            if !grant.is_empty() {
                server.grant = Some(base64::engine::general_purpose::STANDARD.encode(grant));
            }
        })
    }

    /// Persist a pending open *before* the OpenShell request goes out.
    pub fn push_pending_open(&self, key: &str, idempotency_key_hex: &str, name: &str) -> Result<()> {
        self.mutate_server(key, |server| {
            server.pending_opens.push(PendingOpen {
                idempotency_key: idempotency_key_hex.to_string(),
                name: name.to_string(),
            });
        })
    }

    /// Resolve a pending open into a real shell entry (same transaction).
    pub fn resolve_pending_open(
        &self,
        key: &str,
        idempotency_key_hex: &str,
        shell_hex: &str,
        token: &[u8],
        now_ms: i64,
    ) -> Result<()> {
        use base64::Engine;
        self.mutate_server(key, |server| {
            let name = server
                .pending_opens
                .iter()
                .find(|p| p.idempotency_key == idempotency_key_hex)
                .map(|p| p.name.clone())
                .unwrap_or_else(|| "shell".to_string());
            server
                .pending_opens
                .retain(|p| p.idempotency_key != idempotency_key_hex);
            server.shells.insert(
                shell_hex.to_string(),
                ShellRecord {
                    token: base64::engine::general_purpose::STANDARD.encode(token),
                    idempotency_key: Some(idempotency_key_hex.to_string()),
                    name,
                    last_attached_at_ms: now_ms,
                },
            );
        })
    }

    pub fn drop_pending_open(&self, key: &str, idempotency_key_hex: &str) -> Result<()> {
        self.mutate_server(key, |server| {
            server
                .pending_opens
                .retain(|p| p.idempotency_key != idempotency_key_hex);
        })
    }

    /// Update a shell's token (rotation). Preserves name and recovery key.
    pub fn update_token(&self, key: &str, shell_hex: &str, token: &[u8], now_ms: i64) -> Result<()> {
        use base64::Engine;
        self.mutate_server(key, |server| {
            if let Some(shell) = server.shells.get_mut(shell_hex) {
                shell.token = base64::engine::general_purpose::STANDARD.encode(token);
                shell.last_attached_at_ms = now_ms;
            }
        })
    }

    pub fn shell(&self, key: &str, shell_hex: &str) -> Option<ShellRecord> {
        self.data
            .lock()
            .unwrap()
            .servers
            .get(key)
            .and_then(|s| s.shells.get(shell_hex).cloned())
    }

    pub fn remove_shell(&self, key: &str, shell_hex: &str) -> Result<()> {
        self.mutate_server(key, |server| {
            server.shells.remove(shell_hex);
        })
    }

    pub fn rename_shell(&self, key: &str, shell_hex: &str, name: &str) -> Result<()> {
        self.mutate_server(key, |server| {
            if let Some(shell) = server.shells.get_mut(shell_hex) {
                shell.name = name.to_string();
            }
        })
    }

    fn mutate_server(&self, key: &str, f: impl FnOnce(&mut ServerRecord)) -> Result<()> {
        let mut data = self.data.lock().unwrap();
        if let Some(server) = data.servers.get_mut(key) {
            f(server);
        }
        self.save(&data)
    }

    fn save(&self, data: &StoreData) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let json = serde_json::to_string_pretty(data)?;
        let tmp = self.path.with_extension("json.tmp");
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            // Tokens and grants live here (threat model T1).
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            use std::io::Write;
            let mut file = opts
                .open(&tmp)
                .with_context(|| format!("create {}", tmp.display()))?;
            file.write_all(json.as_bytes())?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("rename {} over {}", tmp.display(), self.path.display()))?;
        Ok(())
    }
}

fn new_server_key() -> String {
    let bytes: [u8; 8] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (Store, PathBuf) {
        let dir = std::env::temp_dir().join(format!("hf-store-test-{:032x}", rand::random::<u128>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("desktop.json");
        let loaded = Store::load(path.clone()).unwrap();
        assert!(loaded.warning.is_none());
        (loaded.store, path)
    }

    #[test]
    fn round_trip_add_update_remove() {
        let (store, path) = temp_store();
        let key = store
            .add_server(ServerRecord {
                url: "https://a".into(),
                display_name: "a".into(),
                username: Some("alice".into()),
                ssh_key_path: None,
                grant: None,
                shells: BTreeMap::new(),
                pending_opens: Vec::new(),
            })
            .unwrap();
        store.push_pending_open(&key, "00ff", "build shell").unwrap();
        store
            .resolve_pending_open(&key, "00ff", "aabb", b"tok", 42)
            .unwrap();
        store.update_token(&key, "aabb", b"tok2", 43).unwrap();

        let reloaded = Store::load(path.clone()).unwrap().store;
        let server = reloaded.server(&key).unwrap();
        assert!(server.pending_opens.is_empty());
        let shell = server.shells.get("aabb").unwrap();
        assert_eq!(shell.name, "build shell");
        assert_eq!(shell.idempotency_key.as_deref(), Some("00ff"));
        assert_eq!(shell.last_attached_at_ms, 43);
        assert!(!path.with_extension("json.tmp").exists());

        reloaded.remove_shell(&key, "aabb").unwrap();
        reloaded.remove_server(&key).unwrap();
        assert!(Store::load(path).unwrap().store.snapshot().servers.is_empty());
    }

    #[test]
    fn corrupt_store_is_backed_up_with_warning() {
        let (_store, path) = temp_store();
        std::fs::write(&path, "{ nope").unwrap();
        let loaded = Store::load(path.clone()).unwrap();
        assert!(loaded.warning.is_some());
        assert!(loaded.store.snapshot().servers.is_empty());
        let backups = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("desktop.json.corrupt-")
            })
            .count();
        assert_eq!(backups, 1);
    }

    #[test]
    fn newer_schema_is_refused() {
        let (_store, path) = temp_store();
        std::fs::write(&path, r#"{"version":99,"servers":{}}"#).unwrap();
        assert!(Store::load(path).is_err());
    }

    #[test]
    fn v1_import_brings_over_shells_and_grants_once() {
        let (store, _path) = temp_store();
        let dir = std::env::temp_dir().join(format!("hf-v1-test-{:032x}", rand::random::<u128>()));
        std::fs::create_dir_all(&dir).unwrap();
        let v1 = dir.join("state.json");
        std::fs::write(
            &v1,
            r#"{"version":1,
               "servers":{"https://old":{"aa":{"token":"dG9r","name":"n","idempotency_key":"00ff"}}},
               "grants":{"https://old":"Zw=="}}"#,
        )
        .unwrap();
        assert_eq!(store.import_v1(&v1).unwrap(), 1);
        let snap = store.snapshot();
        let (_, server) = snap.servers.iter().next().unwrap();
        assert_eq!(server.url, "https://old");
        assert_eq!(server.grant.as_deref(), Some("Zw=="));
        assert_eq!(
            server.shells.get("aa").unwrap().idempotency_key.as_deref(),
            Some("00ff")
        );
        // Second import is a no-op (store no longer empty).
        assert_eq!(store.import_v1(&v1).unwrap(), 0);
    }
}
