//! Desktop client persistence (schema v3): per-server config + grants +
//! per-shell resume tokens and idempotency keys, in `holdfast/desktop.json`
//! under the per-user config dir (`HOLDFAST_DESKTOP_STATE` overrides).
//!
//! Deliberately a separate file from the hf CLI's `state.json` so the two
//! clients never clobber each other's tokens (single-use tokens make the
//! last attacher win regardless — that is protocol-correct). The CLI's v1
//! file is imported once on first run.
//!
//! Same write discipline as ADR 0018: atomic tmp+rename created 0600 (unix),
//! Invalid files are retained and refused; newer schema versions are refused.
//! Windows encrypts the entire file using user-scoped DPAPI (ADR 0031).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const STORE_VERSION: u32 = 3;
/// Hard ceiling for serialized state, including migration input.
const MAX_STATE_BYTES: usize = 8 * 1024 * 1024;
#[cfg(windows)]
const PROTECTED_HEADER: &[u8] = b"HOLDFAST-DPAPI-1\n";

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
    /// Explicit consent to retain a login across app restarts.
    #[serde(default)]
    pub remember_login: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Base64 connection grant; persisted only with explicit consent.
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
        let bytes = match read_bounded(&path) {
            Ok(bytes) => Some(bytes),
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                None
            }
            Err(e) => return Err(e).context("read desktop state"),
        };
        let mut data = StoreData::default();
        let mut migrated = false;
        if let Some(bytes) = bytes {
            #[cfg(windows)]
            let protected = bytes.starts_with(PROTECTED_HEADER);
            #[cfg(windows)]
            let bytes = if protected {
                crate::dpapi::unprotect(&bytes[PROTECTED_HEADER.len()..]).context(
                    "unlock desktop state with this Windows account; original file retained",
                )?
            } else {
                bytes
            };
            anyhow::ensure!(
                bytes.len() <= MAX_STATE_BYTES,
                "desktop state exceeds 8 MiB"
            );
            let bytes = zeroize::Zeroizing::new(bytes);
            data = serde_json::from_slice(&bytes)
                .context("invalid desktop state; original file retained")?;
            anyhow::ensure!(
                data.version <= STORE_VERSION,
                "desktop state is schema v{}; upgrade this client",
                data.version
            );
            migrated = data.version < STORE_VERSION;
            #[cfg(windows)]
            anyhow::ensure!(
                protected || migrated,
                "unencrypted v3 desktop state refused"
            );
            for server in data.servers.values_mut() {
                // Old versions never asked consent. Do not use their grants even once.
                if migrated {
                    server.remember_login = false;
                }
                if !server.remember_login {
                    server.grant = None;
                }
            }
            data.version = STORE_VERSION;
        }
        let store = Store {
            path,
            data: Mutex::new(data),
        };
        if migrated {
            // Replace legacy plaintext before any supervisor can authenticate.
            store.save(&store.data.lock().unwrap())?;
        }
        Ok(Loaded {
            store,
            warning: migrated.then(|| {
                "Saved login cleared on upgrade. Log in again; your shells have been retained."
                    .into()
            }),
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

        let text = match read_bounded(v1_path) {
            Ok(text) => text,
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(0)
            }
            Err(e) => return Err(e).with_context(|| format!("read {}", v1_path.display())),
        };
        let v1: V1State = match serde_json::from_slice(&text) {
            Ok(v1) => v1,
            // A corrupt CLI file is the CLI's problem; never block first run.
            Err(_) => return Ok(0),
        };

        let mut data = self.data.lock().unwrap();
        if !data.servers.is_empty() {
            return Ok(0);
        }
        let mut next = data.clone();
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
            next.servers.insert(
                new_server_key(),
                ServerRecord {
                    url: url.clone(),
                    display_name: url.clone(),
                    username: None,
                    ssh_key_path: None,
                    remember_login: false,
                    grant: None,
                    shells,
                    pending_opens: Vec::new(),
                },
            );
            imported += 1;
        }
        if imported > 0 {
            self.save(&next)?;
            *data = next;
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
        let mut next = data.clone();
        next.servers.insert(key.clone(), record);
        self.save(&next)?;
        *data = next;
        Ok(key)
    }

    pub fn remove_server(&self, key: &str) -> Result<()> {
        let mut data = self.data.lock().unwrap();
        let mut next = data.clone();
        next.servers.remove(key);
        self.save(&next)?;
        *data = next;
        Ok(())
    }

    pub fn set_remember_login(&self, key: &str, remember: bool) -> Result<()> {
        self.mutate_server(key, |server| server.remember_login = remember)
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
    pub fn push_pending_open(
        &self,
        key: &str,
        idempotency_key_hex: &str,
        name: &str,
    ) -> Result<()> {
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
    pub fn update_token(
        &self,
        key: &str,
        shell_hex: &str,
        token: &[u8],
        now_ms: i64,
    ) -> Result<()> {
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
        let mut next = data.clone();
        let server = next.servers.get_mut(key).context("unknown server")?;
        f(server);
        self.save(&next)?;
        *data = next;
        Ok(())
    }

    fn save(&self, data: &StoreData) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut persisted = data.clone();
        for server in persisted.servers.values_mut() {
            if !server.remember_login {
                server.grant = None;
            }
        }
        let mut writer = BoundedState(Vec::new());
        serde_json::to_writer(&mut writer, &persisted)?;
        let bytes = zeroize::Zeroizing::new(writer.0);
        #[cfg(windows)]
        let bytes = {
            let encrypted = crate::dpapi::protect(&bytes).context("protect desktop state")?;
            let mut framed = PROTECTED_HEADER.to_vec();
            framed.extend_from_slice(&encrypted);
            anyhow::ensure!(
                framed.len() <= MAX_STATE_BYTES,
                "protected state exceeds 8 MiB"
            );
            zeroize::Zeroizing::new(framed)
        };
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
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("rename {} over {}", tmp.display(), self.path.display()))?;
        Ok(())
    }
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    anyhow::ensure!(
        file.metadata()?.len() <= MAX_STATE_BYTES as u64,
        "desktop state exceeds 8 MiB"
    );
    let mut bytes = Vec::new();
    file.take(MAX_STATE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= MAX_STATE_BYTES,
        "desktop state exceeds 8 MiB"
    );
    Ok(bytes)
}

struct BoundedState(Vec<u8>);
impl std::io::Write for BoundedState {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_STATE_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("desktop state exceeds 8 MiB"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
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
        let dir =
            std::env::temp_dir().join(format!("hf-store-test-{:032x}", rand::random::<u128>()));
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
                remember_login: false,
                grant: None,
                shells: BTreeMap::new(),
                pending_opens: Vec::new(),
            })
            .unwrap();
        store
            .push_pending_open(&key, "00ff", "build shell")
            .unwrap();
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
        assert!(Store::load(path)
            .unwrap()
            .store
            .snapshot()
            .servers
            .is_empty());
    }

    #[test]
    fn corrupt_store_is_retained_and_refused() {
        let (_store, path) = temp_store();
        std::fs::write(&path, "{ nope").unwrap();
        assert!(Store::load(path.clone()).is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "{ nope");
    }

    #[test]
    fn newer_schema_is_refused() {
        let (_store, path) = temp_store();
        std::fs::write(&path, r#"{"version":99,"servers":{}}"#).unwrap();
        assert!(Store::load(path).is_err());
    }

    #[test]
    fn v1_import_brings_over_shells_without_grants_once() {
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
        assert!(server.grant.is_none());
        assert_eq!(
            server.shells.get("aa").unwrap().idempotency_key.as_deref(),
            Some("00ff")
        );
        // Second import is a no-op (store no longer empty).
        assert_eq!(store.import_v1(&v1).unwrap(), 0);
    }
    fn record() -> ServerRecord {
        ServerRecord {
            url: "https://example.test".into(),
            display_name: "example".into(),
            username: Some("alice".into()),
            ssh_key_path: Some("id_ed25519_sk".into()),
            remember_login: false,
            grant: None,
            shells: BTreeMap::new(),
            pending_opens: Vec::new(),
        }
    }

    #[test]
    fn grant_is_available_for_reconnect_but_not_app_restart() {
        let (store, path) = temp_store();
        let key = store.add_server(record()).unwrap();
        store.set_grant(&key, b"secret-grant").unwrap();
        assert!(store.server(&key).unwrap().grant.is_some());
        // Subsequent shell updates must not accidentally persist the runtime grant.
        store
            .push_pending_open(&key, "recovery-secret", "build")
            .unwrap();
        assert!(Store::load(path)
            .unwrap()
            .store
            .server(&key)
            .unwrap()
            .grant
            .is_none());
    }

    #[test]
    fn remembering_is_opt_in_and_disabling_removes_disk_grant_immediately() {
        let (store, path) = temp_store();
        let key = store.add_server(record()).unwrap();
        store.set_grant(&key, b"secret-grant").unwrap();
        store.set_remember_login(&key, true).unwrap();
        assert!(Store::load(path.clone())
            .unwrap()
            .store
            .server(&key)
            .unwrap()
            .grant
            .is_some());
        store.set_remember_login(&key, false).unwrap();
        assert!(
            store.server(&key).unwrap().grant.is_some(),
            "in-process reconnect retained"
        );
        assert!(Store::load(path)
            .unwrap()
            .store
            .server(&key)
            .unwrap()
            .grant
            .is_none());
    }

    #[test]
    fn legacy_grant_is_discarded_before_use_and_shell_recovery_survives() {
        let (_store, path) = temp_store();
        let legacy = br#"{"version":2,"servers":{"a":{"url":"https://example.test","displayName":"example","username":"alice","sshKeyPath":"id_ed25519_sk","grant":"legacy-secret","shells":{"s":{"token":"shell-secret","idempotencyKey":"recovery-secret","name":"build","lastAttachedAtMs":1}}}}}"#;
        std::fs::write(&path, legacy).unwrap();
        let loaded = Store::load(path.clone()).unwrap();
        assert!(loaded.warning.is_some());
        let server = loaded.store.server("a").unwrap();
        assert!(!server.remember_login);
        assert!(server.grant.is_none());
        assert_eq!(
            server.shells["s"].idempotency_key.as_deref(),
            Some("recovery-secret")
        );
        assert!(Store::load(path.clone()).unwrap().warning.is_none());
        let disk = std::fs::read(&path).unwrap();
        assert!(!disk
            .windows(b"legacy-secret".len())
            .any(|w| w == b"legacy-secret"));
        #[cfg(windows)]
        {
            assert!(disk.starts_with(PROTECTED_HEADER));
            assert!(!disk
                .windows(b"shell-secret".len())
                .any(|w| w == b"shell-secret"));
            assert!(!disk
                .windows(b"recovery-secret".len())
                .any(|w| w == b"recovery-secret"));
        }
    }

    #[test]
    fn oversized_input_and_failed_preference_save_are_refused() {
        let (store, path) = temp_store();
        let key = store.add_server(record()).unwrap();
        // Force atomic write failure without touching the current state.
        std::fs::create_dir(path.with_extension("json.tmp")).unwrap();
        assert!(store.set_remember_login(&key, true).is_err());
        assert!(!store.server(&key).unwrap().remember_login);
        assert!(
            !Store::load(path.clone())
                .unwrap()
                .store
                .server(&key)
                .unwrap()
                .remember_login
        );
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_STATE_BYTES as u64 + 1).unwrap();
        assert!(Store::load(path).is_err());
        let mut writer = BoundedState(vec![0; MAX_STATE_BYTES]);
        assert!(std::io::Write::write(&mut writer, b"x").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn encrypted_state_is_opaque_and_unreadable_state_is_never_overwritten() {
        let (store, path) = temp_store();
        let key = store.add_server(record()).unwrap();
        store.set_remember_login(&key, true).unwrap();
        store.set_grant(&key, b"secret-grant").unwrap();
        let mut disk = std::fs::read(&path).unwrap();
        assert!(disk.starts_with(PROTECTED_HEADER));
        assert!(serde_json::from_slice::<serde_json::Value>(&disk).is_err());
        assert!(Store::load(path.clone())
            .unwrap()
            .store
            .server(&key)
            .unwrap()
            .grant
            .is_some());
        disk.truncate(disk.len() / 2);
        std::fs::write(&path, &disk).unwrap();
        assert!(Store::load(path.clone()).is_err());
        assert_eq!(std::fs::read(path).unwrap(), disk);
    }
}
