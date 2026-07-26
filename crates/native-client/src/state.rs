//! Client-side persistence: shell IDs and their latest rotated resume tokens
//! per server, in the per-user config dir (`~/.config/holdfast/state.json` on
//! unix, `%APPDATA%\holdfast\state.json` on Windows), mode 0600 on unix. The
//! token stored is always the newest rotation — stale tokens are useless by
//! design (spec §12).
//!
//! Writes are atomic (temp file + rename) so a crash mid-save never truncates
//! the only copy of every resume token. A file that fails to parse is renamed
//! aside — never silently replaced (ADR 0018).

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Schema version written by this client. Files with a *newer* version are
/// refused rather than rewritten (a downgrade would drop fields the newer
/// client depends on).
pub const STATE_VERSION: u32 = 1;

fn state_version_default() -> u32 {
    // Pre-versioning files carry no `version` field; they are schema 1.
    STATE_VERSION
}

#[derive(Debug, Serialize, Deserialize)]
pub struct State {
    #[serde(default = "state_version_default")]
    pub version: u32,
    /// server url → shell-id hex → entry
    #[serde(default)]
    pub servers: BTreeMap<String, BTreeMap<String, ShellEntry>>,
    /// server url → base64 connection grant (reused for cheap reconnects).
    #[serde(default)]
    pub grants: BTreeMap<String, String>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            servers: BTreeMap::new(),
            grants: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellEntry {
    /// base64 resume token (latest rotation)
    pub token: String,
    pub name: String,
    /// hex idempotency key from `OpenShell`; lets the client recover a shell
    /// whose token was lost or superseded (spec §12, ADR 0018).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

/// `HOLDFAST_STATE` overrides the whole path (tests, portable installs).
fn state_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("HOLDFAST_STATE") {
        if !path.is_empty() {
            return Ok(PathBuf::from(path));
        }
    }
    let config = dirs::config_dir().context("no per-user config directory")?;
    Ok(config.join("holdfast/state.json"))
}

pub fn load() -> Result<State> {
    let path = state_path()?;
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(State::default()),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    match serde_json::from_str::<State>(&text) {
        Ok(state) if state.version > STATE_VERSION => bail!(
            "{} is schema v{} but this client only understands v{}; upgrade the client",
            path.display(),
            state.version,
            STATE_VERSION
        ),
        Ok(state) => Ok(state),
        Err(parse_err) => {
            // Corrupt file: move it aside so the tokens inside stay
            // recoverable by hand, then start fresh.
            let backup = path.with_file_name(format!(
                "state.json.corrupt-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis())
                    .unwrap_or(0)
            ));
            std::fs::rename(&path, &backup)
                .with_context(|| format!("back up corrupt {}", path.display()))?;
            eprintln!(
                "[holdfast: {} did not parse ({parse_err}); moved to {}]",
                path.display(),
                backup.display()
            );
            Ok(State::default())
        }
    }
}

pub fn save(state: &State) -> Result<()> {
    let path = state_path()?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let json = serde_json::to_string_pretty(state)?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        // Tokens live here: private from the first byte (threat model T1).
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
    std::fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} over {}", tmp.display(), path.display()))?;
    Ok(())
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

    // Serialize access to the process-wide HOLDFAST_STATE variable.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_state_file<R>(f: impl FnOnce(&std::path::Path) -> R) -> R {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("hf-state-test-{:032x}", rand::random::<u128>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        std::env::set_var("HOLDFAST_STATE", &path);
        let out = f(&path);
        std::env::remove_var("HOLDFAST_STATE");
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    #[test]
    fn round_trip_and_missing_file() {
        with_state_file(|path| {
            assert!(load().unwrap().servers.is_empty());
            let mut state = State::default();
            state.grants.insert("https://a".into(), "Zw==".into());
            state.servers.entry("https://a".into()).or_default().insert(
                "aa".into(),
                ShellEntry {
                    token: "dG9r".into(),
                    name: "shell 1".into(),
                    idempotency_key: Some("00ff".into()),
                },
            );
            save(&state).unwrap();
            assert!(!path.with_extension("json.tmp").exists());
            let loaded = load().unwrap();
            assert_eq!(loaded.version, STATE_VERSION);
            assert_eq!(loaded.grants["https://a"], "Zw==");
            let entry = &loaded.servers["https://a"]["aa"];
            assert_eq!(entry.idempotency_key.as_deref(), Some("00ff"));
        });
    }

    #[test]
    fn pre_versioning_file_is_schema_one() {
        with_state_file(|_path| {
            let legacy = r#"{"servers":{},"grants":{"https://a":"Zw=="}}"#;
            std::fs::write(state_path().unwrap(), legacy).unwrap();
            let loaded = load().unwrap();
            assert_eq!(loaded.version, STATE_VERSION);
            assert_eq!(loaded.grants["https://a"], "Zw==");
        });
    }

    #[test]
    fn corrupt_file_is_renamed_aside_not_lost() {
        with_state_file(|path| {
            std::fs::write(path, "{ definitely not json").unwrap();
            let loaded = load().unwrap();
            assert!(loaded.servers.is_empty());
            assert!(!path.exists(), "corrupt file must be moved, not left");
            let dir = path.parent().unwrap();
            let backups: Vec<_> = std::fs::read_dir(dir)
                .unwrap()
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .starts_with("state.json.corrupt-")
                })
                .collect();
            assert_eq!(backups.len(), 1, "expected exactly one backup");
        });
    }

    #[test]
    fn newer_schema_is_refused() {
        with_state_file(|path| {
            std::fs::write(path, r#"{"version":99,"servers":{},"grants":{}}"#).unwrap();
            let err = load().unwrap_err().to_string();
            assert!(err.contains("schema v99"), "got: {err}");
            assert!(path.exists(), "newer-schema file must not be touched");
        });
    }
}
