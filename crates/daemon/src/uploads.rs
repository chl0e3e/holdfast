//! Standalone-daemon upload backend selection and bounded global accounting.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use hf_protocol::pb::{BeginUpload, UploadChunk};
use hf_protocol::upload::{validate_begin, UploadValidationError};
use hf_protocol::{UPLOAD_FILE_BYTES_DEFAULT, UPLOAD_ID_BYTES, UPLOAD_SHA256_BYTES};
use hf_spawner::{ReceiveUploadRequest, RemoteUpload, UploadReply};
use hf_upload_store::{StoreConfig, StoreError, UploadStore, UploadWriter};

pub(crate) const MAX_UPLOADS_PER_CONNECTION: usize = 2;
pub(crate) const MAX_UPLOADS_PER_USER: usize = 4;
pub(crate) const MAX_UPLOADS_GLOBAL: usize = 16;
pub(crate) const UPLOAD_COMMAND_QUEUE_MESSAGES: usize = 4;
pub(crate) const UPLOAD_INACTIVITY_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub(crate) enum UploadError {
    #[error(transparent)]
    Validation(#[from] UploadValidationError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Spawner(#[from] hf_spawner::SpawnError),
    #[error("upload concurrency limit exceeded")]
    LimitExceeded,
    #[error("multi-user upload has no resolved Unix account")]
    MissingAccount,
    #[error("upload backend returned a malformed response")]
    MalformedBackendResponse,
    #[error("committed upload path is not UTF-8")]
    NonUtf8Path,
    #[error("upload worker failed: {0}")]
    Worker(String),
}

#[derive(Clone)]
enum Backend {
    SameUid(UploadStore),
    Spawner { socket: PathBuf },
}

#[derive(Default)]
struct Counts {
    global: usize,
    by_user: HashMap<String, usize>,
}

pub(crate) struct UploadService {
    backend: Backend,
    max_file_bytes: u64,
    counts: Arc<Mutex<Counts>>,
}

impl UploadService {
    pub(crate) fn same_uid(root: PathBuf, max_file_bytes: u64) -> Result<Self, UploadError> {
        let store = UploadStore::open(StoreConfig {
            root,
            max_file_bytes,
        })?;
        Ok(Self {
            backend: Backend::SameUid(store),
            max_file_bytes,
            counts: Arc::new(Mutex::new(Counts::default())),
        })
    }

    pub(crate) fn spawner(socket: PathBuf, max_file_bytes: u64) -> Self {
        Self {
            backend: Backend::Spawner { socket },
            max_file_bytes,
            counts: Arc::new(Mutex::new(Counts::default())),
        }
    }

    pub(crate) fn try_acquire(&self, user: &str) -> Result<UploadPermit, UploadError> {
        let mut counts = self.counts.lock().unwrap();
        let user_count = counts.by_user.get(user).copied().unwrap_or(0);
        if counts.global >= MAX_UPLOADS_GLOBAL || user_count >= MAX_UPLOADS_PER_USER {
            return Err(UploadError::LimitExceeded);
        }
        counts.global += 1;
        counts.by_user.insert(user.to_string(), user_count + 1);
        Ok(UploadPermit {
            counts: Arc::clone(&self.counts),
            user: user.to_string(),
        })
    }

    pub(crate) fn begin(
        &self,
        account: Option<&str>,
        metadata: &BeginUpload,
        maximum_chunk_bytes: u32,
    ) -> Result<ActiveUpload, UploadError> {
        validate_begin(metadata, self.max_file_bytes)?;
        match &self.backend {
            Backend::SameUid(store) => Ok(ActiveUpload::SameUid(
                Box::new(store.begin_with_chunk_limit(metadata, maximum_chunk_bytes)?),
            )),
            Backend::Spawner { socket } => {
                let account = account.ok_or(UploadError::MissingAccount)?;
                let remote = hf_spawner::begin_upload(
                    socket,
                    &ReceiveUploadRequest {
                        account: account.to_string(),
                        original_name: metadata.original_name.clone(),
                        total_bytes: metadata.total_bytes,
                        sha256: metadata.sha256.clone(),
                        maximum_chunk_bytes,
                    },
                )?;
                Ok(ActiveUpload::Spawner(remote))
            }
        }
    }

    pub(crate) fn reap_expired(
        &self,
        now: std::time::SystemTime,
        retention: std::time::Duration,
    ) -> Result<usize, UploadError> {
        match &self.backend {
            Backend::SameUid(store) => Ok(store.reap_expired(now, retention)?),
            // The multi-user tmpfiles rule runs with the privilege needed to
            // traverse and remove target-account-owned 0700 directories.
            Backend::Spawner { .. } => Ok(0),
        }
    }
}

pub(crate) struct UploadPermit {
    counts: Arc<Mutex<Counts>>,
    user: String,
}

impl Drop for UploadPermit {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap();
        counts.global = counts.global.saturating_sub(1);
        if let Some(count) = counts.by_user.get_mut(&self.user) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.by_user.remove(&self.user);
            }
        }
    }
}

pub(crate) enum ActiveUpload {
    SameUid(Box<UploadWriter>),
    Spawner(RemoteUpload),
}

impl ActiveUpload {
    pub(crate) fn upload_id(&self) -> Vec<u8> {
        match self {
            Self::SameUid(writer) => writer.upload_id().to_vec(),
            Self::Spawner(remote) => remote.upload_id().to_vec(),
        }
    }

    pub(crate) fn maximum_chunk_bytes(&self) -> u32 {
        match self {
            Self::SameUid(writer) => writer.maximum_chunk_bytes(),
            Self::Spawner(remote) => remote.maximum_chunk_bytes(),
        }
    }

    pub(crate) fn write_chunk(&mut self, chunk: &UploadChunk) -> Result<(), UploadError> {
        match self {
            Self::SameUid(writer) => writer.write_chunk(chunk)?,
            Self::Spawner(remote) => {
                remote.write_wire_chunk(chunk)?;
            }
        }
        Ok(())
    }

    pub(crate) fn finish(self, upload_id: &[u8]) -> Result<FinishedUpload, UploadError> {
        match self {
            Self::SameUid(writer) => {
                let committed = writer.finish(upload_id)?;
                let remote_path = committed
                    .remote_path
                    .to_str()
                    .ok_or(UploadError::NonUtf8Path)?
                    .to_string();
                Ok(FinishedUpload {
                    upload_id: committed.upload_id,
                    remote_path,
                    bytes_written: committed.bytes_written,
                    sha256: committed.sha256,
                })
            }
            Self::Spawner(remote) => {
                if upload_id != remote.upload_id() {
                    return Err(UploadValidationError::InvalidUploadId.into());
                }
                match remote.finish()? {
                    UploadReply::Finished {
                        upload_id,
                        remote_path,
                        bytes_written,
                        sha256,
                    } => {
                        let upload_id: [u8; UPLOAD_ID_BYTES] = upload_id
                            .try_into()
                            .map_err(|_| UploadError::MalformedBackendResponse)?;
                        let sha256: [u8; UPLOAD_SHA256_BYTES] = sha256
                            .try_into()
                            .map_err(|_| UploadError::MalformedBackendResponse)?;
                        Ok(FinishedUpload {
                            upload_id,
                            remote_path,
                            bytes_written,
                            sha256,
                        })
                    }
                    _ => Err(UploadError::MalformedBackendResponse),
                }
            }
        }
    }
}

pub(crate) struct FinishedUpload {
    pub(crate) upload_id: [u8; UPLOAD_ID_BYTES],
    pub(crate) remote_path: String,
    pub(crate) bytes_written: u64,
    pub(crate) sha256: [u8; UPLOAD_SHA256_BYTES],
}

impl Default for UploadService {
    fn default() -> Self {
        Self::spawner(PathBuf::new(), UPLOAD_FILE_BYTES_DEFAULT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_releases_user_entries_and_enforces_both_bounds() {
        let service = UploadService::default();
        let permits: Vec<_> = (0..MAX_UPLOADS_PER_USER)
            .map(|_| service.try_acquire("alice").unwrap())
            .collect();
        assert!(matches!(
            service.try_acquire("alice"),
            Err(UploadError::LimitExceeded)
        ));
        drop(permits);
        assert!(service.counts.lock().unwrap().by_user.is_empty());

        let permits: Vec<_> = (0..MAX_UPLOADS_GLOBAL)
            .map(|index| service.try_acquire(&format!("user-{index}")).unwrap())
            .collect();
        assert!(matches!(
            service.try_acquire("one-more"),
            Err(UploadError::LimitExceeded)
        ));
        drop(permits);
    }
}
