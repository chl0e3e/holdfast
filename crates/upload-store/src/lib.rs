//! Bounded, transport-neutral temporary upload storage (ADR 0028).
//!
//! The caller supplies already-authorized upload metadata and ordered chunks.
//! This crate deliberately knows nothing about transports, shells, PTYs, or
//! authentication.

use std::fs::File;
use std::io::{self, Write};
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use hf_protocol::pb::{BeginUpload, UploadChunk};
use hf_protocol::upload::{validate_begin, validate_chunk, UploadValidationError};
use hf_protocol::{UPLOAD_FILE_BYTES_DEFAULT, UPLOAD_ID_BYTES, UPLOAD_SHA256_BYTES};
use nix::fcntl::{open, openat, AtFlags, OFlag};
use nix::sys::stat::{fchmod, mkdirat, Mode};
use nix::unistd::{fchown, linkat, unlinkat, Gid, Uid, UnlinkatFlags};
use rand::RngCore;
use sha2::{Digest, Sha256};

const DIRECTORY_MODE: Mode = Mode::from_bits_truncate(0o700);
const FILE_MODE: Mode = Mode::from_bits_truncate(0o600);
const PARTIAL_NAME: &str = ".partial";
const RANDOM_ID_ATTEMPTS: usize = 8;
/// Keeps one reaper pass bounded even if the configured root is unexpectedly
/// filled with unrelated entries.
pub const REAPER_SCAN_ENTRIES_MAX: usize = 1024;
/// Leaves room below typical `NAME_MAX` values and for internal names.
pub const STORED_BASENAME_BYTES_MAX: usize = 200;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("upload root must be an absolute directory opened without following symlinks")]
    InvalidRoot,
    #[error(transparent)]
    InvalidUpload(#[from] UploadValidationError),
    #[error("upload id collided after bounded retries")]
    IdCollision,
    #[error("selected upload chunk limit must be greater than zero")]
    InvalidChunkLimit,
    #[error("received {actual} bytes but expected {expected}")]
    LengthMismatch { actual: u64, expected: u64 },
    #[error("upload SHA-256 does not match the declaration")]
    ChecksumMismatch,
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone)]
pub struct StoreConfig {
    pub root: PathBuf,
    pub max_file_bytes: u64,
}

impl StoreConfig {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            max_file_bytes: UPLOAD_FILE_BYTES_DEFAULT,
        }
    }
}

/// A pre-opened upload root. Opening rejects relative paths and symlink roots;
/// later operations are relative to this descriptor.
#[derive(Debug, Clone)]
pub struct UploadStore {
    config: StoreConfig,
    root_fd: Arc<OwnedFd>,
}

impl UploadStore {
    pub fn open(config: StoreConfig) -> Result<Self, StoreError> {
        if !config.root.is_absolute() {
            return Err(StoreError::InvalidRoot);
        }
        let root_fd = open(
            &config.root,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| StoreError::InvalidRoot)?;
        Ok(Self {
            config,
            root_fd: Arc::new(root_fd),
        })
    }

    pub fn begin(&self, metadata: &BeginUpload) -> Result<UploadWriter, StoreError> {
        self.begin_with_chunk_limit(metadata, hf_protocol::UPLOAD_CHUNK_BYTES_MAX as u32)
    }

    /// Begin with a connection-specific chunk bound selected to fit its
    /// negotiated frame size.
    pub fn begin_with_chunk_limit(
        &self,
        metadata: &BeginUpload,
        maximum_chunk_bytes: u32,
    ) -> Result<UploadWriter, StoreError> {
        validate_begin(metadata, self.config.max_file_bytes)?;
        if maximum_chunk_bytes == 0 {
            return Err(StoreError::InvalidChunkLimit);
        }
        let maximum_chunk_bytes =
            maximum_chunk_bytes.min(hf_protocol::UPLOAD_CHUNK_BYTES_MAX as u32);
        let mut rng = rand::rng();
        for _ in 0..RANDOM_ID_ATTEMPTS {
            let mut id = [0_u8; UPLOAD_ID_BYTES];
            rng.fill_bytes(&mut id);
            match self.begin_with_id(metadata, id, maximum_chunk_bytes) {
                Err(StoreError::IdCollision) => continue,
                result => return result,
            }
        }
        Err(StoreError::IdCollision)
    }

    fn begin_with_id(
        &self,
        metadata: &BeginUpload,
        upload_id: [u8; UPLOAD_ID_BYTES],
        maximum_chunk_bytes: u32,
    ) -> Result<UploadWriter, StoreError> {
        validate_begin(metadata, self.config.max_file_bytes)?;
        let directory_name = hex_id(&upload_id);
        match mkdirat(&*self.root_fd, directory_name.as_str(), DIRECTORY_MODE) {
            Ok(()) => {}
            Err(nix::errno::Errno::EEXIST) => return Err(StoreError::IdCollision),
            Err(error) => return Err(nix_io(error).into()),
        }

        let result = self.open_new_writer(
            metadata,
            upload_id,
            directory_name.clone(),
            maximum_chunk_bytes,
        );
        if result.is_err() {
            let _ = unlinkat(
                &*self.root_fd,
                directory_name.as_str(),
                UnlinkatFlags::RemoveDir,
            );
        }
        result
    }

    fn open_new_writer(
        &self,
        metadata: &BeginUpload,
        upload_id: [u8; UPLOAD_ID_BYTES],
        directory_name: String,
        maximum_chunk_bytes: u32,
    ) -> Result<UploadWriter, StoreError> {
        let directory_fd = openat(
            &*self.root_fd,
            directory_name.as_str(),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(nix_io)?;
        fchmod(&directory_fd, DIRECTORY_MODE).map_err(nix_io)?;
        let file_fd = openat(
            &directory_fd,
            PARTIAL_NAME,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            FILE_MODE,
        )
        .map_err(nix_io)?;
        if let Err(error) = fchmod(&file_fd, FILE_MODE) {
            drop(file_fd);
            let _ = unlinkat(&directory_fd, PARTIAL_NAME, UnlinkatFlags::NoRemoveDir);
            return Err(nix_io(error).into());
        }

        let mut expected_sha256 = [0_u8; UPLOAD_SHA256_BYTES];
        expected_sha256.copy_from_slice(&metadata.sha256);
        Ok(UploadWriter {
            root_path: self.config.root.clone(),
            root_fd: Arc::clone(&self.root_fd),
            directory_fd,
            directory_name,
            stored_basename: sanitize_basename(&metadata.original_name),
            upload_id,
            expected_bytes: metadata.total_bytes,
            expected_sha256,
            maximum_chunk_bytes,
            written: 0,
            hasher: Sha256::new(),
            file: File::from(file_fd),
            committed: false,
        })
    }

    /// Remove up to `REAPER_SCAN_ENTRIES_MAX` expired upload directories.
    /// Unknown names and symlinks are ignored.
    pub fn reap_expired(&self, now: SystemTime, retention: Duration) -> Result<usize, StoreError> {
        let mut removed = 0;
        for entry in std::fs::read_dir(&self.config.root)?.take(REAPER_SCAN_ENTRIES_MAX) {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !is_hex_id(name) {
                continue;
            }
            let metadata = std::fs::symlink_metadata(entry.path())?;
            if !metadata.file_type().is_dir() {
                continue;
            }
            let age = now.duration_since(metadata.modified()?).unwrap_or_default();
            if age < retention {
                continue;
            }
            std::fs::remove_dir_all(entry.path())?;
            removed += 1;
        }
        Ok(removed)
    }
}

pub struct UploadWriter {
    root_path: PathBuf,
    root_fd: Arc<OwnedFd>,
    directory_fd: OwnedFd,
    directory_name: String,
    stored_basename: String,
    upload_id: [u8; UPLOAD_ID_BYTES],
    expected_bytes: u64,
    expected_sha256: [u8; UPLOAD_SHA256_BYTES],
    maximum_chunk_bytes: u32,
    written: u64,
    hasher: Sha256,
    file: File,
    committed: bool,
}

impl UploadWriter {
    pub fn upload_id(&self) -> [u8; UPLOAD_ID_BYTES] {
        self.upload_id
    }

    pub fn maximum_chunk_bytes(&self) -> u32 {
        self.maximum_chunk_bytes
    }

    pub fn bytes_written(&self) -> u64 {
        self.written
    }

    pub fn write_chunk(&mut self, chunk: &UploadChunk) -> Result<(), StoreError> {
        validate_chunk(
            chunk,
            &self.upload_id,
            self.written,
            self.maximum_chunk_bytes,
            self.expected_bytes,
        )?;
        self.file.write_all(&chunk.data)?;
        self.hasher.update(&chunk.data);
        self.written += chunk.data.len() as u64;
        Ok(())
    }

    pub fn finish(mut self, upload_id: &[u8]) -> Result<CommittedUpload, StoreError> {
        self.finish_inner(upload_id, None)
    }

    /// Commit and transfer ownership while the private directory is still
    /// owned by the writer. This is used only by the privileged spawner.
    pub fn finish_as(
        mut self,
        upload_id: &[u8],
        uid: u32,
        gid: u32,
    ) -> Result<CommittedUpload, StoreError> {
        self.finish_inner(upload_id, Some((Uid::from_raw(uid), Gid::from_raw(gid))))
    }

    fn finish_inner(
        &mut self,
        upload_id: &[u8],
        owner: Option<(Uid, Gid)>,
    ) -> Result<CommittedUpload, StoreError> {
        if upload_id != self.upload_id {
            return Err(UploadValidationError::InvalidUploadId.into());
        }
        if self.written != self.expected_bytes {
            return Err(StoreError::LengthMismatch {
                actual: self.written,
                expected: self.expected_bytes,
            });
        }
        let actual: [u8; UPLOAD_SHA256_BYTES] = self.hasher.clone().finalize().into();
        if actual != self.expected_sha256 {
            return Err(StoreError::ChecksumMismatch);
        }

        self.file.flush()?;
        self.file.sync_all()?;
        // A hard-link commit is atomic and refuses to replace an existing name.
        // Both names are in the same private directory and point to one inode.
        linkat(
            &self.directory_fd,
            PARTIAL_NAME,
            &self.directory_fd,
            self.stored_basename.as_str(),
            AtFlags::empty(),
        )
        .map_err(nix_io)?;
        unlinkat(&self.directory_fd, PARTIAL_NAME, UnlinkatFlags::NoRemoveDir).map_err(nix_io)?;
        File::from(self.directory_fd.try_clone()?).sync_all()?;

        if let Some((uid, gid)) = owner {
            // Change the file first while the directory is still private to us.
            // Directory ownership is the final visibility step: once it
            // succeeds, the target account sees an already-complete 0600 file.
            fchown(&self.file, Some(uid), Some(gid)).map_err(nix_io)?;
            fchown(&self.directory_fd, Some(uid), Some(gid)).map_err(nix_io)?;
        }

        self.committed = true;
        Ok(CommittedUpload {
            upload_id: self.upload_id,
            remote_path: self
                .root_path
                .join(&self.directory_name)
                .join(&self.stored_basename),
            bytes_written: self.written,
            sha256: actual,
        })
    }

    pub fn abort(self) {}
}

impl Drop for UploadWriter {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let _ = unlinkat(&self.directory_fd, PARTIAL_NAME, UnlinkatFlags::NoRemoveDir);
        let _ = unlinkat(
            &self.directory_fd,
            self.stored_basename.as_str(),
            UnlinkatFlags::NoRemoveDir,
        );
        let _ = unlinkat(
            &*self.root_fd,
            self.directory_name.as_str(),
            UnlinkatFlags::RemoveDir,
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedUpload {
    pub upload_id: [u8; UPLOAD_ID_BYTES],
    pub remote_path: PathBuf,
    pub bytes_written: u64,
    pub sha256: [u8; UPLOAD_SHA256_BYTES],
}

/// Convert an untrusted display name into one safe path component. Runs of
/// disallowed characters collapse to one underscore.
pub fn sanitize_basename(original: &str) -> String {
    let mut result = String::with_capacity(original.len().min(STORED_BASENAME_BYTES_MAX));
    let mut in_replacement = false;
    for character in original.chars() {
        if result.len() >= STORED_BASENAME_BYTES_MAX {
            break;
        }
        if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
            result.push(character);
            in_replacement = false;
        } else if !in_replacement {
            result.push('_');
            in_replacement = true;
        }
    }
    if result.is_empty() || result == "." || result == ".." || result == PARTIAL_NAME {
        "upload".into()
    } else {
        result
    }
}

fn hex_id(id: &[u8; UPLOAD_ID_BYTES]) -> String {
    let mut output = String::with_capacity(UPLOAD_ID_BYTES * 2);
    for byte in id {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn is_hex_id(name: &str) -> bool {
    name.len() == UPLOAD_ID_BYTES * 2
        && name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn nix_io(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{symlink, PermissionsExt};

    use super::*;

    fn metadata(name: &str, bytes: &[u8]) -> BeginUpload {
        BeginUpload {
            original_name: name.into(),
            total_bytes: bytes.len() as u64,
            sha256: Sha256::digest(bytes).to_vec(),
        }
    }

    fn store() -> (tempfile::TempDir, UploadStore) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("uploads");
        std::fs::create_dir(&root).unwrap();
        let store = UploadStore::open(StoreConfig::new(root)).unwrap();
        (temp, store)
    }

    fn chunk(id: [u8; UPLOAD_ID_BYTES], offset: u64, data: &[u8]) -> UploadChunk {
        UploadChunk {
            upload_id: id.to_vec(),
            offset,
            data: data.to_vec(),
        }
    }

    #[test]
    fn sanitizes_to_one_bounded_component() {
        assert_eq!(sanitize_basename("../../etc/passwd"), ".._.._etc_passwd");
        assert_eq!(sanitize_basename("a 😀 / b.txt"), "a_b.txt");
        assert_eq!(sanitize_basename(""), "upload");
        assert_eq!(sanitize_basename(".."), "upload");
        assert_eq!(sanitize_basename(PARTIAL_NAME), "upload");
        assert!(sanitize_basename(&"x".repeat(500)).len() <= STORED_BASENAME_BYTES_MAX);
    }

    #[test]
    fn streams_verifies_and_atomically_commits() {
        let (_temp, store) = store();
        let content = b"bounded chunks, not whole-file queues";
        let mut writer = store
            .begin(&metadata("notes / final.txt", content))
            .unwrap();
        let id = writer.upload_id();
        writer.write_chunk(&chunk(id, 0, &content[..10])).unwrap();
        writer.write_chunk(&chunk(id, 10, &content[10..])).unwrap();
        let committed = writer.finish(&id).unwrap();

        assert_eq!(committed.bytes_written, content.len() as u64);
        assert_eq!(std::fs::read(&committed.remote_path).unwrap(), content);
        assert_eq!(
            committed.remote_path.file_name().unwrap(),
            "notes_final.txt"
        );
        assert_eq!(
            std::fs::metadata(committed.remote_path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&committed.remote_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn short_long_checksum_and_abort_paths_remove_partials() {
        let (_temp, store) = store();

        let content = b"expected";
        let writer = store.begin(&metadata("short", content)).unwrap();
        let id = writer.upload_id();
        let directory = store.config.root.join(hex_id(&id));
        assert!(matches!(
            writer.finish(&id),
            Err(StoreError::LengthMismatch { .. })
        ));
        assert!(!directory.exists());

        let mut writer = store.begin(&metadata("long", content)).unwrap();
        let id = writer.upload_id();
        assert!(matches!(
            writer.write_chunk(&chunk(id, 0, b"expected!")),
            Err(StoreError::InvalidUpload(
                UploadValidationError::ExceedsDeclaredLength
            ))
        ));
        let directory = store.config.root.join(hex_id(&id));
        writer.abort();
        assert!(!directory.exists());

        let mut wrong = metadata("digest", content);
        wrong.sha256 = vec![0; UPLOAD_SHA256_BYTES];
        let mut writer = store.begin(&wrong).unwrap();
        let id = writer.upload_id();
        let directory = store.config.root.join(hex_id(&id));
        writer.write_chunk(&chunk(id, 0, content)).unwrap();
        assert!(matches!(
            writer.finish(&id),
            Err(StoreError::ChecksumMismatch)
        ));
        assert!(!directory.exists());
    }

    #[test]
    fn root_symlink_and_id_symlink_are_never_followed() {
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real");
        let linked = temp.path().join("linked");
        std::fs::create_dir(&real).unwrap();
        symlink(&real, &linked).unwrap();
        assert!(matches!(
            UploadStore::open(StoreConfig::new(linked)),
            Err(StoreError::InvalidRoot)
        ));

        let store = UploadStore::open(StoreConfig::new(real.clone())).unwrap();
        let id = [0x44; UPLOAD_ID_BYTES];
        symlink(temp.path(), real.join(hex_id(&id))).unwrap();
        assert!(matches!(
            store.begin_with_id(
                &metadata("file", b"x"),
                id,
                hf_protocol::UPLOAD_CHUNK_BYTES_MAX as u32,
            ),
            Err(StoreError::IdCollision)
        ));
        assert!(!temp.path().join(PARTIAL_NAME).exists());
    }

    #[test]
    fn collision_is_rejected_without_touching_existing_directory() {
        let (_temp, store) = store();
        let id = [0x77; UPLOAD_ID_BYTES];
        let existing = store.config.root.join(hex_id(&id));
        std::fs::create_dir(&existing).unwrap();
        std::fs::write(existing.join("sentinel"), b"keep").unwrap();
        assert!(matches!(
            store.begin_with_id(
                &metadata("file", b"x"),
                id,
                hf_protocol::UPLOAD_CHUNK_BYTES_MAX as u32,
            ),
            Err(StoreError::IdCollision)
        ));
        assert_eq!(std::fs::read(existing.join("sentinel")).unwrap(), b"keep");
    }

    #[test]
    fn connection_specific_chunk_limit_is_enforced() {
        let (_temp, store) = store();
        let content = b"12345";
        let mut writer = store
            .begin_with_chunk_limit(&metadata("small", content), 4)
            .unwrap();
        let id = writer.upload_id();
        assert_eq!(writer.maximum_chunk_bytes(), 4);
        assert!(matches!(
            writer.write_chunk(&chunk(id, 0, content)),
            Err(StoreError::InvalidUpload(
                UploadValidationError::ChunkTooLarge {
                    actual: 5,
                    maximum: 4
                }
            ))
        ));
    }

    #[test]
    fn caller_timeout_drop_removes_the_partial() {
        let (_temp, store) = store();
        let mut writer = store.begin(&metadata("slow", b"eventually")).unwrap();
        let id = writer.upload_id();
        let directory = store.config.root.join(hex_id(&id));
        writer.write_chunk(&chunk(id, 0, b"event")).unwrap();

        // The transport owns the timer; expiry cancels by dropping its writer.
        drop(writer);
        assert!(!directory.exists());
    }

    #[test]
    fn reaper_is_bounded_and_ignores_unknown_names_and_symlinks() {
        let (temp, store) = store();
        let content = b"old";
        let mut writer = store.begin(&metadata("old.txt", content)).unwrap();
        let id = writer.upload_id();
        writer.write_chunk(&chunk(id, 0, content)).unwrap();
        let committed = writer.finish(&id).unwrap();
        let unrelated = store.config.root.join("not-an-upload");
        std::fs::create_dir(&unrelated).unwrap();
        let outside = temp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        symlink(
            &outside,
            store.config.root.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        )
        .unwrap();

        assert_eq!(
            store
                .reap_expired(SystemTime::now(), Duration::ZERO)
                .unwrap(),
            1
        );
        assert!(!committed.remote_path.exists());
        assert!(unrelated.exists());
        assert!(outside.exists());
    }
}
