//! End-to-end exercise of the real `holdfast-spawner` binary (ADR 0024).
//!
//! These run unprivileged: the request names the *test user's own* account, so
//! `build_launch` skips the setpriv wrap (switching to yourself is a no-op) and
//! no capabilities are needed. What is still covered is everything specific to
//! the split — the seqpacket protocol, passing the PTY master over SCM_RIGHTS,
//! driving an adopted PTY, kill, and exit reporting — plus the authorization
//! backstop, which must hold whether or not the caller is privileged.

use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

use hf_pty::{PtyProcess, RemoteChild};
use hf_spawner::{
    recv_message, send_message, InitialRequest, ReceiveUploadRequest, SpawnReply, SpawnRequest,
    UploadReply, WireLimits,
};
use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
use sha2::{Digest, Sha256};

const T: Duration = Duration::from_secs(10);

fn me() -> String {
    nix::unistd::User::from_uid(nix::unistd::geteuid())
        .unwrap()
        .unwrap()
        .name
}

fn limits() -> WireLimits {
    WireLimits {
        // Deliberately at or below the ceiling this test process already has:
        // prlimit cannot *raise* a hard limit without CAP_SYS_RESOURCE, and the
        // suite may itself be running inside a resource-limited holdfast shell.
        max_processes: 128,
        max_open_files: 128,
        max_core_bytes: 0,
    }
}

/// Start the helper with one end of a seqpacket pair as its stdin, exactly as
/// systemd's `Accept=yes` would.
fn start_spawner(extra: &[&str]) -> (Child, OwnedFd) {
    let (ours, theirs) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_holdfast-spawner"))
        .args(extra)
        .stdin(Stdio::from(theirs))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    (child, ours)
}

fn request(account: &str) -> SpawnRequest {
    SpawnRequest {
        account: account.to_string(),
        command: Some("bash".into()),
        args: vec!["--norc".into(), "--noprofile".into()],
        cols: 80,
        rows: 24,
        limits: limits(),
    }
}

fn send_spawn(sock: &OwnedFd, request: SpawnRequest) {
    send_message(sock.as_raw_fd(), &InitialRequest::SpawnShell(request), None).unwrap();
}

fn upload_request(account: &str, name: &str, content: &[u8]) -> ReceiveUploadRequest {
    ReceiveUploadRequest {
        account: account.into(),
        original_name: name.into(),
        total_bytes: content.len() as u64,
        sha256: Sha256::digest(content).to_vec(),
        maximum_chunk_bytes: hf_spawner::UPLOAD_CHUNK_BYTES_MAX as u32,
    }
}

#[test]
fn a_shell_launches_echoes_and_reports_its_exit() {
    let user = me();
    let (mut helper, sock) = start_spawner(&["--allow-account", &user]);
    send_spawn(&sock, request(&user));

    let (reply, master): (SpawnReply, Option<OwnedFd>) =
        recv_message(sock.as_raw_fd()).unwrap().unwrap();
    let pid = match reply {
        SpawnReply::Spawned { pid } => pid,
        SpawnReply::Error { message, .. } => panic!("spawn refused: {message}"),
    };
    assert!(pid > 0);
    let master = master.expect("the PTY master must arrive with the reply");

    // The daemon's view: an adopted PTY behaves like a locally spawned one.
    let mut pty = PtyProcess::adopt(master, Box::new(NoopChild(pid))).unwrap();
    let output = pty.take_output().unwrap();
    pty.write(b"echo SPAWNER_OK\n").unwrap();

    let deadline = Instant::now() + T;
    let mut seen = Vec::new();
    loop {
        assert!(
            Instant::now() < deadline,
            "timed out; saw {:?}",
            String::from_utf8_lossy(&seen)
        );
        match output.recv_timeout(deadline - Instant::now()) {
            Ok(chunk) => {
                seen.extend_from_slice(&chunk);
                // Skip the echoed command line itself: the shell's own exit
                // banner would otherwise match on the first read.
                if String::from_utf8_lossy(&seen).matches("SPAWNER_OK").count() >= 2 {
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => {
                panic!("PTY closed early; saw {:?}", String::from_utf8_lossy(&seen))
            }
        }
    }

    // Resize must reach the shell through the adopted fd, not through
    // portable-pty's master handle.
    pty.resize(100, 30).unwrap();

    pty.write(b"exit 7\n").unwrap();
    let status = helper.wait().unwrap();
    assert!(
        status.success(),
        "helper should exit cleanly after the shell"
    );
}

#[test]
fn an_account_outside_the_allowlist_is_forbidden() {
    // The backstop under the daemon's own policy: even a daemon asking for a
    // real, resolvable account gets nothing if the spawner was not configured
    // for it.
    let (mut helper, sock) = start_spawner(&["--allow-account", "someone-else-entirely"]);
    send_spawn(&sock, request(&me()));

    let (reply, fd): (SpawnReply, Option<OwnedFd>) =
        recv_message(sock.as_raw_fd()).unwrap().unwrap();
    match reply {
        SpawnReply::Error { forbidden, .. } => assert!(forbidden),
        SpawnReply::Spawned { .. } => panic!("spawner launched a shell it should have refused"),
    }
    assert!(fd.is_none(), "a refusal must not pass a descriptor");
    assert!(!helper.wait().unwrap().success());
}

#[test]
fn root_is_refused_even_when_allowlisted() {
    // Misconfiguration must not be enough: a root shell would hand back exactly
    // the privilege the spawner split exists to withhold.
    let (mut helper, sock) = start_spawner(&["--allow-account", "root"]);
    send_spawn(&sock, request("root"));

    let (reply, _): (SpawnReply, Option<OwnedFd>) =
        recv_message(sock.as_raw_fd()).unwrap().unwrap();
    match reply {
        SpawnReply::Error { forbidden, message } => {
            assert!(forbidden);
            assert!(message.contains("uid 0"), "unexpected message: {message}");
        }
        SpawnReply::Spawned { .. } => panic!("spawner launched a root shell"),
    }
    assert!(!helper.wait().unwrap().success());
}

#[test]
fn a_wrong_peer_uid_is_refused_before_the_request_is_read() {
    // SO_PEERCRED is checked first, so a caller that is not the daemon cannot
    // even get its request parsed.
    let wrong = nix::unistd::geteuid().as_raw() + 1;
    let (mut helper, sock) =
        start_spawner(&["--allow-account", &me(), "--peer-uid", &wrong.to_string()]);
    send_spawn(&sock, request(&me()));

    let (reply, _): (SpawnReply, Option<OwnedFd>) =
        recv_message(sock.as_raw_fd()).unwrap().unwrap();
    assert!(matches!(
        reply,
        SpawnReply::Error {
            forbidden: true,
            ..
        }
    ));
    assert!(!helper.wait().unwrap().success());
}

#[test]
fn refusing_to_start_without_an_allowlist_is_fail_closed() {
    let (mut helper, _sock) = start_spawner(&[]);
    let status = helper.wait().unwrap();
    assert_eq!(status.code(), Some(2));
    let mut stderr = String::new();
    helper
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(stderr.contains("--allow-account"), "unexpected: {stderr}");
}

#[test]
fn an_upload_streams_commits_and_is_owned_by_the_target_account() {
    let user = me();
    if user == "root" {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("uploads");
    std::fs::create_dir(&root).unwrap();
    let root_arg = root.to_string_lossy().into_owned();
    let (mut helper, sock) = start_spawner(&["--allow-account", &user, "--upload-root", &root_arg]);
    let content = b"spawner-owned bounded upload";
    let mut request = upload_request(&user, "../../release payload.txt", content);
    request.maximum_chunk_bytes = 1024;
    send_message(
        sock.as_raw_fd(),
        &InitialRequest::ReceiveUpload(request),
        None,
    )
    .unwrap();

    let (ready, fd): (UploadReply, Option<OwnedFd>) =
        recv_message(sock.as_raw_fd()).unwrap().unwrap();
    assert!(fd.is_none());
    let (upload_id, maximum_chunk_bytes) = match ready {
        UploadReply::Ready {
            upload_id,
            maximum_chunk_bytes,
        } => (upload_id, maximum_chunk_bytes),
        other => panic!("unexpected upload reply: {other:?}"),
    };
    assert_eq!(maximum_chunk_bytes, 1024);
    send_message(
        sock.as_raw_fd(),
        &hf_spawner::UploadDaemonMsg::Chunk {
            upload_id: upload_id.clone(),
            offset: 0,
            data: content.to_vec(),
        },
        None,
    )
    .unwrap();
    send_message(
        sock.as_raw_fd(),
        &hf_spawner::UploadDaemonMsg::Finish {
            upload_id: upload_id.clone(),
        },
        None,
    )
    .unwrap();
    let (finished, _): (UploadReply, Option<OwnedFd>) =
        recv_message(sock.as_raw_fd()).unwrap().unwrap();
    let remote_path = match finished {
        UploadReply::Finished {
            upload_id: returned_id,
            remote_path,
            bytes_written,
            sha256,
        } => {
            assert_eq!(returned_id, upload_id);
            assert_eq!(bytes_written, content.len() as u64);
            assert_eq!(sha256, Sha256::digest(content).as_slice());
            std::path::PathBuf::from(remote_path)
        }
        other => panic!("unexpected upload result: {other:?}"),
    };
    assert!(helper.wait().unwrap().success());
    assert_eq!(std::fs::read(&remote_path).unwrap(), content);
    let ids = hf_launch::resolve_account_ids(&user).unwrap();
    let file_metadata = std::fs::metadata(&remote_path).unwrap();
    let directory_metadata = std::fs::metadata(remote_path.parent().unwrap()).unwrap();
    assert_eq!(file_metadata.uid(), ids.uid);
    assert_eq!(file_metadata.gid(), ids.gid);
    assert_eq!(file_metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(directory_metadata.uid(), ids.uid);
    assert_eq!(directory_metadata.gid(), ids.gid);
    assert_eq!(directory_metadata.permissions().mode() & 0o777, 0o700);
}

#[test]
fn disconnected_upload_removes_its_partial() {
    let user = me();
    if user == "root" {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("uploads");
    std::fs::create_dir(&root).unwrap();
    let root_arg = root.to_string_lossy().into_owned();
    let (mut helper, sock) = start_spawner(&["--allow-account", &user, "--upload-root", &root_arg]);
    send_message(
        sock.as_raw_fd(),
        &InitialRequest::ReceiveUpload(upload_request(&user, "partial", b"unfinished")),
        None,
    )
    .unwrap();
    let _: (UploadReply, Option<OwnedFd>) = recv_message(sock.as_raw_fd()).unwrap().unwrap();
    drop(sock);
    assert!(helper.wait().unwrap().success());
    assert_eq!(std::fs::read_dir(root).unwrap().count(), 0);
}

#[test]
fn upload_capability_is_confined_to_the_spawner_unit() {
    let daemon = include_str!("../../../deploy/systemd/holdfastd-multiuser.service");
    let spawner = include_str!("../../../deploy/systemd/holdfast-spawner@.service");
    let daemon_ambient = daemon
        .lines()
        .find(|line| line.starts_with("AmbientCapabilities="))
        .unwrap();
    assert!(!daemon_ambient.contains("CAP_CHOWN"));
    assert!(spawner.contains("AmbientCapabilities=CAP_SETUID CAP_SETGID CAP_KILL CAP_CHOWN"));
}

/// The `RemoteChild` half is covered by the crate's own unit tests; these
/// integration tests only need something to satisfy `adopt`.
struct NoopChild(u32);

impl RemoteChild for NoopChild {
    fn try_wait(&mut self) -> Result<Option<hf_pty::ExitSummary>, hf_pty::PtyError> {
        Ok(None)
    }
    fn wait(&mut self) -> Result<hf_pty::ExitSummary, hf_pty::PtyError> {
        Ok(hf_pty::ExitSummary {
            success: true,
            exit_code: 0,
        })
    }
    fn kill(&mut self) -> Result<(), hf_pty::PtyError> {
        Ok(())
    }
    fn process_id(&self) -> Option<u32> {
        Some(self.0)
    }
}
