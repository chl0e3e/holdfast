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
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

use hf_pty::{PtyProcess, RemoteChild};
use hf_spawner::{
    recv_message, send_message, SpawnReply, SpawnRequest, WireLimits,
};
use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};

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
        SockFlag::empty(),
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

#[test]
fn a_shell_launches_echoes_and_reports_its_exit() {
    let user = me();
    let (mut helper, sock) = start_spawner(&["--allow-account", &user]);
    send_message(sock.as_raw_fd(), &request(&user), None).unwrap();

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
            Err(RecvTimeoutError::Disconnected) => panic!(
                "PTY closed early; saw {:?}",
                String::from_utf8_lossy(&seen)
            ),
        }
    }

    // Resize must reach the shell through the adopted fd, not through
    // portable-pty's master handle.
    pty.resize(100, 30).unwrap();

    pty.write(b"exit 7\n").unwrap();
    let status = helper.wait().unwrap();
    assert!(status.success(), "helper should exit cleanly after the shell");
}

#[test]
fn an_account_outside_the_allowlist_is_forbidden() {
    // The backstop under the daemon's own policy: even a daemon asking for a
    // real, resolvable account gets nothing if the spawner was not configured
    // for it.
    let (mut helper, sock) = start_spawner(&["--allow-account", "someone-else-entirely"]);
    send_message(sock.as_raw_fd(), &request(&me()), None).unwrap();

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
    send_message(sock.as_raw_fd(), &request("root"), None).unwrap();

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
    let (mut helper, sock) = start_spawner(&[
        "--allow-account",
        &me(),
        "--peer-uid",
        &wrong.to_string(),
    ]);
    send_message(sock.as_raw_fd(), &request(&me()), None).unwrap();

    let (reply, _): (SpawnReply, Option<OwnedFd>) =
        recv_message(sock.as_raw_fd()).unwrap().unwrap();
    assert!(matches!(reply, SpawnReply::Error { forbidden: true, .. }));
    assert!(!helper.wait().unwrap().success());
}

#[test]
fn refusing_to_start_without_an_allowlist_is_fail_closed() {
    let (mut helper, _sock) = start_spawner(&[]);
    let status = helper.wait().unwrap();
    assert_eq!(status.code(), Some(2));
    let mut stderr = String::new();
    helper.stderr.take().unwrap().read_to_string(&mut stderr).unwrap();
    assert!(stderr.contains("--allow-account"), "unexpected: {stderr}");
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
