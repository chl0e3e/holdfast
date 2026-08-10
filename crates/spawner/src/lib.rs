//! Shell spawning across a privilege boundary (ADR 0024).
//!
//! The capability bounding set is a one-way ratchet: it is inherited by every
//! descendant and can never be widened again. A tight `CapabilityBoundingSet=`
//! on the daemon's unit therefore also applies to the shells it launches, where
//! it defangs `sudo` — root without `CAP_CHOWN`/`CAP_DAC_OVERRIDE`/`CAP_FOWNER`
//! cannot run `apt`, `passwd` or `mount`. Removing the line to fix the shells
//! gives the network-facing daemon a full bounding set, which is the thing we
//! wanted to avoid.
//!
//! Shells therefore stop being descendants of the daemon. `holdfast-spawner` is
//! started by **PID 1** through socket activation, so it gets its own bounding
//! set independent of the daemon's, and the daemon's unit can be locked down to
//! `CAP_NET_BIND_SERVICE` + `CAP_DAC_READ_SEARCH` — tighter than before, since
//! `CAP_SETUID`/`CAP_SETGID`/`CAP_KILL` move to the helper. `systemd-run` would
//! have been the obvious alternative, but polkit denies it to an unprivileged
//! service account ("Interactive authentication required"), and a polkit rule
//! permitting it would grant strictly *more* than the two capabilities it
//! replaces.
//!
//! # Protocol
//!
//! One connection per shell, over `SOCK_SEQPACKET` (systemd
//! `ListenSequentialPacket=`), so every message is a datagram and needs no
//! length framing. The connection lives as long as the shell:
//!
//! 1. daemon → [`SpawnRequest`]
//! 2. spawner → [`SpawnReply`], carrying the PTY **master fd** in `SCM_RIGHTS`
//!    on success
//! 3. daemon → [`DaemonMsg::Kill`] at any point (terminate this shell)
//! 4. spawner → [`SpawnerMsg::Exited`] when the shell exits, then closes
//!
//! Losing the connection kills the shell. The daemon holds shell state in
//! memory, so a daemon that dies has already forgotten its shells; killing them
//! keeps a restart from leaving orphaned, unreachable processes behind.
//!
//! # Trust
//!
//! The spawner does **not** trust the daemon for authorization. It enforces its
//! own `--allow-account` list and refuses uid 0 outright, so a compromised
//! daemon cannot ask for a shell as an arbitrary account. Account *policy*
//! (which user may request which account) still lives in the daemon; this is
//! the backstop underneath it.

use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::path::Path;

use hf_pty::{ExitSummary, PtyError, RemoteChild};
use nix::sys::socket::{
    connect, recvmsg, sendmsg, socket, AddressFamily, ControlMessage, ControlMessageOwned,
    MsgFlags, SockFlag, SockType, UnixAddr,
};
use serde::{Deserialize, Serialize};

/// Hard ceiling on a single protocol message. The messages are a request with a
/// short argv and small replies; anything larger is a bug or an attack, and is
/// rejected rather than allocated for.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// Per-shell limits, mirrored on the wire so the spawner applies exactly what
/// the daemon was configured with (`hf_launch::ShellResourceLimits` is not
/// serializable, and giving it a serde dependency would push serde into every
/// crate that merely launches a shell).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireLimits {
    pub max_processes: u64,
    pub max_open_files: u64,
    pub max_core_bytes: u64,
}

impl From<hf_launch::ShellResourceLimits> for WireLimits {
    fn from(l: hf_launch::ShellResourceLimits) -> WireLimits {
        WireLimits {
            max_processes: l.max_processes,
            max_open_files: l.max_open_files,
            max_core_bytes: l.max_core_bytes,
        }
    }
}

impl From<WireLimits> for hf_launch::ShellResourceLimits {
    fn from(l: WireLimits) -> hf_launch::ShellResourceLimits {
        hf_launch::ShellResourceLimits {
            max_processes: l.max_processes,
            max_open_files: l.max_open_files,
            max_core_bytes: l.max_core_bytes,
        }
    }
}

/// Everything the spawner needs to launch one shell. The account is a *name*,
/// not a uid: the spawner resolves it itself against its own allowlist, so a
/// compromised daemon cannot smuggle in a uid the allowlist would have refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpawnRequest {
    pub account: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub cols: u16,
    pub rows: u16,
    pub limits: WireLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpawnReply {
    /// Shell running as `pid`; the PTY master fd rides along in `SCM_RIGHTS`.
    Spawned { pid: u32 },
    /// `forbidden` distinguishes "not allowed" from "went wrong" so the daemon
    /// can map it back onto its own `Forbidden` and not leak the difference
    /// between an absent and an unauthorized account to a client.
    Error { message: String, forbidden: bool },
}

/// Daemon → spawner, after a successful spawn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaemonMsg {
    Kill,
}

/// Spawner → daemon, once.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpawnerMsg {
    Exited { success: bool, exit_code: u32 },
}

#[derive(Debug, thiserror::Error)]
pub enum SpawnError {
    #[error("spawner refused the request: {0}")]
    Forbidden(String),
    #[error("spawner error: {0}")]
    Spawner(String),
    #[error("spawner socket {path}: {source}")]
    Connect {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("spawner protocol error: {0}")]
    Protocol(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Exit status reported when the spawner vanishes without an `Exited` message
/// (it crashed, or was killed). The shell is gone either way; callers must see
/// *an* exit rather than waiting forever.
pub const LOST_SPAWNER_EXIT_CODE: u32 = 255;

// --- framing -----------------------------------------------------------------

/// Send one JSON message as a single datagram, optionally passing one fd.
pub fn send_message<T: Serialize>(
    sock: RawFd,
    msg: &T,
    fd: Option<RawFd>,
) -> Result<(), SpawnError> {
    let bytes = serde_json::to_vec(msg)
        .map_err(|e| SpawnError::Protocol(format!("encode: {e}")))?;
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(SpawnError::Protocol(format!(
            "message of {} bytes exceeds the {MAX_MESSAGE_BYTES}-byte limit",
            bytes.len()
        )));
    }
    let iov = [IoSlice::new(&bytes)];
    let fds = fd.map(|f| [f]);
    let cmsgs: Vec<ControlMessage> = match &fds {
        Some(fds) => vec![ControlMessage::ScmRights(fds)],
        None => vec![],
    };
    // SAFETY: `sock` is a connected socket owned by the caller for the duration.
    let borrowed = unsafe { BorrowedFd::borrow_raw(sock) };
    sendmsg::<()>(borrowed.as_raw_fd(), &iov, &cmsgs, MsgFlags::empty(), None)
        .map_err(|e| SpawnError::Protocol(format!("sendmsg: {e}")))?;
    Ok(())
}

/// Receive one JSON message, plus any fd that came with it.
///
/// `Ok(None)` is a clean EOF (peer closed). `nonblocking` maps `EAGAIN` onto
/// [`SpawnError::Protocol`]-free polling via [`recv_message_nonblocking`].
fn recv_raw(
    sock: RawFd,
    flags: MsgFlags,
) -> Result<Option<(Vec<u8>, Option<OwnedFd>)>, nix::Error> {
    let mut buf = vec![0u8; MAX_MESSAGE_BYTES];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsg = nix::cmsg_space!([RawFd; 1]);
    let msg = recvmsg::<()>(sock, &mut iov, Some(&mut cmsg), flags)?;
    let len = msg.bytes;
    if len == 0 {
        return Ok(None);
    }
    let mut received_fd = None;
    for c in msg.cmsgs()? {
        if let ControlMessageOwned::ScmRights(fds) = c {
            for raw in fds {
                if received_fd.is_none() {
                    // SAFETY: the kernel just installed this fd in our table and
                    // no one else holds it.
                    received_fd = Some(unsafe { OwnedFd::from_raw_fd_checked(raw) });
                } else {
                    // Never leak an unexpected extra fd.
                    let _ = nix::unistd::close(raw);
                }
            }
        }
    }
    buf.truncate(len);
    Ok(Some((buf, received_fd)))
}

/// Blocking receive of one decoded message plus any passed fd.
pub fn recv_message<T: for<'de> Deserialize<'de>>(
    sock: RawFd,
) -> Result<Option<(T, Option<OwnedFd>)>, SpawnError> {
    match recv_raw(sock, MsgFlags::empty()) {
        Ok(None) => Ok(None),
        Ok(Some((bytes, fd))) => {
            let msg = serde_json::from_slice(&bytes)
                .map_err(|e| SpawnError::Protocol(format!("decode: {e}")))?;
            Ok(Some((msg, fd)))
        }
        Err(e) => Err(SpawnError::Protocol(format!("recvmsg: {e}"))),
    }
}

/// Non-blocking variant: `Ok(None)` means "nothing yet *or* peer gone"; the
/// caller distinguishes them with [`PeerState`].
pub fn recv_message_nonblocking<T: for<'de> Deserialize<'de>>(
    sock: RawFd,
) -> Result<(PeerState, Option<T>), SpawnError> {
    match recv_raw(sock, MsgFlags::MSG_DONTWAIT) {
        Ok(None) => Ok((PeerState::Closed, None)),
        Ok(Some((bytes, _fd))) => {
            let msg = serde_json::from_slice(&bytes)
                .map_err(|e| SpawnError::Protocol(format!("decode: {e}")))?;
            Ok((PeerState::Open, Some(msg)))
        }
        Err(nix::Error::EAGAIN) => Ok((PeerState::Open, None)),
        Err(e) => Err(SpawnError::Protocol(format!("recvmsg: {e}"))),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    Open,
    Closed,
}

// `OwnedFd::from_raw_fd` is unsafe and unchecked; this wrapper exists to keep
// the unsafety in one documented place.
trait FromRawFdChecked {
    /// # Safety
    /// `raw` must be an open fd that no other value owns.
    unsafe fn from_raw_fd_checked(raw: RawFd) -> OwnedFd;
}

impl FromRawFdChecked for OwnedFd {
    unsafe fn from_raw_fd_checked(raw: RawFd) -> OwnedFd {
        use std::os::fd::FromRawFd;
        OwnedFd::from_raw_fd(raw)
    }
}

// --- client ------------------------------------------------------------------

/// Ask the spawner for a shell. On success returns the PTY master fd and a
/// handle that drives the shell's lifetime over the same connection.
pub fn spawn_shell(
    socket_path: &Path,
    req: &SpawnRequest,
) -> Result<(OwnedFd, RemoteShell), SpawnError> {
    let sock = socket(
        AddressFamily::Unix,
        SockType::SeqPacket,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .map_err(|e| SpawnError::Connect {
        path: socket_path.display().to_string(),
        source: std::io::Error::from(e),
    })?;
    let addr = UnixAddr::new(socket_path).map_err(|e| SpawnError::Connect {
        path: socket_path.display().to_string(),
        source: std::io::Error::from(e),
    })?;
    connect(sock.as_raw_fd(), &addr).map_err(|e| SpawnError::Connect {
        path: socket_path.display().to_string(),
        source: std::io::Error::from(e),
    })?;

    send_message(sock.as_raw_fd(), req, None)?;

    let (reply, fd): (SpawnReply, Option<OwnedFd>) = recv_message(sock.as_raw_fd())?
        .ok_or_else(|| SpawnError::Protocol("spawner closed before replying".into()))?;

    match reply {
        SpawnReply::Spawned { pid } => {
            let master = fd.ok_or_else(|| {
                SpawnError::Protocol("spawner reported success without a PTY fd".into())
            })?;
            Ok((
                master,
                RemoteShell {
                    sock,
                    pid,
                    exit: None,
                },
            ))
        }
        SpawnReply::Error {
            message,
            forbidden: true,
        } => Err(SpawnError::Forbidden(message)),
        SpawnReply::Error { message, .. } => Err(SpawnError::Spawner(message)),
    }
}

/// The daemon's handle on a shell owned by the spawner.
pub struct RemoteShell {
    sock: OwnedFd,
    pid: u32,
    exit: Option<ExitSummary>,
}

impl RemoteShell {
    /// Treat a vanished spawner as an exit: the shell died with it, and callers
    /// must never block forever waiting for a message that cannot arrive.
    fn lost(&mut self) -> ExitSummary {
        let summary = ExitSummary {
            success: false,
            exit_code: LOST_SPAWNER_EXIT_CODE,
        };
        self.exit = Some(summary);
        summary
    }

    fn record(&mut self, msg: SpawnerMsg) -> ExitSummary {
        let SpawnerMsg::Exited {
            success,
            exit_code,
        } = msg;
        let summary = ExitSummary {
            success,
            exit_code,
        };
        self.exit = Some(summary);
        summary
    }
}

impl RemoteChild for RemoteShell {
    fn try_wait(&mut self) -> Result<Option<ExitSummary>, PtyError> {
        if let Some(exit) = self.exit {
            return Ok(Some(exit));
        }
        match recv_message_nonblocking::<SpawnerMsg>(self.sock.as_raw_fd()) {
            Ok((PeerState::Closed, _)) => Ok(Some(self.lost())),
            Ok((PeerState::Open, Some(msg))) => Ok(Some(self.record(msg))),
            Ok((PeerState::Open, None)) => Ok(None),
            Err(e) => Err(PtyError::Spawn(e.to_string())),
        }
    }

    fn wait(&mut self) -> Result<ExitSummary, PtyError> {
        if let Some(exit) = self.exit {
            return Ok(exit);
        }
        match recv_message::<SpawnerMsg>(self.sock.as_raw_fd()) {
            Ok(Some((msg, _))) => Ok(self.record(msg)),
            Ok(None) => Ok(self.lost()),
            Err(e) => Err(PtyError::Spawn(e.to_string())),
        }
    }

    fn kill(&mut self) -> Result<(), PtyError> {
        if self.exit.is_some() {
            return Ok(()); // Already exited: killing is idempotent (spec §9).
        }
        // A failed send means the spawner is already gone, which is the outcome
        // kill was asking for.
        let _ = send_message(self.sock.as_raw_fd(), &DaemonMsg::Kill, None);
        Ok(())
    }

    fn process_id(&self) -> Option<u32> {
        Some(self.pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::socket::socketpair;

    fn pair() -> (OwnedFd, OwnedFd) {
        socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .unwrap()
    }

    #[test]
    fn request_round_trips_over_a_seqpacket_pair() {
        let (a, b) = pair();
        let req = SpawnRequest {
            account: "alice".into(),
            command: Some("bash".into()),
            args: vec!["--norc".into()],
            cols: 80,
            rows: 24,
            limits: WireLimits {
                max_processes: 512,
                max_open_files: 1024,
                max_core_bytes: 0,
            },
        };
        send_message(a.as_raw_fd(), &req, None).unwrap();
        let (got, fd): (SpawnRequest, _) = recv_message(b.as_raw_fd()).unwrap().unwrap();
        assert_eq!(got, req);
        assert!(fd.is_none());
    }

    #[test]
    fn a_passed_fd_arrives_as_a_usable_descriptor() {
        // The whole design rests on SCM_RIGHTS moving the PTY master across, so
        // assert the received fd is genuinely the same open file.
        let (a, b) = pair();
        let (r, w) = nix::unistd::pipe().unwrap();
        send_message(a.as_raw_fd(), &SpawnReply::Spawned { pid: 42 }, Some(r.as_raw_fd())).unwrap();
        let (reply, fd): (SpawnReply, _) = recv_message(b.as_raw_fd()).unwrap().unwrap();
        assert_eq!(reply, SpawnReply::Spawned { pid: 42 });
        let received = fd.expect("fd should have been passed");
        nix::unistd::write(&w, b"ping").unwrap();
        let mut buf = [0u8; 4];
        nix::unistd::read(&received, &mut buf).unwrap();
        assert_eq!(&buf, b"ping");
    }

    #[test]
    fn closed_peer_reads_as_eof_not_an_error() {
        let (a, b) = pair();
        drop(a);
        let got: Option<(SpawnerMsg, _)> = recv_message(b.as_raw_fd()).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn a_lost_spawner_still_produces_an_exit() {
        // A daemon must never hang because the helper died; wait() reports the
        // sentinel instead of blocking forever.
        let (a, b) = pair();
        let mut shell = RemoteShell {
            sock: b,
            pid: 7,
            exit: None,
        };
        drop(a);
        let exit = shell.wait().unwrap();
        assert!(!exit.success);
        assert_eq!(exit.exit_code, LOST_SPAWNER_EXIT_CODE);
        // And it is sticky, so a second call cannot block either.
        assert_eq!(shell.try_wait().unwrap(), Some(exit));
    }

    #[test]
    fn try_wait_is_none_while_the_shell_runs() {
        let (a, b) = pair();
        let mut shell = RemoteShell {
            sock: b,
            pid: 7,
            exit: None,
        };
        assert_eq!(shell.try_wait().unwrap(), None);
        send_message(
            a.as_raw_fd(),
            &SpawnerMsg::Exited {
                success: true,
                exit_code: 0,
            },
            None,
        )
        .unwrap();
        let exit = shell.try_wait().unwrap().unwrap();
        assert!(exit.success);
        assert_eq!(exit.exit_code, 0);
    }

    #[test]
    fn oversized_messages_are_refused_before_they_are_sent() {
        let (a, _b) = pair();
        let req = SpawnRequest {
            account: "alice".into(),
            command: None,
            args: vec!["x".repeat(MAX_MESSAGE_BYTES)],
            cols: 80,
            rows: 24,
            limits: WireLimits {
                max_processes: 1,
                max_open_files: 1,
                max_core_bytes: 0,
            },
        };
        assert!(matches!(
            send_message(a.as_raw_fd(), &req, None),
            Err(SpawnError::Protocol(_))
        ));
    }
}
