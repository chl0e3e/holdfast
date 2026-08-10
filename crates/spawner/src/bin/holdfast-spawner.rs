//! `holdfast-spawner` — the privileged half of shell launching (ADR 0024).
//!
//! systemd starts one of these per connection (`Accept=yes`), so the process is
//! forked by **PID 1** and its capability bounding set comes from its own unit,
//! not from the daemon's. That is the entire point: the shell it launches
//! inherits a full bounding set and `sudo` behaves as in a normal login, while
//! the network-facing daemon keeps a tight one.
//!
//! stdin is the accepted connection. The helper handles exactly one shell and
//! exits when that shell does.
//!
//! It re-checks authorization rather than trusting the daemon: the account must
//! appear in `--allow-account`, must resolve, and must not be uid 0. A
//! compromised daemon can therefore still only reach accounts the deployment
//! already exposes over the network.

use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::atomic::{AtomicI32, Ordering};

use hf_launch::{build_launch, resolve_account_ids, LaunchError, ShellResourceLimits};
use hf_spawner::{
    recv_message, send_message, DaemonMsg, SpawnReply, SpawnRequest, SpawnerMsg,
};
use nix::sys::signal::{kill, Signal};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

/// The accepted connection, per systemd `Accept=yes`.
const CONN: RawFd = 0;

/// Set once the shell is running, so the socket-reader thread can signal it.
static CHILD_PID: AtomicI32 = AtomicI32::new(0);

struct Config {
    allowed_accounts: Vec<String>,
    /// uid the daemon must connect as. `None` disables the check, which is only
    /// appropriate for tests — the socket unit's ownership is the other half of
    /// this defence.
    peer_uid: Option<u32>,
}

fn parse_args() -> Result<Config, String> {
    let mut allowed_accounts = Vec::new();
    let mut peer_uid = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--allow-account" => allowed_accounts.push(
                args.next()
                    .ok_or("--allow-account needs an account name")?,
            ),
            "--peer-user" => {
                let name = args.next().ok_or("--peer-user needs a username")?;
                let ids = resolve_account_ids(&name)
                    .map_err(|_| format!("--peer-user {name:?} does not resolve"))?;
                peer_uid = Some(ids.uid);
            }
            "--peer-uid" => {
                let raw = args.next().ok_or("--peer-uid needs a uid")?;
                peer_uid = Some(raw.parse().map_err(|_| format!("bad uid {raw:?}"))?);
            }
            other => {
                return Err(format!(
                    "unknown argument: {other} (supported: --allow-account <name>, \
                     --peer-user <name>, --peer-uid <uid>)"
                ))
            }
        }
    }
    if allowed_accounts.is_empty() {
        // Fail closed exactly as the daemon does for --drop-privileges: with no
        // allowlist every request would be permitted.
        return Err("at least one --allow-account is required".into());
    }
    Ok(Config {
        allowed_accounts,
        peer_uid,
    })
}

/// Authorization failure (reported as `forbidden`) vs anything else.
enum Refusal {
    Forbidden(String),
    Failed(String),
}

impl From<LaunchError> for Refusal {
    fn from(e: LaunchError) -> Refusal {
        match e {
            LaunchError::Forbidden => Refusal::Forbidden("account is not available".into()),
            LaunchError::Internal(m) => Refusal::Failed(m),
        }
    }
}

fn check_peer(cfg: &Config) -> Result<(), Refusal> {
    let Some(expected) = cfg.peer_uid else {
        return Ok(());
    };
    let conn = unsafe { std::os::fd::BorrowedFd::borrow_raw(CONN) };
    let creds = getsockopt(&conn, PeerCredentials)
        .map_err(|e| Refusal::Failed(format!("SO_PEERCRED: {e}")))?;
    if creds.uid() != expected {
        return Err(Refusal::Forbidden(format!(
            "connection from uid {} but only uid {expected} may request shells",
            creds.uid()
        )));
    }
    Ok(())
}

/// Launch the shell on a fresh PTY. Returns the master fd and the child pid.
fn spawn_shell(cfg: &Config, req: &SpawnRequest) -> Result<(OwnedFd, u32), Refusal> {
    if !cfg.allowed_accounts.iter().any(|a| *a == req.account) {
        return Err(Refusal::Forbidden(format!(
            "account {:?} is not in this spawner's allowlist",
            req.account
        )));
    }
    // Independent of the allowlist: a root shell would hand back everything the
    // split was meant to prevent, so it is refused even if misconfigured in.
    let ids = resolve_account_ids(&req.account)?;
    if ids.uid == 0 {
        return Err(Refusal::Forbidden(
            "refusing to launch a shell as uid 0".into(),
        ));
    }

    let limits: ShellResourceLimits = req.limits.into();
    let launch = build_launch(
        true,
        limits,
        Some(&req.account),
        req.command.as_deref(),
        &req.args,
    )?;
    let program = launch
        .program
        .ok_or_else(|| Refusal::Failed("launch produced no program".into()))?;

    let winsize = nix::pty::Winsize {
        ws_row: req.rows,
        ws_col: req.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let pty = nix::pty::openpty(Some(&winsize), None)
        .map_err(|e| Refusal::Failed(format!("openpty: {e}")))?;
    let slave_raw = pty.slave.as_raw_fd();

    let mut cmd = Command::new(&program);
    cmd.args(&launch.args);
    // `setpriv --reset-env` keeps TERM from this process's environment, and a
    // systemd-started helper has none — without this the shell comes up dumb.
    cmd.env("TERM", "xterm-256color");
    // SAFETY: everything between fork and exec is async-signal-safe — dup2,
    // setsid and an ioctl, no allocation and no locks.
    unsafe {
        cmd.pre_exec(move || {
            // New session, so the shell owns the terminal and job control works.
            nix::unistd::setsid().map_err(std::io::Error::from)?;
            // Make the slave our controlling terminal.
            nix::ioctl_none_bad!(set_ctty, nix::libc::TIOCSCTTY);
            set_ctty(slave_raw).map_err(std::io::Error::from)?;
            let slave = std::os::fd::BorrowedFd::borrow_raw(slave_raw);
            // Not `dup2_raw`: it hands back an `OwnedFd` for the *new* fd, so
            // dropping the result closes the descriptor it just installed —
            // stdin/stdout/stderr would all end up closed and the shell would
            // read EOF and exit immediately.
            nix::unistd::dup2_stdin(&slave).map_err(std::io::Error::from)?;
            nix::unistd::dup2_stdout(&slave).map_err(std::io::Error::from)?;
            nix::unistd::dup2_stderr(&slave).map_err(std::io::Error::from)?;
            if slave_raw > 2 {
                let _ = nix::unistd::close(slave_raw);
            }
            Ok(())
        });
    }

    let child = cmd
        .spawn()
        .map_err(|e| Refusal::Failed(format!("spawn {program}: {e}")))?;
    // The parent must not keep the slave open, or the master never reports EOF
    // when the shell exits.
    drop(pty.slave);
    Ok((pty.master, child.id()))
}

/// Watch the connection for a kill request, and treat the daemon going away as
/// one: the daemon keeps shell state in memory, so a daemon that died has
/// already forgotten this shell and nothing would ever reap it.
fn watch_for_kill() {
    // A single read settles it: `DaemonMsg::Kill` is the only message the
    // daemon ever sends, and the two failure cases — a closed connection or a
    // decode error — mean the same thing here.
    match recv_message::<DaemonMsg>(CONN) {
        Ok(Some((DaemonMsg::Kill, _))) => {}
        Ok(None) => {
            eprintln!("holdfast-spawner: daemon closed the connection; killing the shell");
        }
        Err(e) => {
            eprintln!("holdfast-spawner: control channel error: {e}; killing the shell");
        }
    }
    signal_child(Signal::SIGKILL);
}

fn signal_child(sig: Signal) {
    let pid = CHILD_PID.load(Ordering::SeqCst);
    if pid > 0 {
        // Already-exited children are an expected race, not an error.
        let _ = kill(Pid::from_raw(pid), sig);
    }
}

fn main() {
    let cfg = match parse_args() {
        Ok(cfg) => cfg,
        Err(msg) => {
            eprintln!("holdfast-spawner: {msg}");
            std::process::exit(2);
        }
    };

    let outcome = check_peer(&cfg).and_then(|()| {
        let (req, _) = match recv_message::<SpawnRequest>(CONN) {
            Ok(Some(msg)) => msg,
            Ok(None) => {
                // Nothing to refuse and no one to tell.
                std::process::exit(0);
            }
            Err(e) => return Err(Refusal::Failed(format!("reading request: {e}"))),
        };
        spawn_shell(&cfg, &req)
    });

    let (master, pid) = match outcome {
        Ok(v) => v,
        Err(refusal) => {
            let (message, forbidden) = match refusal {
                Refusal::Forbidden(m) => (m, true),
                Refusal::Failed(m) => (m, false),
            };
            eprintln!("holdfast-spawner: refused: {message}");
            let _ = send_message(CONN, &SpawnReply::Error { message, forbidden }, None);
            std::process::exit(1);
        }
    };

    CHILD_PID.store(pid as i32, Ordering::SeqCst);

    // Hand the master over, then drop our copy: the daemon owns it now, and the
    // shell must see a hangup when *the daemon* lets go, not later.
    let send = send_message(
        CONN,
        &SpawnReply::Spawned { pid },
        Some(master.as_raw_fd()),
    );
    drop(master);
    if let Err(e) = send {
        eprintln!("holdfast-spawner: could not hand over the PTY: {e}");
        signal_child(Signal::SIGKILL);
        let _ = waitpid(Pid::from_raw(pid as i32), None);
        std::process::exit(1);
    }

    std::thread::Builder::new()
        .name("hf-spawner-control".into())
        .spawn(watch_for_kill)
        .expect("spawn control thread");

    let summary = match waitpid(Pid::from_raw(pid as i32), None) {
        Ok(WaitStatus::Exited(_, code)) => SpawnerMsg::Exited {
            success: code == 0,
            exit_code: code as u32,
        },
        // Match the shell convention the rest of the system reports for signals.
        Ok(WaitStatus::Signaled(_, sig, _)) => SpawnerMsg::Exited {
            success: false,
            exit_code: 128 + sig as u32,
        },
        Ok(other) => {
            eprintln!("holdfast-spawner: unexpected wait status {other:?}");
            SpawnerMsg::Exited {
                success: false,
                exit_code: 1,
            }
        }
        Err(e) => {
            eprintln!("holdfast-spawner: waitpid: {e}");
            SpawnerMsg::Exited {
                success: false,
                exit_code: 1,
            }
        }
    };

    let _ = send_message(CONN, &summary, None);
}
