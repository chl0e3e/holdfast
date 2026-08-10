//! Linux PTY process management.
//!
//! Owns nothing but the PTY and its child process: no protocol, no terminal
//! model, no networking (enforced dependency direction). Session-core drives
//! this crate and connects its output to the terminal model.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::mpsc::Receiver;

use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};

/// PTY reader → shell-model pump queue. Each chunk is at most 8 KiB, so the
/// queue retains at most 512 KiB. Filling it backpressures this shell's PTY;
/// slow network attachments are detached independently in session-core.
const PTY_OUTPUT_QUEUE_CHUNKS: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum PtyError {
    #[error("failed to open PTY: {0}")]
    Open(String),
    #[error("failed to spawn child: {0}")]
    Spawn(String),
    #[error("PTY I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("resize failed: {0}")]
    Resize(String),
}

/// What to launch inside the PTY.
#[derive(Debug, Clone)]
pub struct PtyConfig {
    /// Program to execute; `None` = `$SHELL`, falling back to `/bin/bash`.
    pub program: Option<String>,
    pub args: Vec<String>,
    /// Extra environment (inherits the daemon's environment otherwise).
    pub env: Vec<(String, String)>,
    pub cwd: Option<std::path::PathBuf>,
    pub cols: u16,
    pub rows: u16,
}

impl Default for PtyConfig {
    fn default() -> PtyConfig {
        PtyConfig {
            program: None,
            args: vec![],
            env: vec![],
            cwd: None,
            cols: 80,
            rows: 24,
        }
    }
}

/// Exit information, normalized for `ShellExited` (spec §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExitSummary {
    pub success: bool,
    pub exit_code: u32,
}

// TIOCSWINSZ on an adopted master fd — the same call portable-pty makes for a
// locally opened PTY, which we cannot reach through its `MasterPty` trait.
nix::ioctl_write_ptr_bad!(set_winsize, nix::libc::TIOCSWINSZ, nix::pty::Winsize);

/// A shell process this crate did not fork, driven over some out-of-band
/// channel instead of by `waitpid`.
///
/// The privileged spawner (ADR 0024) is the only implementor: shells launched
/// from it are children of a PID 1-forked helper, not of the daemon, so the
/// daemon cannot reap or signal them directly and asks the helper instead.
/// Implementations must keep `kill` idempotent — session-core calls it on
/// paths where the shell may already have exited.
pub trait RemoteChild {
    /// Non-blocking exit check; `None` while still running.
    fn try_wait(&mut self) -> Result<Option<ExitSummary>, PtyError>;
    /// Block until the shell exits, and ensure it leaves no zombie.
    fn wait(&mut self) -> Result<ExitSummary, PtyError>;
    /// Forcibly terminate the shell. Idempotent.
    fn kill(&mut self) -> Result<(), PtyError>;
    fn process_id(&self) -> Option<u32>;
}

/// Where the PTY master came from: either portable-pty opened it here, or it
/// arrived over a unix socket from the spawner.
enum MasterHandle {
    Local(Box<dyn MasterPty + Send>),
    Adopted(OwnedFd),
}

/// Who owns the shell process: this crate, or the spawner on the other end of
/// a control connection.
enum ChildHandle {
    Local(Box<dyn Child + Send + Sync>),
    Remote(Box<dyn RemoteChild + Send + Sync>),
}

/// A live PTY with its child process.
///
/// Output arrives on the channel returned by [`PtyProcess::take_output`], in
/// raw byte chunks, ending (channel disconnect) at PTY EOF. The channel has an
/// explicit 64-chunk / 512-KiB bound; session-core drains it into the bounded
/// terminal model and separately enforces each attachment's output bound.
pub struct PtyProcess {
    master: MasterHandle,
    child: ChildHandle,
    writer: Box<dyn Write + Send>,
    output: Option<Receiver<Vec<u8>>>,
}

impl PtyProcess {
    pub fn spawn(config: &PtyConfig) -> Result<PtyProcess, PtyError> {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: config.rows,
                cols: config.cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| PtyError::Open(e.to_string()))?;

        let program = config
            .program
            .clone()
            .or_else(|| std::env::var("SHELL").ok())
            .unwrap_or_else(|| "/bin/bash".to_string());
        let mut cmd = CommandBuilder::new(program);
        cmd.args(&config.args);
        cmd.env("TERM", "xterm-256color");
        // A shell with no locale at all runs under POSIX/ASCII and locale-aware
        // programs (screen, ncurses) render every non-ASCII char as `?`; the
        // clients only speak UTF-8, so guarantee at least a UTF-8 locale.
        // C.UTF-8 is built into glibc — no locale generation required.
        let locale_keys = ["LANG", "LC_ALL", "LC_CTYPE"];
        let inherited = locale_keys.iter().any(|k| std::env::var_os(k).is_some());
        let configured = config.env.iter().any(|(k, _)| locale_keys.contains(&k.as_str()));
        if !inherited && !configured {
            cmd.env("LANG", "C.UTF-8");
        }
        for (k, v) in &config.env {
            cmd.env(k, v);
        }
        if let Some(cwd) = &config.cwd {
            cmd.cwd(cwd);
        }

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| PtyError::Spawn(e.to_string()))?;
        drop(pair.slave);

        let writer = pair
            .master
            .take_writer()
            .map_err(|e| PtyError::Open(e.to_string()))?;
        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| PtyError::Open(e.to_string()))?;

        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(PTY_OUTPUT_QUEUE_CHUNKS);
        std::thread::Builder::new()
            .name("hf-pty-reader".into())
            .spawn(move || {
                let mut buf = [0u8; 8192];
                while let Ok(n) = reader.read(&mut buf) {
                    if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            })
            .expect("spawn PTY reader thread");

        Ok(PtyProcess {
            master: MasterHandle::Local(pair.master),
            child: ChildHandle::Local(child),
            writer,
            output: Some(rx),
        })
    }

    /// Wrap a PTY master fd opened by another process, whose shell that process
    /// owns (ADR 0024).
    ///
    /// The fd is duplicated for the reader thread and the writer, so this type
    /// still owns everything it touches. Behaviour is identical to [`spawn`]
    /// from every caller's point of view — the difference is only who forked
    /// the shell, and therefore who can reap and signal it.
    ///
    /// [`spawn`]: PtyProcess::spawn
    pub fn adopt(
        master: OwnedFd,
        child: Box<dyn RemoteChild + Send + Sync>,
    ) -> Result<PtyProcess, PtyError> {
        let writer = std::fs::File::from(master.try_clone()?);
        let mut reader = std::fs::File::from(master.try_clone()?);

        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(PTY_OUTPUT_QUEUE_CHUNKS);
        std::thread::Builder::new()
            .name("hf-pty-reader".into())
            .spawn(move || {
                let mut buf = [0u8; 8192];
                // A PTY master reports EIO (not EOF) once the last slave closes;
                // `read` returning an error ends the loop either way, which
                // disconnects the channel exactly as the local path does.
                while let Ok(n) = reader.read(&mut buf) {
                    if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            })
            .expect("spawn PTY reader thread");

        Ok(PtyProcess {
            master: MasterHandle::Adopted(master),
            child: ChildHandle::Remote(child),
            writer: Box::new(writer),
            output: Some(rx),
        })
    }

    /// Take the output channel. Callable once; the channel disconnects at EOF.
    pub fn take_output(&mut self) -> Option<Receiver<Vec<u8>>> {
        self.output.take()
    }

    /// Write raw input bytes to the PTY (keyboard input path).
    pub fn write(&mut self, data: &[u8]) -> Result<(), PtyError> {
        self.writer.write_all(data)?;
        self.writer.flush()?;
        Ok(())
    }

    /// Resize the PTY; delivers SIGWINCH to the foreground process group.
    pub fn resize(&mut self, cols: u16, rows: u16) -> Result<(), PtyError> {
        match &self.master {
            MasterHandle::Local(master) => master
                .resize(PtySize {
                    rows,
                    cols,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .map_err(|e| PtyError::Resize(e.to_string())),
            // Same ioctl portable-pty performs, on the fd the spawner sent.
            // SIGWINCH reaches the shell because the kernel delivers it to the
            // terminal's foreground process group, regardless of who forked it.
            MasterHandle::Adopted(fd) => {
                let size = nix::pty::Winsize {
                    ws_row: rows,
                    ws_col: cols,
                    ws_xpixel: 0,
                    ws_ypixel: 0,
                };
                // SAFETY: `fd` is an open PTY master owned by this struct and
                // `size` is a valid, fully initialized winsize.
                unsafe { set_winsize(fd.as_raw_fd(), &size) }
                    .map(|_| ())
                    .map_err(|e| PtyError::Resize(e.to_string()))
            }
        }
    }

    /// Non-blocking exit check; `None` while still running.
    pub fn try_wait(&mut self) -> Result<Option<ExitSummary>, PtyError> {
        match &mut self.child {
            ChildHandle::Local(child) => {
                Ok(child.try_wait().map_err(PtyError::Io)?.map(|s| ExitSummary {
                    success: s.success(),
                    exit_code: s.exit_code(),
                }))
            }
            ChildHandle::Remote(child) => child.try_wait(),
        }
    }

    /// Block until the child exits and is reaped (no zombie remains).
    pub fn wait(&mut self) -> Result<ExitSummary, PtyError> {
        match &mut self.child {
            ChildHandle::Local(child) => {
                let status = child.wait().map_err(PtyError::Io)?;
                Ok(ExitSummary {
                    success: status.success(),
                    exit_code: status.exit_code(),
                })
            }
            ChildHandle::Remote(child) => child.wait(),
        }
    }

    /// Forcibly terminate the child. Idempotent; always follow with
    /// [`PtyProcess::wait`] to reap.
    pub fn kill(&mut self) -> Result<(), PtyError> {
        const ESRCH: i32 = 3;
        match &mut self.child {
            ChildHandle::Local(child) => match child.kill() {
                Ok(()) => Ok(()),
                // Already exited/reaped: killing is idempotent (spec §9).
                Err(e)
                    if e.kind() == std::io::ErrorKind::InvalidInput
                        || e.raw_os_error() == Some(ESRCH) =>
                {
                    Ok(())
                }
                Err(e) => Err(PtyError::Io(e)),
            },
            ChildHandle::Remote(child) => child.kill(),
        }
    }

    pub fn process_id(&self) -> Option<u32> {
        match &self.child {
            ChildHandle::Local(child) => child.process_id(),
            ChildHandle::Remote(child) => child.process_id(),
        }
    }
}
