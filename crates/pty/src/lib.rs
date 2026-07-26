//! Linux PTY process management.
//!
//! Owns nothing but the PTY and its child process: no protocol, no terminal
//! model, no networking (enforced dependency direction). Session-core drives
//! this crate and connects its output to the terminal model.

use std::io::{Read, Write};
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

/// A live PTY with its child process.
///
/// Output arrives on the channel returned by [`PtyProcess::take_output`], in
/// raw byte chunks, ending (channel disconnect) at PTY EOF. The channel has an
/// explicit 64-chunk / 512-KiB bound; session-core drains it into the bounded
/// terminal model and separately enforces each attachment's output bound.
pub struct PtyProcess {
    master: Box<dyn MasterPty + Send>,
    child: Box<dyn Child + Send + Sync>,
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
            master: pair.master,
            child,
            writer,
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
        self.master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| PtyError::Resize(e.to_string()))
    }

    /// Non-blocking exit check; `None` while still running.
    pub fn try_wait(&mut self) -> Result<Option<ExitSummary>, PtyError> {
        Ok(self
            .child
            .try_wait()
            .map_err(PtyError::Io)?
            .map(|s| ExitSummary {
                success: s.success(),
                exit_code: s.exit_code(),
            }))
    }

    /// Block until the child exits and is reaped (no zombie remains).
    pub fn wait(&mut self) -> Result<ExitSummary, PtyError> {
        let status = self.child.wait().map_err(PtyError::Io)?;
        Ok(ExitSummary {
            success: status.success(),
            exit_code: status.exit_code(),
        })
    }

    /// Forcibly terminate the child. Idempotent; always follow with
    /// [`PtyProcess::wait`] to reap.
    pub fn kill(&mut self) -> Result<(), PtyError> {
        const ESRCH: i32 = 3;
        match self.child.kill() {
            Ok(()) => Ok(()),
            // Already exited/reaped: killing is idempotent (spec §9).
            Err(e)
                if e.kind() == std::io::ErrorKind::InvalidInput
                    || e.raw_os_error() == Some(ESRCH) =>
            {
                Ok(())
            }
            Err(e) => Err(PtyError::Io(e)),
        }
    }

    pub fn process_id(&self) -> Option<u32> {
        self.child.process_id()
    }
}
