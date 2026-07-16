//! Phase 0 spike: Linux PTY creation, interactive I/O, resize and clean child
//! termination via `portable-pty` (wezterm's PTY layer). Disposable code.

use std::io::{Read, Write};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};

pub struct PtyShell {
    pub master: Box<dyn MasterPty + Send>,
    pub child: Box<dyn Child + Send + Sync>,
    pub writer: Box<dyn Write + Send>,
    output: Receiver<Vec<u8>>,
}

impl PtyShell {
    /// Launch `bash` in a fresh PTY under the current Unix user.
    pub fn spawn_bash(rows: u16, cols: u16) -> Result<PtyShell> {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
            .context("openpty")?;

        let mut cmd = CommandBuilder::new("bash");
        cmd.arg("--norc");
        cmd.env("PS1", "SPIKE$ ");
        cmd.env("TERM", "xterm-256color");
        let child = pair.slave.spawn_command(cmd).context("spawn bash")?;
        drop(pair.slave);

        let writer = pair.master.take_writer().context("take writer")?;
        let mut reader = pair.master.try_clone_reader().context("clone reader")?;

        // Blocking reader thread; ends when the child exits and the PTY EOFs.
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });

        Ok(PtyShell { master: pair.master, child, writer, output: rx })
    }

    /// Accumulate PTY output until `needle` appears or `timeout` elapses.
    pub fn read_until(&mut self, needle: &str, timeout: Duration) -> Result<String> {
        let deadline = Instant::now() + timeout;
        let mut collected = Vec::new();
        loop {
            let now = Instant::now();
            if now >= deadline {
                bail!(
                    "timed out waiting for {needle:?}; got so far: {:?}",
                    String::from_utf8_lossy(&collected)
                );
            }
            match self.output.recv_timeout(deadline - now) {
                Ok(chunk) => {
                    collected.extend_from_slice(&chunk);
                    let text = String::from_utf8_lossy(&collected);
                    if text.contains(needle) {
                        return Ok(text.into_owned());
                    }
                }
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => {
                    bail!(
                        "PTY closed before {needle:?} appeared; got: {:?}",
                        String::from_utf8_lossy(&collected)
                    );
                }
            }
        }
    }

    pub fn send(&mut self, input: &str) -> Result<()> {
        self.writer.write_all(input.as_bytes())?;
        self.writer.flush()?;
        Ok(())
    }

    pub fn resize(&mut self, rows: u16, cols: u16) -> Result<()> {
        self.master
            .resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
            .context("resize PTY")
    }
}
