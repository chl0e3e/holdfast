//! Interactive demo of the PTY spike:
//!
//! ```bash
//! cargo run -p spike-pty
//! ```

use std::time::Duration;

use spike_pty::PtyShell;

fn main() -> anyhow::Result<()> {
    let mut sh = PtyShell::spawn_bash(24, 80)?;
    sh.send("echo hello from a holdfast pty: $((6 * 7))\r")?;
    let out = sh.read_until("42", Duration::from_secs(10))?;
    println!("captured PTY output:\n{out}");
    sh.send("exit\r")?;
    let status = sh.child.wait()?;
    println!("child exited: {status:?}");
    Ok(())
}
