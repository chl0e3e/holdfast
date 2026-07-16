//! Phase 0 PTY spike tests. Reproduce with:
//!
//! ```bash
//! cargo test -p spike-pty
//! ```
//!
//! Proves the Phase 0 exit criterion: PTY creation, interactive command
//! execution, resize propagation (SIGWINCH → `stty size`), graceful exit, and
//! clean kill with no zombie left behind.

use std::time::Duration;

use spike_pty::PtyShell;

const T: Duration = Duration::from_secs(10);

#[test]
fn run_command_and_read_output() {
    let mut sh = PtyShell::spawn_bash(24, 80).expect("spawn bash in PTY");
    sh.send("echo spike-$((6 * 7))\r").unwrap();
    let out = sh.read_until("spike-42", T).unwrap();
    assert!(out.contains("spike-42"));

    // Graceful exit: shell terminates on `exit` and is reaped with status 0.
    sh.send("exit\r").unwrap();
    let status = sh.child.wait().expect("wait for child");
    assert!(status.success(), "bash should exit cleanly, got {status:?}");
}

#[test]
fn resize_reaches_the_child() {
    let mut sh = PtyShell::spawn_bash(24, 80).expect("spawn bash in PTY");
    sh.send("stty size\r").unwrap();
    sh.read_until("24 80", T).expect("initial size visible to child");

    sh.resize(50, 120).unwrap();
    sh.send("stty size\r").unwrap();
    sh.read_until("50 120", T).expect("resized dimensions visible to child");
}

#[test]
fn kill_terminates_cleanly_without_zombie() {
    let mut sh = PtyShell::spawn_bash(24, 80).expect("spawn bash in PTY");
    // Park the shell in a long-running foreground command first.
    sh.send("sleep 300\r").unwrap();

    let pid = sh.child.process_id().expect("child pid") as i32;
    sh.child.kill().expect("kill child");
    let status = sh.child.wait().expect("child reaped");
    assert!(!status.success(), "killed child must not report success");

    // After wait(), the pid must be gone (not a zombie): /proc/<pid> absent,
    // or present only for an unrelated recycled pid.
    let proc_state = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok();
    if let Some(stat) = proc_state {
        let state = stat.rsplit(") ").next().and_then(|s| s.chars().next());
        assert_ne!(state, Some('Z'), "child left as zombie: {stat}");
    }
}
