//! hf-pty integration tests. Reproduce with: `cargo test -p hf-pty`

use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use hf_pty::{PtyConfig, PtyProcess};

const T: Duration = Duration::from_secs(10);

fn bash(cols: u16, rows: u16) -> PtyConfig {
    PtyConfig {
        program: Some("bash".into()),
        args: vec!["--norc".into()],
        env: vec![("PS1".into(), "T$ ".into())],
        cols,
        rows,
        ..Default::default()
    }
}

fn read_until(rx: &Receiver<Vec<u8>>, needle: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    let mut collected = Vec::new();
    loop {
        let now = Instant::now();
        assert!(
            now < deadline,
            "timeout waiting for {needle:?}; got {:?}",
            String::from_utf8_lossy(&collected)
        );
        match rx.recv_timeout(deadline - now) {
            Ok(chunk) => {
                collected.extend_from_slice(&chunk);
                let text = String::from_utf8_lossy(&collected);
                if text.contains(needle) {
                    return text.into_owned();
                }
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => panic!(
                "PTY closed before {needle:?}; got {:?}",
                String::from_utf8_lossy(&collected)
            ),
        }
    }
}

#[test]
fn interactive_io_and_graceful_exit() {
    let mut pty = PtyProcess::spawn(&bash(80, 24)).unwrap();
    let rx = pty.take_output().unwrap();
    assert!(pty.take_output().is_none(), "output channel is single-take");

    pty.write(b"echo pty-$((6 * 7))\r").unwrap();
    read_until(&rx, "pty-42", T);

    pty.write(b"exit\r").unwrap();
    let status = pty.wait().unwrap();
    assert!(status.success);
}

#[test]
fn bounded_output_queue_applies_backpressure_without_losing_output() {
    let mut pty = PtyProcess::spawn(&bash(80, 24)).unwrap();
    let rx = pty.take_output().unwrap();

    // More than twice the 512-KiB reader queue. The producer may block while
    // the queue is full, but draining must resume it and deliver the tail.
    pty.write(b"yes x | head -c 1048576; echo BOUNDED-$((20+22))-DONE\r")
        .unwrap();
    let output = read_until(&rx, "BOUNDED-42-DONE", T);
    assert!(output.len() > 512 * 1024, "large output was truncated");

    pty.write(b"exit\r").unwrap();
    let status = pty.wait().unwrap();
    assert!(status.success);
}

#[test]
fn resize_propagates_to_child() {
    let mut pty = PtyProcess::spawn(&bash(80, 24)).unwrap();
    let rx = pty.take_output().unwrap();
    pty.write(b"stty size\r").unwrap();
    read_until(&rx, "24 80", T);

    pty.resize(120, 50).unwrap();
    pty.write(b"stty size\r").unwrap();
    read_until(&rx, "50 120", T);
}

#[test]
fn kill_is_clean_and_idempotent() {
    let mut pty = PtyProcess::spawn(&bash(80, 24)).unwrap();
    let _rx = pty.take_output().unwrap();
    pty.write(b"sleep 300\r").unwrap();

    let pid = pty.process_id().expect("pid") as i32;
    assert!(
        pty.try_wait().unwrap().is_none(),
        "still running before kill"
    );

    pty.kill().unwrap();
    let status = pty.wait().unwrap();
    assert!(!status.success);
    pty.kill().unwrap(); // idempotent after exit

    if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        let state = stat.rsplit(") ").next().and_then(|s| s.chars().next());
        assert_ne!(state, Some('Z'), "child left as zombie: {stat}");
    }
}
