//! Privilege-drop *mechanism* verification (threat model T12, ADR 0007).
//!
//! The authorization half is covered by `policy.rs`/`auth.rs`; this exercises
//! the actual uid/gid switch: with `privilege_drop` enabled, a shell whose
//! resolved account differs from the daemon's user runs under that account.
//!
//! It requires root (to switch uid) and a real secondary account, so it is
//! `#[ignore]`d and run via `tests/authorization/run.sh` (which re-execs under
//! sudo). Run directly as non-root it skips with a message rather than fails.
//! Reproduce with:
//!
//! ```bash
//! tests/authorization/run.sh
//! ```

use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

use hf_session_core::{
    Attachment, AttachmentEvent, OpenShellRequest, SessionCoreConfig, ShellManager,
};

const T: Duration = Duration::from_secs(10);

/// A real, non-root account to drop into. `nobody` exists on essentially every
/// Linux host and is never uid 0, so the switch is always a genuine change.
const TARGET_ACCOUNT: &str = "nobody";

fn is_root() -> bool {
    // Effective uid from /proc, avoiding an extra libc/nix dependency in tests.
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .map(|uid| uid == "0")
        })
        .unwrap_or(false)
}

fn account_exists(name: &str) -> bool {
    std::fs::read_to_string("/etc/passwd")
        .map(|s| s.lines().any(|l| l.starts_with(&format!("{name}:"))))
        .unwrap_or(false)
}

fn account_uid(name: &str) -> Option<String> {
    let passwd = std::fs::read_to_string("/etc/passwd").ok()?;
    passwd
        .lines()
        .find(|l| l.starts_with(&format!("{name}:")))
        .and_then(|l| l.split(':').nth(2))
        .map(str::to_string)
}

/// Drain attachment output until `needle` appears.
fn read_until(attachment: &Attachment, needle: &str) -> String {
    let deadline = Instant::now() + T;
    let mut collected = Vec::new();
    loop {
        let now = Instant::now();
        assert!(
            now < deadline,
            "timeout waiting for {needle:?}; got {:?}",
            String::from_utf8_lossy(&collected)
        );
        match attachment.events.recv_timeout(deadline - now) {
            Ok(AttachmentEvent::Output(bytes)) => {
                collected.extend_from_slice(&bytes);
                if String::from_utf8_lossy(&collected).contains(needle) {
                    return String::from_utf8_lossy(&collected).into_owned();
                }
            }
            Ok(AttachmentEvent::Exited(e)) => panic!("shell exited early: {e:?}"),
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => {
                panic!("detached while waiting for {needle:?}")
            }
        }
    }
}

fn drop_request(account: Option<&str>, key: u8) -> OpenShellRequest {
    OpenShellRequest {
        command: Some("bash".into()),
        args: vec!["--norc".into()],
        requested_account: account.map(str::to_string),
        cols: 40,
        rows: 6,
        idempotency_key: [key; 16],
        ..Default::default()
    }
}

/// With privilege drop enabled, a shell requesting a different account actually
/// runs under that account's uid; requesting no account still runs as the
/// daemon's own (root) uid — proving the switch is real and scoped.
#[test]
#[ignore = "needs root + a secondary account; run via tests/authorization/run.sh"]
fn shell_runs_under_the_resolved_account_uid() {
    if !is_root() {
        eprintln!("SKIP: privilege-drop test needs root (run via tests/authorization/run.sh)");
        return;
    }
    if !account_exists(TARGET_ACCOUNT) {
        eprintln!("SKIP: target account {TARGET_ACCOUNT:?} not present on this host");
        return;
    }
    let target_uid = account_uid(TARGET_ACCOUNT).expect("target account uid");
    assert_ne!(
        target_uid, "0",
        "target account must not be root for a meaningful test"
    );

    let config = SessionCoreConfig {
        privilege_drop: true,
        ..Default::default()
    };
    let mgr = ShellManager::new(config);

    // The needle is synthesized by the shell (`$(id -u)`), so the number never
    // appears in the *typed* command line the PTY echoes back — matching the
    // echo instead of the command output is the trap here.
    // --- Dropped shell: runs as TARGET_ACCOUNT. ---
    let dropped = mgr
        .open_shell(&drop_request(Some(TARGET_ACCOUNT), 1))
        .unwrap();
    let a = mgr
        .attach("", &dropped.shell_id, &dropped.resume_token, 40, 6)
        .unwrap();
    mgr.write_input(&dropped.shell_id, b"echo RID=$(id -u)RID\r")
        .unwrap();
    read_until(&a, &format!("RID={target_uid}RID"));
    // The prlimit wrapper runs outside setpriv; its hard ceilings must survive
    // the uid/gid switch into the target account.
    mgr.write_input(&dropped.shell_id, b"ulimit -Hu\r").unwrap();
    read_until(&a, "512");
    mgr.write_input(&dropped.shell_id, b"ulimit -Hn\r").unwrap();
    read_until(&a, "1024");
    mgr.write_input(&dropped.shell_id, b"ulimit -Hc\r").unwrap();
    read_until(&a, "0");
    mgr.terminate(&dropped.shell_id).unwrap();

    // --- No account requested: still runs as the daemon's own (root) uid,
    // proving the drop is scoped to the resolved account, not blanket. ---
    let own = mgr.open_shell(&drop_request(None, 2)).unwrap();
    let a2 = mgr
        .attach("", &own.shell_id, &own.resume_token, 40, 6)
        .unwrap();
    mgr.write_input(&own.shell_id, b"echo RID=$(id -u)RID\r")
        .unwrap();
    read_until(&a2, "RID=0RID");
    mgr.terminate(&own.shell_id).unwrap();
}

/// Enabling privilege drop must not disturb the ordinary path: with no account
/// requested, everything behaves exactly as with the flag off. Runs unprivileged
/// too (no switch happens), so it is not ignored.
#[test]
fn privilege_drop_flag_is_inert_without_a_requested_account() {
    let config = SessionCoreConfig {
        privilege_drop: true,
        ..Default::default()
    };
    let mgr = ShellManager::new(config);
    let opened = mgr.open_shell(&drop_request(None, 3)).unwrap();
    let a = mgr
        .attach("", &opened.shell_id, &opened.resume_token, 40, 6)
        .unwrap();
    // Synthesized needle (see note above): "42" is computed, not typed.
    mgr.write_input(&opened.shell_id, b"echo INERT=$((21*2))OK\r")
        .unwrap();
    read_until(&a, "INERT=42OK");
    mgr.terminate(&opened.shell_id).unwrap();
}
