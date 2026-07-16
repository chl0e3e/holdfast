//! Phase 1 exit-criterion tests (plan: "an in-process test can create,
//! detach, reattach and terminate a PTY while retaining bounded scrollback").
//! Reproduce with: `cargo test -p hf-session-core`

use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

use hf_session_core::{
    Attachment, AttachmentEvent, OpenShellRequest, SessionCoreConfig, SessionError, ShellManager,
    ShellState,
};

const T: Duration = Duration::from_secs(10);

fn bash_request(key: u8) -> OpenShellRequest {
    OpenShellRequest {
        command: Some("bash".into()),
        args: vec!["--norc".into()],
        cols: 40,
        rows: 6,
        idempotency_key: [key; 16],
        ..Default::default()
    }
}

/// Drain attachment output until `needle` appears (raw PTY bytes).
fn read_until(attachment: &Attachment, needle: &str) -> String {
    let deadline = Instant::now() + T;
    let mut collected = Vec::new();
    loop {
        let now = Instant::now();
        assert!(now < deadline, "timeout waiting for {needle:?}; got {:?}",
            String::from_utf8_lossy(&collected));
        match attachment.events.recv_timeout(deadline - now) {
            Ok(AttachmentEvent::Output(bytes)) => {
                collected.extend_from_slice(&bytes);
                let text = String::from_utf8_lossy(&collected);
                if text.contains(needle) {
                    return text.into_owned();
                }
            }
            Ok(AttachmentEvent::Exited(e)) => panic!("shell exited early: {e:?}"),
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => panic!(
                "detached while waiting for {needle:?}; got {:?}",
                String::from_utf8_lossy(&collected)
            ),
        }
    }
}

/// The Phase 1 exit criterion, end to end.
#[test]
fn create_detach_reattach_terminate_with_retained_scrollback() {
    let mgr = ShellManager::new(SessionCoreConfig::default());
    let opened = mgr.open_shell(&bash_request(1)).unwrap();

    // First attachment: generate more output than the 6-row screen holds.
    let a1 = mgr
        .attach(&opened.shell_id, &opened.resume_token, 40, 6)
        .unwrap();
    mgr.write_input(&opened.shell_id, b"for i in $(seq 1 30); do echo scroll-$i; done\r")
        .unwrap();
    read_until(&a1, "scroll-30");
    let token_after_first = a1.rotated_resume_token.clone();

    // Detach. The shell must keep running and keep accumulating output.
    mgr.detach(&opened.shell_id, a1.attachment_id).unwrap();
    mgr.write_input(&opened.shell_id, b"echo while-detached\r").unwrap();
    // Give the pump a moment to feed the model while nobody is attached.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(mgr.shell_info(&opened.shell_id).unwrap().state, ShellState::Running);

    // Reattach with the rotated token: snapshot + history must cover both
    // pre-detach scrollback and output produced while detached.
    let a2 = mgr.attach(&opened.shell_id, &token_after_first, 40, 6).unwrap();
    let snapshot = String::from_utf8_lossy(&a2.snapshot).into_owned();
    assert!(snapshot.contains("while-detached"), "snapshot misses detached-era output");
    assert!(a2.screen_revision > 0);
    assert!(a2.newest_history_line_id > a2.oldest_history_line_id);

    let history = mgr
        .history(&opened.shell_id, 0, 1000, 1 << 20)
        .unwrap();
    let all = history.lines.join("\n");
    assert!(all.contains("scroll-1") && all.contains("scroll-25"),
        "retained scrollback must include pre-detach lines: {all}");

    // The shell is still interactive after reattach.
    mgr.write_input(&opened.shell_id, b"echo after-reattach\r").unwrap();
    read_until(&a2, "after-reattach");

    // Terminate: exits, is idempotent, and notifies the attachment.
    let exit = mgr.terminate(&opened.shell_id).unwrap();
    assert!(!exit.success, "SIGKILL'd shell must not report success");
    assert_eq!(mgr.terminate(&opened.shell_id).unwrap(), exit, "terminate is idempotent");
    assert_eq!(mgr.shell_info(&opened.shell_id).unwrap().state, ShellState::Exited);

    let deadline = Instant::now() + T;
    loop {
        match a2.events.recv_timeout(deadline - Instant::now()) {
            Ok(AttachmentEvent::Exited(e)) => {
                assert_eq!(e, exit);
                break;
            }
            Ok(AttachmentEvent::Output(_)) => continue,
            Err(e) => panic!("expected Exited event, got {e:?}"),
        }
    }
}

#[test]
fn open_shell_is_idempotent_per_key() {
    let mgr = ShellManager::new(SessionCoreConfig::default());
    let first = mgr.open_shell(&bash_request(2)).unwrap();
    let second = mgr.open_shell(&bash_request(2)).unwrap();
    assert_eq!(first.shell_id, second.shell_id, "same key must not create a second shell");
    assert!(second.reused);
    assert_eq!(mgr.list_shells().len(), 1);
    mgr.terminate(&first.shell_id).unwrap();
}

#[test]
fn rotated_token_rejects_replay() {
    let mgr = ShellManager::new(SessionCoreConfig::default());
    let opened = mgr.open_shell(&bash_request(3)).unwrap();

    let a1 = mgr.attach(&opened.shell_id, &opened.resume_token, 40, 6).unwrap();
    // The original token was rotated away by the successful attach.
    assert!(matches!(
        mgr.attach(&opened.shell_id, &opened.resume_token, 40, 6),
        Err(SessionError::InvalidToken)
    ));
    // The rotated token works, and rotates again.
    let a2 = mgr.attach(&opened.shell_id, &a1.rotated_resume_token, 40, 6).unwrap();
    assert!(matches!(
        mgr.attach(&opened.shell_id, &a1.rotated_resume_token, 40, 6),
        Err(SessionError::InvalidToken)
    ));
    drop(a2);
    mgr.terminate(&opened.shell_id).unwrap();
}

#[test]
fn detach_does_not_kill_and_terminate_does() {
    let mgr = ShellManager::new(SessionCoreConfig::default());
    let opened = mgr.open_shell(&bash_request(4)).unwrap();
    let a = mgr.attach(&opened.shell_id, &opened.resume_token, 40, 6).unwrap();

    mgr.detach(&opened.shell_id, a.attachment_id).unwrap();
    assert_eq!(mgr.shell_info(&opened.shell_id).unwrap().state, ShellState::Running);

    mgr.terminate(&opened.shell_id).unwrap();
    assert_eq!(mgr.shell_info(&opened.shell_id).unwrap().state, ShellState::Exited);

    // Input to an exited shell is an error, not a panic.
    assert!(matches!(
        mgr.write_input(&opened.shell_id, b"x"),
        Err(SessionError::NotRunning)
    ));

    mgr.remove_exited(&opened.shell_id).unwrap();
    assert!(matches!(
        mgr.shell_info(&opened.shell_id),
        Err(SessionError::ShellNotFound)
    ));
}

/// A malicious or buggy client can drive the shell to hostile terminal
/// dimensions. avt 0.18 hangs at 0 columns and panics at 1 column (wide-glyph
/// split) or 0 rows; the manager must clamp every open/attach/resize so those
/// never reach the emulator (threat model T9). A hang here fails via the T
/// timeout in read_until; a panic fails the test thread.
#[test]
fn hostile_resize_dimensions_do_not_crash_or_hang_the_shell() {
    let mgr = ShellManager::new(SessionCoreConfig::default());

    // Open with a degenerate 1x0 request: must be clamped, not fatal.
    let opened = mgr
        .open_shell(&OpenShellRequest {
            command: Some("bash".into()),
            args: vec!["--norc".into()],
            cols: 1,
            rows: 0,
            idempotency_key: [90; 16],
            ..Default::default()
        })
        .unwrap();
    let a = mgr.attach(&opened.shell_id, &opened.resume_token, 40, 6).unwrap();

    // Put a wide glyph on screen — the ingredient for the 1-column panic.
    mgr.write_input(&opened.shell_id, b"printf '\\xf0\\x9f\\xa6\\x80wide\\n'\r").unwrap();
    read_until(&a, "wide");

    // Every degenerate size the emulator would otherwise choke on.
    for (cols, rows) in [(0u16, 24u16), (1, 24), (80, 0), (0, 0), (1, 1), (2, 1)] {
        mgr.resize(&opened.shell_id, cols, rows).unwrap();
    }

    // Back to a sane size, the shell is still alive and responsive.
    mgr.resize(&opened.shell_id, 40, 6).unwrap();
    mgr.write_input(&opened.shell_id, b"echo still-alive-$((6*7))\r").unwrap();
    read_until(&a, "still-alive-42");

    mgr.terminate(&opened.shell_id).unwrap();
}

#[test]
fn shell_and_attachment_limits_are_enforced() {
    let mgr = ShellManager::new(SessionCoreConfig {
        max_shells: 2,
        max_attachments_per_shell: 2,
        ..Default::default()
    });

    let s1 = mgr.open_shell(&bash_request(10)).unwrap();
    let _s2 = mgr.open_shell(&bash_request(11)).unwrap();
    assert!(matches!(
        mgr.open_shell(&bash_request(12)),
        Err(SessionError::LimitExceeded("max_shells"))
    ));

    let a1 = mgr.attach(&s1.shell_id, &s1.resume_token, 40, 6).unwrap();
    let a2 = mgr.attach(&s1.shell_id, &a1.rotated_resume_token, 40, 6).unwrap();
    assert!(matches!(
        mgr.attach(&s1.shell_id, &a2.rotated_resume_token, 40, 6),
        Err(SessionError::LimitExceeded("max_attachments_per_shell"))
    ));
}

#[test]
fn natural_exit_is_observed_without_terminate() {
    let mgr = ShellManager::new(SessionCoreConfig::default());
    let opened = mgr.open_shell(&bash_request(5)).unwrap();
    let a = mgr.attach(&opened.shell_id, &opened.resume_token, 40, 6).unwrap();

    mgr.write_input(&opened.shell_id, b"exit 7\r").unwrap();
    let deadline = Instant::now() + T;
    loop {
        match a.events.recv_timeout(deadline - Instant::now()) {
            Ok(AttachmentEvent::Exited(e)) => {
                assert_eq!(e.exit_code, 7);
                break;
            }
            Ok(AttachmentEvent::Output(_)) => continue,
            Err(e) => panic!("expected natural exit, got {e:?}"),
        }
    }
    assert_eq!(mgr.shell_info(&opened.shell_id).unwrap().state, ShellState::Exited);
    // Terminating an already-exited shell returns the recorded status.
    assert_eq!(mgr.terminate(&opened.shell_id).unwrap().exit_code, 7);
}
