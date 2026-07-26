//! Phase 1 exit-criterion tests (plan: "an in-process test can create,
//! detach, reattach and terminate a PTY while retaining bounded scrollback").
//! Reproduce with: `cargo test -p hf-session-core`

use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

use hf_session_core::{
    Attachment, AttachmentEvent, OpenShellRequest, ResumeToken, SessionCoreConfig, SessionError,
    ShellManager, ShellResourceLimits, ShellState,
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
        assert!(
            now < deadline,
            "timeout waiting for {needle:?}; got {:?}",
            String::from_utf8_lossy(&collected)
        );
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
        .attach("", &opened.shell_id, &opened.resume_token, 40, 6)
        .unwrap();
    mgr.write_input(
        &opened.shell_id,
        b"for i in $(seq 1 30); do echo scroll-$i; done\r",
    )
    .unwrap();
    read_until(&a1, "scroll-30");
    let token_after_first = a1.rotated_resume_token.clone();

    // Detach. The shell must keep running and keep accumulating output.
    mgr.detach(&opened.shell_id, a1.attachment_id).unwrap();
    mgr.write_input(&opened.shell_id, b"echo while-detached\r")
        .unwrap();
    // Give the pump a moment to feed the model while nobody is attached.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        mgr.shell_info(&opened.shell_id).unwrap().state,
        ShellState::Running
    );

    // Reattach with the rotated token: snapshot + history must cover both
    // pre-detach scrollback and output produced while detached.
    let a2 = mgr
        .attach("", &opened.shell_id, &token_after_first, 40, 6)
        .unwrap();
    let snapshot = String::from_utf8_lossy(&a2.snapshot).into_owned();
    assert!(
        snapshot.contains("while-detached"),
        "snapshot misses detached-era output"
    );
    assert!(a2.screen_revision > 0);
    assert!(a2.newest_history_line_id > a2.oldest_history_line_id);

    let history = mgr.history(&opened.shell_id, 0, 1000, 1 << 20).unwrap();
    let all = history.lines.join("\n");
    assert!(
        all.contains("scroll-1") && all.contains("scroll-25"),
        "retained scrollback must include pre-detach lines: {all}"
    );

    // The shell is still interactive after reattach.
    mgr.write_input(&opened.shell_id, b"echo after-reattach\r")
        .unwrap();
    read_until(&a2, "after-reattach");

    // Terminate: exits, is idempotent, and notifies the attachment.
    let exit = mgr.terminate(&opened.shell_id).unwrap();
    assert!(!exit.success, "SIGKILL'd shell must not report success");
    assert_eq!(
        mgr.terminate(&opened.shell_id).unwrap(),
        exit,
        "terminate is idempotent"
    );
    assert_eq!(
        mgr.shell_info(&opened.shell_id).unwrap().state,
        ShellState::Exited
    );

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
    assert_eq!(
        first.shell_id, second.shell_id,
        "same key must not create a second shell"
    );
    assert!(second.reused);
    assert_eq!(mgr.list_shells().len(), 1);
    mgr.terminate(&first.shell_id).unwrap();
}

/// Idempotency reuse is scoped to the original owner (threat model T12): the
/// same key from a different user must not mint a token for someone else's
/// shell — it opens a distinct shell instead.
#[test]
fn idempotency_reuse_is_scoped_to_owner() {
    let mgr = ShellManager::new(SessionCoreConfig::default());
    let alice = OpenShellRequest {
        user: "alice".into(),
        command: Some("bash".into()),
        args: vec!["--norc".into()],
        cols: 40,
        rows: 6,
        idempotency_key: [42; 16],
        ..Default::default()
    };
    let bob = OpenShellRequest {
        user: "bob".into(),
        ..alice.clone()
    };

    let a = mgr.open_shell(&alice).unwrap();
    // Bob reuses the *same* idempotency key: must NOT get Alice's shell.
    let b = mgr.open_shell(&bob).unwrap();
    assert_ne!(
        a.shell_id, b.shell_id,
        "bob must not receive alice's shell via a shared key"
    );
    assert!(
        !b.reused,
        "cross-owner key collision must open a fresh shell, not reuse"
    );

    // Alice reusing her own key is still idempotent.
    let a2 = mgr.open_shell(&alice).unwrap();
    assert_eq!(a.shell_id, a2.shell_id);
    assert!(a2.reused);

    mgr.terminate(&a.shell_id).unwrap();
    mgr.terminate(&b.shell_id).unwrap();
}

/// A valid resume token remains scoped to its authenticated owner (spec §12).
#[test]
fn resume_token_does_not_bypass_owner_check() {
    let mgr = ShellManager::new(SessionCoreConfig::default());
    let opened = mgr
        .open_shell(&OpenShellRequest {
            user: "alice".into(),
            command: Some("bash".into()),
            args: vec!["--norc".into()],
            cols: 40,
            rows: 6,
            idempotency_key: [43; 16],
            ..Default::default()
        })
        .unwrap();

    assert!(matches!(
        mgr.attach("bob", &opened.shell_id, &opened.resume_token, 40, 6),
        Err(SessionError::ShellNotFound)
    ));

    // The rejected attempt neither consumes nor rotates Alice's token.
    let attachment = mgr
        .attach("alice", &opened.shell_id, &opened.resume_token, 40, 6)
        .unwrap();
    mgr.detach(&opened.shell_id, attachment.attachment_id)
        .unwrap();
    mgr.terminate(&opened.shell_id).unwrap();
}

/// The agent transport may attach only after independently checking its signed
/// grant. The core API still enforces local owner isolation without exposing a
/// resume token to the gateway.
#[test]
fn transport_authorized_attach_is_owner_scoped() {
    let mgr = ShellManager::new(SessionCoreConfig::default());
    let opened = mgr
        .open_shell(&OpenShellRequest {
            user: "alice".into(),
            command: Some("bash".into()),
            args: vec!["--norc".into()],
            cols: 40,
            rows: 6,
            idempotency_key: [44; 16],
            ..Default::default()
        })
        .unwrap();

    assert!(matches!(
        mgr.attach_authorized("bob", &opened.shell_id, 40, 6),
        Err(SessionError::ShellNotFound)
    ));
    let attachment = mgr
        .attach_authorized("alice", &opened.shell_id, 40, 6)
        .unwrap();
    assert_eq!(
        mgr.shell_info(&opened.shell_id).unwrap().attachment_count,
        1
    );
    mgr.detach(&opened.shell_id, attachment.attachment_id)
        .unwrap();
    mgr.terminate(&opened.shell_id).unwrap();
}

#[test]
fn rotated_token_rejects_replay() {
    let mgr = ShellManager::new(SessionCoreConfig::default());
    let opened = mgr.open_shell(&bash_request(3)).unwrap();

    let a1 = mgr
        .attach("", &opened.shell_id, &opened.resume_token, 40, 6)
        .unwrap();
    // The original token was rotated away by the successful attach: replaying
    // it is the distinct possible-theft signal, not generic invalidity
    // (spec §12).
    assert!(matches!(
        mgr.attach("", &opened.shell_id, &opened.resume_token, 40, 6),
        Err(SessionError::TokenReplayed)
    ));
    // The rotated token works, and rotates again.
    let a2 = mgr
        .attach("", &opened.shell_id, &a1.rotated_resume_token, 40, 6)
        .unwrap();
    assert!(matches!(
        mgr.attach("", &opened.shell_id, &a1.rotated_resume_token, 40, 6),
        Err(SessionError::TokenReplayed)
    ));
    // A token that was never valid for this shell stays InvalidToken.
    assert!(matches!(
        mgr.attach("", &opened.shell_id, &ResumeToken::generate(), 40, 6),
        Err(SessionError::InvalidToken)
    ));
    drop(a2);
    mgr.terminate(&opened.shell_id).unwrap();
}

#[test]
fn idempotent_reopen_supersedes_the_old_token_as_a_replay() {
    // The idempotent-reuse path also rotates; the token it replaced must be
    // recognized as replayed, since client recovery leans on this path.
    let mgr = ShellManager::new(SessionCoreConfig::default());
    let opened = mgr.open_shell(&bash_request(30)).unwrap();
    let reopened = mgr.open_shell(&bash_request(30)).unwrap();
    assert!(reopened.reused);
    assert_eq!(reopened.shell_id, opened.shell_id);
    assert!(matches!(
        mgr.attach("", &opened.shell_id, &opened.resume_token, 40, 6),
        Err(SessionError::TokenReplayed)
    ));
    let a = mgr
        .attach("", &opened.shell_id, &reopened.resume_token, 40, 6)
        .unwrap();
    drop(a);
    mgr.terminate(&opened.shell_id).unwrap();
}

#[test]
fn detach_does_not_kill_and_terminate_does() {
    let mgr = ShellManager::new(SessionCoreConfig::default());
    let opened = mgr.open_shell(&bash_request(4)).unwrap();
    let a = mgr
        .attach("", &opened.shell_id, &opened.resume_token, 40, 6)
        .unwrap();

    mgr.detach(&opened.shell_id, a.attachment_id).unwrap();
    assert_eq!(
        mgr.shell_info(&opened.shell_id).unwrap().state,
        ShellState::Running
    );

    mgr.terminate(&opened.shell_id).unwrap();
    assert_eq!(
        mgr.shell_info(&opened.shell_id).unwrap().state,
        ShellState::Exited
    );

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

/// Per-owner fairness cap: one user cannot exhaust the global shell pool and
/// starve others (threat model T1/T5).
#[test]
fn per_user_shell_cap_is_enforced_and_isolated() {
    let mgr = ShellManager::new(SessionCoreConfig {
        max_shells: 100,
        max_shells_per_user: 2,
        ..Default::default()
    });
    let open = |user: &str, key: u8| {
        mgr.open_shell(&OpenShellRequest {
            user: user.into(),
            command: Some("bash".into()),
            args: vec!["--norc".into()],
            cols: 40,
            rows: 6,
            idempotency_key: [key; 16],
            ..Default::default()
        })
    };

    let a1 = open("alice", 1).unwrap();
    let _a2 = open("alice", 2).unwrap();
    // Alice's 3rd exceeds her per-user cap even though the global pool is free.
    assert!(matches!(
        open("alice", 3),
        Err(SessionError::LimitExceeded("max_shells_per_user"))
    ));
    // Bob is unaffected by Alice's usage.
    let _b1 = open("bob", 4).unwrap();
    let _b2 = open("bob", 5).unwrap();
    assert!(matches!(
        open("bob", 6),
        Err(SessionError::LimitExceeded("max_shells_per_user"))
    ));

    // Freeing one of Alice's shells lets her open again.
    mgr.terminate(&a1.shell_id).unwrap();
    mgr.remove_exited(&a1.shell_id).unwrap();
    let a3 = open("alice", 7).unwrap();
    mgr.terminate(&a3.shell_id).unwrap();
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
    let a = mgr
        .attach("", &opened.shell_id, &opened.resume_token, 40, 6)
        .unwrap();

    // Put a wide glyph on screen — the ingredient for the 1-column panic.
    mgr.write_input(&opened.shell_id, b"printf '\\xf0\\x9f\\xa6\\x80wide\\n'\r")
        .unwrap();
    read_until(&a, "wide");

    // Every degenerate size the emulator would otherwise choke on.
    for (cols, rows) in [(0u16, 24u16), (1, 24), (80, 0), (0, 0), (1, 1), (2, 1)] {
        mgr.resize(&opened.shell_id, cols, rows).unwrap();
    }

    // Back to a sane size, the shell is still alive and responsive.
    mgr.resize(&opened.shell_id, 40, 6).unwrap();
    mgr.write_input(&opened.shell_id, b"echo still-alive-$((6*7))\r")
        .unwrap();
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

    let a1 = mgr
        .attach("", &s1.shell_id, &s1.resume_token, 40, 6)
        .unwrap();
    let a2 = mgr
        .attach("", &s1.shell_id, &a1.rotated_resume_token, 40, 6)
        .unwrap();
    assert!(matches!(
        mgr.attach("", &s1.shell_id, &a2.rotated_resume_token, 40, 6),
        Err(SessionError::LimitExceeded("max_attachments_per_shell"))
    ));
}

#[test]
fn shell_process_inherits_hard_resource_limits() {
    let mgr = ShellManager::new(SessionCoreConfig {
        shell_resource_limits: ShellResourceLimits {
            // Kept comfortably above the host test user's current process
            // count: RLIMIT_NPROC is per real uid, not per shell, on Linux.
            max_processes: 4_096,
            max_open_files: 333,
            max_core_bytes: 0,
        },
        ..Default::default()
    });
    let opened = mgr.open_shell(&bash_request(13)).unwrap();
    let attachment = mgr
        .attach("", &opened.shell_id, &opened.resume_token, 40, 6)
        .unwrap();

    // `ulimit` is a bash builtin, so these checks do not need to fork while
    // inspecting the inherited hard ceilings.
    mgr.write_input(&opened.shell_id, b"ulimit -Hu\r").unwrap();
    read_until(&attachment, "4096");
    mgr.write_input(&opened.shell_id, b"ulimit -Hn\r").unwrap();
    read_until(&attachment, "333");
    mgr.write_input(&opened.shell_id, b"ulimit -Hc\r").unwrap();
    read_until(&attachment, "0");

    mgr.terminate(&opened.shell_id).unwrap();
}

#[test]
fn natural_exit_is_observed_without_terminate() {
    let mgr = ShellManager::new(SessionCoreConfig::default());
    let opened = mgr.open_shell(&bash_request(5)).unwrap();
    let a = mgr
        .attach("", &opened.shell_id, &opened.resume_token, 40, 6)
        .unwrap();

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
    assert_eq!(
        mgr.shell_info(&opened.shell_id).unwrap().state,
        ShellState::Exited
    );
    // Terminating an already-exited shell returns the recorded status.
    assert_eq!(mgr.terminate(&opened.shell_id).unwrap().exit_code, 7);
}

#[test]
fn idle_reaper_reclaims_only_detached_expired_shells() {
    // ADR 0021: expiry targets shells with zero attachments past the TTL;
    // attached shells and fresh detaches survive.
    let mgr = ShellManager::new(SessionCoreConfig::default());

    // Shell A: attached the whole time — must survive any TTL.
    let a = mgr.open_shell(&bash_request(40)).unwrap();
    let a_attach = mgr.attach("", &a.shell_id, &a.resume_token, 40, 6).unwrap();

    // Shell B: attached once, then detached — idles from last_attached_at.
    let b = mgr.open_shell(&bash_request(41)).unwrap();
    let b_attach = mgr.attach("", &b.shell_id, &b.resume_token, 40, 6).unwrap();
    mgr.detach(&b.shell_id, b_attach.attachment_id).unwrap();

    // Shell C: never attached — idles from creation.
    let c = mgr.open_shell(&bash_request(42)).unwrap();

    // Nothing is older than a generous TTL.
    assert!(mgr.reap_idle(Duration::from_secs(3600)).is_empty());

    std::thread::sleep(Duration::from_millis(250));
    let reaped = mgr.reap_idle(Duration::from_millis(200));
    let reaped_ids: Vec<_> = reaped.iter().map(|(_, id, _)| *id).collect();
    assert!(
        reaped_ids.contains(&b.shell_id),
        "detached B must be reaped"
    );
    assert!(
        reaped_ids.contains(&c.shell_id),
        "never-attached C must be reaped"
    );
    assert!(
        !reaped_ids.contains(&a.shell_id),
        "attached A must never be reaped"
    );
    assert_eq!(
        mgr.shell_info(&a.shell_id).unwrap().state,
        ShellState::Running
    );
    assert_eq!(
        mgr.shell_info(&b.shell_id).unwrap().state,
        ShellState::Exited
    );

    // Reaping is idempotent: a second pass finds nothing new.
    assert!(mgr.reap_idle(Duration::from_millis(200)).is_empty());

    drop(a_attach);
    mgr.terminate(&a.shell_id).unwrap();
}
