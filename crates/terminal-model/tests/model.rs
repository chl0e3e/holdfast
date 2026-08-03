//! hf-terminal-model integration tests. Reproduce with:
//! `cargo test -p hf-terminal-model`

use hf_terminal_model::{TerminalModel, TerminalModelConfig};

fn small(max_lines: usize, max_bytes: usize) -> TerminalModel {
    TerminalModel::new(TerminalModelConfig {
        cols: 20,
        rows: 4,
        max_history_lines: max_lines,
        max_history_bytes: max_bytes,
    })
}

#[test]
fn scrolled_lines_commit_to_history_with_stable_ids() {
    let mut m = small(1000, 1 << 20);
    for i in 1..=10 {
        m.feed(format!("line-{i}\r\n").as_bytes());
    }
    // 4-row screen: line-8..line-10 + prompt row visible; 1..=7 in history.
    assert_eq!((m.oldest_line_id(), m.newest_line_id()), (1, 7));
    let range = m.history_range(0, 100, 1 << 20);
    assert_eq!(
        range.lines,
        (1..=7).map(|i| format!("line-{i}")).collect::<Vec<_>>()
    );
    assert!(!range.truncated_by_eviction);
}

#[test]
fn history_eviction_is_reported() {
    let mut m = small(5, 1 << 20);
    for i in 1..=20 {
        m.feed(format!("line-{i}\r\n").as_bytes());
    }
    assert_eq!(m.history_range(0, 100, 1 << 20).lines.len(), 5);
    assert!(m.oldest_line_id() > 1);
    assert!(m.history_range(0, 100, 1 << 20).truncated_by_eviction);
}

#[test]
fn alternate_screen_does_not_pollute_history() {
    let mut m = small(1000, 1 << 20);
    m.feed(b"before-alt\r\n");
    let history_before = m.newest_line_id();

    m.feed(b"\x1b[?1049h"); // smcup
    for i in 0..50 {
        m.feed(format!("alt-noise-{i}\r\n").as_bytes());
    }
    m.feed(b"\x1b[?1049l"); // rmcup

    assert_eq!(
        m.newest_line_id(),
        history_before,
        "alt screen must not add history"
    );
    assert!(
        m.visible_lines()[0].starts_with("before-alt"),
        "primary screen restored"
    );
}

#[test]
fn snapshot_reconstructs_screen_in_fresh_emulator() {
    let mut m = small(1000, 1 << 20);
    m.feed(b"hello \x1b[1;31mred\x1b[0m\r\nsecond\r\n");

    let mut replica = small(1000, 1 << 20);
    replica.feed(&m.snapshot());
    assert_eq!(m.visible_lines(), replica.visible_lines());
}

// Zero-width characters (combining marks, ZWJ, VS16) must not advance the
// model's cursor: wcwidth and xterm.js give them zero cells, and any drift
// shifts every later wrap point, so an attach snapshot replays a sheared
// screen (the "weechat garbled after Zalgo text" bug, 2026-08-03).

#[test]
fn combining_marks_do_not_shift_wrap_points() {
    let mut m = small(1000, 1 << 20);
    // Ten e+U+0301 pairs = 10 display columns on the 20-column screen.
    m.feed("e\u{0301}".repeat(10).as_bytes());
    m.feed(b"X");

    let lines = m.visible_lines();
    assert_eq!(lines[0], format!("{}X", "e\u{0301}".repeat(10)));
    assert_eq!(lines[1], "", "combining marks must not cause a wrap");
}

#[test]
fn vs16_emoji_occupies_one_cell() {
    let mut m = small(1000, 1 << 20);
    // U+2764 is narrow; VS16 must not take a cell of its own, so 19 'a's
    // exactly fill the remainder of the 20-column row without wrapping.
    m.feed("\u{2764}\u{fe0f}".as_bytes());
    m.feed("a".repeat(19).as_bytes());
    assert_eq!(m.visible_lines()[1], "");

    m.feed(b"b");
    assert_eq!(m.visible_lines()[1], "b", "row was exactly full");
}

#[test]
fn zero_width_text_survives_snapshot_round_trip() {
    let mut m = small(1000, 1 << 20);
    m.feed("caf\u{0065}\u{0301} \u{2764}\u{fe0f} \u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}".as_bytes());
    m.feed(b"\r\nnext");

    let mut replica = small(1000, 1 << 20);
    replica.feed(&m.snapshot());
    assert_eq!(m.visible_lines(), replica.visible_lines());
}

#[test]
fn zalgo_stacks_are_bounded_but_keep_geometry() {
    let mut m = small(1000, 1 << 20);
    // 40 marks on one glyph (attacker-style Zalgo): the model caps what it
    // retains, but the cursor must stay at column 1 either way.
    m.feed(b"z");
    m.feed("\u{0300}".repeat(40).as_bytes());
    m.feed("y".repeat(19).as_bytes());
    assert_eq!(m.visible_lines()[1], "", "z + 19 'y's fit the 20-col row");

    let mut replica = small(1000, 1 << 20);
    replica.feed(&m.snapshot());
    assert_eq!(m.visible_lines(), replica.visible_lines());
}

#[test]
fn combining_marks_reach_history_lines() {
    let mut m = small(1000, 1 << 20);
    for _ in 0..6 {
        m.feed("ne\u{0301}e\r\n".as_bytes());
    }
    let range = m.history_range(0, 100, 1 << 20);
    assert!(
        range.lines.iter().all(|l| l == "ne\u{0301}e"),
        "history keeps combining marks: {:?}",
        range.lines
    );
}

/// Snapshot as text, for asserting on the replayed mode sequences.
fn snapshot_text(m: &TerminalModel) -> String {
    String::from_utf8(m.snapshot()).unwrap()
}

#[test]
fn snapshot_replays_mouse_tracking_modes() {
    let mut m = small(1000, 1 << 20);
    // weechat `/mouse enable`: button-event tracking + SGR encoding.
    m.feed(b"\x1b[?1002h\x1b[?1006h");
    let snap = snapshot_text(&m);
    assert!(snap.contains("\x1b[?1002h"), "got {snap:?}");
    assert!(snap.contains("\x1b[?1006h"), "got {snap:?}");

    m.feed(b"\x1b[?1002l");
    let snap = snapshot_text(&m);
    assert!(!snap.contains("\x1b[?1002h"), "DECRST must clear: {snap:?}");
    assert!(snap.contains("\x1b[?1006h"), "encoding stays: {snap:?}");
}

#[test]
fn snapshot_replays_modes_from_combined_param_list() {
    let mut m = small(1000, 1 << 20);
    m.feed(b"\x1b[?1000;1006;2004h");
    let snap = snapshot_text(&m);
    for seq in ["\x1b[?1000h", "\x1b[?1006h", "\x1b[?2004h"] {
        assert!(snap.contains(seq), "missing {seq:?} in {snap:?}");
    }
}

#[test]
fn mode_sequence_split_across_feeds_is_tracked() {
    let mut m = small(1000, 1 << 20);
    m.feed(b"\x1b[?10");
    m.feed(b"06h");
    assert!(snapshot_text(&m).contains("\x1b[?1006h"));
}

#[test]
fn mouse_protocols_are_mutually_exclusive() {
    let mut m = small(1000, 1 << 20);
    m.feed(b"\x1b[?1000h\x1b[?1003h");
    let snap = snapshot_text(&m);
    assert!(!snap.contains("\x1b[?1000h"), "1003 replaces 1000: {snap:?}");
    assert!(snap.contains("\x1b[?1003h"));
}

#[test]
fn application_cursor_keys_survive_snapshot() {
    let mut m = small(1000, 1 << 20);
    m.feed(b"\x1b[?1h");
    assert!(snapshot_text(&m).contains("\x1b[?1h"));
    m.feed(b"\x1b[?1l");
    assert!(!snapshot_text(&m).contains("\x1b[?1h"));
}

#[test]
fn full_reset_clears_tracked_modes() {
    let mut m = small(1000, 1 << 20);
    m.feed(b"\x1b[?1002h\x1b[?1006h");
    m.feed(b"\x1bc"); // RIS
    let snap = snapshot_text(&m);
    assert!(!snap.contains("\x1b[?1002h"), "got {snap:?}");
    assert!(!snap.contains("\x1b[?1006h"), "got {snap:?}");
}

#[test]
fn non_private_set_mode_is_not_replayed_as_private() {
    let mut m = small(1000, 1 << 20);
    m.feed(b"\x1b[4h"); // IRM insert mode: not ours
    assert!(!snapshot_text(&m).contains("\x1b[?4h"));
}

#[test]
fn resize_updates_size_and_bumps_revision_once() {
    let mut m = small(1000, 1 << 20);
    m.feed(b"resize-me\r\n");
    let r0 = m.revision();

    let r1 = m.resize(40, 10);
    assert_eq!(m.size(), (40, 10));
    assert_eq!(r1, r0 + 1);
    // No-op resize does not bump.
    assert_eq!(m.resize(40, 10), r1);
    assert!(m.visible_lines().iter().any(|l| l.starts_with("resize-me")));
}

#[test]
fn revision_is_monotonic_and_starts_above_reserved_zero() {
    let mut m = small(1000, 1 << 20);
    assert!(m.revision() >= 1, "revision 0 is reserved (spec §1)");
    let r1 = m.feed(b"a");
    let r2 = m.feed(b"b");
    assert!(r2 > r1);
    assert_eq!(m.feed(b""), r2, "empty feed does not bump");
}

#[test]
fn utf8_split_across_feeds_renders_correctly() {
    let mut m = small(1000, 1 << 20);
    let text = "wide: 🦀émoji".as_bytes();
    // Split mid-emoji (🦀 is 4 bytes starting at "wide: ".len()).
    let split = "wide: ".len() + 2;
    m.feed(&text[..split]);
    m.feed(&text[split..]);
    assert!(
        m.visible_lines()[0].starts_with("wide: 🦀émoji"),
        "got {:?}",
        m.visible_lines()[0]
    );
}
