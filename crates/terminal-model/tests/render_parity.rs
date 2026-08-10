//! Regression tests for divergences between the server model's attach
//! snapshot and what xterm.js renders from the same bytes. Each one below was
//! a real defect: the screen looked correct while attached and came back
//! different after a roam or reload.
//!
//! The exhaustive version of these checks is the differential harness in
//! `tools/render-diff`, which replays a 200-case corpus through both the model
//! and a headless xterm.js. These are the cheap in-crate guards so a
//! regression fails `cargo test -p hf-terminal-model` on its own.

use hf_terminal_model::{TerminalModel, TerminalModelConfig};

fn model(cols: u16, rows: u16) -> TerminalModel {
    TerminalModel::new(TerminalModelConfig {
        cols,
        rows,
        ..TerminalModelConfig::default()
    })
}

fn snapshot_of(m: &TerminalModel) -> String {
    String::from_utf8(m.snapshot()).expect("snapshot is valid UTF-8")
}

#[test]
fn truecolor_survives_the_snapshot_in_semicolon_form() {
    let mut m = model(20, 4);
    m.feed(b"\x1b[38;2;255;100;0mORANGE\x1b[0m");
    let snap = snapshot_of(&m);

    // The colon form `38:2:R:G:B` omits ITU T.416's colour-space slot, and a
    // spec-following parser reads R as the colour space — rgb(255,100,0) came
    // back as rgb(100,0,0) on every reattach.
    assert!(
        snap.contains("38;2;255;100;0"),
        "expected semicolon-form RGB, got {snap:?}"
    );
    assert!(!snap.contains("38:2:"), "ambiguous colon form in {snap:?}");
}

#[test]
fn legacy_and_indexed_palette_colours_keep_their_own_form() {
    let mut m = model(20, 4);
    m.feed(b"\x1b[31mA\x1b[38;5;1mB\x1b[0m");
    let snap = snapshot_of(&m);

    // xterm.js records these as different colour modes and renders them
    // differently under bold, so the snapshot must not collapse one into the
    // other.
    assert!(snap.contains("\x1b[31m"), "legacy red lost in {snap:?}");
    assert!(snap.contains("38;5;1"), "indexed red lost in {snap:?}");
}

#[test]
fn underline_colour_does_not_become_blink() {
    let mut m = model(20, 4);
    m.feed(b"\x1b[4m\x1b[58;5;196mUCOL\x1b[0m");
    let snap = snapshot_of(&m);

    // SGR 58's operands used to be left unconsumed, so the `5` was re-read as
    // SGR 5 and underlined text came back blinking.
    assert!(snap.contains("\x1b[4m"), "underline lost in {snap:?}");
    assert!(
        !snap.contains("\x1b[4;5m") && !snap.contains("\x1b[5m"),
        "underline colour leaked into blink: {snap:?}"
    );
}

#[test]
fn colon_form_underline_styles_are_kept() {
    let mut m = model(20, 4);
    m.feed(b"\x1b[4:3mCURLY\x1b[0m");
    assert!(
        snapshot_of(&m).contains("\x1b[4m"),
        "curly underline dropped entirely"
    );
}

#[test]
fn invisible_attribute_survives_the_snapshot() {
    let mut m = model(20, 4);
    m.feed(b"\x1b[8mHIDDEN\x1b[0m");
    assert!(snapshot_of(&m).contains("\x1b[8m"), "SGR 8 not preserved");
}

#[test]
fn invalid_utf8_occupies_no_columns() {
    let mut m = model(20, 4);
    // A latin-1 byte inside otherwise valid text. xterm.js drops invalid
    // sequences; emitting U+FFFD here gave the model an extra column and
    // sheared every following wrap point.
    m.feed(b"caf\xe9 au lait");
    assert_eq!(m.visible_lines()[0].trim_end(), "caf au lait");
}

#[test]
fn emoji_tag_sequence_flag_is_not_truncated() {
    let mut m = model(20, 4);
    // U+1F3F4 plus six tag characters plus the terminator: seven zero-width
    // characters on one cell, which the previous cap of three cut short.
    let flag = "\u{1f3f4}\u{e0067}\u{e0062}\u{e0073}\u{e0063}\u{e0074}\u{e007f}";
    m.feed(flag.as_bytes());
    assert!(
        m.visible_lines()[0].contains(flag),
        "tag sequence truncated: {:?}",
        m.visible_lines()[0]
    );
}

#[test]
fn narrowing_keeps_every_character() {
    for len in [61usize, 80, 160, 200, 250, 300] {
        let mut m = model(80, 24);
        m.feed("w".repeat(len).as_bytes());
        m.feed(b"\r\n");
        m.resize(60, 24);

        let on_screen: usize = m.visible_lines().iter().map(|l| l.trim_end().len()).sum();
        let in_history: usize = m
            .history_range(0, 10_000, 1 << 20)
            .lines
            .iter()
            .map(|l| l.trim_end().len())
            .sum();
        assert_eq!(
            on_screen + in_history,
            len,
            "narrowing lost characters for a {len}-char line"
        );
    }
}

#[test]
fn narrowing_anchors_content_that_still_fits() {
    let mut m = model(80, 24);
    m.feed("w".repeat(250).as_bytes());
    m.feed(b"\r\n");
    m.resize(60, 24);

    // 250 characters need five 60-column rows, and a 24-row screen has room,
    // so nothing may scroll off the top: the extra rows come out of the blank
    // space below the cursor instead.
    let lines = m.visible_lines();
    assert_eq!(lines[0].trim_end().len(), 60, "top row scrolled away");
    assert_eq!(lines[4].trim_end().len(), 10, "last row not where expected");
    assert!(
        m.history_range(0, 10, 1 << 20).lines.is_empty(),
        "nothing should have been evicted"
    );
}

#[test]
fn lines_pushed_off_by_narrowing_reach_history() {
    let mut m = model(80, 4);
    m.feed("w".repeat(300).as_bytes());
    m.resize(40, 4);

    // 300 characters at 40 columns need more rows than the screen has, so the
    // overflow must scroll into history rather than being discarded.
    let in_history: usize = m
        .history_range(0, 10_000, 1 << 20)
        .lines
        .iter()
        .map(|l| l.trim_end().len())
        .sum();
    let on_screen: usize = m.visible_lines().iter().map(|l| l.trim_end().len()).sum();
    assert!(in_history > 0, "overflow was dropped instead of retained");
    assert_eq!(on_screen + in_history, 300);
}
