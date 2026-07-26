//! Phase 1 spike: verify the terminal-model candidates against spec §10
//! requirements before choosing (ADR 0004). Reproduce with:
//!
//! ```bash
//! cargo test -p spike-terminal-model
//! ```

/// avt: lines evicted from the (deliberately zero-length) internal scrollback
/// are handed back from feed_str — we can own the history ring with stable
/// line IDs.
#[test]
fn avt_hands_over_scrolled_off_lines() {
    let mut vt = avt::Vt::builder().size(20, 4).scrollback_limit(0).build();

    let mut history: Vec<String> = Vec::new();
    for i in 1..=10 {
        let changes = vt.feed_str(&format!("line-{i}\r\n"));
        // Note: avt pads lines to terminal width; the model trims on commit.
        history.extend(changes.scrollback.map(|l| l.text().trim_end().to_string()));
    }

    // 10 lines printed on a 4-row screen; the newline after line-10 leaves
    // rows: line-8, line-9, line-10, (blank). Everything above was evicted.
    assert_eq!(
        history,
        (1..=7).map(|i| format!("line-{i}")).collect::<Vec<_>>(),
        "scrolled-off primary lines must be handed to the caller in order"
    );
    let visible: Vec<String> = vt.view().map(|l| l.text()).collect();
    assert!(visible[0].starts_with("line-8") && visible[2].starts_with("line-10"));
}

/// Alternate-screen output (vim, less, top) must never pollute primary
/// scrollback (spec §10).
#[test]
fn avt_alternate_screen_produces_no_history() {
    let mut vt = avt::Vt::builder().size(20, 4).scrollback_limit(0).build();
    vt.feed_str("before-alt\r\n");

    let mut evicted = 0;
    // Enter alt screen (smcup), spew many lines, leave (rmcup).
    evicted += vt.feed_str("\x1b[?1049h").scrollback.count();
    for i in 0..50 {
        evicted += vt
            .feed_str(&format!("alt-noise-{i}\r\n"))
            .scrollback
            .count();
    }
    evicted += vt.feed_str("\x1b[?1049l").scrollback.count();

    assert_eq!(
        evicted, 0,
        "alt-screen output must not generate history lines"
    );
    let visible: Vec<String> = vt.view().map(|l| l.text()).collect();
    assert!(
        visible[0].starts_with("before-alt"),
        "primary screen must be restored after rmcup, got {visible:?}"
    );
}

/// dump() must produce a byte sequence that reconstructs the current screen in
/// a fresh emulator — our attach-snapshot mechanism.
#[test]
fn avt_dump_reconstructs_screen_state() {
    let mut vt = avt::Vt::builder().size(20, 4).scrollback_limit(0).build();
    vt.feed_str("hello \x1b[1;31mred-bold\x1b[0m\r\nsecond line\r\n");

    let mut replica = avt::Vt::builder().size(20, 4).scrollback_limit(0).build();
    replica.feed_str(&vt.dump());

    let a: Vec<String> = vt.view().map(|l| l.text()).collect();
    let b: Vec<String> = replica.view().map(|l| l.text()).collect();
    assert_eq!(a, b, "dump replay must reproduce the visible screen");
    assert_eq!(vt.cursor().col, replica.cursor().col);
    assert_eq!(vt.cursor().row, replica.cursor().row);
}

/// Resize must be handled without losing the screen; avt reflows and reports
/// affected lines.
#[test]
fn avt_resize_keeps_content() {
    let mut vt = avt::Vt::builder().size(20, 5).scrollback_limit(0).build();
    vt.feed_str("resize-me\r\n");
    vt.resize(40, 10);
    assert_eq!(vt.size(), (40, 10));
    let visible: Vec<String> = vt.view().map(|l| l.text()).collect();
    assert!(visible.iter().any(|l| l.starts_with("resize-me")));
}

/// vt100 comparison point: redraw via contents_formatted works, but there is
/// no eviction hand-off — scrolled-off lines can only be read back by
/// paging set_scrollback(), and nothing signals eviction. Recorded for the
/// ADR; not chosen.
#[test]
fn vt100_has_redraw_but_no_eviction_handoff() {
    let mut parser = vt100::Parser::new(4, 20, 5);
    for i in 1..=10 {
        parser.process(format!("line-{i}\r\n").as_bytes());
    }
    let formatted = parser.screen().contents_formatted();
    assert!(!formatted.is_empty());

    // Scrollback is readable only by mutating the view offset:
    parser.screen_mut().set_scrollback(5);
    let top = parser.screen().contents();
    assert!(top.contains("line-3"), "scrollback view: {top:?}");
    parser.screen_mut().set_scrollback(0);
}
