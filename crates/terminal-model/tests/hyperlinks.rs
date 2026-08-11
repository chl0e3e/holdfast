//! OSC 8 hyperlinks must survive the feed → snapshot round trip.
//!
//! The model used to discard every OSC (upstream avt's `osc_put` was a no-op),
//! so a link was visible while you watched the stream and gone the moment you
//! reattached — the exact "looked right, wrong when you came back" shape every
//! render bug in this project has had. Two `tools/render-diff` cases
//! (`hyperlink-osc8`, `hyperlink-osc8-with-id`) failed on it.

use hf_terminal_model::{TerminalModel, TerminalModelConfig};

fn snapshot_of(cols: u16, input: &str) -> String {
    let mut model = TerminalModel::new(TerminalModelConfig {
        cols,
        rows: 6,
        ..Default::default()
    });
    model.feed(input.as_bytes());
    String::from_utf8(model.snapshot()).expect("snapshot is valid UTF-8")
}

const ST: &str = "\x1b\\";

#[test]
fn hyperlink_survives_the_snapshot() {
    let snap = snapshot_of(
        40,
        &format!("\x1b]8;;https://example.com/irc{ST}LINKTEXT\x1b]8;;{ST}\r\n"),
    );
    assert!(
        snap.contains("]8;;https://example.com/irc"),
        "snapshot dropped the hyperlink: {snap:?}",
    );
    assert!(
        snap.contains("LINKTEXT"),
        "snapshot dropped the link text: {snap:?}",
    );
}

#[test]
fn hyperlink_id_param_is_preserved() {
    // xterm.js needs `id=` to treat a link split across a wrap as one link.
    let snap = snapshot_of(
        40,
        &format!("\x1b]8;id=x1;https://example.com/a{ST}LINK2\x1b]8;;{ST}\r\n"),
    );
    assert!(
        snap.contains("]8;id=x1;https://example.com/a"),
        "snapshot dropped the id= param: {snap:?}",
    );
}

/// The trap that makes this change dangerous rather than merely additive: a
/// run differing only by hyperlink produces zero SGR ops, and an empty
/// `Sgr` dumps as bare `CSI m` — a full attribute reset that silently wipes
/// colour for the rest of the snapshot.
#[test]
fn a_link_change_alone_never_emits_a_full_sgr_reset() {
    let snap = snapshot_of(
        40,
        &format!(
            "\x1b[31mRED\x1b]8;;https://example.com/x{ST}LINK\x1b]8;;{ST}STILLRED\r\n"
        ),
    );
    assert!(
        !snap.contains("\x1b[m"),
        "a link-only pen change emitted a bare CSI m (full reset): {snap:?}",
    );
    // The colour must still be in force after the link closes.
    let after = snap.split("STILLRED").next().unwrap_or_default();
    assert!(
        !after.contains("\x1b[0m"),
        "colour was reset before STILLRED: {snap:?}",
    );
}

/// xterm.js's `_eraseAttrData()` strips the extended attrs that hold the link,
/// so an erased region never becomes clickable. Without matching that, the
/// active link bleeds into every blank the pen touches.
#[test]
fn erase_does_not_inherit_the_active_hyperlink() {
    // Lay down plain text, then erase a hole in the middle of it while a link
    // is open. The blanks in that hole must not become linked. The link is
    // closed afterwards so the live pen carries none either, which makes the
    // URI's absence from the whole dump the exact statement of the property.
    let snap = snapshot_of(
        20,
        &format!(
            "AAAAAAAA\r\x1b[3C\x1b]8;;https://example.com/x{ST}\x1b[3X\x1b]8;;{ST}"
        ),
    );
    assert!(
        !snap.contains("https://example.com/x"),
        "erased blanks inherited the open hyperlink: {snap:?}",
    );
    assert!(
        snap.contains("AAA"),
        "the surrounding text should survive: {snap:?}",
    );
}

/// The link table is grow-only and capped, so a shell cannot make its own
/// session unattachable by interning links without limit. Past the cap new
/// links degrade to unlinked text — never to some other link's destination.
#[test]
fn link_table_is_bounded() {
    let mut input = String::new();
    for i in 0..400 {
        input.push_str(&format!("\x1b]8;;https://example.com/{i}{ST}L"));
    }
    input.push_str(&format!("\x1b]8;;{ST}\r\n"));

    let snap = snapshot_of(200, &input);

    // Well under the 16 KiB negotiable frame floor.
    assert!(
        snap.len() < 8 * 1024,
        "snapshot grew to {} bytes under link flooding",
        snap.len(),
    );
    // And nothing beyond the cap may be mislabelled with a wrong URI: every
    // URI that does appear must be one that was actually opened.
    for chunk in snap.split("]8;;").skip(1) {
        let uri: String = chunk.chars().take_while(|c| *c != '\x1b').collect();
        if uri.is_empty() {
            continue;
        }
        assert!(
            uri.starts_with("https://example.com/"),
            "snapshot invented a destination: {uri:?}",
        );
    }
}

/// An oversized OSC payload is dropped whole rather than truncated — a
/// truncated URI is a different destination, not a shorter one.
#[test]
fn oversized_hyperlink_is_dropped_not_truncated() {
    let huge = "a".repeat(8192);
    let snap = snapshot_of(40, &format!("\x1b]8;;https://example.com/{huge}{ST}X\r\n"));
    assert!(
        !snap.contains("https://example.com/aaa"),
        "an over-long URI leaked into the snapshot: {}",
        &snap[..snap.len().min(200)],
    );
    assert!(snap.contains('X'), "the text after it should still print");
}

/// Every other OSC number keeps its existing parsed-and-ignored behaviour;
/// only OSC 8 was given meaning.
#[test]
fn other_osc_sequences_are_still_ignored() {
    let snap = snapshot_of(40, &format!("\x1b]0;window title{ST}TEXT\r\n"));
    assert!(
        !snap.contains("window title"),
        "OSC 0 title leaked into the snapshot: {snap:?}",
    );
    assert!(snap.contains("TEXT"));
}
