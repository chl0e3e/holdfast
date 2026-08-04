//! Emoji (astral-plane and VS16-qualified) must survive the feed → snapshot
//! round trip byte-for-byte: the 2026-08-04 "emojis show as ?" report turned
//! out to be a shell-locale issue, and this pins down that the model itself
//! never substitutes or drops them.

use hf_terminal_model::{TerminalModel, TerminalModelConfig};

#[test]
fn emoji_survive_snapshot() {
    let mut model = TerminalModel::new(TerminalModelConfig {
        cols: 40,
        rows: 5,
        ..Default::default()
    });
    let input = "A \u{1F642} B \u{1F980} C \u{2764}\u{FE0F} D \u{1FAE0} E";
    model.feed(input.as_bytes());
    let snap = String::from_utf8(model.snapshot()).expect("snapshot is valid UTF-8");
    for needle in ["\u{1F642}", "\u{1F980}", "\u{2764}", "\u{1FAE0}"] {
        assert!(
            snap.contains(needle),
            "snapshot lost {needle:?}; visible lines: {:?}",
            model.visible_lines()
        );
    }
    println!("visible: {:?}", model.visible_lines());
}
