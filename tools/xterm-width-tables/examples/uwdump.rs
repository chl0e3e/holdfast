//! Dumps one character per codepoint giving `unicode-width`'s answer.
//!
//! This is no longer the width authority — ADR 0026 made glibc's `wcwidth(3)`
//! authoritative, because that is what the terminal *application* (weechat,
//! anything on ncurses) lays its screen out with, and 304 codepoints
//! disagreed. This example survives as the audit tool: diff it against the
//! committed dump to see exactly where the crate and the deployment differ.
//!
//! ```text
//! cargo run -p hf-xterm-width-tables --example uwdump    > /tmp/uw-widths.txt
//! cargo run -p hf-xterm-width-tables --example glibcdump > /tmp/glibc-widths.txt
//! cmp -l /tmp/uw-widths.txt /tmp/glibc-widths.txt | wc -l
//! ```
//!
//! Output: one character per codepoint from U+0020 up, `0`/`1`/`2` for a
//! width, `N` for unassigned, `s` for a surrogate. Note `glibcdump` also emits
//! `N`, but there it means glibc returned -1 ("not printable in this locale");
//! the two dumps line up positionally but their `N`s have different causes.
fn main() {
    let mut buf = String::with_capacity(1_114_080);
    for cp in 32u32..0x110000 {
        if (0xD800..=0xDFFF).contains(&cp) {
            buf.push('s');
            continue;
        }
        let ch = char::from_u32(cp).unwrap();
        buf.push(match unicode_width::UnicodeWidthChar::width(ch) {
            Some(0) => '0',
            Some(1) => '1',
            Some(2) => '2',
            Some(_) => '?',
            None => 'N',
        });
    }
    print!("{buf}");
}
