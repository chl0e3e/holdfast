//! Dumps one character per codepoint giving `unicode-width`'s answer, for
//! diffing against a shell's own `wcwidth`. The two MUST agree: the terminal
//! application (weechat) lays its screen out with glibc's `wcwidth`, while the
//! clients measure with the table generated from this crate. Where they
//! disagree, a line is laid out at one width and drawn at another, and
//! everything after it on that row is displaced.
//!
//! ```text
//! # on the server running the application:
//! python3 -c 'import ctypes,ctypes.util; ...'   # see tools/render-diff/README.md
//! # here:
//! cargo run -p hf-xterm-width-tables --example uwdump > uw-widths.txt
//! ```
//!
//! Output: one character per codepoint from U+0020 up, `0`/`1`/`2` for a
//! width, `N` for unassigned, `s` for a surrogate.
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
