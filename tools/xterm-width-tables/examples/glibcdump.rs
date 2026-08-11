//! Dumps one character per codepoint giving **glibc's** `wcwidth(3)` answer.
//!
//! Since ADR 0026 this is the width authority for the whole project: the
//! terminal application (weechat, ncurses, anything using `wcwidth`) lays its
//! screen out with these numbers, so the server model and both clients must
//! draw with them too. Where they disagree a line is laid out at one width and
//! drawn at another, and everything after it on that row is displaced.
//!
//! The output of this example, wrapped and given a provenance header, is
//! committed as `data/wcwidth-glibc-<version>-<locale>.txt` and is the input
//! the generator reads. Regenerate it only deliberately — a new dump means a
//! new reference glibc, which is an ADR-level change, not a refresh.
//!
//! ```text
//! cargo run -p hf-xterm-width-tables --example glibcdump > /tmp/glibc-widths.txt
//! # and to see what the crate would have said instead:
//! cargo run -p hf-xterm-width-tables --example uwdump > /tmp/uw-widths.txt
//! ```
//!
//! Output: one character per codepoint from U+0020 up — `0`/`1`/`2` for a
//! width, `N` where glibc returns -1 ("not printable in this locale"), `s` for
//! a surrogate. Note that `N` does *not* mean the same thing as `uwdump`'s `N`
//! (which is `unicode-width` returning `None`); the two dumps are diffable but
//! their `N`s have different causes. ADR 0026 maps `N` to width 1.

use std::ffi::CString;

/// The locale the dump is taken under. `crates/pty` guarantees every served
/// shell has at least a UTF-8 locale and falls back to exactly this one, and
/// glibc's `wcwidth` is identical across UTF-8 locales anyway (measured:
/// `en_US.UTF-8` agrees with `C.UTF-8` on all 1,112,032 codepoints), so this
/// is a stable choice rather than an arbitrary one.
const LOCALE: &str = "C.UTF-8";

// The `libc` crate does not bind `wcwidth(3)` on any platform, so declare it.
// POSIX: `int wcwidth(wchar_t wc)`, and on Linux `wchar_t` is a 32-bit code
// point, so a `char`'s scalar value can be passed straight through.
extern "C" {
    fn wcwidth(wc: libc::wchar_t) -> libc::c_int;
}

fn main() {
    // wcwidth is locale-dependent by definition; without this the process is
    // still in the default "C" locale, where every non-ASCII codepoint is
    // unprintable and the dump would be uniformly -1.
    let locale = CString::new(LOCALE).expect("locale name has no interior nul");
    let applied = unsafe { libc::setlocale(libc::LC_ALL, locale.as_ptr()) };
    assert!(
        !applied.is_null(),
        "setlocale(LC_ALL, {LOCALE}) failed — this host cannot produce the reference dump",
    );

    let mut buf = String::with_capacity(1_114_080);
    for cp in 32u32..0x110000 {
        if (0xD800..=0xDFFF).contains(&cp) {
            buf.push('s');
            continue;
        }
        // Every non-surrogate scalar value is a valid wchar_t on Linux, where
        // wchar_t is a 32-bit code point.
        let width = unsafe { wcwidth(cp as libc::wchar_t) };
        buf.push(match width {
            0 => '0',
            1 => '1',
            2 => '2',
            -1 => 'N',
            other => panic!("wcwidth(U+{cp:04X}) returned {other}, which no width class covers"),
        });
    }
    print!("{buf}");
}
