//! The model must lay out a row at the same width the *application* does.
//!
//! ADR 0026. Until 2026-08-11 the model measured with the `unicode-width`
//! crate while weechat — and everything else built on ncurses — wrapped and
//! padded with glibc's `wcwidth(3)`. 304 codepoints disagreed, so a row was
//! laid out at one width and painted at another and everything after the
//! disagreeing glyph on that row was displaced.
//!
//! `tools/render-diff` cannot catch this: both of its sides (the model and
//! xterm.js via the generated `ServerWidthAddon`) are generated from the same
//! table, so they agree with each other and disagree with the application
//! together. These tests are the model-side statement of the fix, one per
//! disagreement class.

use hf_terminal_model::{TerminalModel, TerminalModelConfig};

/// Feed `input` into a `cols`-wide model and return the visible rows.
fn rows_of(cols: u16, input: &str) -> Vec<String> {
    let mut model = TerminalModel::new(TerminalModelConfig {
        cols,
        rows: 6,
        ..Default::default()
    });
    model.feed(input.as_bytes());
    model.visible_lines()
}

/// The dominant class: 206 codepoints glibc calls 2 cells wide and the crate
/// called 1, a contiguous block from U+2630 (the trigrams) onward.
///
/// This is the one that shears an IRC client: at 80 columns weechat wraps a
/// run of these after 40 glyphs, and the model used to fit 80.
#[test]
fn wide_symbols_wrap_where_the_application_wraps() {
    let rows = rows_of(80, &"\u{2630}".repeat(60));

    let first = rows[0].chars().filter(|&c| c == '\u{2630}').count();
    assert_eq!(
        first, 40,
        "U+2630 is 2 cells under glibc, so 80 columns holds 40 — got {first} on row 0: {:?}",
        &rows[..2],
    );
    let second = rows[1].chars().filter(|&c| c == '\u{2630}').count();
    assert_eq!(second, 20, "the remaining 20 belong on row 1: {:?}", &rows[..2]);
}

/// 58 codepoints glibc calls 1 cell and the crate called 0 — headed by
/// U+00AD SOFT HYPHEN, which arrives from any web paste and was previously
/// dismissed as "very rare". A width-0 character attaches to the preceding
/// glyph's cell instead of occupying its own, so getting this wrong loses a
/// column on every occurrence.
#[test]
fn soft_hyphen_occupies_its_own_cell() {
    let rows = rows_of(10, "ab\u{00AD}cd");
    assert_eq!(
        rows[0].trim_end(),
        "ab\u{00AD}cd",
        "U+00AD is 1 cell under glibc and must not attach to the previous cell",
    );

    // At exactly the wrap boundary the width difference is visible as a wrap.
    let rows = rows_of(4, "abc\u{00AD}d");
    assert_eq!(
        rows[0].trim_end(),
        "abc\u{00AD}",
        "4 columns hold 'abc' plus the soft hyphen: {rows:?}",
    );
    assert_eq!(rows[1].trim_end(), "d", "'d' wraps to row 1: {rows:?}");
}

/// 37 codepoints glibc calls 0 and the crate called 1. These must attach to
/// the preceding glyph and consume no column.
#[test]
fn glibc_zero_width_marks_consume_no_column() {
    let rows = rows_of(6, "ab\u{0897}cdef");
    assert_eq!(
        rows[0].trim_end(),
        "ab\u{0897}cdef",
        "U+0897 is width 0 under glibc, so all six letters still fit in 6 columns: {rows:?}",
    );
}

/// The two-class jump: U+302E/U+302F are 2 cells under glibc and were 0 under
/// the crate — the largest single disagreement in the set.
#[test]
fn hangul_tone_marks_are_double_width() {
    let rows = rows_of(8, &"\u{302E}".repeat(6));
    let first = rows[0].chars().filter(|&c| c == '\u{302E}').count();
    assert_eq!(
        first, 4,
        "U+302E is 2 cells under glibc, so 8 columns holds 4: {rows:?}",
    );
}

/// The lone glibc=1/crate=2 case, proving the change is not simply "widen
/// everything": U+17A4 got *narrower*.
#[test]
fn khmer_sign_narrowed_to_one_cell() {
    let rows = rows_of(4, "\u{17A4}\u{17A4}\u{17A4}\u{17A4}");
    let first = rows[0].chars().filter(|&c| c == '\u{17A4}').count();
    assert_eq!(
        first, 4,
        "U+17A4 is 1 cell under glibc, so 4 columns holds 4 (it held 2 before): {rows:?}",
    );
}

/// ASCII is untouched by ADR 0026 — measured, no codepoint below U+00AD
/// disagrees — and the model keeps a fast path that assumes it. If that ever
/// stops holding, this catches it before the fast path silently lies.
#[test]
fn ascii_is_unaffected() {
    let rows = rows_of(10, "hello");
    assert_eq!(rows[0].trim_end(), "hello");

    let rows = rows_of(4, "abcdef");
    assert_eq!(rows[0].trim_end(), "abcd", "plain ASCII still wraps at the column count");
    assert_eq!(rows[1].trim_end(), "ef");
}
