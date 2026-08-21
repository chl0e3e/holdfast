//! Emits the project's width tables from one authority: a committed dump of
//! **glibc's `wcwidth(3)`** (ADR 0026). Three files are generated from it —
//! `server-width.ts` for each client (an xterm.js Unicode version provider)
//! and `widths.rs` for the server-side terminal model (vendored avt).
//!
//! The authority used to be the `unicode-width` crate, which is not what the
//! terminal *application* measures with: weechat and everything else built on
//! ncurses lay their screens out with `wcwidth`, and 304 codepoints disagreed.
//! Where they disagree a row is laid out at one width and painted at another,
//! displacing everything after it. `tools/render-diff` is structurally blind
//! to this — both of its sides load the table generated here — so the guard is
//! `--check` in CI plus the pins in `server-width.test.ts`.
//!
//! ```text
//! cargo run -p hf-xterm-width-tables            # regenerate all three files
//! cargo run -p hf-xterm-width-tables -- --check # fail if any is out of date
//! ```
//!
//! Regenerate after changing the committed dump — and only then. Bumping
//! `unicode-width` no longer affects these tables at all.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// The committed measurement, relative to the repo root. Changing which dump
/// is authoritative is an ADR-level decision (ADR 0026), not a config knob, so
/// the path is a constant rather than an argument.
const AUTHORITY: &str = "tools/xterm-width-tables/data/wcwidth-glibc-2.41-C.UTF-8.txt";

/// First codepoint the dump covers. Below this everything is width 1 (C0 is
/// special-cased by each consumer's control-character fast path).
const DUMP_LO: u32 = 0x20;

/// The width authority: one measured cell width per codepoint, plus the
/// provenance that makes the numbers auditable.
struct Authority {
    /// Indexed by `cp - DUMP_LO`, already reduced to 0/1/2.
    widths: Vec<u8>,
    glibc: String,
    locale: String,
}

impl Authority {
    fn load(repo_root: &Path) -> Authority {
        let path = repo_root.join(AUTHORITY);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

        let mut glibc = String::new();
        let mut locale = String::new();
        let mut widths = Vec::with_capacity(0x110000 - DUMP_LO as usize);
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix('#') {
                let rest = rest.trim();
                if let Some(v) = rest.strip_prefix("glibc:") {
                    glibc = v.trim().to_string();
                } else if let Some(v) = rest.strip_prefix("locale:") {
                    locale = v.trim().to_string();
                }
                continue;
            }
            for c in line.chars() {
                widths.push(match c {
                    '0' => 0,
                    '1' => 1,
                    '2' => 2,
                    // ADR 0026: glibc reports -1 ("not printable in this
                    // locale") for ~820k codepoints where both emulators
                    // place a one-cell glyph. Following it literally would
                    // swallow them and desynchronise the cursor across a far
                    // larger set than the bug being fixed, so -1 maps to 1.
                    // This is the one place the authority is overridden, and
                    // it is deliberately applied here rather than in the
                    // measurement so the raw glibc answer stays auditable.
                    'N' => 1,
                    // Surrogates are never printed; keep xterm's default.
                    's' => 1,
                    other => panic!("unknown width class {other:?} in {}", path.display()),
                });
            }
        }

        let expected = 0x110000 - DUMP_LO as usize;
        assert_eq!(
            widths.len(),
            expected,
            "{} covers {} codepoints, expected {expected}",
            path.display(),
            widths.len(),
        );
        assert!(!glibc.is_empty(), "{} has no `# glibc:` line", path.display());
        assert!(!locale.is_empty(), "{} has no `# locale:` line", path.display());

        Authority {
            widths,
            glibc,
            locale,
        }
    }

    /// Codepoint width class for table generation. Control chars (C0, DEL, C1)
    /// are special-cased in each emitted consumer exactly like xterm's own
    /// providers, so the ranges only ever cover printable codepoints.
    fn width_of(&self, cp: u32) -> u8 {
        if cp < DUMP_LO {
            return 1;
        }
        self.widths[(cp - DUMP_LO) as usize]
    }

    /// Collect maximal [start, end] runs of codepoints in `lo..=hi` whose
    /// width class is `class`.
    fn ranges(&self, lo: u32, hi: u32, class: u8) -> Vec<(u32, u32)> {
        let mut out: Vec<(u32, u32)> = Vec::new();
        let mut run: Option<(u32, u32)> = None;
        for cp in lo..=hi {
            if self.width_of(cp) == class {
                run = match run {
                    Some((s, e)) if e + 1 == cp => Some((s, cp)),
                    Some(done) => {
                        out.push(done);
                        Some((cp, cp))
                    }
                    None => Some((cp, cp)),
                };
            }
        }
        if let Some(done) = run {
            out.push(done);
        }
        out
    }
}

fn emit_ranges_ts(name: &str, ranges: &[(u32, u32)]) -> String {
    let mut s = format!("const {name}: [number, number][] = [\n");
    for chunk in ranges.chunks(3) {
        s.push_str("  ");
        for (start, end) in chunk {
            let _ = write!(s, "[0x{start:04X}, 0x{end:04X}], ");
        }
        s.pop();
        s.push('\n');
    }
    s.push_str("];\n");
    s
}

fn emit_ranges_rs(name: &str, ranges: &[(u32, u32)]) -> String {
    let mut s = format!("static {name}: &[(u32, u32)] = &[\n");
    for chunk in ranges.chunks(3) {
        s.push_str("    ");
        for (start, end) in chunk {
            let _ = write!(s, "(0x{start:04X}, 0x{end:04X}), ");
        }
        s.pop();
        s.push('\n');
    }
    s.push_str("];\n");
    s
}

struct Tables {
    bmp_zero: Vec<(u32, u32)>,
    bmp_wide: Vec<(u32, u32)>,
    high_zero: Vec<(u32, u32)>,
    high_wide: Vec<(u32, u32)>,
}

fn build_typescript(a: &Authority, t: &Tables) -> String {
    let (glibc, locale) = (&a.glibc, &a.locale);
    let mut ts = String::new();
    let _ = write!(
        ts,
        r#"/**
 * GENERATED FILE — DO NOT EDIT.
 *
 * xterm.js width provider generated from the project's width authority: a
 * committed dump of glibc {glibc}'s wcwidth(3) under {locale} (ADR 0026),
 * which is what the terminal *application* lays its screen out with. The
 * server-side model (vendored avt) is generated from the same dump. The
 * application, the server and this provider must agree on every character's
 * cell width: a single disagreement shifts every later wrap point and shears
 * the attach snapshot (see README "Zero-width characters sheared attach
 * snapshots" and the Unicode-11 note it supersedes).
 *
 * Regenerate with: cargo run -p hf-xterm-width-tables
 * Verify with:     cargo run -p hf-xterm-width-tables -- --check
 */

import type {{ Terminal, ITerminalAddon, IUnicodeVersionProvider }} from "@xterm/xterm";

export const SERVER_WIDTH_VERSION = "server";

"#
    );

    ts.push_str(&emit_ranges_ts("BMP_ZERO", &t.bmp_zero));
    ts.push('\n');
    ts.push_str(&emit_ranges_ts("BMP_WIDE", &t.bmp_wide));
    ts.push('\n');
    ts.push_str(&emit_ranges_ts("HIGH_ZERO", &t.high_zero));
    ts.push('\n');
    ts.push_str(&emit_ranges_ts("HIGH_WIDE", &t.high_wide));

    ts.push_str(
        r#"
// BMP lookup table, built lazily on first use (64 KiB).
let table: Uint8Array | undefined;

function buildTable(): Uint8Array {
  const t = new Uint8Array(65536);
  t.fill(1);
  t.fill(0, 0, 32); // C0 + NUL
  t.fill(0, 0x7f, 0xa0); // DEL + C1
  for (const [start, end] of BMP_ZERO) t.fill(0, start, end + 1);
  for (const [start, end] of BMP_WIDE) t.fill(2, start, end + 1);
  return t;
}

function bisearch(cp: number, ranges: [number, number][]): boolean {
  let lo = 0;
  let hi = ranges.length - 1;
  const first = ranges[0];
  const last = ranges[hi];
  if (first === undefined || last === undefined || cp < first[0] || cp > last[1]) return false;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const range = ranges[mid];
    if (range === undefined) return false;
    if (cp > range[1]) lo = mid + 1;
    else if (cp < range[0]) hi = mid - 1;
    else return true;
  }
  return false;
}

// xterm's UnicodeCharProperties packing (public provider contract):
// bit 0 = shouldJoin, bits 1-2 = width, bits 3+ = state.
function createPropertyValue(state: number, width: number, shouldJoin = false): number {
  return ((state & 0xffffff) << 3) | ((width & 3) << 1) | (shouldJoin ? 1 : 0);
}

function extractWidth(value: number): number {
  return (value >> 1) & 0x3;
}

export class ServerWidthProvider implements IUnicodeVersionProvider {
  public readonly version = SERVER_WIDTH_VERSION;

  public wcwidth(num: number): 0 | 1 | 2 {
    if (num < 32) return 0;
    if (num < 127) return 1;
    if (num < 65536) {
      if (!table) table = buildTable();
      return table[num] as 0 | 1 | 2;
    }
    if (bisearch(num, HIGH_ZERO)) return 0;
    if (bisearch(num, HIGH_WIDE)) return 2;
    return 1;
  }

  public charProperties(codepoint: number, preceding: number): number {
    let width: number = this.wcwidth(codepoint);
    // xterm clears `preceding` on CSI/SGR even though cursor positioning can
    // leave a physical cell immediately to the left. Its print path checks
    // the actual cursor column before joining, so keep zero-width characters
    // joinable even when this textual state is empty. Without this, a
    // field-leading combining mark creates a hidden width-0 buffer cell,
    // advances the cursor by one and shears live output from the snapshot.
    const shouldJoin = width === 0;
    if (shouldJoin) {
      const oldWidth = extractWidth(preceding);
      if (oldWidth > width) {
        width = oldWidth;
      }
    }
    return createPropertyValue(0, width, shouldJoin);
  }
}

export class ServerWidthAddon implements ITerminalAddon {
  public activate(terminal: Terminal): void {
    terminal.unicode.register(new ServerWidthProvider());
  }

  public dispose(): void {}
}
"#,
    );
    ts
}

fn build_rust(a: &Authority, t: &Tables) -> String {
    let (glibc, locale) = (&a.glibc, &a.locale);
    let mut rs = String::new();
    let _ = write!(
        rs,
        r#"//! GENERATED FILE — DO NOT EDIT.
//!
//! Cell widths for the terminal model, generated from the project's width
//! authority: a committed dump of glibc {glibc}'s `wcwidth(3)` under
//! {locale} (ADR 0026). Both clients' `server-width.ts` are generated from
//! the same dump, so the model and the renderers cannot drift — and, more to
//! the point, both now agree with what the terminal *application* used to lay
//! its screen out with, which the `unicode-width` crate did not (304
//! codepoints disagreed).
//!
//! Regenerate with: cargo run -p hf-xterm-width-tables
//! Verify with:     cargo run -p hf-xterm-width-tables -- --check

"#
    );

    rs.push_str(&emit_ranges_rs("BMP_ZERO", &t.bmp_zero));
    rs.push('\n');
    rs.push_str(&emit_ranges_rs("BMP_WIDE", &t.bmp_wide));
    rs.push('\n');
    rs.push_str(&emit_ranges_rs("HIGH_ZERO", &t.high_zero));
    rs.push('\n');
    rs.push_str(&emit_ranges_rs("HIGH_WIDE", &t.high_wide));

    rs.push_str(
        r#"
fn bisearch(cp: u32, ranges: &[(u32, u32)]) -> bool {
    ranges
        .binary_search_by(|&(start, end)| {
            if cp < start {
                std::cmp::Ordering::Greater
            } else if cp > end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Display width of `ch` in cells: 0 (combining/zero-width), 1 or 2.
///
/// Control characters never reach this — the parser handles them — so C0, DEL
/// and C1 all take the width-1 fast path, exactly as the pre-generation code
/// did (`unicode_width` returned `None` there and it was treated as 1).
pub(crate) fn width_of(ch: char) -> u8 {
    let cp = ch as u32;
    // Measured: nothing below U+00AD disagrees between the authority and the
    // old crate table, so this fast path is free of the ADR 0026 change.
    if cp < 0xa0 {
        return 1;
    }
    if cp <= 0xffff {
        if bisearch(cp, BMP_ZERO) {
            return 0;
        }
        if bisearch(cp, BMP_WIDE) {
            return 2;
        }
        return 1;
    }
    if bisearch(cp, HIGH_ZERO) {
        return 0;
    }
    if bisearch(cp, HIGH_WIDE) {
        return 2;
    }
    1
}
"#,
    );
    rs
}

/// Every file this generator owns, and its content.
fn outputs(repo_root: &Path) -> Vec<(PathBuf, String)> {
    let authority = Authority::load(repo_root);

    // BMP printable region; C0/DEL/C1 are special-cased by each consumer.
    let tables = Tables {
        bmp_zero: authority.ranges(0xA0, 0xFFFF, 0),
        bmp_wide: authority.ranges(0xA0, 0xFFFF, 2),
        high_zero: authority.ranges(0x10000, 0x10FFFF, 0),
        high_wide: authority.ranges(0x10000, 0x10FFFF, 2),
    };

    let ts = build_typescript(&authority, &tables);
    let rs = build_rust(&authority, &tables);

    println!(
        "authority: glibc {} ({}) — {} zero + {} wide BMP ranges, {} zero + {} wide astral ranges",
        authority.glibc,
        authority.locale,
        tables.bmp_zero.len(),
        tables.bmp_wide.len(),
        tables.high_zero.len(),
        tables.high_wide.len(),
    );

    vec![
        (repo_root.join("web/src/client/server-width.ts"), ts.clone()),
        (repo_root.join("desktop/src/server-width.ts"), ts),
        (repo_root.join("vendor/avt/src/widths.rs"), rs),
    ]
}

fn main() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("tools/xterm-width-tables sits two levels below the repo root")
        .to_path_buf();

    let check = std::env::args().any(|a| a == "--check");
    let outputs = outputs(&repo_root);

    if check {
        // The drift gate. Nothing else in the repo notices a hand-edited or
        // stale generated table — and the two `server-width.ts` copies were
        // byte-identical only by this generator's convention until now.
        let mut stale = Vec::new();
        for (path, want) in &outputs {
            let have = std::fs::read_to_string(path).unwrap_or_default();
            if &have != want {
                stale.push(path.clone());
            }
        }
        if stale.is_empty() {
            println!("--check: all {} generated files are up to date", outputs.len());
            return;
        }
        for path in &stale {
            eprintln!("stale: {}", path.display());
        }
        eprintln!(
            "\n{} generated file(s) do not match the authority.\n\
             Run `cargo run -p hf-xterm-width-tables` and commit the result.",
            stale.len(),
        );
        std::process::exit(1);
    }

    for (path, content) in &outputs {
        std::fs::write(path, content)
            .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        println!("wrote {}", path.display());
    }
}
