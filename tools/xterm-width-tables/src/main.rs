//! Emits `server-width.ts` for both clients: an xterm.js Unicode version
//! provider whose width table is generated from the `unicode-width` crate —
//! the exact table the server-side terminal model (vendored avt) uses. One
//! width authority end to end; any other table shears attach snapshots
//! (Unicode-11 addon vs post-U11 emoji, 2026-08-03).
//!
//! Regenerate after any `unicode-width` upgrade in Cargo.lock:
//! `cargo run -p hf-xterm-width-tables` (from anywhere in the workspace).

use std::fmt::Write as _;
use std::path::Path;
use unicode_width::UnicodeWidthChar;

/// Codepoint width class for table generation. Control chars (C0, DEL, C1)
/// are special-cased in the emitted provider exactly like xterm's own
/// providers, so the ranges here only cover printable codepoints.
fn width_of(cp: u32) -> u8 {
    match char::from_u32(cp) {
        // Surrogates and other non-chars: keep xterm's default of 1.
        None => 1,
        Some(c) => match c.width() {
            Some(0) => 0,
            Some(2) => 2,
            // None is only control chars (handled by the provider's
            // fast path); everything else renders one cell wide.
            _ => 1,
        },
    }
}

/// Collect maximal [start, end] runs of codepoints in `lo..=hi` whose width
/// class is `class`.
fn ranges(lo: u32, hi: u32, class: u8) -> Vec<(u32, u32)> {
    let mut out: Vec<(u32, u32)> = Vec::new();
    let mut run: Option<(u32, u32)> = None;
    for cp in lo..=hi {
        if width_of(cp) == class {
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

fn emit_ranges(name: &str, ranges: &[(u32, u32)]) -> String {
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

fn locked_unicode_width_version(repo_root: &Path) -> String {
    let lock = std::fs::read_to_string(repo_root.join("Cargo.lock")).unwrap_or_default();
    let mut lines = lock.lines();
    while let Some(line) = lines.next() {
        if line == "name = \"unicode-width\"" {
            if let Some(version) = lines.next().and_then(|l| l.strip_prefix("version = ")) {
                return version.trim_matches('"').to_string();
            }
        }
    }
    "unknown".to_string()
}

fn main() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("tools/xterm-width-tables sits two levels below the repo root")
        .to_path_buf();

    let version = locked_unicode_width_version(&repo_root);

    // BMP printable region; C0/DEL/C1 are special-cased in the provider.
    let bmp_zero = ranges(0xA0, 0xFFFF, 0);
    let bmp_wide = ranges(0xA0, 0xFFFF, 2);
    let high_zero = ranges(0x10000, 0x10FFFF, 0);
    let high_wide = ranges(0x10000, 0x10FFFF, 2);

    let mut ts = String::new();
    let _ = write!(
        ts,
        r#"/**
 * GENERATED FILE — DO NOT EDIT.
 *
 * xterm.js width provider generated from the `unicode-width` crate
 * (v{version}, pinned in Cargo.lock) — the same table the server-side
 * terminal model (vendored avt) uses. The server, the shell's wcwidth and
 * this provider must agree on every character's cell width: a single
 * disagreement shifts every later wrap point and shears the attach
 * snapshot (see README "Zero-width characters sheared attach snapshots"
 * and the Unicode-11 note it supersedes).
 *
 * Regenerate with: cargo run -p hf-xterm-width-tables
 */

import type {{ Terminal, ITerminalAddon, IUnicodeVersionProvider }} from "@xterm/xterm";

export const SERVER_WIDTH_VERSION = "server";

"#
    );

    ts.push_str(&emit_ranges("BMP_ZERO", &bmp_zero));
    ts.push('\n');
    ts.push_str(&emit_ranges("BMP_WIDE", &bmp_wide));
    ts.push('\n');
    ts.push_str(&emit_ranges("HIGH_ZERO", &high_zero));
    ts.push('\n');
    ts.push_str(&emit_ranges("HIGH_WIDE", &high_wide));

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
    let shouldJoin = width === 0 && preceding !== 0;
    if (shouldJoin) {
      const oldWidth = extractWidth(preceding);
      if (oldWidth === 0) {
        shouldJoin = false;
      } else if (oldWidth > width) {
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

    for rel in ["web/src/client/server-width.ts", "desktop/src/server-width.ts"] {
        let path = repo_root.join(rel);
        std::fs::write(&path, &ts).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
        println!(
            "wrote {rel} (unicode-width {version}, {} zero + {} wide BMP ranges, {} zero + {} wide astral ranges)",
            bmp_zero.len(),
            bmp_wide.len(),
            high_zero.len(),
            high_wide.len()
        );
    }
}
