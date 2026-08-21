// Spot checks that the generated provider matches the project's width
// authority: a committed dump of glibc's wcwidth(3) (ADR 0026), which the
// server model (vendored avt) is generated from too. The generator is the
// authority; these pins catch a stale or hand-edited server-width.ts.
// Reproduce: npm test (web/).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { ServerWidthProvider, SERVER_WIDTH_VERSION } from "./server-width.js";

const p = new ServerWidthProvider();

assert.equal(p.version, SERVER_WIDTH_VERSION);

// ASCII and controls.
assert.equal(p.wcwidth(0x41), 1, "A");
assert.equal(p.wcwidth(0x1b), 0, "ESC");
assert.equal(p.wcwidth(0x7f), 0, "DEL");
assert.equal(p.wcwidth(0x9b), 0, "C1 CSI");

// Zero-width class (the Zalgo/ZWJ/VS16 shear, fixed server-side in b01ce4d).
assert.equal(p.wcwidth(0x0301), 0, "combining acute");
assert.equal(p.wcwidth(0x200d), 0, "zero-width joiner");
assert.equal(p.wcwidth(0xfe0f), 0, "variation selector-16");
assert.equal(p.wcwidth(0x1160), 0, "Hangul jungseong filler");

// Narrow stays narrow.
assert.equal(p.wcwidth(0x2764), 1, "heavy black heart (text presentation)");
assert.equal(p.wcwidth(0x00e9), 1, "precomposed e-acute");

// Wide: CJK and emoji, including post-Unicode-11 emoji the old Unicode-11
// addon measured at 1 cell (the remaining shear class this file closes).
assert.equal(p.wcwidth(0x65e5), 2, "CJK 日");
assert.equal(p.wcwidth(0x1f980), 2, "crab U+1F980");
assert.equal(p.wcwidth(0x1f972), 2, "smiling face with tear (U13)");
assert.equal(p.wcwidth(0x1fae0), 2, "melting face (U14)");
assert.equal(p.wcwidth(0x1faf6), 2, "heart hands (U14)");

// charProperties joining: a zero-width mark joins its base and inherits the
// base's width (xterm packing: bit 0 join, bits 1-2 width).
const base = p.charProperties(0x65, 0); // 'e'
assert.equal(base & 1, 0, "base does not join");
assert.equal((base >> 1) & 0x3, 1, "base is narrow");
const mark = p.charProperties(0x0301, base);
assert.equal(mark & 1, 1, "mark joins preceding cell");
assert.equal((mark >> 1) & 0x3, 1, "joined cell stays one column");
// WeeChat positions coloured fields with CSI/SGR, which resets xterm.js's
// preceding-character state without moving the cursor back to column zero.
// A leading zero-width mark must still join the physical cell on the left.
// Otherwise xterm.js creates a hidden width-0 buffer cell, advances by one,
// and shifts the rest of the field away from the server snapshot. U+1885 is
// the exact leading mark observed in the `ᢅ؄⁐` IRC nickname.
const fieldLeadingMark = p.charProperties(0x1885, 0);
assert.equal(fieldLeadingMark & 1, 1, "field-leading zero-width mark joins left cell");
assert.equal((fieldLeadingMark >> 1) & 0x3, 0, "field-leading mark consumes no column");
const wideBase = p.charProperties(0x1fae0, 0);
assert.equal((wideBase >> 1) & 0x3, 2, "melting face is two columns");
const vs16 = p.charProperties(0xfe0f, wideBase);
assert.equal(vs16 & 1, 1, "VS16 joins");
assert.equal((vs16 >> 1) & 0x3, 2, "joined wide cell stays two columns");

// ADR 0026 — one pin per class where glibc's wcwidth disagreed with the
// `unicode-width` crate this table used to be generated from. Every
// assertion above this point passes under BOTH authorities (verified), so
// without these the suite could not tell the two apart at all. Each of these
// fails against the pre-0026 table.
assert.equal(p.wcwidth(0x2630), 2, "U+2630 trigram: glibc 2, crate 1 (206 such)");
assert.equal(p.wcwidth(0x00ad), 1, "U+00AD soft hyphen: glibc 1, crate 0 (58 such)");
assert.equal(p.wcwidth(0x0897), 0, "U+0897: glibc 0, crate 1 (37 such)");
assert.equal(p.wcwidth(0x302e), 2, "U+302E hangul tone: glibc 2, crate 0 (2 such)");
assert.equal(p.wcwidth(0x17a4), 1, "U+17A4 khmer: glibc 1, crate 2 (the only narrowing)");

// The two generated copies were byte-identical only by the generator's
// convention — nothing asserted it, and the desktop copy has no test of its
// own. A drifted copy means the desktop client wraps differently from the
// server, which is the exact shear this whole table exists to prevent.
const webCopy = fileURLToPath(new URL("./server-width.ts", import.meta.url));
const desktopCopy = fileURLToPath(
  new URL("../../../desktop/src/server-width.ts", import.meta.url),
);
assert.equal(
  readFileSync(webCopy, "utf8"),
  readFileSync(desktopCopy, "utf8"),
  "web and desktop server-width.ts must be byte-identical — regenerate with " +
    "`cargo run -p hf-xterm-width-tables`",
);

console.log("server-width: all width parity spot checks passed");
