// Spot checks that the generated provider matches the server model's width
// table (unicode-width, via vendored avt). The generator is the authority;
// these pins catch a stale or hand-edited server-width.ts.
// Reproduce: npm test (web/).

import assert from "node:assert/strict";
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
const wideBase = p.charProperties(0x1fae0, 0);
assert.equal((wideBase >> 1) & 0x3, 2, "melting face is two columns");
const vs16 = p.charProperties(0xfe0f, wideBase);
assert.equal(vs16 & 1, 1, "VS16 joins");
assert.equal((vs16 >> 1) & 0x3, 2, "joined wide cell stays two columns");

console.log("server-width: all width parity spot checks passed");
