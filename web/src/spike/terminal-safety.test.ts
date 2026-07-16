// Unit tests for the T9 terminal-safety helpers. Run with:
//   cd web && npx tsx src/spike/terminal-safety.test.ts

import assert from "node:assert/strict";
import {
  clipboardWriteDecision,
  MAX_CLIPBOARD_BYTES,
  MAX_TITLE_LEN,
  pasteNeedsConfirmation,
  sanitizeTitle,
} from "../client/terminal-safety.js";

// sanitizeTitle strips control/escape characters.
assert.equal(sanitizeTitle("normal title"), "normal title");
assert.equal(sanitizeTitle("a\x1b[31mred\x1b[0m b"), "a[31mred[0m b");
assert.equal(sanitizeTitle("x\x07\x00\x7f\x9by"), "xy"); // BEL, NUL, DEL, C1
assert.equal(sanitizeTitle("  spaced\t\tout  "), "spaced out");
assert.equal(sanitizeTitle("line1\nline2"), "line1 line2");
assert.equal(sanitizeTitle("a".repeat(MAX_TITLE_LEN + 50)).length, MAX_TITLE_LEN + 1); // +ellipsis
assert.ok(sanitizeTitle("a".repeat(MAX_TITLE_LEN + 50)).endsWith("…"));

// pasteNeedsConfirmation flags newlines and control chars, allows plain text.
assert.equal(pasteNeedsConfirmation("just some text"), false);
assert.equal(pasteNeedsConfirmation("tab\tseparated"), false);
assert.equal(pasteNeedsConfirmation("two\nlines"), true);
assert.equal(pasteNeedsConfirmation("carriage\rreturn"), true);
assert.equal(pasteNeedsConfirmation("bell\x07here"), true);
assert.equal(pasteNeedsConfirmation("esc\x1bseq"), true);

// clipboardWriteDecision enforces the OSC 52 policy.
assert.deepEqual(
  clipboardWriteDecision({ enabled: false, focused: true, byteLength: 1, text: "x" }),
  { allow: false, reason: "clipboard writes disabled" },
);
assert.deepEqual(
  clipboardWriteDecision({ enabled: true, focused: false, byteLength: 1, text: "x" }),
  { allow: false, reason: "terminal not focused" },
);
assert.deepEqual(
  clipboardWriteDecision({
    enabled: true,
    focused: true,
    byteLength: MAX_CLIPBOARD_BYTES + 1,
    text: "x",
  }),
  { allow: false, reason: "clipboard payload too large" },
);
assert.deepEqual(
  clipboardWriteDecision({ enabled: true, focused: true, byteLength: 3, text: "yes" }),
  { allow: true, text: "yes" },
);

console.log("terminal-safety: all assertions passed");
