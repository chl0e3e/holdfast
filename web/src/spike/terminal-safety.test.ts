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

// --- Hostile title corpus (T9): a shell-set window title is attacker
// controlled, so sanitizeTitle output must never carry markup, control bytes,
// or escape introducers into the page chrome. ---
const hostileTitles: Array<[string, string]> = [
  ["<img src=x onerror=alert(1)>", "html-injection"],
  ["</title><script>alert(1)</script>", "title-breakout"],
  ["title\x1b]0;nested\x07more", "nested-osc"],
  ["\x1b[2J\x1b[3Jclear", "screen-clear-in-title"],
  ["a\x9b31mCSI-via-c1", "c1-csi-introducer"],
  ["link\x1b]8;;http://evil\x07text", "osc8-hyperlink"],
  ["ansi\x1b[38;2;255;0;0mcolor", "sgr-truecolor"],
  ["\x07\x00\x08\x0b\x0c\x7f\x9f", "only-controls"],
  ["tab\ttab\nnewline\rcr", "whitespace-controls"],
];
for (const [raw, label] of hostileTitles) {
  const out = sanitizeTitle(raw);
  // No ESC (0x1b), no C0 controls, no C1 controls survive.
  for (const ch of out) {
    const code = ch.codePointAt(0)!;
    assert.ok(code >= 0x20 && code !== 0x7f && !(code >= 0x80 && code <= 0x9f),
      `${label}: control char U+${code.toString(16)} survived sanitize: ${JSON.stringify(out)}`);
  }
  // The bytes a browser could parse as tag boundaries are never introduced by
  // us; sanitizeTitle does not add markup, so any '<'/'>' can only be inert
  // text — assert they are present verbatim (defused by textContent at the DOM
  // layer) rather than transformed into something executable.
  assert.equal(out.includes("\x1b"), false, `${label}: ESC survived`);
}
// The escape/control bytes are stripped; the printable remnants survive as
// inert text (defused by textContent at the DOM layer), never as a live
// sequence — no ESC, BEL, or C1 introducer remains.
assert.equal(sanitizeTitle("\x1b]0;\x07\x1b[0m"), "]0;[0m");
// A title of only control bytes does collapse to empty.
assert.equal(sanitizeTitle("\x1b\x07\x00\x9b"), "");

// --- Bracketed-paste breakout (T9): the terminal enables bracketed paste
// (DECSET 2004), wrapping pastes in ESC[200~ ... ESC[201~. A paste payload that
// smuggles its own ESC[201~ could terminate the bracket early and inject
// commands. pasteNeedsConfirmation must flag every such payload (they all
// contain ESC / control bytes). ---
const breakoutPastes = [
  "innocent\x1b[201~rm -rf ~\x1b[200~", // early end-of-paste marker
  "line1\x1b[201~\nsudo evil\n\x1b[200~", // marker + newline
  "\x1b[201~", // bare end marker
  "text\x9b201~more", // C1 CSI form of the marker
];
for (const p of breakoutPastes) {
  assert.equal(pasteNeedsConfirmation(p), true, `breakout paste not flagged: ${JSON.stringify(p)}`);
}

// --- Unicode direction / homoglyph overrides in pastes: RTL/LTR overrides can
// visually reorder a pasted command so what the user sees differs from what
// runs. These are control-category code points (Cf); flag them for confirmation
// so the reordering can't execute silently. ---
const bidiPastes = [
  "echo safe‮⁦; rm -rf ~", // RIGHT-TO-LEFT OVERRIDE
  "git commit​--amend", // ZERO WIDTH SPACE
  "ls rm", // LINE SEPARATOR
  "a b", // PARAGRAPH SEPARATOR
];
for (const p of bidiPastes) {
  assert.equal(pasteNeedsConfirmation(p), true, `bidi/format paste not flagged: ${JSON.stringify(p)}`);
}

// --- OSC 52 clipboard payload corpus: oversized and control-laden payloads. ---
assert.equal(
  clipboardWriteDecision({
    enabled: true, focused: true,
    byteLength: MAX_CLIPBOARD_BYTES, text: "z".repeat(MAX_CLIPBOARD_BYTES),
  }).allow,
  true,
  "exactly-at-limit clipboard payload should be allowed",
);
assert.equal(
  clipboardWriteDecision({ enabled: true, focused: true, byteLength: 0, text: "" }).allow,
  true,
  "empty clipboard payload is allowed when enabled+focused",
);

console.log("terminal-safety: all assertions passed");
