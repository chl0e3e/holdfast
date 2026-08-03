import assert from "node:assert/strict";

import { InsertedTextForwarder } from "./inserted-text.js";

// The original bug: the picker's insertion arrives as an `input` event that
// xterm.js declines (no onData), so nothing is sent and the emoji vanishes.
// The picker chord's keydown (Win+.) precedes it; its keyup never arrives.
{
  const f = new InsertedTextForwarder();
  f.beginKeyEvent(); // Win+. keydown — xterm.js emits nothing for it
  assert.equal(f.pendingInsert("insertText", "🎉"), "🎉", "declined insert must be forwarded");
}

// The space regression: xterm.js claims printable keys in `keydown` only for
// keyCode >= 48, so space (32) is handled in `keypress` — which it does not
// preventDefault. onData fires first, THEN the leftover `input` event.
// Forwarding that leftover doubled every space.
{
  const f = new InsertedTextForwarder();
  f.beginKeyEvent(); // space keydown
  f.noteTerminalData(); // xterm.js emits " " during keypress
  assert.equal(f.pendingInsert("insertText", " "), null, "keypress-handled space must not be re-sent");
  f.beginKeyEvent(); // space keyup
  // Autorepeat: every repeat cycle is keydown → keypress → input again.
  f.beginKeyEvent();
  f.noteTerminalData();
  assert.equal(f.pendingInsert("insertText", " "), null, "held-down space repeats must not double");
}

// Ordinary letters are claimed in `keydown` (event cancelled, no input event
// follows); the keyup must clear the flag so a later mouse-only picker
// insertion — no keystroke at all — still forwards.
{
  const f = new InsertedTextForwarder();
  f.beginKeyEvent(); // 'a' keydown
  f.noteTerminalData(); // xterm.js emits "a" during keydown
  f.beginKeyEvent(); // 'a' keyup
  assert.equal(f.pendingInsert("insertText", "🙂"), "🙂", "mouse-picker insert after typing must forward");
}

// One key action excuses at most one insertion: the flag is consumed by the
// decision, so back-to-back picker insertions with no keystrokes in between
// all forward. Per-event state, never a de-duplication time window (which
// would swallow fast repeats of the same character).
{
  const f = new InsertedTextForwarder();
  f.beginKeyEvent();
  f.noteTerminalData();
  assert.equal(f.pendingInsert("insertText", " "), null, "keystroke's own leftover is skipped");
  for (const _ of [0, 1, 2]) {
    assert.equal(f.pendingInsert("insertText", "!"), "!", "repeated identical inserts all forward");
  }
}

// Paste keeps flowing through the paste guard, and composition stays with
// xterm.js's own composition helper.
{
  const f = new InsertedTextForwarder();
  for (const inputType of ["insertFromPaste", "insertCompositionText", "deleteContentBackward"]) {
    assert.equal(f.pendingInsert(inputType, "x"), null, `${inputType} must not be forwarded`);
  }
}

// Empty/absent data is not input.
{
  const f = new InsertedTextForwarder();
  assert.equal(f.pendingInsert("insertText", ""), null);
  assert.equal(f.pendingInsert("insertText", null), null);
  assert.equal(f.pendingInsert("insertText", undefined), null);
}

console.log("inserted-text forwarding: all assertions passed");
