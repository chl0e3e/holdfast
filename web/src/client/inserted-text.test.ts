import assert from "node:assert/strict";

import { InsertedTextForwarder } from "./inserted-text.js";

// The bug: the picker's insertion arrives as an `input` event that xterm.js
// declines (no onData), so nothing is sent and the emoji vanishes.
{
  const f = new InsertedTextForwarder();
  f.beginInputEvent();
  assert.equal(f.pendingInsert("insertText", "🎉"), "🎉", "declined insert must be forwarded");
}

// Normal typing: xterm.js emits the character itself — forwarding it again
// would double every keystroke.
{
  const f = new InsertedTextForwarder();
  f.beginInputEvent();
  f.noteTerminalData();
  assert.equal(f.pendingInsert("insertText", "a"), null, "xterm-handled input must not be re-sent");
}

// State must not leak between events: a handled keystroke followed by a
// declined insertion still forwards, and vice versa.
{
  const f = new InsertedTextForwarder();
  f.beginInputEvent();
  f.noteTerminalData();
  f.beginInputEvent();
  assert.equal(f.pendingInsert("insertText", "🙂"), "🙂", "previous event must not suppress this one");

  f.beginInputEvent();
  f.noteTerminalData();
  assert.equal(f.pendingInsert("insertText", "🙂"), null, "handled again after a forwarded insert");
}

// Repeating the same character quickly must keep working — the reason this
// uses per-event state rather than a de-duplication time window.
{
  const f = new InsertedTextForwarder();
  for (const _ of [0, 1, 2]) {
    f.beginInputEvent();
    assert.equal(f.pendingInsert("insertText", "!"), "!", "repeated identical inserts all forward");
  }
}

// Paste keeps flowing through the paste guard, and composition stays with
// xterm.js's own composition helper.
{
  const f = new InsertedTextForwarder();
  for (const inputType of ["insertFromPaste", "insertCompositionText", "deleteContentBackward"]) {
    f.beginInputEvent();
    assert.equal(f.pendingInsert(inputType, "x"), null, `${inputType} must not be forwarded`);
  }
}

// Empty/absent data is not input.
{
  const f = new InsertedTextForwarder();
  f.beginInputEvent();
  assert.equal(f.pendingInsert("insertText", ""), null);
  f.beginInputEvent();
  assert.equal(f.pendingInsert("insertText", null), null);
  f.beginInputEvent();
  assert.equal(f.pendingInsert("insertText", undefined), null);
}

console.log("inserted-text forwarding: all assertions passed");
