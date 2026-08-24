import assert from "node:assert/strict";
import {
  composeBoundedReplay,
  prependBoundedHistory,
  snapshotReplayPreamble,
  TERMINAL_WRITE_QUEUE_CAP,
  TERMINAL_WRITE_QUEUE_CHUNK_CAP,
  viewportFromBottom,
} from "./terminal-render-state.js";

assert.equal(TERMINAL_WRITE_QUEUE_CAP, 256 * 1024);
assert.equal(TERMINAL_WRITE_QUEUE_CHUNK_CAP, 256);

const kept = prependBoundedHistory(["new"], 5, ["oldest", "older"], 3, 18);
assert.deepEqual(kept.lines, ["older", "new"]);
assert.equal(kept.bytes, 12);
assert.equal(kept.acceptedAll, false);

const lineBound = prependBoundedHistory(["c"], 3, ["a", "b"], 2, 100);
assert.deepEqual(lineBound.lines, ["b", "c"]);
assert.equal(lineBound.acceptedAll, false);

assert.deepEqual(
  composeBoundedReplay([new Uint8Array([1, 2]), new Uint8Array([3])], 3),
  new Uint8Array([1, 2, 3]),
);
assert.equal(composeBoundedReplay([new Uint8Array(2), new Uint8Array(2)], 3), null);

const preamble = new TextDecoder().decode(snapshotReplayPreamble(3));
assert.equal(preamble, "\r\n\r\n\r\n\x1b[H");
assert.ok(
  preamble.endsWith("\x1b[H"),
  "the snapshot must start at its fresh-emulator home position after the scrollback spacer",
);
assert.throws(() => snapshotReplayPreamble(0), RangeError);
assert.throws(() => snapshotReplayPreamble(4_097), RangeError);

assert.equal(viewportFromBottom(140, 100), 40);
assert.equal(viewportFromBottom(20, 100), 0);

console.log("terminal render-state tests passed");
