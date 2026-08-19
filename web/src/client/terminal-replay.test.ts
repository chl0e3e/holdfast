import assert from "node:assert/strict";
import { snapshotReplayPreamble } from "./terminal-replay.js";

const preamble = snapshotReplayPreamble(3);
assert.equal(preamble, "\r\n\r\n\r\n\x1b[H");
assert.ok(
  preamble.endsWith("\x1b[H"),
  "the snapshot must start at its fresh-emulator home position after the scrollback spacer",
);
assert.throws(() => snapshotReplayPreamble(0), RangeError);
assert.throws(() => snapshotReplayPreamble(4_097), RangeError);

console.log("terminal replay tests passed");
