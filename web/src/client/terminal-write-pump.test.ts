import assert from "node:assert/strict";
import {
  TERMINAL_WRITE_QUEUE_CAP,
  TerminalWritePump,
} from "./terminal-write-pump.js";

const writes: Uint8Array[] = [];
const completions: Array<() => void> = [];
let overloads = 0;
const pump = new TerminalWritePump(
  (data, complete) => {
    writes.push(data);
    completions.push(complete);
  },
  () => { overloads += 1; },
);

// Model an IRC art burst arriving in normal 8 KiB PTY chunks while xterm is
// still parsing the first chunk. The client must retain at most the explicit
// live-render bound and request exactly one authoritative resynchronization.
const chunk = new Uint8Array(8 * 1024).fill(0x23);
assert.equal(pump.enqueue(chunk), true);
assert.equal(writes.length, 1, "only one xterm write may be in flight");
for (let bytes = 0; bytes < TERMINAL_WRITE_QUEUE_CAP; bytes += chunk.length) {
  assert.equal(pump.enqueue(chunk), true);
}
assert.equal(pump.pendingLiveBytes, TERMINAL_WRITE_QUEUE_CAP);
assert.equal(pump.enqueue(chunk), false);
assert.equal(overloads, 1);
assert.equal(pump.pendingLiveBytes, 0, "obsolete queued art is discarded");
for (let bytes = 0; bytes < 4 * 1024 * 1024; bytes += chunk.length) {
  assert.equal(pump.enqueue(chunk), false);
}
assert.equal(overloads, 1, "one burst cannot create a reattach storm");

// A fresh snapshot waits for the old parser call, resets presentation exactly
// at the write boundary, then reopens the bounded live path.
const events: string[] = [];
const snapshot = Uint8Array.of(0x1b, 0x5b, 0x48);
pump.replace(
  snapshot,
  () => events.push("reset"),
  () => events.push("rendered"),
);
assert.deepEqual(events, []);
completions.shift()!();
assert.deepEqual(events, ["reset"]);
assert.equal(writes.at(-1), snapshot);
completions.shift()!();
assert.deepEqual(events, ["reset", "rendered"]);
assert.equal(pump.enqueue(chunk), true);

assert.throws(
  () => new TerminalWritePump(() => {}, () => {}, 0),
  RangeError,
);

console.log("terminal write-pump tests passed");
