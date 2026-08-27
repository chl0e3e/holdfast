import assert from "node:assert/strict";
import { TerminalInputQueue } from "./terminal-input-queue.js";

const sent: number[] = [];
const releases: Array<() => void> = [];
const queue = new TerminalInputQueue(
  (data) => new Promise<void>((resolve) => {
    sent.push(data[0]!);
    releases.push(resolve);
  }),
  (error) => assert.fail(`unexpected send error: ${error}`),
  4,
  4,
);

assert.equal(queue.enqueue(Uint8Array.of(1)), true);
assert.equal(queue.enqueue(Uint8Array.of(2)), true);
assert.deepEqual(sent, [], "input starts paused until attachment is live");
queue.resume();
assert.deepEqual(sent, [1]);
assert.equal(queue.pendingChunks, 2, "in-flight input remains accounted");

queue.pause();
releases.shift()!();
await new Promise((resolve) => setTimeout(resolve, 0));
assert.deepEqual(sent, [1], "pause prevents the next item overtaking detach");
assert.equal(queue.pendingChunks, 1);

queue.resume();
assert.deepEqual(sent, [1, 2]);
releases.shift()!();
await new Promise((resolve) => setTimeout(resolve, 0));
assert.equal(queue.pendingChunks, 0);

const bounded = new TerminalInputQueue(async () => {}, () => {}, 2, 2);
assert.equal(bounded.enqueue(Uint8Array.of(1, 2)), true);
assert.equal(bounded.enqueue(Uint8Array.of(3)), false, "byte overflow is explicit");
assert.throws(() => new TerminalInputQueue(async () => {}, () => {}, 0), RangeError);

let rejectSend = true;
let failures = 0;
const retrying = new TerminalInputQueue(
  async () => {
    if (rejectSend) throw new Error("attachment rotated");
  },
  () => { failures += 1; },
);
assert.equal(retrying.enqueue(Uint8Array.of(9)), true);
retrying.resume();
await new Promise((resolve) => setTimeout(resolve, 0));
assert.equal(failures, 1);
assert.equal(retrying.pendingChunks, 1, "a rejected invoke retains the input for reattach");
rejectSend = false;
retrying.resume();
await new Promise((resolve) => setTimeout(resolve, 0));
assert.equal(retrying.pendingChunks, 0);

console.log("terminal input-queue tests passed");
