import assert from "node:assert/strict";
import { TerminalInputQueue } from "./terminal-input-queue.js";

const queue = new TerminalInputQueue();
const sent: number[] = [];
assert.equal(queue.enqueue(Uint8Array.of(1)), true);
assert.equal(queue.enqueue(Uint8Array.of(2)), true);
assert.equal(sent.length, 0);
queue.resume((data) => {
  sent.push(data[0]!);
});
assert.deepEqual(sent, [1, 2], "reattach flushes input in original order");
assert.equal(queue.pendingBytes, 0);

queue.pause();
assert.equal(queue.enqueue(new Uint8Array(64 * 1024)), true);
assert.equal(queue.enqueue(Uint8Array.of(3)), false, "overflow is explicitly rejected");
queue.clear();

const retrying = new TerminalInputQueue();
assert.equal(retrying.enqueue(Uint8Array.of(9)), true);
retrying.resume(() => {
  throw new Error("attachment rotated");
});
assert.equal(retrying.pendingBytes, 1, "a failed send stays queued for reattach");
const retried: number[] = [];
retrying.resume((data) => {
  retried.push(data[0]!);
});
assert.deepEqual(retried, [9]);
assert.equal(retrying.pendingBytes, 0);

console.log("terminal input-queue tests passed");
