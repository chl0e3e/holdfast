import assert from "node:assert/strict";
import {
  composeBoundedReplay,
  prependBoundedHistory,
  viewportFromBottom,
} from "./terminal-render-state.js";

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

assert.equal(viewportFromBottom(140, 100), 40);
assert.equal(viewportFromBottom(20, 100), 0);

console.log("terminal render-state tests passed");
