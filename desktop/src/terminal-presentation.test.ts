import assert from "node:assert/strict";
import { repaintVisibleTerminal } from "./terminal-presentation.js";

const calls: string[] = [];
const repainted = repaintVisibleTerminal(
  { active: true, closing: false, width: 1200, height: 700 },
  () => calls.push("fit"),
  () => {
    calls.push("rows");
    return 24;
  },
  (start, end) => calls.push(`refresh:${start}-${end}`),
);
assert.equal(repainted, true);
assert.deepEqual(calls, ["fit", "rows", "refresh:0-23"]);

for (const state of [
  { active: false, closing: false, width: 1200, height: 700 },
  { active: true, closing: true, width: 1200, height: 700 },
  { active: true, closing: false, width: 0, height: 700 },
  { active: true, closing: false, width: 1200, height: 0 },
]) {
  let fitted = false;
  assert.equal(
    repaintVisibleTerminal(state, () => { fitted = true; }, () => 24, () => {}),
    false,
  );
  assert.equal(fitted, false, "an unavailable panel is not measured or refreshed");
}

let refreshed = false;
assert.equal(
  repaintVisibleTerminal(
    { active: true, closing: false, width: 1200, height: 700 },
    () => {},
    () => 0,
    () => { refreshed = true; },
  ),
  false,
);
assert.equal(refreshed, false, "a terminal without measured rows is not refreshed");

console.log("terminal presentation tests passed");
