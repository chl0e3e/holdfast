import assert from "node:assert/strict";
import {
  attachmentAction,
  closeBehavior,
  detachedEventAction,
  emptyWorkspace,
  shouldAttachWhenConnected,
  uploadAction,
  quotePosixShellWord,
  type TabState,
} from "./ui-state.js";

for (const state of ["connecting", "reconnecting", "orphaned", "exited"] satisfies TabState[]) {
  assert.equal(attachmentAction(state, false).enabled, false, state);
}

assert.deepEqual(attachmentAction("live", false), {
  label: "Detach",
  enabled: true,
  title: "Detach while leaving the shell running",
});
assert.deepEqual(attachmentAction("detached", false), {
  label: "Attach",
  enabled: true,
  title: "Attach to the still-running shell",
});
assert.equal(attachmentAction("live", true).enabled, false);
assert.equal(attachmentAction("detached", true).enabled, false);
assert.equal(attachmentAction(null, false).enabled, false);

assert.equal(uploadAction("live", true, true, false).enabled, true);
assert.equal(uploadAction("detached", true, true, false).enabled, true);
assert.equal(uploadAction("reconnecting", true, true, false).enabled, false);
assert.equal(uploadAction("live", false, true, false).enabled, false);
assert.equal(uploadAction("live", true, false, false).enabled, false);
assert.deepEqual(uploadAction("reconnecting", false, false, true), {
  label: "Cancel upload",
  enabled: true,
  title: "Cancel the current upload",
});
assert.equal(quotePosixShellWord("/tmp/a b"), "'/tmp/a b'");
assert.equal(quotePosixShellWord("/tmp/a'b"), "'/tmp/a'\\''b'");

assert.equal(emptyWorkspace(false).action, "Add server");
assert.equal(emptyWorkspace(true).action, "Open shell");

assert.equal(detachedEventAction("live", true), "mark-detached");
assert.equal(detachedEventAction("live", false), "reattach");
assert.equal(detachedEventAction("detached", false), "ignore");
assert.equal(shouldAttachWhenConnected("reconnecting"), true);
assert.equal(shouldAttachWhenConnected("connecting"), true);
assert.equal(shouldAttachWhenConnected("detached"), false);

assert.deepEqual(closeBehavior("live"), { confirmRunning: true, detach: true, forget: false });
assert.deepEqual(closeBehavior("reconnecting"), { confirmRunning: true, detach: true, forget: false });
assert.deepEqual(closeBehavior("detached"), { confirmRunning: true, detach: false, forget: false });
assert.deepEqual(closeBehavior("exited"), { confirmRunning: false, detach: false, forget: true });
assert.deepEqual(closeBehavior("orphaned"), { confirmRunning: false, detach: false, forget: true });

console.log("ui-state tests passed");
