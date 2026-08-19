import assert from "node:assert/strict";
import { attachAfterFirstPayload } from "./attachment-order.js";

type Deferred<T> = {
  promise: Promise<T>;
  resolve(value: T): void;
};

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

// Regression: Tauri may resolve the command before delivering the snapshot
// Channel event. An empty snapshot is still a real first payload and must
// release the gate only after the consumer has seen it.
{
  const reply = deferred<string>();
  let deliver!: (payload: Uint8Array) => void;
  const events: string[] = [];
  const complete = attachAfterFirstPayload(
    (receive) => {
      deliver = receive;
      return reply.promise;
    },
    (payload) => events.push(`snapshot:${payload.length}`),
  ).then((value) => {
    events.push(`complete:${value}`);
    return value;
  });

  reply.resolve("attached");
  await Promise.resolve();
  assert.deepEqual(events, [], "invoke reply alone must not complete attach");
  deliver(new Uint8Array());
  assert.equal(await complete, "attached");
  assert.deepEqual(events, ["snapshot:0", "complete:attached"]);
}

// The usual channel-first ordering remains supported: completion still waits
// for the command metadata reply.
{
  const reply = deferred<number>();
  let deliver!: (payload: Uint8Array) => void;
  let completed = false;
  const complete = attachAfterFirstPayload(
    (receive) => {
      deliver = receive;
      return reply.promise;
    },
    () => {},
  ).then((value) => {
    completed = true;
    return value;
  });

  deliver(Uint8Array.of(1, 2, 3));
  await Promise.resolve();
  assert.equal(completed, false);
  reply.resolve(7);
  assert.equal(await complete, 7);
}

console.log("attachment ordering tests passed");
