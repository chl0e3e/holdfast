import assert from "node:assert/strict";
import { stripBidiIsolates, TerminalOutputFilter } from "./terminal-output.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const title = "[YouTube] \u2068Donny Ben\u00e9t\u2069 | Channel: \u2067example\u2069";
const expected = "[YouTube] Donny Ben\u00e9t | Channel: example";

assert.equal(stripBidiIsolates(title), expected);

const bytes = encoder.encode(title);
for (let split = 0; split <= bytes.length; split += 1) {
  const filter = new TerminalOutputFilter();
  const first = filter.filter(bytes.slice(0, split));
  const second = filter.filter(bytes.slice(split));
  const combined = new Uint8Array(first.length + second.length);
  combined.set(first);
  combined.set(second, first.length);
  assert.equal(decoder.decode(combined), expected, `split at byte ${split}`);
}

const bytewise = new TerminalOutputFilter();
const pieces = [...bytes].map((byte) => bytewise.filter(new Uint8Array([byte])));
assert.equal(decoder.decode(Buffer.concat(pieces)), expected);

console.log("terminal output tests passed");
