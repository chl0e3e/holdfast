import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { stripBidiIsolates, TerminalOutputFilter } from "./terminal-output.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const title = "[YouTube] \u2068Donny Ben\u00e9t\u2069 | Channel: \u2066example\u2069";
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

const malformed = new TerminalOutputFilter();
assert.deepEqual(malformed.filter(new Uint8Array([0xe2])), new Uint8Array());
assert.deepEqual(
  malformed.filter(new Uint8Array([0x81, 0x41])),
  new Uint8Array([0xe2, 0x81, 0x41]),
  "a false UTF-8 prefix is preserved byte-for-byte",
);
malformed.filter(new Uint8Array([0xe2]));
malformed.reset();
assert.deepEqual(malformed.filter(new Uint8Array([0x42])), new Uint8Array([0x42]));

const webCopy = fileURLToPath(new URL("./terminal-output.ts", import.meta.url));
const desktopCopy = fileURLToPath(
  new URL("../../../desktop/src/terminal-output.ts", import.meta.url),
);
assert.equal(
  readFileSync(webCopy, "utf8"),
  readFileSync(desktopCopy, "utf8"),
  "web and desktop terminal output filters must remain byte-identical",
);

console.log("terminal output tests passed");
