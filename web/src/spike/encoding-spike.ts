// Phase 0 encoding spike, TypeScript half.
//
// Reads the envelope encoded by the Rust binary, checks every field survived,
// then re-encodes it for the Rust side to verify. Run via run-interop.sh.

import { readFileSync, writeFileSync } from "node:fs";
import assert from "node:assert/strict";
import { fromBinary, toBinary } from "@bufbuild/protobuf";
import {
  Capability,
  ClientKind,
  Encoding,
  EnvelopeSchema,
} from "../gen/messages_pb.js";

const inPath = process.argv[2] ?? "../target/encoding-spike/rust-envelope.bin";
const outPath = process.argv[3] ?? "../target/encoding-spike/ts-envelope.bin";

const envelope = fromBinary(EnvelopeSchema, readFileSync(inPath));

assert.equal(envelope.requestId, 7n);
assert.deepEqual(Array.from(envelope.serverId), Array.from(new Uint8Array(16).fill(0xab)));
assert.equal(envelope.shellId.length, 0);
if (envelope.message.case !== "clientHello") {
  throw new Error(`expected clientHello, got ${envelope.message.case}`);
}
const hello = envelope.message.value;
assert.equal(hello.protocolMajor, 0);
assert.equal(hello.protocolMinor, 1);
assert.equal(hello.clientKind, ClientKind.NATIVE_QUIC);
assert.equal(hello.clientBuild, "holdfast-encoding-spike ünïcode 🦀");
assert.deepEqual(hello.capabilities, [Capability.DATAGRAMS, Capability.CLIPBOARD]);
assert.equal(hello.maxFrameBytes, 256 * 1024);
assert.equal(hello.maxDatagramBytes, 1200);
assert.deepEqual(hello.encodings, [Encoding.UTF8]);

writeFileSync(outPath, toBinary(EnvelopeSchema, envelope));
console.log(`ts: decoded ${inPath}, all fields match; re-encoded -> ${outPath}`);
