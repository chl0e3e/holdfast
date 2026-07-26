import assert from "node:assert/strict";

import { webTransportCertificateOptions } from "./transport.js";

assert.equal(
  webTransportCertificateOptions(null),
  undefined,
  "configured public certificates must use browser WebPKI",
);

const hash = Buffer.alloc(32, 0x5a).toString("base64");
const pinned = webTransportCertificateOptions(hash);
assert.equal(pinned?.serverCertificateHashes?.length, 1);
assert.equal(pinned?.serverCertificateHashes?.[0]?.algorithm, "sha-256");
assert.deepEqual(
  new Uint8Array(pinned?.serverCertificateHashes?.[0]?.value as ArrayBuffer),
  new Uint8Array(32).fill(0x5a),
);

console.log("transport certificate modes: all assertions passed");
