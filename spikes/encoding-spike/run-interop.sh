#!/usr/bin/env bash
# Phase 0 encoding interop check: Rust (prost) -> TypeScript (@bufbuild) -> Rust.
#
#   spikes/encoding-spike/run-interop.sh
#
# Prerequisites: `npm install` and `npx buf generate ../protocol` in web/.
set -euo pipefail
cd "$(dirname "$0")/../.."

cargo run -q -p spike-encoding -- encode target/encoding-spike/rust-envelope.bin
(cd web && npx tsx src/spike/encoding-spike.ts \
    ../target/encoding-spike/rust-envelope.bin \
    ../target/encoding-spike/ts-envelope.bin)
cargo run -q -p spike-encoding -- verify target/encoding-spike/ts-envelope.bin

echo "encoding interop OK: prost -> @bufbuild/protobuf -> prost round-trip"
