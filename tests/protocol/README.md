# Protocol verification

The normative wire format is `protocol/messages.proto` plus
`protocol/specification.md`. Rust framing and negotiation live in
`crates/protocol`; transport adapters must carry those envelopes rather than
serializing their own Rust types.

Coverage includes:

- four-byte bounded frame lengths and rejection before payload allocation;
- protobuf decoding, malformed/truncated input, and negotiated ceilings;
- version, capability, encoding, and datagram negotiation;
- deterministic parser fuzz cases in both the protocol and daemon; and
- Rust ↔ TypeScript protobuf generation interoperability.

Run the protocol checks with:

```bash
cargo test -p hf-protocol
cargo test -p hf-daemon --test fuzz_wire
spikes/encoding-spike/run-interop.sh
cd web && npm run proto:generate && npx tsc --noEmit
```

Any wire change must update `protocol/messages.proto` and
`protocol/specification.md` together, regenerate `web/src/gen/messages_pb.ts`,
and keep the commands above green.
