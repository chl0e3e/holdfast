# ADR 0003: Phase 0 dependency choices and exit-criteria status

Date: 2026-07-16 · Status: accepted (spike-verified where noted)

Maintenance data below was checked on crates.io on 2026-07-16.

## QUIC / WebTransport: `wtransport` 0.7 (on `quinn` 0.11)

- quinn 0.11.11 (updated 2026-06, 228M downloads) is the de facto Rust QUIC
  implementation: connection migration, streams, datagrams, rustls TLS.
- wtransport 0.7.1 (updated 2026-04) layers browser-interoperable WebTransport
  over quinn and exposes both server and client, including
  `serverCertificateHashes`-style pinning.
- Rejected: `h3`/`h3-webtransport` (0.0.x, last release 2025-05, too immature);
  `quiche` (C-ish FFI surface, no WebTransport server story we'd own less code
  with); `s2n-quic` (no WebTransport layer).
- **Spike-verified:** `cargo test -p spike-webtransport-echo` — echo over real
  QUIC/UDP on loopback, bidirectional stream + datagrams, self-signed cert
  pinned by SHA-256 hash. Native-QUIC-only paths can use quinn directly later
  since wtransport re-exports the same stack.
- Open (needs a machine with a browser): manual verification against Chrome and
  Firefox using `spikes/webtransport-echo/browser-echo.html`; Safari fallback
  behavior is a product requirement, not a spike goal.

## Async runtime: `tokio` 1.x

Required by wtransport/quinn integration and overwhelmingly the ecosystem
default. No alternative evaluated further.

## PTY: `portable-pty` 0.9

- Wezterm's PTY layer: openpty, child spawn, resize, kill, reader/writer
  handles. 8.8M downloads; maintained as part of wezterm.
- Rejected for now: raw `nix`/`rustix-openpty` (more control, more unsafe code
  to own); revisit only if portable-pty blocks privilege separation in agent
  mode (Phase 6 of the original plan / overlay project).
- **Spike-verified:** `cargo test -p spike-pty` — interactive command output,
  resize propagated to the child (`stty size` reports the new dimensions),
  graceful exit reaped with status 0, kill leaves no zombie.

## Wire encoding: Protocol Buffers (`prost` + `protox` / `@bufbuild/protobuf`)

- Rust: prost 0.14 with protox 0.9 compiling `.proto` at build time in pure
  Rust — no system protoc anywhere in the toolchain.
- TypeScript: @bufbuild/protobuf v2 with protoc-gen-es via `buf generate`
  (`web/buf.gen.yaml`).
- **Spike-verified:** `spikes/encoding-spike/run-interop.sh` — a reference
  `Envelope{ClientHello}` (unicode strings, enums, repeated fields, bytes,
  u64 request id) encodes in prost, decodes and re-encodes in TypeScript, and
  decodes back in prost equal to the reference.
- Decision: protobuf is the version-zero wire encoding (open question #2 of the
  plan: resolved). JSON spike deemed unnecessary given the interop test passed
  on the first round trip.

## Terminal model (open question #3 — deferred to Phase 1)

Candidates surveyed, all alive as of 2026-07: `alacritty_terminal` 0.26
(2026-04), `avt` 0.18 (asciinema, 2026-05, built exactly for headless VT +
scrollback), `vt100` 0.16 (2025-07). Decision needs a Phase 1 spike measuring
scrollback/alternate-screen semantics against spec §10; `avt` looks closest to
our server-side use case on paper.

## WebSocket fallback (Phase 2)

`tokio-tungstenite` 0.30 / `axum` 0.8 both current; final pick when the
fallback lands. Not spiked — mature, low-risk.

## Phase 0 exit criteria status

| Criterion | Status |
|---|---|
| Cargo workspace + browser package, mod.uk untouched | done |
| protocol/specification.md before exposing a shell | done (v0 draft) |
| protocol/threat-model.md outline | done (T1–T12; needs pre-beta review) |
| Working secure WebTransport echo | done in Rust client + server; **manual browser run still pending** (no browser on the dev box) |
| Certificate/UDP reachability check from a real browser/network | **pending** — same manual session as above; terminal.asylum.st DNS + ACME cert is a deploy-time task |
| PTY spike with clean termination | done |
| Version-zero encoding decision measured, not guessed | done (protobuf; interop test) |

## Toolchain notes

- Rust stable 1.97 installed via rustup (minimal profile) on 2026-07-16; the
  machine previously had no Rust toolchain.
- Node v24.16 / npm 11.13 already present (plan said 20.19; newer is fine).
- Lockfiles (`Cargo.lock`, `web/package-lock.json`) are committed; add
  `cargo audit` + `npm audit` to CI when CI exists (threat model T11).
