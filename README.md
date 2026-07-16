# Holdfast

**Your sessions hold fast while you roam.**

Holdfast is a Mosh-inspired roaming remote-terminal protocol and daemon built on
QUIC/WebTransport, with persistent server-side scrollback, session resumption,
and multiple simultaneous shells per connection.

The core product is a **standalone daemon** (`holdfastd`) you install on any
server, exactly like `mosh-server`:

- Browser clients connect directly over WebTransport (WebSocket fallback) and
  log in against the daemon itself — no central infrastructure required.
- Native clients connect over raw QUIC.
- Authentication is local-first (SSH `authorized_keys` challenge/response), via
  a pluggable connection-grant issuer.
- The daemon serves its own small browser client page, so any server is
  reachable from a browser on its own.

Multi-server administration (inventory, access policies, central login, an
agentless SSH gateway) is a **separate follow-on overlay project** that reuses
this protocol; `holdfastd` will gain an outbound mTLS "agent mode" for it. The
`gateway`, `control-plane`, `ssh-backend` and `agent` crates in this workspace
are reserved for that overlay and are not part of the core deliverable. The
overlay's full design lives in
`/home/development/src/admin/holdfast-overlay-plan.md`.

Design source of truth: `/home/development/src/admin/quic-terminal-plan.md`
(project handoff, 2026-07-16, plus its addendum recording the core-first split
and naming). Protocol details: `protocol/specification.md`. Security analysis:
`protocol/threat-model.md`. Decisions: `docs/decisions/`.

## Status

**Phase 7 — authentication & hardening: in progress (2026-07-16).**

- `hf-auth` — the local SSH-key issuer and connection grants (ADR 0006):
  SSH public-key challenge/response against `authorized_keys` (SshSig,
  `ssh-keygen -Y sign` compatible, any ed25519/RSA/ECDSA key) and ed25519
  connection grants (audience-bound, expiring, verify-key split).
- `holdfastd` supports real auth (`--ssh-auth <user> <authorized_keys>`) with
  per-source-address rate limiting and lockout, plus an Origin allowlist
  (`--allowed-origin`) for browser endpoints, alongside the retained
  loopback-only dev mode.
- `hf` signs SSH challenges with an OpenSSH key (`hf --user alice --key
  ~/.ssh/id_ed25519 open`) and reuses the issued grant for later reconnects.
- Hardening in place: parser fuzz/robustness harnesses, Origin allowlist, a
  cargo-audit/npm-audit CI gate, browser terminal-escape/clipboard defenses
  (title sanitization, paste-injection guard incl. Trojan-Source bidi/
  zero-width/line-separator characters, inert OSC-52/OSC-8 —
  `web/src/client/terminal-safety.ts`, run `cd web && npm test`), a hostile
  server-side escape/fuzz/resize corpus that also fixed an `avt` 0/1-column
  resize DoS (`crates/terminal-model/tests/hostile.rs`), the netem
  adverse-network suite over real QUIC (`tests/packet-loss/run.sh` — latency/
  jitter/loss/reorder masking plus blackhole-then-resume), Unix account
  authorization (per-user allowlist enforced on shell open, ADR 0007), the
  uid/gid-drop *mechanism* — shells launch under their resolved account via
  `setpriv` (`--drop-privileges` + `--account`, off by default;
  `session-core/src/launch.rs`), verified over a PTY in
  `crates/session-core/tests/privilege_drop.rs` (run `tests/authorization/run.sh`),
  with production `deploy/systemd/` units running the daemon unprivileged
  (ambient `CAP_SETUID`/`CAP_SETGID`, capabilities cleared before the shell),
  and per-user shell isolation (list/terminate/idempotency scoped to the owner).
  A security review has been run; its high-severity findings (per-user
  isolation, `authorized_keys` options fail-closed) are fixed. Still open before
  non-loopback use: the deferred medium findings (rate-limiter map eviction,
  SSH-challenge channel binding, grant `ops` enforcement, per-user shell quota)
  and a multi-user soak. See ADR 0006/0007 and `protocol/threat-model.md`.

**Phase 5 — native client: complete (2026-07-16).** (Phase 4 moved to the
admin-overlay project per the plan addendum.)

- `hf` (crates/native-client) — native terminal client over the same
  WebTransport endpoint: `hf list`, `hf open [command]`,
  `hf attach <id-prefix>`, `hf terminate <id-prefix>`. Interactive sessions
  run in your real terminal (raw mode with restore guard, SIGWINCH resize),
  **Ctrl-]** detaches, and lost connections resume automatically with the
  rotated token. Tokens persist in `~/.config/holdfast/state.json` (0600).
- Exit criterion (list/open/attach/detach + network-transition resume) is
  automated in `crates/native-client/tests/client.rs` over real QUIC.

```bash
cargo run -p hf-daemon -- --web-root web/dist    # terminal 1
cargo run -p hf-native-client -- open            # terminal 2 (or: hf open)
```

**Phase 3 — QUIC and WebTransport: complete (2026-07-16).**

- `holdfastd` now terminates **WebTransport over QUIC** (UDP) alongside the
  WebSocket fallback — identical protocol semantics; every bidirectional
  stream is a channel (ADR 0005). Dev certs are self-signed (14 days) and
  pinned by the browser via `/webtransport-info`; production uses ACME on a
  DNS-only hostname with the daemon owning UDP 443 (nginx keeps TCP 443).
- Browser client tries WebTransport first (3 s timeout) and falls back to
  WebSocket, with the active transport shown in the status bar.
- Tested over real QUIC: full shell cycle, **address-change resume** (new
  client UDP endpoint, rotated token, retained history — the Phase 3 exit
  criterion's resume clause), and cross-transport reattach (open over
  WebTransport, reattach over WebSocket). Adverse-network (netem) tests are
  deferred to Phase 7 — see `tests/packet-loss/README.md`.
- Screen datagrams remain deferred per spec §7 (reliable output baseline).

**Phase 2 — browser proof of concept: complete (2026-07-16).**

- `hf-daemon` / `holdfastd` — WebSocket transport (spec §2 mapping: varint
  channel + one frame per binary message), control channel (hello, dev auth,
  list, open, terminate, ping), attachment channels, static client serving,
  detach-on-disconnect. Dev auth refuses non-loopback binds.
- `web/` — xterm.js client: shells as tabs, reload recovery via persisted
  shell IDs + rotated resume tokens (localStorage), reconnect with backoff,
  detach vs terminate buttons, lazy history paging on scroll-to-top.

Run it locally:

```bash
cd web && npm install && npm run build && cd ..
cargo run -p hf-daemon -- --bind 127.0.0.1:8080 --web-root web/dist
# open http://127.0.0.1:8080 — open two shells, run commands, reload the page
```

The Phase 2 exit criterion (browser reload reattaches two still-running
shells with correct screen + scrollback) is automated over a real WebSocket in
`crates/daemon/tests/ws.rs`; the manual browser walkthrough above demonstrates
the same flow interactively.

**Phase 1 — protocol and PTY core: complete (2026-07-16).**

- `hf-protocol` — full v0 message catalogue in `protocol/messages.proto`,
  length-prefixed framing that rejects oversized frames before allocation,
  version/capability negotiation, opaque 128-bit IDs.
- `hf-pty` — PTY spawn/resize/write, output channel, idempotent clean kill.
- `hf-terminal-model` — avt-backed VT state (ADR 0004), screen revisions,
  attach snapshots via redraw sequences, bounded scrollback ring with stable
  history line IDs, incremental UTF-8 decoding, alt-screen isolation.
- `hf-session-core` — shell/attachment lifecycle: idempotent open, rotating
  hash-stored resume tokens, bounded per-attachment fan-out (slow consumers
  are detached, never block the shell), detach ≠ terminate, exit observation.

Phase 1 exit criterion is covered by
`crates/session-core/tests/lifecycle.rs::create_detach_reattach_terminate_with_retained_scrollback`.

Verify everything: `cargo test --workspace` (52 tests) plus
`./spikes/encoding-spike/run-interop.sh` and `cd web && npx tsc --noEmit`.

Phase 0 spikes remain under `spikes/` (throwaway reference code — never
imported by production crates). Still pending from Phase 0: a manual
real-browser run of `spikes/webtransport-echo/browser-echo.html`.

Next: **Phase 2 — browser proof of concept** (xterm.js over WebSocket,
reconnection after reload, two shells as tabs, lazy history fetch).

## Layout

```
crates/          Rust workspace (hf-* crates; hf-daemon builds holdfastd)
web/             TypeScript/xterm.js browser client
protocol/        Protocol specification, threat model, message schemas
spikes/          Phase 0 disposable proof-of-concept code
deploy/          systemd units, nginx snippets, example config (later phases)
tests/           Cross-cutting integration test areas (later phases)
docs/decisions/  Architecture decision records
```

## Building

```bash
cargo build --workspace
cargo test --workspace
```

Requires Rust stable (1.85+; developed with 1.97). No system `protoc` needed —
protobuf compilation uses the pure-Rust `protox`.

## Hard rules

- Never place terminal daemons, credentials or shell-launching logic in WordPress
  or anything under `/home/development/sites/mod.uk`.
- The admin overlay must not leak into the core: `holdfastd` must remain fully
  functional with zero central infrastructure.
- Control plane must not parse terminal bytes; PTY/terminal-model crates must not
  import HTTP or QUIC implementations.
- Every queue and history buffer is bounded. Security and resource limits are core
  requirements, not polish.
