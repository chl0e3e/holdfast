# Holdfast

**Your sessions hold fast while you roam.**

Holdfast is a Mosh-inspired roaming remote-terminal protocol and daemon built on
QUIC/WebTransport, with persistent server-side scrollback, session resumption,
and multiple simultaneous shells per connection.

The core product is a **standalone daemon** (`holdfastd`) you install on any
server, exactly like `mosh-server`:

- Browser clients connect directly over WebTransport — HTTP/3 only, no TCP
  fallback (ADR 0014) — and log in against the daemon itself; no central
  infrastructure required.
- Native clients connect over the same QUIC/WebTransport endpoint (ADR 0005;
  a distinct raw-QUIC ALPN remains deferred until it adds a real capability).
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

**HTTP/3-only migration: complete (2026-07-19, ADR 0014).**

The QUIC endpoint is now a real HTTP/3 server (hyperium `h3` replacing the
`wtransport` server): the same UDP endpoint serves the browser client page
over plain HTTP/3 GET *and* terminates WebTransport terminal sessions. There
is **no fallback transport**: the browser client is WebTransport-only, and
with an operator certificate the TCP listener serves only a "QUIC required /
loading" interstitial that advertises `Alt-Svc: h3` — the app itself is never
served over TCP in production. In development (hash-pinned self-signed cert)
the TCP side still serves the page, because browsers only Alt-Svc-upgrade
WebPKI origins; terminal traffic is QUIC either way. The legacy WebSocket
endpoint survives only behind a test-only config gate (default off, no CLI
flag) so the protocol suite can keep proving transport-neutral session
semantics; the Origin allowlist (T7) is now enforced on the WebTransport
CONNECT request. Earlier phase notes below that mention a "WebSocket
fallback" describe superseded behavior.

Reproduce: `cargo test -p hf-daemon --test http3_page` (page over HTTP/3,
Alt-Svc + interstitial, dev parity), plus the whole existing real-QUIC suite
which now runs against the h3 server.

**Phase 6 — agent-based managed servers: complete (2026-07-18).**

The registration and local shell-open slices are complete: `hf-agent`
establishes an outbound raw-QUIC link using the dedicated `holdfast-agent/0`
ALPN and mutual TLS;
`hf-gateway` validates the agent CA, maps the presented leaf fingerprint to
exactly one stable `server_id`, and accepts only a matching bounded protobuf
registration. The registry has hard certificate/active-agent capacities and
supports bounded old+next certificate overlap for rotation (ADR 0010). Real
loopback QUIC tests cover trusted registration, wrong-ID rejection, an
untrusted CA, rotation overlap, and reconnect under the unchanged identity.
The feature-gated `holdfastd --agent` runtime is outbound-only and shares one
local `ShellManager` across reconnects. Gateway shell-open requests are checked
against a centrally signed, audience/server/operation/subject-scoped grant and
then by the same local `AccessPolicy`, resource limits, and privileged launcher
as standalone mode. A real-QUIC test rejects a forged grant and unauthorized
account, launches an authorized PTY, forces gateway loss, and recovers the same
still-running shell by its idempotency key (ADR 0011).
The final agent-backend slice uses one separately bounded gateway-opened QUIC
stream per temporary attachment. It independently verifies an `attach`-scoped
central grant and local shell ownership, then carries reliable input/output,
resize, detach, exit and paged history. Fixed limits cover frames, concurrent
streams, QUIC flow-control windows, input frames, the output bridge and history
pages. The real-QUIC test rejects forged and cross-user attachments, exercises
a real PTY and resize, detaches, forces gateway reconnect, and retrieves the
same retained history from the still-running shell (ADR 0012).

This satisfies the core Phase 6 exit criterion. The default daemon build does
not import or depend on the optional agent crate, and standalone operation is
unchanged. The separate administration overlay still needs its client-facing
gateway/control plane and agentless SSH backend.

Phase 6 reproduction commands:

```bash
cargo test -p hf-protocol
cargo test -p hf-gateway
cargo test -p hf-agent
cargo test -p hf-daemon --features agent-mode --test agent_mode
```

**Phase 7 — authentication & hardening: complete (2026-07-18).**

- `hf-auth` — the local SSH-key issuer and connection grants (ADR 0006):
  SSH public-key challenge/response against `authorized_keys` (SshSig,
  `ssh-keygen -Y sign` compatible, any ed25519/RSA/ECDSA key) and ed25519
  connection grants (audience-bound, expiring, verify-key split).
- `holdfastd` supports real auth (`--ssh-auth <user> <authorized_keys>`) with
  per-source-address rate limiting and lockout, plus an Origin allowlist
  (`--allowed-origin`) for browser endpoints, alongside the retained
  loopback-only dev mode. Opt-in password login for allowlisted users
  (`--password-auth <user>`, PAM via the shared `hf-auth` verifier; ADR 0016,
  threat model T13) gives the web client a username/password form that yields
  the same connection grant as the SSH flow — see `deploy/pam/README.md` for
  the PAM stack and the shadow-access note for multi-user daemons.
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
  A security review has been run and its backlog cleared: per-user isolation,
  `authorized_keys` options fail-closed, rate-limiter map eviction, grant `ops`
  enforcement, per-user shell quota, restart-surviving grant key, and
  negotiated-frame-size compliance, and a per-connection WebTransport stream cap
  are all fixed and tested. SSH-challenge channel binding is implemented for
  WebTransport (signature bound to the pinned server cert hash — ADR 0008),
  defeating relay/MITM there; the nginx-fronted WebSocket path relies on the
  operator's TLS/PKI. Shell attachment is now owner-scoped in addition to
  requiring the rotating resume token, so possession of another user's valid
  token cannot cross the authorization boundary. A bounded typed audit ring and
  fixed-label operational counters cover authentication and shell lifecycle
  events without accepting terminal bytes, commands, grants, signatures, or
  resume tokens (`crates/daemon/src/observability.rs`). Shell resource
  containment is enforced too: `prlimit` installs hard per-account/process
  ceilings before exec, and the reference systemd units cap aggregate PIDs and
  memory (ADR 0009). A broader real multi-user soak remains an operational gate
  before wide deployment, not unfinished mechanism. See ADR 0006–0009 and
  `protocol/threat-model.md`.

Phase 7 reproduction commands:

```bash
cargo test -p hf-session-core
cargo test -p hf-daemon
tests/packet-loss/run.sh
tests/authorization/run.sh  # real uid switch needs root + a secondary account
cd web && npm test
```

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
  pinned by the browser via `/webtransport-info`; production loads a bounded
  public PEM chain/key with `--wt-cert`/`--wt-key` and uses browser WebPKI on a
  DNS-only hostname. Non-loopback self-signed WebTransport fails closed. The
  daemon owns UDP 443 while nginx may keep TCP 443.
- Browser client tries WebTransport first (3 s timeout); the WebSocket
  fallback described here was removed by ADR 0014 — the client is now
  QUIC-only and says so when WebTransport is unreachable.
- Tested over real QUIC: full shell cycle, **address-change resume** (new
  client UDP endpoint, rotated token, retained history — the Phase 3 exit
  criterion's resume clause), and cross-transport reattach (open over
  WebTransport, reattach over WebSocket). Phase 7 added the complete
  adverse-network netem suite — see `tests/packet-loss/README.md`.
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

Verify everything: `cargo test --workspace` plus
`./spikes/encoding-spike/run-interop.sh` and `cd web && npx tsc --noEmit`.

Phase 0 spikes remain under `spikes/` (throwaway reference code — never
imported by production crates). Still pending from Phase 0: a manual
real-browser run of `spikes/webtransport-echo/browser-echo.html`; configured
certificate negotiation is automated separately in
`crates/daemon/tests/webtransport_tls.rs`.

**Phase 8 — optional SSH compatibility adapter: complete (2026-07-18).**

`hf-ssh-adapter` terminates a minimal public-key-authenticated SSH server on a
loopback TCP address and maps one interactive PTY shell channel to a Holdfast
shell attachment (ADR 0013). It deliberately rejects exec, SFTP/subsystems,
environment injection, forwarding, X11 and agent forwarding. An opt-in
`--password-auth` mode verifies the local user's Unix password through PAM
(auth + account checks only, adapter-scoped; ADR 0015, threat model T13) —
the default, the daemon and the issuer remain key-only. The real OpenSSH
test covers interactive output, unauthorized keys and rejected remote exec:
`cargo test -p hf-ssh-adapter --test openssh -- --nocapture`; password
negotiation, gating and the password-authenticated shell are covered in
`crates/ssh-adapter/tests/password.rs`, with the real shadow/pam_unix round
trip under `tests/password-auth/run.sh`. Setup and exact manual reproduction
commands are in `crates/ssh-adapter/README.md`.

All core implementation phases are complete. The multi-server control plane,
client-facing gateway and agentless SSH backend remain a separate overlay
project; the manual real-browser Phase 0 echo check and a broader multi-user
soak are still deployment gates before wide production use.

**Desktop client (2026-07-25, ADRs 0017–0020).** A multi-session,
multi-server tabbed client (Tauri 2 + xterm.js, Windows-first) built on the
new GUI-free `hf-client-core` crate: shells survive client disconnects and
client-machine restarts via persisted grants, rotating resume tokens with
idempotency-key recovery, and reattach-all on launch. Groundwork landed
with it: stable standalone server identity (grants survive daemon restarts,
ADR 0017), `ERR_TOKEN_REPLAYED` detection with audit event, a typed
client-side retry policy that never drops a resume token on transient
failures (ADR 0018), and client keepalive (ADR 0020). See
`desktop/README.md`; the Tauri layer builds on Windows/CI (this repo's
Linux container lacks a webview toolchain).

Emoji and character pickers (2026-07-28): text inserted by a picker (Windows
`Win+.`, the browser's emoji menu) reaches the terminal in both clients.
xterm.js drops such an insertion when it has seen a keydown without a
matching keyup — exactly what the picker causes by taking focus mid-chord —
so both clients now forward what it declined, without double-sending ordinary
keystrokes. Pastes still go through the paste-confirmation guard.
Follow-up (2026-08-03): the first cut doubled every space — the one printable
key xterm.js handles in `keypress` (it claims keydown only for `keyCode >=
48`), so its leftover `input` event fired *after* onData and the per-input-
event reset wiped the "already handled" flag. The forwarder now resets on
keydown/keyup instead and consumes the flag per insertion; verified in real
Chromium (typed space sends exactly one, picker inserts still forwarded).

Zero-width characters sheared attach snapshots (2026-08-03, server /
holdfastd v0.0.2): the Unicode-11 width fix below left one class uncovered —
upstream avt 0.18 (the server-side terminal model) gives zero-width
characters (combining marks, ZWJ, VS16) a full cell, so each one advanced
the model's cursor a column no real terminal advances. Zalgo-style IRC
messages shifted every later wrap point in the model, and every subsequent
attach/reload replayed a sheared screen with interleaved stale rows (the
live view stayed correct: raw PTY bytes bypass the model). avt is now
vendored at `vendor/avt` (workspace `[patch.crates-io]`) with zero-width
characters attached to the preceding cell without cursor movement — matching
wcwidth and xterm.js — bounded at 3 retained marks per cell (T9); `dump()`
replays them and never emits REP across them. Reproduce: `cargo test -p
hf-terminal-model` (combining/VS16/ZWJ wrap parity + snapshot round-trips)
and `cargo test` in `vendor/avt` (upstream suite incl. dump round-trip
property tests). Known remaining gap: emoji added after Unicode 11 (e.g.
U+1FAE0) are 2 cells in the model but 1 in the clients' Unicode-11 table;
closing it needs a client width provider generated from unicode-width's
tables. Drop the vendored fork when upstream avt handles zero-width.

Unicode widths (2026-08-03, desktop v0.0.6 + web): xterm.js defaults to a
Unicode 6 width table where most emoji are one cell, but the server model
(avt/unicode-width) and the shell's wcwidth make them two — so any emoji on
screen shifted every wrap point when the attach snapshot was replayed,
garbling full-screen apps (reported as a mangled weechat after roaming).
Both clients now activate `@xterm/addon-unicode11`; wrap parity with the
server model is asserted in a headless-Chromium check (10+2 wrapped wide
glyphs on a 20-column row).

WebView2 drops raw Tauri IPC (2026-08-03, desktop v0.0.5): on Windows the
desktop terminal rendered black and swallowed every keystroke — WebView2
delivers a raw `invoke` body as JSON (each keystroke died with "requires a
raw body") and never delivers raw `Channel` payloads (the attach snapshot
and live PTY bytes silently vanished). Both terminal byte paths are now
JSON-safe: input as a plain byte-array argument, output as base64 channel
strings. Diagnosed against a live daemon in the Windows VM rig with state
smuggled out through the store file; the Linux core path was never at fault
(`cargo run -p hf-client-core --example inputprobe` proves it end-to-end).
Panels also clip overflow now: xterm sizes its screen from rows×cellHeight,
and fractional-DPI rounding could spill past the panel, growing the page
under the terminal's own scrollbar.

Terminal font size (2026-08-03): both clients grew an adjustable font size —
`A−`/`A+` toolbar buttons or Ctrl+scroll over the terminal, persisted in
localStorage (8–40px, default 14). xterm.js draws emoji at cell size, so a
bigger font is also the only way to make them readable.

Password login (ADR 0016 addendum, 2026-07-27): a server record with a
username and no key path authenticates by password, prompted on connect and
never persisted — only the issued grant is stored. Two launch bugs found by
running the built exe on Windows are fixed in v0.0.2: a scheme-less URL in
the add-server form is now read as `https://` (previously it could never
connect, and failed as a *login* error), and the `auth-required` status is
carried in `bootstrap()` rather than only as an event, so a password server
prompts at launch instead of leaving every action refused with
"authentication required". Follow-up (2026-08-03): pressing Enter in the
password field activated the dialog's *Cancel* button — HTML implicit
submission fires the first submit button in tree order, and Cancel came
first — so the password was silently discarded and login only worked by
clicking the button. Cancel is now `type=button` in both the login and
add-server dialogs (the headless core path was re-verified end-to-end
against a live PAM daemon with `--example authprobe`); shipped in v0.0.4. Multi-server is genuinely concurrent — one
supervisor and one QUIC/HTTP3 connection per server; reproduce against your
own hosts with
`cargo run -p hf-client-core --example multiserver -- <url> <user> <key> ...`.

## Layout

```
crates/          Rust workspace (hf-* crates; hf-daemon builds holdfastd)
web/             TypeScript/xterm.js browser client
desktop/         Desktop client: Tauri 2 shell + xterm.js frontend (ADR 0019)
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
