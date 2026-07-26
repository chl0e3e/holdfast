# ADR 0019: desktop client — Tauri 2 + xterm.js over a GUI-free Rust core

- Status: accepted
- Date: 2026-07-25
- Relates to ADRs 0017, 0018, 0020; threat model T1, T9
- Windows is the first shipping target

## Context

The goal is a multi-session, multi-server client — every shell a tab,
shells surviving client disconnects and client-machine restarts — starting
on Windows, where the unix-only `hf` CLI does not apply. The daemon and
protocol already support everything needed (per-shell attachment streams,
rotating resume tokens, snapshot + scrollback replay); the work is client
architecture.

## Decision

**Stack.** Tauri 2 with the platform webview (WebView2 on Windows) and
xterm.js for terminal rendering. The browser client
(`web/src/client/app.ts`) already solved tabs, reattach-all, render
composition and the T9 output-safety rules; the desktop frontend
(`desktop/src`) is a direct port. A pure-Rust GUI would have meant building
a terminal widget (fonts, selection, IME, scrollback UI) from scratch for
no protocol benefit.

**Layering.** All logic lives in a new workspace crate `hf-client-core`
(GUI-free, headless-tested against a real in-process daemon):

- one supervisor task per server: grant-first auth with SSH-key fallback,
  reconnect with 1 s → 15 s backoff, pending-open resolution, and the
  ADR 0020 keepalive via a control-channel actor that multiplexes
  request/response by `request_id`;
- per-attachment reader/writer pumps built on `AttachedShell::split()`;
  every queue bounded; a full GUI sink backpressures through QUIC to the
  server's slow-consumer policy (spec §8) rather than buffering here;
- the ADR 0018 retry/recovery policy, shared with the CLI via
  `hf_native_client::attach_failure_action`; token rotations persist before
  the UI hears about the attach.

`desktop/src-tauri` (`hf-desktop`) is a thin bridge: commands wrap `Core`
methods, `CoreEvent`s are forwarded as Tauri events. It is a **standalone
cargo workspace** excluded from the repo root, so the core repo never
requires webkit2gtk/WebView2 toolchains to build or test.

**IPC hot paths, no JSON on terminal bytes.** Output: one
`tauri::ipc::Channel` per attachment carrying raw payloads; the first
message is always the screen snapshot (even when empty — the frontend
relies on that framing), then live PTY bytes verbatim. Input: a raw-body
command with the shell address in `x-hf-server`/`x-hf-shell` headers.
Lifecycle traffic (open/attach/list/history/…) is ordinary JSON commands.

**Persistence.** Schema v2 in `holdfast/desktop.json` under the per-user
config dir (`%APPDATA%` on Windows; `HOLDFAST_DESKTOP_STATE` override) —
deliberately separate from the CLI's `state.json` so the two clients never
clobber each other's single-use tokens; the v1 file is imported once on
first run. Per server: url, display name, username, SSH key path, grant;
per shell: latest token, idempotency key, name. Plus a `pending_opens`
journal written *before* each `OpenShell` leaves, closing ADR 0018's
deferred crash window: unresolved entries are re-opened idempotently on the
next connect. Atomic writes, corrupt-file rename-aside, newer-version
refusal — same discipline as ADR 0018.

**Windows token-at-rest posture.** v1 relies on `%APPDATA%` per-user ACLs.
Rationale: resume tokens are single-use and rotate on every attach, grants
expire in 12 h, and DPAPI/keyring integration adds native failure modes for
modest gain. The upgrade path, if wanted later, is `CryptProtectData` over
the whole `desktop.json` blob.

## Consequences

- The heavy correctness surface is `cargo test -p hf-client-core` in the
  main workspace; the Tauri layer stays small enough to review by hand and
  is compile-verified only where a webview toolchain exists (Windows/CI —
  this repo's Linux dev container has no webkit2gtk).
- Shells opened by the web client or CLI appear via `ShellsUpdated` but the
  adopt-into-a-tab UX is milestone-2 work.
- Datagram screen sync (spec's `ScreenSnapshot`/`ScreenDelta`) remains
  unused by all clients; reliable `TerminalOutput` is the v0 baseline.
