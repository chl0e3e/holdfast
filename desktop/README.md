# Holdfast desktop client

Multi-session, multi-server tabbed terminal client (ADR 0019): Tauri 2 +
xterm.js on top of the GUI-free `hf-client-core` crate. Windows is the
first shipping target; Linux/macOS work with the same code.

Adding a server takes a URL plus either a username **and** SSH key path
(SSH challenge/response) or a username alone — then the app prompts for the
Unix password on connect (ADR 0016, requires `holdfastd --password-auth
<user>`). Passwords are used for one login and never stored; the issued
12 h grant (refreshed on use) carries reconnects and restarts. Leave both
fields empty only for loopback dev daemons.

Shells live on the server (spec §11): closing the app, losing the network
or rebooting the client machine never kills them. On launch the app
reattaches every stored shell with screen + scrollback restored, using the
persisted grant (12 h, refreshed on use) and per-shell resume tokens; lost
tokens recover via idempotency keys (ADR 0018).

## Layout

- `src/` — frontend (vanilla TS + Vite), ported from `web/src/client/app.ts`
- `src-tauri/` — `hf-desktop`, a thin Tauri bridge over `hf-client-core`.
  **Standalone cargo workspace**, excluded from the repo root so the core
  workspace never needs GUI toolchains.

## Build / run

Frontend only (works anywhere with Node):

```bash
cd desktop && npm install && npm run typecheck && npm run build
```

Full app (needs a webview toolchain):

- **Windows**: WebView2 is preinstalled on Win10/11.
  `cargo install tauri-cli --version '^2' && cd desktop && npm install && cargo tauri build`
  (NSIS installer lands in `src-tauri/target/release/bundle/nsis/`).
- **Linux dev box**: `apt install libwebkit2gtk-4.1-dev librsvg2-dev
  build-essential`, then `cd desktop && npm install && cargo tauri dev`
  against a loopback daemon (`cargo run -p hf-daemon`), URL
  `http://127.0.0.1:8080`.

Core logic is tested headless in the main workspace:

```bash
cargo test -p hf-client-core
```

## State

`%APPDATA%\holdfast\desktop.json` (Windows) /
`~/.config/holdfast/desktop.json` (unix, 0600), override with
`HOLDFAST_DESKTOP_STATE`. Schema v2; the hf CLI's v1 `state.json` is
imported once on first run. Corrupt files are renamed aside, never silently
replaced.

## Manual acceptance (milestone 1)

1. Start a loopback daemon, run the app, add `http://127.0.0.1:8080`.
2. Open three shells, run something long-lived in each (`top`, a build).
3. Quit the app, restart it: all three tabs come back live, screens intact.
4. Kill the network briefly: tabs show `reconnecting`, then recover.
5. Terminate one shell; restart the app: it stays gone, the others return.
