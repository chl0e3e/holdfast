# Holdfast desktop client

Multi-shell, multi-server tabbed terminal client (ADR 0019): Tauri 2 +
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
cd desktop
npm ci
npm test
npm run typecheck
npm run build
```

Full app (needs a webview toolchain):

- **Windows**: WebView2 is preinstalled on Win10/11.
  `cd desktop && npm install && npm run build && cd src-tauri && cargo build --release --locked`.
  The portable `hf-desktop.exe` and its pinned `msquic.dll` runtime land in
  `src-tauri/target/release/`; Holdfast does not build an NSIS installer.
- **Linux dev box**: `apt install libwebkit2gtk-4.1-dev librsvg2-dev
  build-essential`, then `cd desktop && npm install && cargo tauri dev`
  against a loopback daemon (`cargo run -p hf-daemon`), URL
  `http://127.0.0.1:8080`.

Core logic is tested headless in the main workspace:

```bash
cargo test -p hf-client-core
```

## Uploading a file (Windows)

When a direct standalone daemon advertises file transfer, select a running
shell and choose **Upload**. The Windows picker is owned by Rust: neither the
selected local path nor file bytes enter the webview. Holdfast hashes and
streams the regular file in bounded chunks, shows progress, and lets you
cancel. A completed upload offers the private remote path for copying or for
explicit, POSIX-quoted insertion into the original attached shell.

Uploads do not resume invisibly after cancellation or reconnect. Retry starts
from byte zero. The action stays disabled when the daemon has no upload root,
the server is reconnecting, the shell is no longer running, or that tab already
has an upload. Browser and gateway/agent uploads are not part of this release.

Windows manual regression:

1. Enable the daemon's upload root and attach a shell.
2. Upload files of 0 bytes, 1 byte, 65,535 bytes, 65,536 bytes, 65,537 bytes,
   and the configured maximum. Compare `sha256sum` at the returned paths.
3. Cancel a large upload and verify its partial directory disappears.
4. Disconnect during an upload; reconnect and verify the UI reports failure
   without resuming. Retry and confirm progress restarts from zero.
5. Copy the result path, then use **Insert quoted path**. Confirm focus returns
   to the original tab and no command is executed automatically.
6. Repeat while switching tabs and resizing/maximizing the window; the final
   terminal row must remain visible above the Windows taskbar.

## DockerWM links

The terminal link popover's **dockerwm** action first looks for the
authenticated loopback bridge published by a running DockerWM Desktop app. If
present, the link opens in a new tab in that existing app. If no bridge is
reachable, Holdfast opens the existing cookie-authenticated remote URL at
`https://docker.asylum.st/newswall/open` (or the
`holdfast.dockerwm.url` localStorage override). An empty override still hides
the DockerWM action entirely.

This is intentionally a local IPC probe rather than a custom URI protocol: a
URI handler would start DockerWM when closed and cannot give Holdfast a reliable
success/fallback result. The bridge descriptor is bounded to 4 KiB and must be
mode 0600 on Unix; requests use its random bearer token, loopback only, with a
2 KiB URL and 4 KiB response ceiling.

Reproduce the native handoff tests with:

```bash
cargo test -p hf-client-core dockerwm
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
6. Hover a tab: its tooltip identifies title, shell, server, state and shell ID.
   Close the exited tab with its `×`; it disappears without a confirmation.
7. Close a live tab and accept the warning: the attachment closes but the
   shell keeps running. Restart Holdfast and confirm its tab reappears.
8. Run a terminal program that animates its OSC title (for example, one whose
   tab cycles through `Working`, `Working.`, and `Working..`). While the title
   is changing, click repeatedly between that tab and another tab. Every click
   must switch tabs; title updates must not swallow the pointer gesture.

### Terminal burst, scrolling and resize regression

With a shell attached, reproduce a large ordered burst:

```bash
seq 1 200000
```

PASS requires the tab either to render the ordered output or transparently
reattach to a clean authoritative snapshot; it must not show partial/stale
rows from another shell. Then produce at least 1,000 quieter lines, scroll to
the top, and keep scrolling upward. Each history page must preserve the viewed
rows instead of snapping to the bottom. Finally maximize and restore the
window: the xterm viewport must reach the right edge of its black panel and
the document itself must have no horizontal or vertical scrollbar.

On Windows with the taskbar visible, verify that the final terminal row and its
cursor are fully drawn at 100%, 125% and 150% display scaling. Repeat after
maximizing and restoring the window. The terminal inset must remain visible,
and the document itself must not gain a scrollbar.

Open a new shell while another tab is active. Its prompt and snapshot must be
visible immediately after selecting it, without typing or clicking inside the
terminal. Then leave that tab hidden for several minutes while it produces
output, return to it, minimize and restore the Holdfast window, and switch away
and back once more. Each return must show the current terminal immediately;
keyboard or mouse input must not be required to wake a black viewport.

Restart Holdfast with a shell sitting at an ordinary prompt on its first row.
The restored prompt and the outline cursor must both appear on that first row.
They must not split into a prompt at the bottom and a cursor at the top; that
specifically verifies the scrollback-spacer/snapshot replay boundary.

The attach-order regression test deliberately resolves the Tauri command before
delivering its first Channel payload. This is the Windows-observed ordering: the
UI must wait for that snapshot before it marks the attachment ready and renders.

The bounded replay/history policy and close-state decisions are covered by:

```bash
cd desktop
npm test
```

### Windows password-login regression

Build the Windows executable with the Schannel MsQuic package prepared by
`scripts/prepare-msquic.ps1`, add a production server by its full hostname and
configure a username without an SSH key. The login prompt must show both the
hostname and saved username. Submit a deliberately incorrect password once:

- `holdfastd` must audit `AuthenticationFailed`, proving the credential reached
  the daemon through Schannel, HTTP/3 and WebTransport;
- the dialog must say `Password rejected`, not repeat an unexplained prompt;
- a TLS, DNS or stream-setup failure must instead say that the password was not
  checked.

The transport-neutral correct/wrong-password and grant restart paths run with:

```bash
cargo test -p hf-client-core password_login_and_grant_only_restart --locked
```
