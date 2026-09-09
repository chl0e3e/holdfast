# Holdfast desktop client

Multi-shell, multi-server tabbed terminal client (ADR 0019): Tauri 2 +
xterm.js on top of the GUI-free `hf-client-core` crate. Windows is the
first shipping target; Linux/macOS work with the same code.

Adding a server takes a URL plus either a username **and** SSH key path
(SSH challenge/response) or a username alone — then the app prompts for the
Unix password on connect (ADR 0016, requires `holdfastd --password-auth
<user>`). Passwords are used for one login and never stored; the issued
12 h grant carries reconnects while the app is open. Restarting requires a
fresh login unless **Remember login after closing Holdfast** is enabled for
that server. Change this through the server’s **Connect** settings. Leave both
fields empty only for loopback dev daemons.

Shells live on the server (spec §11): closing the app, losing the network
or rebooting the client machine never kills them. On launch the app
reattaches every stored shell with screen + scrollback restored, using the
fresh authentication (or an explicitly remembered 12 h grant) and per-shell resume tokens; lost
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
  `cd desktop && npm install && npm run build && cd src-tauri && cargo build
  --release --locked --features tauri/custom-protocol`. The feature is
  required when invoking Cargo directly; without it Tauri loads the development
  URL (`localhost:1420`) instead of embedding `frontendDist`.
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
reachable, Holdfast opens the anonymous disposable viewer deep link at
`https://docker.direct.asylum.st/?url=...` (or the
`holdfast.dockerwm.url` viewer-origin override). An empty override still hides
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
`HOLDFAST_DESKTOP_STATE`. Schema v3. Windows protects the entire file with user-scoped DPAPI; other
platforms retain 0600 JSON. The CLI’s v1 shell metadata is imported once,
without login grants. Legacy desktop grants are discarded on upgrade and
remembering defaults off; server settings and shell recovery data are retained.
Invalid or undecryptable files are retained and refused. State is limited to
8 MiB. See [ADR 0031](../docs/decisions/0031-desktop-credential-persistence.md)
for migration, threat-model limits and automated/Windows reproduction steps.

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

For the redraw-heavy IRC-art case, download the same Big Matrix fixture used in
the 2026-08-27 regression and pace it at roughly 8 Mbit/s:

```bash
curl -fLo /tmp/bigmatix.txt https://git.supernets.org/ircart/ircart/raw/branch/master/ircart/big/bigmatix.txt
pv -qL 1000000 /tmp/bigmatix.txt
```

On Windows/WebView2 the output must advance in bursts, not pause after each
line-sized chunk for a whole-screen redraw. Keyboard input in another tab must
remain responsive throughout.

PASS requires the tab either to render the ordered output or transparently
reattach to a clean authoritative snapshot; it must not show partial/stale
rows from another shell. While the burst is running, type a short command and
press Enter: its bytes must remain ordered, must not be silently discarded
during an automatic reattach, and the UI must stay responsive. Then produce at
least 1,000 quieter lines, scroll to the top, and keep scrolling upward. Each
history page must preserve the viewed rows instead of snapping to the bottom.
Finally maximize and restore the window: the xterm viewport must reach the
right edge of its black panel and the document itself must have no horizontal
or vertical scrollbar.

Verify that xterm's built-in OSC 8 links use the Holdfast popover too:

```bash
printf '\033]8;;https://example.com/holdfast\033\\OSC8-link\033]8;;\033\\\n'
```

Hover and activate `OSC8-link`, then hover a literal `https://example.com`
printed by the shell. Both must show the same full-destination **Open /
dockerwm** popover; neither may show xterm's confirmation dialog or navigate
directly.

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

The bounded replay/history, ordered input, link-scheme and close-state policies
are covered by:

```bash
cd desktop
npm test && npm run typecheck && npm run build
cd src-tauri
cargo test --locked
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
cargo test -p hf-client-core password_login_ --locked
```

### Windows security-key retry regression

With an expired/removed stored grant and a configured `*-sk` key, deliberately
miss or cancel the first YubiKey touch. Holdfast must show one SSH-key failure
and a **Retry** action; it must not open more prompts or make more daemon
authentication attempts until Retry is pressed. Press Retry, touch once, and
confirm the server connects without entering source-IP lockout. The headless
supervisor gate is:

```bash
cargo test -p hf-client-core --test core ssh_key_failure_waits_for_explicit_retry --locked
```

Windows OpenSSH provides the FIDO implementation used by Holdfast. If its
console reports `invalid format`, record the executables/version before
changing the client configuration:

```powershell
where.exe ssh-keygen
where.exe ssh
ssh -V
```

## Local SOCKS5 proxy (0.4.0)

Choose **Connect** beside a server to manage **Remember login after closing
Holdfast** and the local SOCKS5 proxy. Choose a free local port (default 1080),
then **Start SOCKS**. Configure the other application to use SOCKS5 at
`127.0.0.1:<port>` with proxy DNS enabled. For example:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

Holdfast's own QUIC connection still goes directly to the selected daemon.
SOCKS supports TCP CONNECT, IPv4, IPv6 and server-side DNS. The local listener
is accessible to local processes only; it does not change Windows proxy
settings. **Stop SOCKS** closes its active TCP connections. A server disconnect,
removal or application exit also stops it; Start is explicit after reconnect.
One listener per configured server and at most 16 connections per listener are
allowed. UDP ASSOCIATE, BIND, SOCKS4 and automatic TCP resumption are unsupported.

The server needs holdfastd 0.0.7 with `--tcp-forward-user <authenticated-user>`
(repeat for each allowed user). Without this configuration, Start is disabled.
A scoped grant must also permit `tcp-forward`. The configured account may
access TCP services reachable from the daemon, including its private network.
The proxy uses bounded 8 KiB frames with one outstanding frame per direction;
throughput on high-latency paths is correspondingly limited in this first version.

### Upload disabled regression

0.4.0 fixes live Rust event fields being emitted in snake_case while the desktop
expected camelCase (`file_uploads` versus `fileUploads`, also upload totals and
exit codes). This could overwrite a valid bootstrap capability and disable
Upload on an enabled daemon. The Rust JSON contract test and browser test cover
an initially disabled Upload becoming enabled on the real UI's capability event.
Daemon uploads still require `--upload-root` and a selected running shell.

### Connection UI verification

```sh
cargo test -p hf-client-core --lib --test core --locked -j 2
cargo test -p hf-daemon --test tcp_forward --locked -j 2
cargo test -p hf-native-client --test socks --locked -j 2
cd desktop
npm ci
npm test
npm run typecheck
npm run build
npx playwright install chromium
node scripts/connection-smoke.mjs
```

`HOLDFAST_CHROMIUM=/absolute/path/to/chrome` selects an existing Chromium.
The smoke test starts its own loopback Vite server and mocks only the native IPC
boundary. It checks Connect preferences and failed saves, SOCKS Start/Stop, and
live upload capability rendering. Real TCP/QUIC forwarding and listener teardown
are covered by the Rust integration tests. Native Windows compile, credential
protection tests and executable packaging run in `.github/workflows/audit.yml`.
