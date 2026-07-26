# hf-native-client

`hf` — the native terminal client — plus `hf_native_client`, the client
library (WebTransport connection, channel-bound SSH auth, shell operations,
persisted state). The desktop app builds on the library; the `hf` CLI binary
is unix-only (raw mode, SIGWINCH).

## Reproduce

```bash
# Full suite (spawns a real daemon; unix only):
cargo test -p hf-native-client

# Library portability gate — the lib must keep resolving without unix-only
# deps (nix, hf-daemon/pty/pam) on Windows targets:
cargo tree -p hf-native-client --target x86_64-pc-windows-msvc -e normal \
  | grep -E '\bnix\b|hf-daemon|pam' && echo LEAK || echo ok

# Full cross-check (needs a Windows C toolchain for ring; runs in CI on
# windows-latest, or locally on Linux with gcc-mingw-w64-x86-64 installed):
cargo check -p hf-native-client --lib --target x86_64-pc-windows-msvc

# Adverse-network suite (netem):
tests/packet-loss/run.sh
```

## State file

Client state (resume tokens, grants) lives at
`~/.config/holdfast/state.json` (unix, mode 0600) or
`%APPDATA%\holdfast\state.json` (Windows), overridable with the
`HOLDFAST_STATE` env var. Writes are atomic; a corrupt file is renamed to
`state.json.corrupt-<ts>` rather than silently replaced. Schema is versioned;
files written by a newer client are refused (ADR 0018).
