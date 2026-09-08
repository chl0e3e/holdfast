# ADR 0031: opt-in remembered desktop login and Windows DPAPI state

- Status: accepted
- Date: 2026-09-08
- Supersedes ADR 0019's grant persistence and Windows token-at-rest posture
- Relates to ADRs 0018 and 0025; threat models T1 and T10
- No Holdfast wire or daemon change

## Decision

Desktop connection grants remain available in Rust memory for automatic
reconnects while the app is running. Persisting a grant across app restarts
requires an explicit, per-server **Remember login after closing Holdfast**
choice. It defaults off for every authentication method, including FIDO SSH
keys. Add server exposes the choice; each server's **Login** settings can
change it later. Disabling it immediately rewrites the file without the grant,
while preserving the current connection and in-process reconnect ability.

A fresh hardware login requires a new security-key signature/touch. A remembered
grant can authenticate without the key until its original 12-hour expiry;
reusing a grant does not extend that deadline. This is a client retention
policy, not a new server-enforced authentication lifetime or revocation policy.
Shell IDs, rotating resume tokens and idempotency keys survive app restarts so
fresh authentication can restore the same persistent shells.

On Windows, user-scoped `CryptProtectData` encrypts the entire serialized state
before either the temporary file or destination is written. The format is the
ASCII header `HOLDFAST-DPAPI-1\n` followed by the DPAPI blob, still at
`%APPDATA%\holdfast\desktop.json`. `CRYPTPROTECT_UI_FORBIDDEN` is used;
`CRYPTPROTECT_LOCAL_MACHINE` is never used. This includes remembered grants,
shell tokens and recovery keys. Protection or decryption failure never falls
back to plaintext; unreadable/corrupt state is retained and startup fails with
an error. Unknown newer schemas are likewise retained and refused. There is no
new plaintext corrupt-file backup. Non-Windows desktop builds retain atomic
0600 JSON files with the same opt-in grant retention policy.

Schema v3 migration discards all legacy desktop grants and defaults remembering
off, preserving server configuration and shell recovery metadata. It rewrites
the old file before starting any connections. On Windows only pre-v3 plaintext
is accepted for migration; unprotected v3 is refused. CLI v1 imports retain
shell recovery metadata but never import grants; the CLI-owned file is not
changed. This upgrade does not revoke copies previously stolen or delete
historical backups. Older desktop versions cannot read the new Windows format.

Serialized state and migration input have an 8 MiB hard limit. Reads stop at
that limit, serialization writes through a bounded writer, and encrypted
output is checked before disk writes. Preference changes commit in memory only
after the protected file has been successfully replaced.

DPAPI improves protection against copied files; it does not prevent malware
running as the same Windows user from decrypting state or stealing a live
in-memory grant. See Microsoft's [CryptProtectData documentation](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata).

## Verification

```sh
cargo test -p hf-client-core --lib --tests --locked -j 2
cargo clippy -p hf-client-core --lib --locked -- -D warnings -A clippy::unnecessary-map-or
cd desktop
npm ci
npm test
npm run typecheck
npm run build
```

Native Windows tests (also required by `.github/workflows/audit.yml`):

```powershell
pwsh ./desktop/scripts/prepare-msquic.ps1
$env:PATH = "$env:VCPKG_ROOT\installed\x64-windows\bin;$env:PATH"
cargo test -p hf-client-core --lib --locked
cd desktop/src-tauri
cargo build --release --locked --features tauri/custom-protocol
```

Tests cover user-scoped DPAPI round-trip and tampered/truncated data, encrypted
state opacity, no overwrite on decryption failure, legacy migration without
reusing the grant, preserved shell recovery, in-process grant availability,
opt-in persistence, immediate removal on disabling, bounded state, and failed
preference writes. Real-daemon password integration cases verify both restart
policies and reattach to the same shell after fresh authentication. Existing
SSH tests cover touch enforcement and explicit retry after a missed touch.

Manual Windows hardware acceptance: upgrade an existing v2 profile with a
valid FIDO-issued grant. Confirm it prompts for a touch and restores the same
shells; restart and repeat. Brief network loss while the app stays open should
recover without a touch. Enable remembering under the server's Login settings
and restart within the grant lifetime: no touch. Disable it and restart: a
fresh touch. Confirm the state and temporary file contain no plaintext JSON.
