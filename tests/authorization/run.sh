#!/usr/bin/env bash
# Privilege-drop + resource-limit mechanism test (threat models T12/T6,
# ADRs 0007/0009).
#
# Verifies the actual uid/gid switch: with privilege_drop enabled, a shell whose
# resolved account differs from the daemon's runs under that account, with the
# hard resource limits intact after the switch. This needs root (to switch uid)
# and a secondary account, so the test is #[ignore]d and run here under sudo.
#
# The binary is built as the normal user (so target/ stays user-owned), then run
# via sudo. If sudo is unavailable or the test is not root, it skips rather than
# fails.
#
# Usage: tests/authorization/run.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

echo "== privilege-drop mechanism test =="

if ! command -v sudo >/dev/null 2>&1; then
  echo "SKIP: sudo not available — cannot exercise the uid switch." >&2
  exit 0
fi
if ! sudo -n true 2>/dev/null; then
  echo "SKIP: passwordless sudo not available — run manually as root:" >&2
  echo "      cargo test -p hf-session-core --test privilege_drop -- --ignored --nocapture" >&2
  exit 0
fi

echo "-- building privilege_drop test binary --"
BIN="$(
  cargo test -p hf-session-core --test privilege_drop --no-run --message-format=json 2>/dev/null \
    | "${PYTHON:-python3}" -c '
import json,sys
for line in sys.stdin:
    try: m=json.loads(line)
    except ValueError: continue
    if m.get("reason")=="compiler-artifact" and m.get("target",{}).get("name")=="privilege_drop":
        exe=m.get("executable")
        if exe: print(exe)
' | tail -n1
)"

if [[ -z "${BIN:-}" || ! -x "$BIN" ]]; then
  echo "ERROR: could not locate built privilege_drop test binary" >&2
  exit 1
fi
echo "   $BIN"

echo "-- running the ignored uid-switch test as root --"
# --test-threads=1 for deterministic, serial output; --nocapture so the SKIP/
# assertion messages are visible.
exec sudo -n "$BIN" --ignored --nocapture --test-threads=1
