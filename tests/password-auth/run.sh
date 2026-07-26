#!/usr/bin/env bash
# PAM password-authentication round-trip test (ADRs 0015/0016, threat model
# T13). The verifier under test lives in hf-auth and is shared by the SSH
# compatibility adapter and the daemon's local issuer.
#
# Verifies the real PAM path: a throwaway local account authenticates with its
# correct password and is rejected with a wrong or empty one, through the same
# `PamVerifier` the adapter uses. This needs root (to create the account and
# read shadow), so the test is #[ignore]d and run here under sudo.
#
# The binary is built as the normal user (so target/ stays user-owned), then
# run via sudo. If sudo is unavailable, the script skips rather than fails.
# The account and any installed /etc/pam.d/holdfast-ssh are removed on exit.
#
# Usage: tests/password-auth/run.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

echo "== PAM password authentication test =="

if ! command -v sudo >/dev/null 2>&1; then
  echo "SKIP: sudo not available — cannot create a test account." >&2
  exit 0
fi
if ! sudo -n true 2>/dev/null; then
  echo "SKIP: passwordless sudo not available — run manually as root:" >&2
  echo "      cargo test -p hf-ssh-adapter --lib -- --ignored --nocapture" >&2
  exit 0
fi

TEST_USER="holdfast-pam-test"
PAM_SERVICE="holdfast-ssh"
INSTALLED_PAM=0

cleanup() {
  sudo -n userdel "$TEST_USER" 2>/dev/null || true
  if [[ "$INSTALLED_PAM" == 1 ]]; then
    sudo -n rm -f "/etc/pam.d/$PAM_SERVICE"
  fi
}
trap cleanup EXIT

echo "-- building hf-auth library test binary --"
BIN="$(
  cargo test -p hf-auth --lib --no-run --message-format=json 2>/dev/null \
    | "${PYTHON:-python3}" -c '
import json,sys
for line in sys.stdin:
    try: m=json.loads(line)
    except ValueError: continue
    if m.get("reason")=="compiler-artifact" and m.get("target",{}).get("name")=="hf_auth" \
       and m.get("profile",{}).get("test"):
        exe=m.get("executable")
        if exe: print(exe)
' | tail -n1
)"

if [[ -z "${BIN:-}" || ! -x "$BIN" ]]; then
  echo "ERROR: could not locate built hf-auth test binary" >&2
  exit 1
fi
echo "   $BIN"

if [[ ! -f "/etc/pam.d/$PAM_SERVICE" ]]; then
  echo "-- installing /etc/pam.d/$PAM_SERVICE from deploy/pam/ (removed on exit) --"
  sudo -n install -m 0644 "deploy/pam/$PAM_SERVICE" "/etc/pam.d/$PAM_SERVICE"
  INSTALLED_PAM=1
fi

echo "-- creating throwaway account $TEST_USER --"
sudo -n userdel "$TEST_USER" 2>/dev/null || true
sudo -n useradd --no-create-home --shell /usr/sbin/nologin "$TEST_USER"
TEST_PASSWORD="hf-$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')"
printf '%s:%s\n' "$TEST_USER" "$TEST_PASSWORD" | sudo -n chpasswd

echo "-- running the ignored PAM round-trip test as root --"
# No exec: the EXIT trap must still remove the account and PAM service.
sudo -n env \
  HOLDFAST_PAM_TEST_USER="$TEST_USER" \
  HOLDFAST_PAM_TEST_PASSWORD="$TEST_PASSWORD" \
  HOLDFAST_PAM_TEST_SERVICE="$PAM_SERVICE" \
  "$BIN" --ignored --nocapture --test-threads=1 real_account_round_trip
