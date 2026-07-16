#!/usr/bin/env bash
# Adverse-network (netem) suite runner — Phase 7 testing strategy.
#
# Builds the netem integration test, then runs it inside an unprivileged
# user + network namespace where the test process holds CAP_NET_ADMIN over a
# private loopback. The test itself drives `tc netem` to shape `lo` (latency,
# jitter, loss, reordering, blackhole) while exercising real WebTransport/QUIC
# between holdfastd and the native client library.
#
# No root required: it relies on unprivileged user namespaces
# (kernel.unprivileged_userns_clone = 1). If those are disabled, or tc is
# missing, the tests skip themselves rather than fail.
#
# Usage:
#   tests/packet-loss/run.sh                # run all netem scenarios
#   tests/packet-loss/run.sh blackhole      # run scenarios matching a filter
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

FILTER="${1:-}"
TC_BIN="$(command -v tc || echo /usr/sbin/tc)"
IP_BIN="$(command -v ip || echo /usr/sbin/ip)"

echo "== netem adverse-network suite =="

# --- Preconditions: report clearly (and skip, not fail) if unavailable. ---
if [[ ! -x "$TC_BIN" ]]; then
  echo "SKIP: 'tc' (iproute2) not found — install iproute2 to run netem tests." >&2
  exit 0
fi
if ! unshare -Ur --net --map-root-user true 2>/dev/null; then
  echo "SKIP: unprivileged user+net namespaces unavailable on this host." >&2
  echo "      (need kernel.unprivileged_userns_clone=1)" >&2
  exit 0
fi

# --- Build the test binary OUTSIDE the namespace (the namespace has no
#     network, and we want compilation to use the normal environment). ---
echo "-- building netem test binary --"
BIN="$(
  cargo test -p hf-native-client --test netem --no-run --message-format=json 2>/dev/null \
    | "${PYTHON:-python3}" -c '
import json,sys
for line in sys.stdin:
    try: m=json.loads(line)
    except ValueError: continue
    if m.get("reason")=="compiler-artifact" and m.get("target",{}).get("name")=="netem":
        exe=m.get("executable")
        if exe: print(exe)
' | tail -n1
)"

if [[ -z "${BIN:-}" || ! -x "$BIN" ]]; then
  echo "ERROR: could not locate built netem test binary" >&2
  exit 1
fi
echo "   $BIN"

# --- Run the pre-built binary inside a fresh user+net namespace. `lo` starts
#     DOWN in a new net namespace, so bring it up before the tests, which then
#     apply their own netem qdiscs on top. Single-threaded so scenarios don't
#     fight over the one shared `lo` qdisc. ---
echo "-- running scenarios inside network namespace --"
export HF_NETEM=1
exec unshare -Ur --net --map-root-user bash -c '
  set -e
  "'"$IP_BIN"'" link set lo up
  exec "'"$BIN"'" --ignored --nocapture --test-threads=1 '"$FILTER"'
'
