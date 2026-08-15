# ADR 0027: local-first DockerWM desktop link handoff

- Status: accepted
- Date: 2026-08-15
- Relates to ADR 0019 (desktop client), threat model T9
- No Holdfast wire change

## Context

Holdfast already decorates literal `http`/`https` URLs in terminal output and
offers an explicit **dockerwm** action. That action always opened
`/newswall/open` on a configured DockerWM web service, even when DockerWM
Desktop was already running locally.

A custom URI protocol was considered. It is a poor presence check: invoking it
starts a closed application, failures are inconsistently observable through OS
shell APIs, and browser clients may display an external-protocol prompt. It
therefore cannot support a dependable "running desktop first, remote service
otherwise" policy.

## Decision

DockerWM Desktop publishes a small authenticated descriptor at
`dockerwm/link-bridge-v1.json` under the per-user OS application-data
directory while it is running. The descriptor contains a loopback port, process
ID, protocol version, and random 256-bit bearer token. It is atomically written
mode 0600 and removed on clean shutdown.

The loopback endpoint accepts only `POST /v1/open`, rejects requests carrying a
browser `Origin`, requires the bearer token, and accepts only `http`/`https`
URLs. Request bodies, URLs, headers, concurrent connections, timeouts and
requests per socket all have explicit bounds. A successful request focuses the
existing DockerWM window and opens the URL in a new DockerWM tab.

Holdfast Desktop reads at most 4 KiB from a regular descriptor, rejects broad
Unix permissions and malformed/non-loopback values, and uses short bounded
connect/I/O timeouts. A missing, stale or unreachable descriptor means
"DockerWM is not running" and invokes the existing remote `/newswall/open`
fallback. A reachable bridge rejection is not silently sent elsewhere.

The browser client retains the remote action: a web page cannot safely read a
per-user native capability file, and exposing an unauthenticated localhost API
would reintroduce drive-by navigation.

## Verification

```bash
node /home/development/src/dockerwm/scripts/electron_link_bridge_test.js
cd /home/development/sites/holdfast/desktop && npm test && npm run typecheck
cd /home/development/sites/holdfast && cargo test -p hf-client-core dockerwm
```
