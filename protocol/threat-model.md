# Threat model

```text
Status: Phase 7 in progress — must still be manually reviewed before any
        deployment beyond localhost. Each threat lists its automated coverage.
Last updated: 2026-07-16
```

## Coverage snapshot (as of Phase 7)

| Threat | Status | Where |
|---|---|---|
| T1 stolen token/grant | partial | resume-token rotation + hash storage; rate limiting **with bounded/evicting bucket map** (daemon auth tests); grant expiry/audience; grant `ops` scope enforced end to end (`scoped_grant_ops_are_enforced`); per-user shell cap (`per_user_shell_cap_is_enforced_and_isolated`); `authorized_keys` option-bearing entries skipped, not granted full access. Grant signing key is persistable so grants survive restart. Still open: SSH-challenge channel binding (ADR 0008 — needs a cross-client change; documented limitation until then) |
| T2 cross-user attachment | covered | session-core `rotated_token_rejects_replay`; auth rejects unknown key with generic error; per-user isolation on list/terminate/idempotency (daemon `users_cannot_see_or_terminate_each_others_shells`, session-core `idempotency_reuse_is_scoped_to_owner`) |
| T3 malicious server/agent | pending | agent mode is Phase 6; VT parser fuzzing pending |
| T4 compromised gateway | n/a (core) | gateway is the overlay project; grant verify-key split in place |
| T5 memory exhaustion | covered | framing rejects oversized pre-alloc; bounded queues (session-core); parser fuzz harnesses (protocol/daemon) |
| T6 fork bombs / PTY exhaustion | partial | per-user shell/attachment limits enforced; cgroup/rlimit launcher pending |
| T7 origin confusion | covered | Origin allowlist on the WS endpoint (daemon `origin.rs` tests); dev auth refuses non-loopback |
| T8 replay of open/terminate | covered | idempotency keys + idempotent terminate (session-core) |
| T9 terminal escape attacks | covered | title sanitization, paste-injection guard (incl. bidi/zero-width/line-separator Trojan-Source chars), inert OSC-52/OSC-8 — `web/src/client/terminal-safety.ts` + expanded hostile corpus; server-side model survives a hostile escape/fuzz/resize corpus (`crates/terminal-model/tests/hostile.rs`), incl. the fixed avt 0/1-column resize DoS (clamped in `TerminalModel` + `session-core`, tested end-to-end) |
| T10 secret leakage in logs | partial | ResumeToken/redacted Debug; key fingerprints (not keys) logged |
| T11 supply chain | partial | cargo-audit + npm-audit CI gate (.github/workflows/audit.yml); lockfiles committed |
| T12 privilege escalation | covered | account authorization enforced + tested (session-core `policy.rs`, daemon `account_authorization_is_enforced`); uid/gid-drop **mechanism** implemented via `setpriv` (`session-core/src/launch.rs`, `--drop-privileges`, default off), real switch verified over a PTY in `tests/privilege_drop.rs` (run `tests/authorization/run.sh`). Remaining: production capability/unit hardening (ADR 0007) |

"Covered" = automated test asserts it today. "Partial" = core mechanism exists
and is tested, some hardening remains. "Pending" = designed, not yet built.

## System sketch and trust boundaries

```text
[Browser / native client]        untrusted input source, user-trusted display
        │  TB1: public internet (QUIC/WebTransport/WebSocket)
[Terminal gateway]               unprivileged network daemon; trusted router,
        │                        NOT trusted with root or other users' shells
        │  TB2: gateway ↔ control plane (signed grants, narrow API)
[Web control plane]              holds identity, policy, grant signing key
        │  TB3: gateway ↔ managed servers (SSH first, later agent mTLS)
[Managed server / agent]         runs PTYs under real Unix accounts
```

Assets, in priority order:

1. Shell access on managed servers (highest — equals arbitrary code execution).
2. Backend SSH credentials / agent identities held by the gateway.
3. Grant signing key (control plane).
4. Resume tokens and connection grants in flight or at rest.
5. Terminal contents and scrollback (user data, possibly containing secrets).
6. Availability of the gateway and shells.

## Threats and mitigations

### T1. Stolen browser token or resume token

An attacker exfiltrates a connection grant or resume token (XSS, malware,
shoulder-surfed URL, leaked log).

- Grants and resume tokens are short-lived and narrowly scoped (user, audience,
  shell, operations).
- Resume tokens rotate on every successful attach; replay of a rotated token is
  rejected (`ERR_TOKEN_REPLAYED`) and audited as suspected theft.
- Server stores only token hashes; tokens never appear in logs, metrics, crash
  dumps or URLs (POST bodies / headers only).
- **Tests:** expired grant rejected; rotated-token replay rejected and audited;
  grep-style log scan asserting no token material in captured logs.

### T2. Cross-user attachment to another user's shell

- Authorization checks on every shell-scoped message bind (user_id from grant) ×
  (shell owner) — never trust client-supplied IDs alone.
- Shell IDs are opaque 128-bit random values, but unguessability is NOT the
  control: possession of an ID grants nothing without passing policy.
- `ERR_FORBIDDEN` for other users' shells is indistinguishable from nonexistent
  IDs (no probing oracle).
- **Tests:** user B attempts attach/input/history/terminate on user A's shell by
  ID; all rejected with the same error shape; audit event raised.

### T3. Malicious managed server or compromised agent

Server-supplied terminal output is hostile input.

- The gateway parses terminal bytes only in the terminal-model crate, which is
  fuzzed; parser state is bounded per shell.
- An agent's mTLS identity maps to exactly one server_id; an agent can never
  answer for another server_id or enumerate other servers' shells.
- Backend output cannot trigger gateway-side shell execution by construction
  (no exec paths reachable from parsing).
- **Tests:** fuzzing VT parser; agent presenting wrong identity rejected;
  oversized/rapid output from backend hits bounds, not OOM.

### T4. Compromised gateway attempting lateral movement

The gateway is the highest-value network target (bastion in agentless mode).

- Runs unprivileged, no shells launched on the gateway host itself.
- Agentless mode: SSH keys are per-managed-server, least-privilege accounts,
  loaded via a dedicated secret mechanism (never in the WordPress DB, never in
  repo/config committed to git); host keys pinned.
- Control-plane signing key never resides on the gateway (verify-only key).
- Agent mode narrows this further: agents authorize per-user PTY launches, so a
  stolen gateway identity alone cannot open arbitrary-account shells.
- **Tests:** gateway config with mis-scoped key fails closed; host-key mismatch
  aborts connection.

### T5. Memory exhaustion via datagrams, frames or history requests

- Frame length checked against negotiated max before allocation.
- All queues have byte + message bounds (spec §8); history requests are paged,
  bounded, and limited to 2 in flight per attachment.
- Datagram processing is allocation-free above a small fixed buffer; stale
  revisions are discarded without buffering.
- **Tests:** oversized frame rejected pre-allocation (asserted via allocator
  hooks or memory ceiling in test); flood of history requests throttled; slow
  reader triggers `ERR_TOO_SLOW` detach, not memory growth.

### T6. Shell fork bombs and PTY resource exhaustion

- Per-user limits: max shells, max attachments, max streams (spec §8).
- PTY children run under cgroup/rlimit constraints (pids, memory) set at launch
  by the privileged launcher; limits are configuration, enforcement is default.
- Shell expiry policy reclaims abandoned shells.
- **Tests:** opening shells beyond limit fails with `ERR_LIMIT_EXCEEDED`; fork
  bomb inside a shell cannot prevent other users' shells from opening.

### T7. Origin confusion and cross-site WebTransport/WebSocket

- Browser endpoints validate the `Origin` header against an allowlist; the
  WebSocket fallback additionally requires the connection grant in the first
  frame (grants are never readable cross-origin).
- Control-plane HTTPS API uses SameSite cookies + CSRF tokens or pure
  bearer-token auth; state-changing endpoints reject cross-origin requests.
- Grants are audience-bound to the gateway hostname.
- **Tests:** WebSocket/WebTransport connect with wrong/absent Origin rejected;
  grant minted for another audience rejected.

### T8. Replay of open-shell or terminate-shell commands

- `OpenShell` idempotency keys make retries safe and replay non-amplifying.
- `TerminateShell` is idempotent; grants carry unique token IDs and expiry so a
  captured frame cannot be replayed on a new session.
- Transport-level replay is prevented by TLS 1.3/QUIC; this control addresses
  application-level retry logic and stolen frame contents.
- **Tests:** duplicate OpenShell returns same shell; replayed grant (same jti)
  after expiry/rotation rejected.

### T9. Terminal escape sequences attacking the browser or clipboard

Hostile shell output (e.g. from `cat`ing a malicious file) targets the viewer.

- xterm.js is kept current (supply-chain watch, T11) and configured without
  risky addons by default.
- OSC 52 clipboard writes are disabled by default; if enabled, size-capped and
  user-visible. Clipboard reads are never exposed to the shell.
- Hyperlink (OSC 8) activation requires user gesture and shows the target.
- Terminal-answerback sequences that echo attacker-controlled bytes back as
  input are filtered/disabled in the client emulator configuration.
- The server-side terminal model parses attacker-controlled PTY output, so it
  must never panic, hang, or grow unbounded on hostile input. Client-supplied
  terminal dimensions are clamped to a safe floor (`MIN_COLS`/`MIN_ROWS`) before
  reaching `avt`, which otherwise infinite-loops at 0 columns and panics on a
  1-column split of a wide glyph or 0 rows.
- **Tests:** `crates/terminal-model/tests/hostile.rs` (named hostile corpus,
  byte-at-a-time feeding, seeded random + escape-biased fuzz, resize storm,
  history-bound flood, degenerate-dimension clamping); the resize DoS is also
  covered end-to-end over a real PTY in
  `hostile_resize_dimensions_do_not_crash_or_hang_the_shell`
  (`crates/session-core/tests/lifecycle.rs`); browser-side title/paste/clipboard
  corpora in `web/src/spike/terminal-safety.test.ts`; clipboard write attempts
  without the feature enabled are no-ops.

### T10. Secrets leaked through logs, crash dumps or metrics

- Structured logging with an explicit schema; terminal bytes, typed commands,
  credentials and complete tokens are never loggable fields (enforced by type:
  secrets wrapped in types whose Debug/Display redact).
- Audit events record lifecycle metadata only (opened/attached/detached/
  terminated, actor, IDs, result).
- Metrics are counters/gauges/histograms only — no free-text labels derived
  from user input.
- **Tests:** log-capture assertions in integration tests; Debug-format snapshot
  tests on secret-bearing types.

### T11. Supply-chain compromise (QUIC stack, VT parsing, browser deps)

- `Cargo.lock` and `package-lock.json` committed; `cargo audit` (RustSec) and
  `npm audit` in CI; dependency updates reviewed, not auto-merged.
- Dependency policy recorded in docs/decisions: prefer widely-used, actively
  maintained crates (quinn/wtransport/tokio/prost) and pin major versions.
- Minimal feature flags on all dependencies.
- **Tests/CI:** audit jobs fail the build on known-vulnerable versions.

### T12. Privilege escalation on managed servers (agent mode)

- The network-facing daemon is unprivileged. A small, separately auditable
  privileged launcher performs exactly: authenticate request → setuid to target
  account → create PTY → exec shell. It accepts requests only over a local,
  credential-checked channel.
- The launcher never takes a path, environment or argv from the network without
  policy validation. Allowed Unix accounts come from AccessPolicy, not client
  input.
- Implemented (ADR 0007): when `privilege_drop` is enabled, the resolved account
  (from AccessPolicy, never raw client input) is launched via
  `setpriv --reuid --regid --init-groups --reset-env` at an absolute path. The
  child receives exactly the target account's uid/gid and supplementary groups
  and a reset environment; it keeps none of the daemon's groups. It is
  fail-closed: a missing account or absent `setpriv` aborts the open, and if the
  daemon lacks the privilege to switch, `setpriv` changes uid/gid *before*
  exec'ing the shell and aborts on failure — so the shell fails to start rather
  than ever running under the daemon's (more-privileged) identity. There is no
  unprivileged fallback. The drop is off by default, so the standalone
  single-user daemon runs every shell as its own (correct, only) account.
- Production model (`deploy/systemd/`): the daemon runs unprivileged with only
  `AmbientCapabilities=CAP_SETUID CAP_SETGID`. Since ambient caps survive
  `setuid`, the launcher clears the inheritable+ambient sets before exec so the
  shell inherits none of the daemon's capabilities (bounding set left intact so
  `sudo`/`ping` still work). `--drop-privileges` refuses to start without an
  explicit `--account` allowlist, so it can never fall back to permissive
  `AllowAll`.
- **Tests:** authorization rejects accounts outside policy
  (`account_authorization_is_enforced`); pure argv-construction/resolver unit
  tests (`launch.rs`); the real uid switch verified over a PTY
  (`privilege_drop.rs` via `tests/authorization/run.sh` — a `nobody`-scoped
  shell reports uid 65534, a no-account shell stays as the daemon's uid).

## Residual risks accepted for now (revisit before beta)

- Agentless mode makes the gateway a full bastion (T4): accepted for Phase 4
  development against controlled test servers only.
- Single-node gateway: a gateway crash drops live SSH backend sessions
  (documented; clustering is an explicit non-goal until the state model is
  correct).
- No durable scrollback: also a privacy *feature*; durable recording, if ever
  added, needs its own threat review (encryption at rest, retention, consent
  indication).

## Operational security requirements

- Rate limiting on authentication attempts, connection attempts and
  OpenShell/AttachShell per user and per source address.
- TLS certificates via ACME with automated renewal and gateway reload.
- UDP 443 owned solely by the gateway; never run the gateway or control plane
  as root; no privileged operations inside WordPress/PHP-FPM.
- Security-relevant audit events (auth failures, token replay, cross-user
  attempts, limit hits) must be queryable via the control plane.
