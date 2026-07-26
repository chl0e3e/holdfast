# Threat model

```text
Status: Phase 7 complete — manual security review performed; residual
        deployment risks are listed below. Each threat lists automated coverage.
Last updated: 2026-07-18
```

## Coverage snapshot (as of Phase 7)

| Threat | Status | Where |
|---|---|---|
| T1 stolen token/grant | partial | resume-token rotation + hash storage; rate limiting **with bounded/evicting bucket map** (daemon auth tests); grant expiry/audience; grant `ops` scope enforced end to end (`scoped_grant_ops_are_enforced`); per-user shell cap (`per_user_shell_cap_is_enforced_and_isolated`); `authorized_keys` option-bearing entries skipped, not granted full access. Grant signing key is persistable so grants survive restart (standalone server identity derives from it, keeping the audience stable — ADR 0017; `persisted_grant_key_gives_stable_server_id_and_grants_survive_restart`). SSH-challenge channel binding implemented for WebTransport (signature bound to the server cert hash — ADR 0008; `ssh_channel_binding_is_enforced_over_webtransport`), defeating relay/MITM; with the WebSocket fallback removed from the product (ADR 0014), browser terminal traffic is always channel-bound |
| T2 cross-user attachment | covered | attachment checks authenticated owner **and** resume token (`resume_token_does_not_bypass_owner_check`); end-to-end stolen-valid-token/list/terminate isolation (`users_cannot_see_or_terminate_each_others_shells`); idempotency is owner-scoped (`idempotency_reuse_is_scoped_to_owner`) |
| T3 malicious server/agent | partial | hostile VT/escape/fuzz/resize corpus covered (`terminal-model/tests/hostile.rs`); Phase 6 registration enforces mTLS CA trust plus exact leaf-fingerprint → `server_id` mapping. Agent shell-open and attach independently verify central grants; attach also checks local ownership and applies fixed frame/stream/flow-control/input/output/history bounds. Real QUIC/PTY coverage exercises forged and cross-user rejection, I/O, resize, history, detach and reconnect (`daemon/tests/agent_mode.rs`, ADRs 0010–0012). The client-facing gateway and hostile-backend end-to-end corpus remain overlay work |
| T4 compromised gateway | n/a (core) | gateway is the overlay project; grant verify-key split in place |
| T5 memory exhaustion | covered | framing rejects oversized pre-alloc; bounded PTY/model/attachment/transport queues; rate-limiter map bounded/evicting; concurrent WebTransport streams per connection explicitly capped (`concurrent_bidi_streams_are_capped`); parser fuzz harnesses (protocol/daemon) |
| T6 fork bombs / PTY exhaustion | covered | per-user shell/attachment limits; hard inherited `prlimit` ceilings (`NPROC=512`, `NOFILE=1024`, `CORE=0`); aggregate systemd `TasksMax`/`MemoryHigh`/`MemoryMax` (ADR 0009); ordinary + uid-dropped PTY tests |
| T7 origin confusion | covered | Origin allowlist on the WS endpoint (daemon `origin.rs` tests); dev auth refuses non-loopback |
| T8 replay of open/terminate | covered | idempotency keys + idempotent terminate (session-core) |
| T9 terminal escape attacks | covered | title sanitization, paste-injection guard (incl. bidi/zero-width/line-separator Trojan-Source chars), inert OSC-52/OSC-8 — `web/src/client/terminal-safety.ts` + expanded hostile corpus; server-side model survives a hostile escape/fuzz/resize corpus (`crates/terminal-model/tests/hostile.rs`), incl. the fixed avt 0/1-column resize DoS (clamped in `TerminalModel` + `session-core`, tested end-to-end) |
| T10 secret leakage in logs | covered | ResumeToken/redacted Debug; bounded closed-schema audit records and fixed-label counters accept no terminal bytes, commands, grants, signatures, or tokens (`daemon::observability` unit tests + daemon auth integration) |
| T11 supply chain | partial | cargo-audit + npm-audit CI gate (.github/workflows/audit.yml); lockfiles committed |
| T12 privilege escalation | covered | account authorization enforced + tested (session-core `policy.rs`, daemon `account_authorization_is_enforced`); uid/gid-drop **mechanism** implemented via `setpriv` (`session-core/src/launch.rs`, `--drop-privileges`, default off), real switch verified over a PTY in `tests/privilege_drop.rs` (run `tests/authorization/run.sh`); production capability/unit hardening is in `deploy/systemd/` (ADR 0007). A broader multi-user soak remains an operational gate |

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
- Attachment authorization checks the authenticated owner before validating or
  rotating the token. A token copied from another user receives the same
  not-found response as an unknown shell and remains unusable.
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
- **Tests:** fuzzing VT parser; real-QUIC agent tests reject a wrong identity
  and an untrusted CA and exercise bounded certificate rotation/reconnect;
  oversized/rapid backend routing remains a Phase 6 test obligation.

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
- The HTTP/3 static-file surface (ADR 0014) shares the per-connection stream
  cap with protocol channels and adds its own bounds: request-path length
  cap, literal matching (no percent-decoding), traversal-shaped paths
  rejected before filesystem access, fixed per-file size ceiling.
- **Tests:** oversized frame rejected pre-allocation (asserted via allocator
  hooks or memory ceiling in test); flood of history requests throttled; slow
  reader triggers `ERR_TOO_SLOW` detach, not memory growth.

### T6. Shell fork bombs and PTY resource exhaustion

- Per-user limits: max shells, max attachments, max streams (spec §8).
- PTY children run under cgroup/rlimit constraints (pids, memory) set at launch
  by the privileged launcher; limits are configuration, enforcement is default.
- Implemented (ADR 0009): `/usr/bin/prlimit` installs hard inherited process,
  open-file and core-dump ceilings before optional `setpriv`; invalid limits or
  a missing wrapper fail shell open. Reference systemd units cap aggregate tasks
  and resident memory for the daemon plus every child shell.
- Shell expiry policy reclaims abandoned shells.
- **Tests:** opening shells beyond the logical limit fails with
  `ERR_LIMIT_EXCEEDED`; ordinary and uid-dropped PTYs observe the configured
  hard ceilings; both reference cgroup units pass `systemd-analyze verify`.

### T7. Origin confusion and cross-site WebTransport

- The Origin allowlist is enforced on the WebTransport CONNECT request
  headers (ADR 0014) — browsers always send `Origin` there; requests without
  one (native clients) are allowed. The legacy WebSocket endpoint is off by
  default (test-only config gate) and enforces the same allowlist when
  enabled.
- Control-plane HTTPS API uses SameSite cookies + CSRF tokens or pure
  bearer-token auth; state-changing endpoints reject cross-origin requests.
- Grants are audience-bound to the gateway hostname.
- **Tests:** WebTransport (and gated WebSocket) connect with wrong/absent
  Origin rejected; grant minted for another audience rejected.

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
- Implemented in `hf-daemon::observability`: a closed event enum (no
  content/credential fields), control-character stripping and a 128-character
  metadata cap, a 4,096-record FIFO ring, and fixed-label monotonic counters.
  The daemon exposes snapshots to deployment/overlay adapters; nothing is sent
  to a central service by the standalone core.
- **Tests:** bounded-ring and metadata-sanitization unit tests; fixed-label
  counter tests; Debug-format snapshot tests on secret-bearing types; daemon
  auth integration asserts emitted records contain no secret/content fields.

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

### T13. Password authentication brute force and credential exposure (opt-in)

- Password authentication is **off by default everywhere** and exists in two
  opt-in places, both backed by the same fail-closed verifier
  (`crates/auth/src/pam.rs`; auth + account checks only — no PAM session, no
  credential installation, ADR 0007's launch path untouched):
  1. the loopback SSH compatibility adapter (`--password-auth`, ADR 0015);
  2. the daemon's local issuer for web/native login
     (`--password-auth <user>`, ADR 0016).
- Adapter exposure: the listener is loopback-only (ADR 0013), so guessing
  requires code execution on the same host. Bounded: foreign usernames, empty
  and oversized (> `MAX_PASSWORD_BYTES`) passwords are rejected before any
  PAM work; every failed attempt (password or public-key alike) pays a
  constant `auth_rejection_time` of 1 s; at most 3 attempts per connection
  and a bounded connection count cap parallelism.
- Daemon exposure: the password crosses the network only inside the encrypted
  transport (WebTransport TLS 1.3; the WS path exists only behind the
  test-only gate). Only allowlisted usernames are accepted, the same
  pre-verifier bounds apply, failures collapse into one indistinguishable
  reply and count toward the per-source rate limiter (5 failures/min → 60 s
  lockout, bounded tracking map). Refused entirely in dev-insecure mode. The
  audit ring records `AuthMethod::Password`, never password material. Unlike
  the SSH challenge, a password carries no ADR 0008 channel binding — an
  accepted residual of the method itself, mitigated by TLS and by grants
  (which are what the client actually stores and replays).
- Account lockout (`pam_faillock`) can be layered in
  `deploy/pam/holdfast-ssh` without code changes.
- Fail closed: unknown PAM service (`/etc/pam.d/other` denies), any PAM
  error, interior NUL in credentials, or a process lacking the privilege to
  verify the target user (pam_unix's `unix_chkpwd` refuses foreign-user
  checks without root/shadow access) all deny.
- **Tests:** adapter negotiation/gating/bridge with an injected verifier
  (`crates/ssh-adapter/tests/password.rs`); daemon wire tests with injected
  verifiers (`crates/daemon/tests/auth.rs` — grant issuance + reconnect,
  verifier-call counting on foreign/oversized input, refusal when disabled,
  audit content checks); PAM fail-closed unit tests (`crates/auth/src/pam.rs`);
  real shadow/pam_unix round trip via `tests/password-auth/run.sh` (root,
  throwaway account).

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
