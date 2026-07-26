# ADR 0021: idle-shell expiry reaper (operator opt-in, default off)

- Status: accepted
- Date: 2026-07-26
- Relates to spec §11 (expiry policy), §8 (limits); threat model T6;
  ADRs 0018, 0019
- No wire change

## Context

Spec §11 has always listed "expiry policy" as a legitimate way for a shell
to end, and threat model T6 leans on "shell expiry policy reclaims
abandoned shells" — but no reaper existed. The desktop client (ADR 0019)
makes the gap real: it is *designed* to keep shells alive indefinitely and
to reattach after arbitrarily long client absences, so abandoned shells
(lost tokens with no recovery key, users who never return) would otherwise
accumulate against `max_shells_per_user` forever, each holding a PTY,
scrollback memory, and a process.

## Decision

- `SessionCoreConfig.idle_shell_ttl: Option<Duration>`, default `None` —
  **off unless the operator opts in** (`holdfastd --shell-idle-ttl
  <seconds>`). Keep-shells-forever is the product's point; expiry is a
  resource policy, not a default behavior.
- `ShellManager::reap_idle(ttl)` terminates shells that are `Running` with
  **zero attachments** whose last attach (or creation, if never attached)
  is older than the TTL. Attached shells are never candidates, no matter
  how old. Candidates are re-checked under the runtime lock immediately
  before the kill, so an attach that lands after the scan wins; the
  residual race is identical to a manual terminate racing an attach.
- The daemon drives it from a timer task (period `clamp(ttl/4, 1s..60s)`,
  scan on a blocking thread since terminate waits on child reaping) and
  records a **distinct** `ShellExpired { user, shell_id, exit_code }`
  audit event plus a `shells_expired` metric — expiry must never be
  mistaken for a user/admin `TerminateShell` in the audit stream.

## Consequences

- T6's reclaim claim is now true when enabled; deployments that want it
  add one flag. The reference systemd units deliberately do not set it.
- A reaped shell's resume token and idempotency key become useless;
  clients observe `ERR_NOT_FOUND` on the next attach and drop the stored
  entry (the ADR 0018 policy's only legitimate forget), so the failure
  mode is clean.
- Client-visible semantics are unchanged when the flag is absent.
