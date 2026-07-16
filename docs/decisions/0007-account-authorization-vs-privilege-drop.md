# ADR 0007: Account authorization now; uid/gid drop as a deployment integration

Date: 2026-07-16 · Status: accepted (authorization tested) · Relates to threat model T12

## Context

Privilege separation (T12) has two halves:

1. **Authorization** — decide whether an authenticated user may run a shell
   under a requested Unix account.
2. **Mechanism** — actually launch the PTY process under that account's
   uid/gid (dropping the daemon's privileges).

The mechanism requires either a `pre_exec` hook to `setuid`/`setgid` before
exec, or a privilege-dropping exec wrapper. Two constraints shape this ADR:

- `portable-pty` 0.9 (ADR 0003) does **not** expose a `pre_exec` / uid hook on
  its `CommandBuilder`; it uses `pre_exec` internally for its own PTY setup.
- The actual uid switch cannot be exercised without a rooted, multi-user host,
  which the development environment is not.

Shipping an untested privilege-drop path would violate the project's own rule
(threat model: security is a core requirement, verified by tests).

## Decision

Build and test the **authorization** half now; defer the **mechanism** to a
documented deployment integration point.

- `hf-session-core` gains an `AccessPolicy` (`resolve(user, requested) ->
  account | Denied`). `StaticPolicy` enforces a per-user allowlist (first
  listed = default); `AllowAll` is the permissive dev default. `open_shell`
  authorizes before spending resources and records the resolved account on the
  shell; denial is `SessionError::Forbidden` → wire `ERR_FORBIDDEN`.
- The daemon threads the authenticated user id into `open_shell` and configures
  the policy from `DaemonConfig::account_policy`.
- Tested: `crates/session-core/tests/policy.rs` (policy resolution + Forbidden,
  nothing spawned on denial) and `crates/daemon/tests/auth.rs`
  (`account_authorization_is_enforced`, end to end over WebSocket).

## The mechanism (not built here)

Until the mechanism lands, a shell runs under the daemon's own uid regardless
of the resolved account. The resolved account name is exactly what a
privilege-dropping launch would switch to. Recommended integration when
deploying multi-user:

- **Preferred:** wrap the shell command with a privilege-dropping exec —
  `runuser -u <account> -- <shell>` (util-linux, root-only, no PAM password)
  or `setpriv --reuid/--regid/--clear-groups`. The launcher builds this argv
  only for the resolved account; command construction is pure and testable.
- **Alternative:** replace or patch the PTY layer to expose `pre_exec`, and
  `setgid`→`initgroups`→`setuid` in the child before exec.

Either way the daemon must run with just enough privilege to switch to the
allowed accounts (a narrow, auditable boundary — never "the whole gateway as
root", per the plan), and this must be verified on a real multi-user host with
integration tests before any multi-user deployment.

## Consequences

- The authorization boundary — the part most prone to a logic bug — is in place
  and tested, so the mechanism integration is mechanical and self-contained.
- Single-user use (the common standalone case) is unaffected: the daemon runs
  shells as its own user, which is the correct and only account.
- Agent mode (Phase 6) reuses this exact policy layer on the managed server.
