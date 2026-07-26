# ADR 0018: client resume-token lifecycle and idempotency-key recovery

- Status: accepted
- Date: 2026-07-25
- Relates to ADR 0017, spec §9 (idempotency), §12 (resume tokens); threat
  model T1, T6
- Client side of "shells survive client restarts"

## Context

Resume tokens are single-use: every successful attach rotates them. That is
the right theft posture (spec §12), but it makes the client's persistence
discipline load-bearing in two ways the original `hf` got wrong:

1. **Forgetting on transient failure.** `run_session` dropped the stored
   token on *any* attach error — including plain transport loss — and the
   token is the only credential for the shell. One flaky reconnect orphaned
   a running shell permanently.
2. **The crash window.** A client that crashes between `ShellAttached` and
   persisting the rotated token comes back holding only the superseded
   token. The server-side escape hatch already existed — `OpenShell` with
   the same `(owner, idempotency_key)` returns the *same* shell with a
   fresh token (spec §9) — but the client generated the key per call and
   never stored it.

## Decision

**Typed failures.** `ServerConn::attach` returns `AttachError::Transport`
(token never judged) vs `AttachError::Rejected { code, retryable, message }`
(the server's `Error`), so policy can key off the wire code instead of
string matching. The daemon now emits the distinct `ERR_TOKEN_REPLAYED`
(code 11) for superseded tokens, backed by a bounded per-shell ring of the
last 64 superseded token hashes in session-core, plus a
`ShellOperationRejected` audit event with a dedicated `TokenReplayed`
reason and a `token_replays_detected` metric (spec §12's "possible theft"
signal).

**Retry policy** (pure function `attach_failure_action`, unit-tested):

| Failure | Action |
|---|---|
| `Transport` | retry with backoff, same token |
| `ERR_TOKEN_EXPIRED` / `ERR_TOKEN_REPLAYED`, key stored | recover via idempotency key |
| same, no key stored | forget entry, exit |
| `ERR_NOT_FOUND` | forget entry, exit (the only other legitimate forget) |
| any `retryable: true` | retry with backoff |
| other non-retryable (auth, forbidden) | exit, **keep** the token |

**Recovery** first confirms via `ListShells` that the shell still exists
and is running (re-opening with the old key after the shell died would
silently create a fresh shell), then re-opens with the stored key, verifies
the returned shell id matches (terminating the accidental shell on the
impossible mismatch), persists the fresh token, and reattaches.

**State schema.** `ShellEntry` gains an optional hex `idempotency_key`,
written at open time and preserved across token rotations. The file gains a
`version` field (currently 1; newer versions are refused, not rewritten),
atomic tmp+rename writes created 0600, a rename-aside backup on parse
failure instead of the old silent reset, a `dirs::config_dir()`-based
portable path, and a `HOLDFAST_STATE` override for tests and the desktop
client.

## Deliberately deferred

- A crash between *sending* `OpenShell` and the first persist can still
  orphan a brand-new shell (the key exists only in memory during that
  window). The desktop client closes this with a persist-before-send
  journal (`pending_opens`); retrofitting `hf` was not worth the churn for
  an interactive open.
- `AttachShell.last_seen_revision` / `last_history_line_id` remain unused —
  every reattach ships a full snapshot. Acceptable at current sizes; a
  bandwidth optimization for a many-shell desktop client later.
- An idle-shell expiry reaper (threat model T6) becomes more pressing as
  clients hold shells indefinitely; separate ADR when designed.
