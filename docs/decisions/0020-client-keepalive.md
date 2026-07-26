# ADR 0020: client-driven keepalive

- Status: accepted
- Date: 2026-07-25
- Relates to spec §6 (Ping/Pong on any channel, both directions), §14
  (liveness); ADR 0019
- No wire change

## Context

Spec §14 makes the *server* the pinger (interval from `ServerHello.
keepalive_interval_ms`, 3 missed pongs → detach), but the daemon has never
implemented its ping ticker — it only answers pings. Worse, the original
native client silently discarded any `Ping` it received (both
`AttachedShell::next_event` and the split reader dropped them), so §14
enforcement, if ever added server-side, would have detached every native
client. Meanwhile a desktop client that keeps connections open for days
needs a *fast local* failure detector: QUIC's own idle timeout is too slow
for a good "reconnecting" UX, and a half-dead NAT path can otherwise linger
for minutes.

## Decision

- The client library surfaces `ShellEvent::Ping(nonce)` and provides
  `pong()` on both `AttachedShell` and `AttachmentWriter`; every driver
  (hf CLI, ssh-adapter bridge, client-core pumps) answers pings on every
  channel. This makes clients forward-compatible with server-side §14
  enforcement.
- The desktop core's control-channel actor additionally *sends* `Ping` on
  the control channel at the negotiated `keepalive_interval_ms` (daemon
  advertises 15 s; fallback 15 s when absent) and declares the connection
  dead after 3 unanswered pings, triggering the supervisor's
  reconnect/backoff path. Spec §6 already allows client→server pings on any
  channel, so this needs no wire or spec change.
- The hf CLI does not send pings (a human notices a dead session; the
  automatic resume loop already covers it).

## Notes

- The daemon's own §14 ping ticker remains unimplemented; when it lands,
  clients built on this ADR already comply.
- Ping/pong traffic is nonce-matched per channel; the control actor resets
  its miss counter on any pong (matching by nonce adds state for no extra
  signal — a late pong still proves the path is alive).
