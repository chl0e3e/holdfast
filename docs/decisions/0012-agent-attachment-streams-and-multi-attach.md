# ADR 0012: Agent attachment streams and bounded multi-attach

Date: 2026-07-18 · Status: accepted; Phase 6 attachment slice implemented ·
Relates to core Phase 6 / overlay Phase O2 / open question O6

## Decision

Use one gateway-opened bidirectional QUIC stream for each temporary attachment
to a shell on an outbound agent. The registration/control stream remains
limited to registration, keepalive and shell lifecycle metadata; terminal
bytes never appear on it.

The first attachment-stream frame carries the user, shell identity, dimensions
and central connection grant. The managed daemon independently verifies the
grant's signature, time, configured audience, explicit server scope, `attach`
operation and subject, then checks local shell ownership. The gateway does not
receive or validate the managed daemon's local resume token. A future
client-facing gateway layer will issue its own client resume token and map it
to this backend attachment boundary.

An attachment stream has a fixed 256-KiB frame ceiling, a 64-KiB input-frame
limit, an output bridge capped at 64 messages / 512 KiB, sequential history
requests capped at 10,000 lines and half a frame in bytes, and a connection cap
of 64 attachment streams. QUIC flow control is explicitly bounded to 256 KiB
per stream and 16 MiB per connection. All size headers are rejected before
allocation.
Stream loss, detach, backpressure and grant expiry detach only the attachment;
the local `ShellManager` continues to own the PTY and bounded scrollback.

## Open question O6

v0 deliberately allows one user to attach the same shell from multiple clients,
bounded by `max_attachments_per_shell` (default 4). Each attachment has an
independent output queue. Input is ordered within each stream; when multiple
attachments send input concurrently, the local manager serializes writes in
arrival/lock-acquisition order. The newest applied resize wins. Collaborative
editing semantics, cursor ownership and stronger fairness are out of scope;
operators may configure the bound to 1 when exclusive attachment is required.

This matches the already implemented standalone behavior and avoids inventing
a different shell lifecycle for agents. The bound prevents fan-out from being
an unbounded memory or stream multiplier.

## Verification

The Phase 6 integration test must use real loopback QUIC/mTLS and a real PTY to
cover signed attach authorization, cross-user rejection, input/output, resize,
paged history, detach, gateway reconnect and history recovery from the same
logical shell. Protocol tests must cover the separate frame ceiling and reject
oversized length prefixes before allocation.

Exact commands are recorded in the daemon, agent and gateway READMEs when this
slice is complete.
