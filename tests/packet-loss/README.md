# Adverse-network tests (pending — Phase 7)

Planned per the project plan's testing strategy: latency/jitter, packet loss
and reordering, UDP blocked, client address change, long-pause reconnect,
duplicate/late datagrams, slow-consumer flow-control pressure.

These need `tc netem` inside Linux network namespaces (root), so they are not
part of the default `cargo test` run. Until they land, the covered subset is:

- Client address change + resume: `cargo test -p hf-daemon --test webtransport`
  (`address_change_resume_over_webtransport`).
- Slow-consumer detach: bounded attachment queues in hf-session-core
  (`pump` drops slow attachments, never blocks the shell).
- UDP unavailable: the browser client falls back to WebSocket when the
  WebTransport connect fails or times out (3 s).
