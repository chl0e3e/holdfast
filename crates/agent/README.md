# hf-agent

`hf-agent` owns the optional administration overlay's outbound managed-server
link. It is not imported by standalone daemon mode.

The current Phase 6 slice establishes mutual-TLS QUIC registration over ALPN
`holdfast-agent/0`, sends the explicit bounded `AgentEnvelope` protobuf, and
verifies the gateway's accepted stable `server_id`, and exchanges bounded
application keepalives. One `AgentConnector` can reconnect without owning or
resetting local shell state.

The reconnect supervisor now composes the link with one shared
`hf-session-core` manager. Gateway shell-open requests pass through the local
policy and launcher only after the agent independently verifies the central
grant's signature, expiry, audience, server, operation, and subject. Idempotent
retries after reconnect recover the same shell.

Each temporary attachment uses its own gateway-opened bidirectional QUIC stream.
The agent re-verifies an `attach`-scoped central grant and local shell ownership,
then routes reliable input/output, resize, detach, exit and paged history. Frame,
stream, QUIC flow-control, input, output-queue and history bounds are fixed by
protocol specification §16. Dropping the stream or gateway link detaches without
terminating the locally owned shell.

Verify the unit and real loopback mTLS integration tests with:

```bash
cargo test -p hf-agent
cargo test -p hf-daemon --features agent-mode --test agent_mode
```
