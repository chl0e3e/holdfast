# hf-gateway

`hf-gateway` is reserved for the optional administration overlay. The current
Phase 6 agent backend accepts outbound registrations, can request a shell
through the agent's local policy, and exposes bounded terminal attachments. It
does not yet serve browser/native sessions or provide the agentless SSH backend.

The gateway requires an agent-CA certificate during QUIC TLS, hashes the
presented leaf certificate, resolves that fingerprint through a hard-bounded
registry, and checks that the protobuf registration claims the same stable
`server_id`. Multiple bounded fingerprints may map to one server during
certificate rotation, while rebinding one fingerprint to another server is
rejected. Active registrations are also bounded.

`AgentOpenShell` carries fixed-bounded metadata and an idempotency key. A retry
after agent reconnect receives the same live shell identity rather than
launching a duplicate. It also carries the central issuer's opaque connection
grant; the agent independently verifies that grant, so gateway mTLS alone does
not authorize shell creation.

`RegisteredAgent::attach_shell` opens a separate bidirectional QUIC stream and
returns the coherent screen snapshot plus input, output, resize, detach, exit
and paged-history operations. The agent independently verifies an `attach`-
scoped grant and shell ownership. Backend stream loss never ends the shell;
after agent reconnect the gateway can attach again and retrieve retained local
history. See ADR 0012 and protocol specification §16 for exact bounds.

Verify it with:

```bash
cargo test -p hf-gateway
cargo test -p hf-agent --test mtls_registration
cargo test -p hf-daemon --features agent-mode --test agent_mode
```
