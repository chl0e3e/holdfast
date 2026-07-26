# ADR 0011: Agent-mode shell ownership and reconnect

Date: 2026-07-18 · Status: accepted; shell-open slice implemented · Relates to
core Phase 6 / overlay Phase O2

## Decision

Build `holdfastd --agent` as an outbound-only, feature-gated runtime:

- the default `hf-daemon` build remains standalone and has no `hf-agent`
  dependency;
- `cargo build -p hf-daemon --features agent-mode` enables the agent CLI and
  requires an explicit gateway address/name, stable `server_id`, agent CA,
  certificate/private key, central grant verification key, and grant audience;
- agent mode starts no HTTP, WebSocket, or WebTransport listener;
- one shared local `ShellManager` owns every PTY and scrollback ring; the
  reconnect supervisor owns only the temporary QUIC link;
- gateway `AgentOpenShell` requests pass through that manager's local
  `AccessPolicy`, privilege-drop launcher, resource limits, and local quotas.
- agent mode refuses to start without an explicit account policy; the
  standalone development `AllowAll` fallback is unavailable.

Every shell-open also carries a central connection grant. The agent holds the
central issuer's verification key and independently verifies signature, expiry,
configured gateway audience, explicit server scope, `open` operation, and the
signed subject. mTLS authenticates the gateway transport; it does not authorize
the gateway to invent a user. Only after grant verification does local account
policy run.

The control frame carries bounded user/account/command metadata and an exact
16-byte idempotency key. A policy denial returns `ERR_FORBIDDEN`; the gateway
cannot bypass local policy. Repeating the same `(owner, idempotency_key)` after
re-registration returns the original running `shell_id`, which both makes
gateway retries safe and proves that link loss did not recreate the shell. A
grant is capped at 8 KiB and the configured audience at 256 bytes.

Reconnect delay uses bounded exponential backoff (250 ms initially, 10 seconds
maximum by default). Status is fixed-size atomics (`connected`, registration
count); reconnect logs contain no gateway-provided free text, terminal content,
commands, users, credentials, or tokens.

## Why feature-gated

Agent mode is shared with the optional administration overlay, while direct
browser/native login to a standalone daemon remains the primary product. An
optional Cargo dependency makes that boundary enforceable: ordinary builds do
not compile or import overlay registration code, and agent mode cannot silently
start an inbound core listener.

## Scope

This slice satisfies outbound registration, local-policy-authorized PTY launch,
and recovery of the same live shell identity after a forced gateway disconnect.
ADR 0012 subsequently adds bounded gateway-to-agent attachment streams. The
client-facing gateway routing layer remains separate overlay work.

## Verification

```bash
cargo test -p hf-daemon --features agent-mode --test agent_mode
cargo test -p hf-agent
cargo test -p hf-gateway
```

The daemon integration test uses real loopback QUIC/mTLS, rejects a forged grant
and a disallowed Unix account, opens an allowed PTY, closes the gateway
connection, waits for automatic registration, and retries the same idempotency
key. It receives the same still-running `shell_id` with `reused=true`.
