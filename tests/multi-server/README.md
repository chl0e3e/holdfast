# Managed-server and overlay boundary

The standalone `holdfastd` daemon is the core product and has no central-service
dependency. Multi-server administration is a separate overlay described by
`/home/development/src/admin/holdfast-overlay-plan.md`.

The reusable Phase 6 agent backend is implemented: an outbound mTLS agent
registers one stable `server_id`, verifies scoped central grants, opens a local
PTY through the same policy/limits as standalone mode, and routes bounded
attachments across gateway reconnects. It does not yet constitute the
client-facing multi-server product; inventory UI, control-plane service, and
agentless SSH backend remain overlay work.

```bash
cargo test -p hf-agent --test mtls_registration
cargo test -p hf-gateway
cargo test -p hf-daemon --features agent-mode --test agent_mode
```

Cross-server identity and authorization assertions belong here when the overlay
is implemented; they must not be coupled into default standalone builds.
