# holdfastd

The default build is the standalone Holdfast daemon with direct browser and
native login:

```bash
cargo run -p hf-daemon -- --web-root web/dist
```

That default is loopback development mode with a generated, hash-pinned
WebTransport certificate. A non-loopback UDP bind requires a configured public
certificate and private key:

```bash
cargo run -p hf-daemon -- \
  --bind 127.0.0.1:8080 \
  --wt-bind 0.0.0.0:443 \
  --wt-cert /etc/holdfast/tls/fullchain.pem \
  --wt-key /etc/holdfast/tls/privkey.pem \
  --web-root web/dist \
  --ssh-auth admin /var/lib/holdfast/authorized_keys \
  --allowed-origin https://terminal.example.com
```

The configured key must be mode 0600 or stricter. Renewed files take effect
after restarting the daemon.

The optional administration overlay enables an outbound-only agent runtime. It
starts no inbound HTTP/WebSocket/WebTransport listener:

```bash
cargo run -p hf-daemon --features agent-mode -- \
  --agent \
  --gateway 203.0.113.10:4433 \
  --gateway-name gateway.example.test \
  --server-id srv_0123456789abcdef0123456789abcdef \
  --agent-ca /etc/holdfast/gateway-ca.pem \
  --agent-cert /etc/holdfast/agent.pem \
  --agent-key /etc/holdfast/agent-key.pem \
  --grant-verify-key /etc/holdfast/central-grant-pubkey.hex \
  --grant-audience terminal-gateway \
  --account alice alice \
  --drop-privileges
```

The gateway must pre-authorize the SHA-256 fingerprint of the agent leaf
certificate for exactly that `server_id`. Old and next fingerprints may overlap
during rotation. Agent shell requests are always rechecked against the local
`--account` policy and use the same `prlimit`/optional `setpriv` launcher as
standalone mode. The grant verification file contains exactly 64 hexadecimal
characters (the central issuer's 32-byte Ed25519 public key). Each shell-open
grant must be signed, unexpired, audience-bound, explicitly scoped to the agent
server ID, permit the requested `open` or `attach` operation, and name the same
user sent by the gateway. The agent private-key file must be mode `0600` or
stricter on Unix.

The Phase 6 agent backend can register, launch an authorized shell, route a
bounded terminal attachment, detach, reconnect and recover retained history
from the same live shell. The separate overlay still lacks its client-facing
gateway service and agentless SSH backend.

Agent mode refuses to start without at least one explicit `--account` mapping;
it never falls back to the standalone development `AllowAll` policy.

Verify both build modes and the real-QUIC agent lifecycle with:

```bash
cargo test -p hf-daemon
cargo test -p hf-daemon --test webtransport_tls
cargo test -p hf-daemon --features agent-mode --test agent_mode
```
