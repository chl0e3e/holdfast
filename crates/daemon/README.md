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

## Temporary file uploads

Uploads are off by default. Enable them on a standalone daemon with an
absolute root:

```bash
holdfastd \
  --upload-root /var/lib/holdfast/uploads \
  --upload-max-bytes 268435456 \
  --upload-retention-hours 24 \
  # ...the normal bind, TLS and authentication options
```

The daemon creates private `0700` per-upload directories and `0600` files,
streams no more than 64 KiB at a time, checks the declared length and SHA-256,
and returns a path only after commit. The default file limit is 256 MiB, with a
hard 4 GiB ceiling. Limits are 2 active uploads per connection, 4 per user and
16 per daemon; inactive and disconnected uploads are aborted after 30 seconds.
Committed files are temporary and the bounded in-process reaper removes them
after the configured retention period.

Privilege-dropped multi-user deployments must configure the same upload root
on both `holdfastd` and `holdfast-spawner`, and install the tmpfiles rule:

```bash
sudo install -Dm644 deploy/tmpfiles.d/holdfast-uploads.conf \
  /etc/tmpfiles.d/holdfast-uploads.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/holdfast-uploads.conf
```

The spawner repeats peer/account authorization and changes ownership only
after verification. The network daemon does not gain `CAP_CHOWN`. Remove the
`--upload-root` argument (from both services in multi-user mode) to disable the
capability. Gateway/agent forwarding and browser uploads are intentionally not
implemented in this release.

Reproduce the upload gates with:

```bash
cargo test -p hf-upload-store --locked
cargo test -p hf-spawner --locked
cargo test -p hf-daemon --test ws --test webtransport --test auth --locked
cargo test -p hf-native-client --test client --locked
cargo test -p hf-client-core --locked
```

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
