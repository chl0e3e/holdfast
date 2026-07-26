# Example Holdfast configuration

`holdfastd` currently uses explicit CLI flags; the reference systemd units in
`deploy/systemd/` are the production configuration examples. There is no
silently searched global config file.

## Loopback development

Development authentication and the generated 14-day WebTransport certificate
are loopback-only:

```bash
cargo run -p hf-daemon -- \
  --bind 127.0.0.1:8080 \
  --wt-bind 127.0.0.1:4433 \
  --web-root web/dist
```

## Single-account production

Production WebTransport uses a publicly trusted PEM chain/key. The daemon owns
UDP 443; nginx may independently own TCP 443 for HTTPS and WebSocket fallback.

```bash
holdfastd \
  --bind 127.0.0.1:8080 \
  --wt-bind 0.0.0.0:443 \
  --wt-cert /etc/holdfast/tls/fullchain.pem \
  --wt-key /etc/holdfast/tls/privkey.pem \
  --web-root /var/lib/holdfast/web \
  --ssh-auth admin /var/lib/holdfast/authorized_keys \
  --allowed-origin https://terminal.example.com \
  --grant-key /var/lib/holdfast/grant.key
```

Always set `--grant-key` in production: it persists the grant-signing seed
(generated 0600 on first start) **and** pins the server identity, which is
derived from that key's public half (ADR 0017). Both are needed for stored
client logins to survive a daemon restart — grants are audience-bound to the
server id, so an ephemeral id would invalidate them even with a persisted
signing key. `--server-id srv_<hex>` overrides the derived identity if you
need to pin it independently (e.g. when rotating the signing key without
changing identity is required — note that rotation invalidates outstanding
grants regardless).

The private key must be mode `0600` or stricter. Certificate chains are capped
at 1 MiB/eight certificates and keys at 64 KiB before parsing. Install renewed
ACME material atomically, preserve permissions, and restart `holdfastd`; live
certificate reload is not implemented.

## Multi-user Unix accounts

Add one authentication and account mapping per user, then enable the
privilege-separated launcher:

```text
--drop-privileges
--ssh-auth alice /home/alice/.ssh/authorized_keys --account alice alice
--ssh-auth bob /home/bob/.ssh/authorized_keys --account bob bob
```

`--drop-privileges` refuses to start without an explicit account allowlist.
See `deploy/systemd/README.md` for capabilities and resource limits, and
`crates/daemon/README.md` for the separate outbound agent mode.
