# ADR 0032: local SOCKS5 forwarding through a standalone daemon

- Status: accepted; implemented
- Date: 2026-09-09
- Scope: Windows desktop, native client and standalone daemon

The user requests an `ssh -D` style local proxy. Holdfast's own QUIC connection
continues to connect directly. This follow-on to the completed core phases adds
TCP forwarding without coupling the daemon to the administration overlay.

The desktop starts a loopback-only SOCKS5 listener on an explicitly chosen port
(1080 by default) for a selected server. It supports no-auth CONNECT with IPv4,
IPv6 and DNS names as defined in [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928).
DNS names are resolved on the daemon. BIND, UDP ASSOCIATE and SOCKS4 are rejected.
The listener is deliberately like loopback `ssh -D`: other local processes may
use it while it is enabled. Starting it does not change OS proxy settings.

The daemon enables forwarding only for explicitly configured authenticated
usernames (`--tcp-forward-user USER`, repeatable), with an additional `tcp-forward`
grant operation check. This grants access to TCP destinations reachable by the
daemon, including its loopback/private network; sockets run as the daemon's
unprivileged account, not a shell account. No destination restrictions are
silently inferred. Operators may constrain daemon egress with their firewall.

Protocol minor 3 adds a negotiated TCP_FORWARD capability and separate framed
forwarding channels. No proxy traffic enters a PTY, terminal model, history or
control channel. Each direction has one outstanding data frame (8 KiB maximum)
or EOF, acknowledged only after its destination socket accepts it. This bounds
buffering without blocking the connection dispatcher on a slow TCP peer. EOF
half-closes one direction; full close, error, Stop or connection loss aborts the
forward. TCP connections are never resumed/replayed after reconnect.

Bounds: 16 forwards per connection/listener, 32 per authenticated user, 128 per
daemon; at most 256 configured forwarding users; 255-byte ASCII hostname/IP,
port 1..65535; 10-second SOCKS handshake and destination connect deadlines;
30-second write/ack deadlines; 5-minute connection inactivity deadline. The local TCP accept backlog is 16. Per-forward input
and acknowledgement queues each hold at most one message. The desktop permits
one listener per configured server, stops it on disconnect/removal, and requires
an explicit Start after reconnect or application restart. No listener is saved.

Implementation gates are sequential:

1. Schema/specification, negotiation and validation tests.
2. Daemon authorization, limits, stream isolation and forwarding tests.
3. Native SOCKS listener and real-QUIC TCP/half-close/rejection tests.
4. Desktop commands, status controls, frontend checks and client-core tests.

Reproduce each gate:

```sh
cargo test -p hf-protocol --locked -j 2
cargo test -p hf-daemon --test tcp_forward --locked -j 2
cargo test -p hf-native-client --test socks --locked -j 2
cargo test -p hf-client-core --lib --test core --locked -j 2
cargo test --workspace --locked -j 2
cargo clippy -p hf-protocol -p hf-daemon -p hf-native-client -p hf-client-core \
  --lib --bins --locked -j 2 -- -D warnings -A clippy::unnecessary-map-or
cd desktop && npm test && npm run typecheck && npm run build
npx playwright install chromium
node scripts/connection-smoke.mjs
```

The desktop server action is now **Connect**, containing the remembered-login
preference and SOCKS controls. The authentication prompt also offers the existing
opt-in preference before submitting a login. This keeps ADR 0031's DPAPI and
default-off persistence policy intact. Separately, `CoreEvent` uses explicit
camelCase variant fields so live `fileUploads`, `totalBytes`, and `exitCode`
match the desktop IPC contract; a regression test failed before that fix.

Trade-off: stop-and-wait 8 KiB forwarding limits throughput on high-RTT links.
A larger negotiated credit window may follow with its own bounds and tests.
