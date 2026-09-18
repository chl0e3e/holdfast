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

Bounds: 32 forwards per connection/listener, 64 per authenticated user, 256 per
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

## Browsing capacity and stream cleanup (2026-09-18)

The deployed proxy reached its original 16 concurrent TCP connections during
ordinary browsing. The listener accepted and immediately dropped excess
connections, producing browser failures. Raise the explicit bounds to 32 per
connection/listener, 64 per user and 256 per daemon. This leaves room within the
existing 64 QUIC stream ceiling for control, attachments and uploads. At local
capacity stop accepting until a task completes; the existing 16-entry TCP
backlog bounds pending connections. Reap completed tasks before accepting more.
Sustained saturation can still exceed the backlog or browser deadlines.

A real-QUIC regression also stalled on request 63: completed channel readers
left their writer queues and stream send halves alive, exhausting stream
credit. Closing a channel now closes its writer and completed reader tasks are
reaped. On Windows, explicitly cancel dropped stream halves because the
MsQuic wrapper does not do this on drop. A successful SOCKS relay finishes its
send stream after both EOF exchanges, preserving the final acknowledgement.
Cancelled forwards remain non-resumable; existing byte, queue and timeout
bounds are unchanged. There are no new messages or capability requirements.

Reproduce cleanup, capacity admission, half-close and authorization regressions:

```sh
cargo test -p hf-native-client --test socks --locked -j 2
cargo test -p hf-daemon --lib --test tcp_forward --test webtransport --test frontdoor_bridge --locked -j 2
cargo check -p hf-native-client --lib --target x86_64-pc-windows-msvc --locked -j 2
```

The SOCKS tests make 100 successive requests on one QUIC connection and hold
32 simultaneous forwards while checking that the next request waits and is
admitted after a slot is released. Windows runtime verification remains a
separate gate from the Linux integration and Windows compilation checks.
