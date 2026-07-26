# ADR 0014: HTTP/3-only — the QUIC endpoint serves the page, no TCP fallback

- Status: accepted
- Date: 2026-07-19

## Context

Until now the QUIC endpoint spoke only WebTransport (the `wtransport` server
rejects every HTTP/3 request whose method is not an extended CONNECT), so the
browser client page had to be served over the TCP HTTP listener, and a
WebSocket transport existed as a silent fallback for browsers whose UDP path
was blocked. The operator asked for the opposite posture: the product is
QUIC-only — the same HTTP/3 endpoint should serve the page, and there must be
no fallback transport.

Two browser realities constrain the design:

- Browsers never *start* at HTTP/3. A typed URL is fetched over TCP first;
  HTTP/3 is used only after the origin advertises it (an `Alt-Svc` response
  header or an HTTPS DNS record), and only on an origin with WebPKI TLS.
- The `serverCertificateHashes` mechanism that lets the development
  self-signed certificate work applies exclusively to the JavaScript
  WebTransport API, never to page navigation. A development page load can
  therefore never arrive over HTTP/3.

## Decision

The daemon's QUIC endpoint is now a real HTTP/3 server (hyperium `h3` +
`h3-quinn` + `h3-webtransport`, replacing the `wtransport` server; the native
client and tests keep the `wtransport` client, which interoperates over the
shared `h3` ALPN). Per connection, the first request decides the mode: an
extended CONNECT (`:protocol = webtransport`) upgrades the connection into a
WebTransport session whose bidirectional streams are protocol channels exactly
as before; any other request is served as a bounded static-file GET from the
web root (plus `/webtransport-info`). Browsers give each WebTransport session
its own QUIC connection, so page and terminal traffic never contend.

The TCP listener is demoted to a bootstrap:

- **Production (operator certificate, WebPKI):** every TCP path returns a
  small interstitial ("loading over QUIC / QUIC is required") carrying
  `Alt-Svc: h3=":<udp-port>"`. The interstitial reloads a few times while the
  browser adopts the Alt-Svc route; once requests move to HTTP/3 the daemon
  serves the real app. If the browser never upgrades, the page states that
  QUIC is required — there is no TCP fallback and the app is not served over
  TCP at all.
- **Development (self-signed, hash-pin):** the TCP side serves the app
  directly (a browser cannot load a page over HTTP/3 from a hash-pinned
  certificate), and the app's terminal connection is WebTransport with the
  pinned hash, as before.

The browser client is WebTransport-only: the WebSocket transport, the silent
3-second fallback, and every fallback affordance are removed. When QUIC is
unreachable the client says so and retries with backoff.

The WebSocket endpoint (`/terminal/ws`) survives only behind
`DaemonConfig::enable_websocket`, default **off**, with no CLI flag: the
shipped binary never exposes it. It exists so protocol tests can continue to
prove the session layer is transport-neutral (spec §2) over a second
transport. The Origin allowlist (T7) is now enforced on the WebTransport
CONNECT request headers (browsers always send `Origin` there); requests
without an Origin header — native clients — remain allowed.

## Consequences

- One public contact surface story: UDP/QUIC carries everything a browser
  needs; TCP exists to say "go to QUIC" (and for nginx-fronted deployments,
  which keep working — nginx forwards the interstitial and its Alt-Svc
  header while the daemon owns UDP).
- Networks that block UDP can no longer use the browser client at all. That
  is the point of this decision, and the interstitial says it plainly.
- The h3 GET surface is new parseable input on the public endpoint. It is
  bounded like everything else: explicit stream caps (shared with channel
  streams), a request-path length cap, literal path matching (no
  percent-decoding), traversal-shaped paths rejected before touching the
  filesystem, and a fixed per-file size ceiling.
- The `wtransport` server dependency is replaced by hyperium `h3 0.0.8`,
  `h3-quinn 0.0.10` (datagram feature) and `h3-webtransport 0.1.2` — younger
  crates than `wtransport`; the compensating control is the existing
  real-QUIC integration suite (session lifecycle, address-change resume,
  channel binding, stream caps, origin enforcement, page serving), which all
  passes against the new stack.
- Dropping WebSocket from the product removes the nginx-TLS-terminated
  browser path, which was the one transport where SSH-challenge channel
  binding (ADR 0008) could not apply. Browser terminal traffic is now always
  channel-bound.
