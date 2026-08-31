# ADR 0030: opt-in shared HTTP/3 front door with a bounded Unix stream bridge

- Status: accepted; implemented and source-qualified
- Date: 2026-08-31
- Relates to ADRs 0001, 0008, 0014 and 0022; threat models T1, T7 and T11
- No Holdfast wire-protocol change

## Context

Holdfast currently owns its UDP HTTP/3 listener. dockerwm now has a separately
packaged HTTP/3 front door that can select independent certificates, assets and
WebTransport routes for multiple exact TLS SNI hostnames on one UDP port. The
operator wants Holdfast and dockerwm to share UDP 443 without terminating
Holdfast through TCP, WebSocket, HTTP/2 or a browser fallback.

The front door cannot merely open a second local WebTransport connection to
Holdfast. SSH challenge authentication is bound to the SHA-256 of the public
leaf certificate (ADR 0008); a second TLS hop would substitute the local
certificate and make a correctly signed browser response fail. It would also
hide the original peer address. Conversely, importing Holdfast's terminal or
authentication protocol into the router would turn a least-authority routing
process into an application server and violate the core-first boundary.

## Decision

`holdfastd` gains an optional shared-front-door backend mode. Standalone mode
and its direct HTTP/3 listener remain the default and retain all existing
behaviour. Backend mode is mutually exclusive with the direct QUIC listener.

The front door and daemon communicate through the version-2 bounded Unix
bridge already implemented by `dockerwm-h3-frontdoord` (`DWMH3B02` request and
`DWMH3A02` acknowledgement). The bridge carries only:

- one random 256-bit session identity;
- monotonically increasing stream identities;
- the original peer socket address;
- the exact canonical TLS SNI hostname; and
- the SHA-256 of the leaf certificate selected for that hostname.

Each WebTransport bidirectional stream is proxied byte-for-byte over a separate
Unix stream. Holdfast framing, authentication, shell ownership, terminal data,
uploads and grants remain entirely inside `holdfastd`. The bridge adds no
Holdfast envelope and changes no protocol capability.

`holdfastd` validates the kernel peer UID on every bridge connection, the exact
configured hostname on every session and stream header, all reserved bytes,
address family and port, the non-zero session identity, the non-zero
certificate binding, monotonically ordered stream identities, session and
stream limits, handshake deadlines and bounded queues before acknowledging a
connection. The socket lives in an operator-protected runtime directory and is
removed only if it is still the inode created by this daemon.

The selected public leaf hash becomes `Conn`'s ADR 0008 channel binding for
that session. The front door already enforces exact SNI, HTTP/3 authority,
WebTransport path and same-origin browser `Origin` before it creates the
bridge. `holdfastd` independently rejects a bridged hostname different from its
configured hostname. Native clients may omit `Origin`, exactly as with the
direct listener.

The front door serves Holdfast's bounded built assets and a root-owned static
`/webtransport-info` document. For WebPKI production it contains the public UDP
port, `certificateMode: "webpki"`, the base64 SHA-256 of the exact public leaf
certificate (required by ADR 0008's browser signing flow), and the configured
password-authentication availability. Certificate renewal must regenerate and
atomically install this document with the certificate. The normal TCP endpoint
remains only an Alt-Svc/"QUIC required" bootstrap; it never becomes an
application fallback.

The two implementations deliberately share a wire contract rather than a Rust
crate or source-tree dependency. Holdfast therefore stays buildable and usable
without dockerwm. Cross-repository conformance tests send malformed headers in
both directions and run a real browser through the packaged front door to the
real Holdfast session handler. Any bridge revision requires a new magic/version
and simultaneous compatibility evidence.

## Consequences

- One Quinn/rustls UDP listener can route Holdfast and the disposable dockerwm
  viewer by exact TLS SNI while preserving distinct certificates and service
  identities.
- Holdfast remains a standalone product; deployments that do not configure the
  bridge compile and run as before.
- The shared front door becomes part of Holdfast's production trust path, but
  it gains no terminal or authentication authority and runs under a distinct
  unprivileged UID.
- HTTP assets are an explicit allowlist loaded from protected files. Adding a
  new web asset requires updating the front-door configuration rather than
  silently widening a filesystem-serving surface.
- A front-door restart ends current WebTransport attachments. Shells remain
  owned by `ShellManager` and clients reattach using their normal tokens.

## Required verification

1. Unit tests round-trip the exact bridge header and reject wrong magic,
   reserved bytes, hostname, UID, identity, binding, address and stream order.
2. A daemon integration test drives a real Holdfast control channel through
   the Unix bridge and proves the supplied certificate hash is required by SSH
   challenge verification.
3. A cross-repository test runs Holdfast and the dockerwm viewer on two SNI
   hostnames behind one front-door UDP socket, loads both pages over HTTP/3 and
   opens both WebTransport sessions.
4. The existing Holdfast workspace, direct WebTransport, origin, HTTP/3 page,
   native client and Windows Schannel compile gates continue to pass.
5. Installed-package and live UDP-443 tests verify service identities,
   protected assets/configuration, restart behaviour and removal independently
   for each backend.
