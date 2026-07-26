# ADR 0005: One WebTransport endpoint for browser and native clients (v0)

Date: 2026-07-16 · Status: accepted and implemented (updated 2026-07-18;
partially resolves plan open question O5/#12)

## Decision

v0 exposes a **single WebTransport endpoint** (HTTP/3 over QUIC, UDP) that
both browser and native clients use. A separate raw-QUIC ALPN for native
clients is deferred: wtransport's Rust client gives native code the full
stream + datagram feature set through the same endpoint, so a second ALPN
would duplicate surface area without adding capability today. Revisit if the
native client (Phase 5) needs QUIC features WebTransport cannot expose
(e.g. finer migration control).

Channel mapping (spec §2): every bidirectional stream is a channel; the first
client-opened stream is control (0); frames are the plain §3 encoding.
WebSocket remains the fallback with identical semantics — verified by a test
that opens a shell over WebTransport and reattaches it over WebSocket.

## Certificates in development vs production

- Development: fresh self-signed identity per daemon start, 14-day validity
  (the `serverCertificateHashes` ceiling); the browser fetches the SHA-256
  from `/webtransport-info` and pins it. No trust-store changes needed.
- Production: publicly trusted ACME certificate on a DNS-only hostname,
  UDP 443 owned by the daemon/gateway (nginx keeps TCP 443; it cannot proxy
  WebTransport — verified against nginx docs/feature requests 2026-07).

Production identity loading is implemented with the paired CLI flags
`--wt-cert <fullchain.pem>` and `--wt-key <privkey.pem>`. The chain and key are
read with pre-allocation ceilings (1 MiB/eight certificates and 64 KiB), the
private key must be mode 0600 or stricter, and a non-loopback WebTransport bind
refuses the generated self-signed development identity. `/webtransport-info`
returns `certificateMode`: browsers use `serverCertificateHashes` only for
`hash-pin` development identities and normal WebPKI for configured `webpki`
identities. The SHA-256 remains available for native pinning and SSH challenge
channel binding in both modes.

Certificate/key pairing, permissions, non-loopback fail-closed behaviour, the
discovery mode, and a real configured-certificate WebTransport handshake are
covered by `crates/daemon/tests/webtransport_tls.rs`. Renewal currently requires
an atomic file update followed by a daemon restart.

## Datagrams

Still deferred per spec §7: reliable `TerminalOutput` is the baseline; screen
datagrams are a Phase 3+ experiment to run only after adverse-network testing
exists. Negotiation already strips the DATAGRAMS capability on WebSocket.

## Migration and resume

QUIC-level connection migration is transparent when the client's QUIC stack
performs it. The tested guarantee (Phase 3 exit criterion, resume clause) is
application-level: a client reconnecting from a different UDP address resumes
the logical shell with its rotated resume token and retained history —
`address_change_resume_over_webtransport` in `crates/daemon/tests/webtransport.rs`.
Adverse-network tests (loss/reorder/netem) need root/namespaces and live in
`tests/packet-loss/` as Phase 7 work.
