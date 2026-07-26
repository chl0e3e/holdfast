# ADR 0010: Separate mTLS agent identity and registration link

Date: 2026-07-18 · Status: accepted; registration foundation implemented ·
Relates to overlay Phase O2 / core Phase 6

## Decision

Managed-server agents connect outbound to a dedicated raw-QUIC endpoint using
ALPN `holdfast-agent/0`. The gateway requires a client certificate issued by an
agent CA. After PKI validation, it hashes the presented leaf certificate with
SHA-256 and looks that fingerprint up in a bounded local registry. Each
fingerprint maps to exactly one stable opaque `server_id`.

The first bidirectional stream uses the explicit `AgentEnvelope` protobuf schema
in `protocol/messages.proto`, framed by a checked u32 big-endian payload length.
The authenticated certificate mapping and the claimed `server_id` must agree.
The 1–16 KiB registration/keepalive frame range is checked before payload
allocation, and build metadata is capped at 128 bytes.

Certificate rotation uses bounded overlap: operators register the next leaf
fingerprint for the same `server_id`, deploy it, observe a successful reconnect,
then remove the old fingerprint. Rebinding a fingerprint to a different server
is rejected. The CA proves membership in the agent PKI; the explicit registry
mapping proves which server that member represents.

## Why a separate link

Browser/client sessions and managed-server agents have different trust roots,
roles, and allowed messages. A separate ALPN prevents either peer type from
being routed into the other's protocol state machine and keeps overlay code out
of the standalone listener. Raw QUIC also leaves later shell-routing streams
independent of the small registration control stream.

Certificate subject/SAN text is not used as authorization identity. It is
operator-chosen display metadata and is awkward to rotate safely. Fingerprints
are exact, stable registry keys and allow an explicit two-certificate overlap.

## Scope and follow-up

This decision covers the first Phase 6 slice: mTLS establishment, stable
identity selection, bounded registration, and reconnect. ADR 0011 subsequently
added locally authorized shell-open operations and preservation across gateway
loss. ADR 0012 subsequently added the explicit bounded terminal attachment
stream protocol.

## Verification

```bash
cargo test -p hf-protocol
cargo test -p hf-agent
cargo test -p hf-gateway
```

The integration suite uses a disposable CA and real loopback QUIC connections
to cover trusted registration, certificate/server-ID mismatch, certificate
rotation overlap, and reconnect under the same stable server identity.
