# ADR 0008: SSH challenge channel binding

Date: 2026-07-16 · Status: **accepted and implemented for WebTransport** (the
WebSocket path remains a documented limitation) · Relates to threat model T1/T4

> **Update (2026-07-16):** the WebTransport cert-hash binding designed below has
> since been implemented. The original deferral rationale is kept for the
> record; see "Implemented" at the end.

## Context

SSH-key authentication (ADR 0006) is challenge/response: the server sends a
random 32-byte nonce, the client returns an `SshSig` over it under namespace
`holdfast-auth@v0`. A security review flagged that the signed material is bound
to nothing about *this* server or *this* connection. That enables a relay /
man-in-the-middle: if a client is steered to a hostile server M (DNS/routing
manipulation, a malicious link), M opens its own connection to the real server
R, forwards R's challenge to the client, relays the client's signature back to
R, and is authenticated to R **as the client**.

What is already sound: the nonce is CSPRNG, single-use, and connection-scoped
(held in `pending_challenge`, `.take()`n on response), and the namespace is
checked. So cross-server *replay* of a captured signature already fails (R and S
issue independent nonces). The gap is specifically an **active relay** while the
client is signing.

## Why a server-only change does not fix it

The obvious idea — embed the server's audience/id in the challenge bytes — does
not help. The client signs whatever nonce it is handed; a relay forwards R's
audience-bearing challenge unchanged, the client signs it, and R accepts. Relay
protection *requires the client to independently bind to the identity of the
server it believes it reached* and sign that. There is no server-only fix.

## The correct fix (channel binding) and why it is deferred

Bind the signature to the TLS channel the client actually authenticated:

- **WebTransport (daemon owns TLS):** the browser already pins the server
  certificate via `serverCertificateHashes`, and the daemon knows that hash
  (`webtransport_cert_hash_base64`). Have the client sign
  `cert_hash ‖ nonce` and the server verify over `own_cert_hash ‖ nonce`. A
  relay M presents its *own* certificate to the client, so the client signs
  `M_cert_hash ‖ nonce`; R verifies against `R_cert_hash ‖ nonce` and rejects.
  Relay defeated. The native QUIC client can bind the same way.
- **WebSocket behind nginx (nginx terminates TLS):** the daemon does not see the
  client's TLS channel at all, so cert-hash binding is impossible there. The
  fallback is a weaker binding to the intended host (the `Host`/origin the
  client dialed), which stops naive cross-host relay but not an attacker who
  also controls DNS for the real hostname. This path's security therefore rests
  on the operator's TLS/PKI, as it does today.

This is deferred rather than implemented now because it is a coordinated
protocol change, not a local hardening: it alters the challenge/response wire
format and must land in lockstep across the server, the browser client
(`web/`), and the native client (`crates/native-client`), with transport-
specific handling and its own interop tests. Shipping only the server half — or
only one transport — would create false confidence without closing the attack.
A half-built authentication control is worse than a clearly documented gap.

## Decision

Defer channel binding to a dedicated, cross-client change implementing the
WebTransport cert-hash binding above (and `Host` binding for the WebSocket
path). Until then this is a known, documented limitation: **SSH-key auth
assumes the client reaches the intended server over a trustworthy TLS channel**
(correct hostname/PKI, or a pinned WebTransport cert). The connection *grant*
issued after auth is already audience-bound to the server id, so a grant cannot
be replayed to a different daemon; only the initial live challenge is
relay-exposed.

## Consequences

- Threat model T1/T4 record channel binding as the specified next step, not an
  open question.
- No wire-format churn now; the binding lands once as one reviewed, tested,
  cross-client change.
- Operators fronting the WebSocket path with nginx must treat their TLS/PKI as
  the trust anchor for that transport (already an operational requirement).

## Implemented (2026-07-16)

The WebTransport cert-hash binding is now in place:

- `hf_auth::ssh::channel_bound_message(binding, nonce)` defines the exact signed
  bytes (`binding ‖ nonce`), used identically by signer and verifier.
  `SshVerifier::verify_response` takes the binding and verifies over it.
- The daemon threads a per-connection channel binding into `Conn`: the server's
  raw certificate SHA-256 for WebTransport connections, empty for WebSocket
  (`AppState::webtransport_cert_hash` → `webtransport.rs`/`ws.rs`).
- The native client signs `pinned_cert_hash ‖ nonce`
  (`crates/native-client/src/lib.rs`), the same hash it pins for
  `serverCertificateHashes`.
- The browser client is unaffected — it does not perform SSH-key signing.

Tests: `hf-auth` `channel_binding_defeats_a_relayed_signature` (a signature over
one binding fails against another); end-to-end over real WebTransport in
`crates/daemon/tests/webtransport.rs`
`ssh_channel_binding_is_enforced_over_webtransport` (correct binding
authenticates, a relayed/wrong binding is rejected); the existing native-client
WebTransport SSH test and the WebSocket SSH tests (empty binding) continue to
pass, confirming both transports behave correctly.

Still a documented limitation: the WebSocket path carries an empty binding
(nginx terminates TLS, so the daemon cannot see the client's channel) and thus
relies on the operator's TLS/PKI — `Host` binding for it remains possible future
work but was not needed to close the WebTransport attack.
