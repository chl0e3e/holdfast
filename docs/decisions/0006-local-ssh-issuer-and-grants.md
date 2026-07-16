# ADR 0006: Local SSH-key issuer and connection grants

Date: 2026-07-16 · Status: accepted (spike/test-verified) · Resolves plan open
questions O8 (browser identity — partial) and O9 (credential strategy — local case)

## Decision

The standalone daemon's local issuer (spec §5) authenticates with an **SSH
public-key challenge/response** and mints **ed25519-signed connection grants**.

### SSH challenge/response (hf-auth::ssh)

1. Client sends `SshChallengeRequest { username, public_key }` where
   `public_key` is an OpenSSH one-line key (`ssh-ed25519 AAAA… comment`).
2. Daemon checks the key against that user's `authorized_keys`. If unknown it
   fails with a generic "authentication failed" — no oracle for whether the
   user or the key was the miss (threat model T2 shape).
3. Daemon returns a random 32-byte challenge.
4. Client signs it with `SshSig` under namespace `holdfast-auth@v0`
   (`ssh-keygen -Y sign` compatible — any ed25519/RSA/ECDSA key, standard
   tooling).
5. Daemon verifies the signature against the authorized key and, on success,
   issues a grant.

Using `SshSig` rather than a bespoke signature scheme means clients can reuse
existing SSH keys and agents, and we lean on `ssh-key`'s audited verification.

### Connection grants (hf-auth::grant)

`base64url(claims).base64url(ed25519_sig)`. Claims: `sub, aud, servers, ops,
iat_ms, exp_ms, jti`. The daemon holds the signing key and verifies with the
public half — the same asymmetric split the overlay's central control plane
will use (issuer holds private key, gateways hold verify key). A successful SSH
auth hands the grant back to the client (in the AuthenticationResult
`challenge` field), so a reconnect can present the grant directly without
re-signing. Grants are audience-bound to the server id and expire (12 h default).

### Rate limiting

Per-source-address failed-attempt limiter (default: 5 failures / 60 s → 60 s
lockout), keyed by peer IP from the transport (axum `ConnectInfo` for
WebSocket, `Connection::remote_address` for WebTransport). Success clears the
bucket.

## Consequences / scope

- Dev mode (`AuthConfig::DevInsecure`) is retained for local development and
  the existing test suite, and still refuses non-loopback binds.
- The daemon maps `username → authorized_keys` from configuration
  (`--ssh-auth <user> <path>`). It does **not** yet resolve
  `~<user>/.ssh/authorized_keys` itself or setuid to the target account —
  that privilege-separated launcher is Phase 6/agent work (threat model T12),
  and until it exists the daemon runs shells as its own user.
- The **native client** (`hf`) signs SSH challenges with an OpenSSH private
  key (`--user`/`--key`) and reuses the issued grant for cheap reconnects
  (`crates/native-client/tests/ssh_auth.rs`). Passphrase-protected keys are
  not yet supported.
- Grant signing keys are per-process (regenerated each start); persisting them
  and key rotation are deployment concerns for before-beta.

## Phase 7 hardening status

Done: native-client SSH signing + grant reuse; parser fuzz/robustness
harnesses (`crates/protocol/tests/fuzz_framing.rs`,
`crates/daemon/tests/fuzz_wire.rs`); Origin allowlist (T7,
`crates/daemon/tests/origin.rs`); supply-chain CI gate
(`.github/workflows/audit.yml`).

Remaining: the netem adverse-network suite (needs root/namespaces —
`tests/packet-loss/`), the privilege-separated PTY launcher (T12, Phase
6/agent), terminal-escape/clipboard hardening in the browser client (T9), and
a manual security review before any non-loopback deployment.
