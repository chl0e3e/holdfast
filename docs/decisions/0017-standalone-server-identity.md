# ADR 0017: standalone server identity derived from the grant signing key

- Status: accepted
- Date: 2026-07-25
- Relates to ADRs 0006 (grants), 0011 (agent identity); threat model T1
- Fixes the standalone half of "grants survive a daemon restart"

## Context

Connection grants are audience-bound: `GrantClaims.aud` is the issuing
daemon's `server_id` hex, and `GrantVerifier::verify` rejects any other
audience. The standalone daemon, however, generated a fresh random
`ServerId` on every start. `--grant-key` therefore only half-worked: the
signature still verified after a restart, but the audience check failed
(`WrongAudience`), so every stored client grant died with the process. The
threat-model claim that the signing key is persistable "so grants survive
restart" was unachievable in standalone mode; `--server-id` existed but was
compiled in only for agent mode, where the gateway needs a pre-agreed
identity.

This matters more with clients designed to reattach everything after a
client-machine reboot (desktop client): every daemon restart (ACME renewal
restarts it every few weeks) would otherwise force interactive SSH re-auth.

## Decision

Standalone identity resolves in this order:

1. `DaemonConfig.server_id` / `--server-id srv_<hex>` — explicit pin, now
   available standalone (previously agent-mode only).
2. Derived from the grant signing key when `--grant-key` is set:
   `ServerId` = first 16 bytes of
   `SHA-256("holdfast-server-id-v1" || ed25519 public key of the signer)`.
3. Random per start (dev only; grants are ephemeral there anyway).

Deriving from the key's **public** half keeps seed material out of anything
that carries the id (logs, wire envelopes, audit records). Persisting the
one secret an operator already manages yields both signature and audience
stability; no second state file is introduced.

Consequences:

- Rotating the grant signing key changes the derived identity. That is
  coherent: rotation invalidates all outstanding grants regardless, so
  keeping the old id has no value — unless an operator pins `--server-id`
  explicitly, which is supported but not needed by any current flow.
- The reference systemd units now pass
  `--grant-key /var/lib/holdfast/grant.key` (under `StateDirectory=holdfast`)
  so production deployments get stable identity by default.

## Migration

On the first restart after deploying this change with `--grant-key`, the
audience changes once (old random id → derived id). Stored client grants
fail verification once; clients fall back to SSH-key auth automatically and
store a fresh grant. Shells never survived daemon restarts, so nothing else
is lost. No client changes are required.

## Alternatives considered

- **Separate id file in the state directory**: a second secretless artifact
  to create, back up, and desynchronize from the key; rejected as more
  moving parts for no additional property.
- **Mandatory `--server-id`**: pushes a hex-generation step onto every
  operator and invites copy-paste collisions across hosts; rejected as a
  default (kept as an override).
- **Decoupling the audience from the server id**: would let identity float
  while grants stay valid, but the id is on every wire envelope and in every
  audit record — two identities for one daemon invites confusion; rejected.
