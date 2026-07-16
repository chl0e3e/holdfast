# ADR 0001: Core-first split — standalone daemon vs admin overlay

Date: 2026-07-16 · Status: accepted (decided with the user)

## Decision

The core product is the standalone `holdfastd` daemon: a per-server install in
the spirit of `mosh-server`, speaking the Holdfast protocol directly to browser
(WebTransport, WebSocket fallback) and native (raw QUIC) clients, with
local-first authentication and a self-served browser client page.

Multi-server administration — control plane, server inventory, access policies,
central login, agentless SSH gateway — is a separate follow-on overlay project
that reuses the same protocol. `holdfastd` will gain an outbound mTLS agent
mode for it. The overlay crates (`hf-gateway`, `hf-control-plane`,
`hf-ssh-backend`, `hf-agent`) stay reserved in this workspace until the
protocol stabilizes, then may move to their own repository. The overlay's
consolidated design handoff is
`/home/development/src/admin/holdfast-overlay-plan.md`.

## Consequences

- Connection grants are issued by a pluggable issuer (spec §5): the local
  daemon (SSH authorized_keys challenge/response) or a central control plane.
  Terminal endpoints only verify signatures.
- Direct browser login requires each server to hold a publicly trusted
  certificate (ACME) and reachable UDP 443; `serverCertificateHashes` +
  self-signed (≤14-day) certs are development-only.
- Roaming and resumption live entirely in the daemon; no central service is on
  the session path.
- Core phases 0–3 of the plan are unchanged; the original Phase 4 moves to the
  overlay project and is replaced by standalone-auth hardening.
- The core must never grow a hard dependency on the overlay.
