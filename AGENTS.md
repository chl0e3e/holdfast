# Agent instructions for Holdfast

1. Read `/home/development/src/admin/quic-terminal-plan.md` (including its
   addendum) before making changes; it is the design source of truth. Then read
   `protocol/specification.md` and `docs/decisions/`.
0. Core-first: the primary product is the standalone `holdfastd` daemon with
   direct browser WebTransport / native QUIC login and local authentication.
   Multi-server administration is a separate overlay project; do not couple the
   core daemon to any central service.
2. Do not modify `/home/development/sites/mod.uk` or its Nginx preview config.
3. Work phase by phase (Phase 0 → 8 in the plan). Do not start a later phase's
   surface area to "save time".
4. Respect crate dependency direction, documented in the workspace `Cargo.toml`:
   `protocol`, `terminal-model` and `pty` must not import HTTP or QUIC
   implementations; the control plane must never parse terminal bytes.
5. Terminology is normative (see the plan's Terminology section): a **shell** is a
   persistent logical PTY; an **attachment** is a temporary stream bound to it;
   never use "session" where "shell" is meant.
6. Wire-format changes require updating `protocol/specification.md` and
   `protocol/messages.proto` in the same change. Do not serialize Rust structs as
   an accidental wire format.
7. Every queue, buffer and scrollback ring must have an explicit bound. Reject
   oversized frames before allocation.
8. The open questions listed at the end of the plan must be decided deliberately
   and recorded in `docs/decisions/` — never silently guessed in code.
9. Verify each phase with automated tests and record exact reproduction commands
   in the relevant README or decision record.
10. Code in `spikes/` is disposable and must never be imported by `crates/`.
