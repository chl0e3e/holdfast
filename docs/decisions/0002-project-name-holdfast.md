# ADR 0002: Project name — Holdfast

Date: 2026-07-16 · Status: accepted (decided with the user)

The project is named **Holdfast**: the anchoring structure a kelp uses to stay
attached through storms, and the naval order "hold fast". Sessions hold fast
while the client roams.

- Daemon binary: `holdfastd`
- Workspace crates: `hf-*`
- Project directory: `/home/development/sites/holdfast/`
- Candidate CLI name: `hf` (final decision when the native client lands)

Checked 2026-07-16: `holdfast` was unregistered on crates.io. Alternatives
considered: limpet (crates.io squatted), roamsh, quicksh, tern (conflicts with
the well-known Go migration tool and a 164k-download crate), quill, remora,
barnacle, peregrine (all taken).
