# ADR 0004: Terminal model library — avt

Date: 2026-07-16 · Status: accepted (spike-verified)

## Decision

`hf-terminal-model` wraps **avt 0.18** (asciinema's virtual terminal).
Holdfast owns the scrollback ring; avt owns VT semantics.

Configuration: `scrollback_limit(0)` on the primary buffer, so every line that
scrolls off the visible screen is immediately evicted by avt and handed back
from `feed_str(...).scrollback` — the model commits those lines to its own
bounded ring with stable, monotonically increasing history line IDs (spec §10).

Spike evidence (`cargo test -p spike-terminal-model`):

- Scrolled-off primary lines are returned to the caller in order (padded to
  terminal width; the model trims on commit).
- Alternate-screen output (smcup/rmcup) yields zero history lines and restores
  the primary screen — avt's alternate buffer is created with no scrollback.
- `Vt::dump()` reproduces the visible screen and cursor in a fresh emulator —
  used directly as the attach `ScreenSnapshot` payload.
- Resize reflows without losing content.

## Alternatives

- **vt100 0.16** — excellent redraw primitives (`contents_formatted`,
  `contents_diff`, useful again in Phase 3 for screen deltas), but no eviction
  hand-off: scrolled-off lines are only reachable by mutating a scrollback
  view offset, and nothing signals eviction, so stable line IDs would require
  fragile bookkeeping. Verified in the same spike.
- **alacritty_terminal 0.26** — most battle-tested grid, but a heavyweight
  dependency designed for a GUI emulator (event-listener plumbing, config
  surface), with history access oriented at rendering, not hand-off. Not
  integrated in the spike; rejected on dependency-weight and API-fit grounds.

## Consequences

- avt takes `&str`, so the model maintains an incremental UTF-8 decoder for
  chunk boundaries (spec: UTF-8 only; split multi-byte sequences must be
  handled). Raw bytes are still forwarded verbatim to live attachments; only
  the model's copy goes through the decoder.
- History lines are stored as styled text reconstructed from avt `Line`
  chunks (v0: plain text + trailing-whitespace trim; styling revisit noted in
  the spec's reflow decision).
- If avt's semantics prove insufficient later (e.g. Phase 3 deltas), vt100's
  diff primitives are the fallback; the model's public API must not leak avt
  types so the swap stays contained.
