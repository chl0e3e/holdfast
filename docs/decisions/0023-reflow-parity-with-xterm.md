# ADR 0023: reflow parity between the server model and xterm.js

- Status: accepted
- Date: 2026-08-10
- Relates to spec §8 (screen model, snapshots), §10 (v0 history keeps its
  original wrapping); ADR 0004 (server-authoritative screen model)
- No wire change

## Context

The attach snapshot and the live byte stream are rendered by two independent
terminal emulators: the vendored `avt` on the server, and xterm.js in the
browser and desktop clients. Any disagreement between them is invisible while
a client stays attached and appears the moment it reattaches — the class of
bug that produced the zero-width shearing, the Unicode-11 emoji garbling and
the burst-wedge stale frames.

`tools/render-diff` now makes that disagreement measurable: it replays one
corpus through both sides and diffs the resulting grids, including after a
roaming resize. It found, and we fixed, several outright defects — most
seriously that narrowing the terminal *destroyed* text (reflow overflow was
neither kept on screen nor pushed into history) and that content which still
fitted was scrolled off the top instead of absorbed into the blank rows below
the cursor.

What remains is narrower and different in kind. When re-wrapped content
genuinely cannot fit the new screen, the two emulators agree on the content
but disagree, by one row, about how far the screen has scrolled. Eleven corpus
cases show it; a weechat-shaped layout shrunk from 80 to 60 columns comes back
with every row shifted by one. Nothing is lost, but the screen is visibly not
where it was.

Two ways to close it:

1. **Match xterm.js's `_reflowSmaller` exactly** in the vendored fork. This
   chases a specific implementation rather than a specification, and xterm.js
   is free to change it. The fork already carries several holdfast-specific
   patches; making it track another project's internals would make it
   permanently un-droppable and every upstream bump a re-verification.
2. **Make the server authoritative across a resize.** The screen model is
   already the authority everywhere else (ADR 0004): reflow parity only
   matters because the client renders its *own* reflow and then keeps it.
   If, after a resize settles, the client re-rendered from a fresh
   server snapshot at the new size, no client-side reflow would survive to
   diverge — and the whole class closes rather than these eleven cases.

## Decision

- Option 2 is the direction. The client's own reflow is a rendering
  convenience, not a source of truth, and it should not outlive the resize
  that produced it.
- It needs **no wire change**: `AttachShell` already carries the requested
  `cols`/`rows` and already returns a `ScreenSnapshot` for exactly this
  purpose, and the web client already has the reattach-and-re-render path
  (`reattachDropped` → `attachShell` → `render`). The change is to debounce
  resize and drive that existing path, not to add a message.
- It is **deliberately not part of this change**. It alters live client
  behaviour under window dragging, interacts with the `presented` gating and
  live-chunk buffering added for the burst wedge, and cannot be verified from
  the harness alone — it needs a real browser and a live daemon. Shipping it
  untested next to a batch of model fixes would risk trading a one-row offset
  for a reattach storm.
- Until then the eleven cases stay **reported, not suppressed**: the harness
  lists them as failures and `tools/render-diff/README.md` names them.
- Reimplementing xterm.js's reflow in the fork is rejected outright.

## Notes

- Divergences that are a *bounded* model behaviour rather than a defect (the
  per-cell zero-width cap, the ambiguous 4-subparameter colon colour form) are
  flagged `bounded` in the corpus and reported in their own section, so the
  failure list stays meaningful.
- The vendored `avt` fork has now diverged further from upstream: zero-width
  cell attachment, the zero-width cap, colour-form preservation
  (`Color::Ansi` vs `Color::Indexed`), SGR 8/58/`4:n`, semicolon-form colour
  dumps, TBC/HTS instead of CTC for tab stops, and reflow absorption. An
  upstream bump must re-run the harness, not just avt's own tests.
