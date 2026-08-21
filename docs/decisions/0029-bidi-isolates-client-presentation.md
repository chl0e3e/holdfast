# ADR 0029: discard bidi isolates at the client presentation boundary

- Status: accepted
- Date: 2026-08-21
- Relates to ADRs 0004 (server-authoritative screen model), 0023 (render
  differential parity), 0026 (glibc width authority), and threat model T9
- No wire change, no protocol change

## Context

WeeChat title bots emit U+2068 FIRST STRONG ISOLATE and U+2069 POP
DIRECTIONAL ISOLATE around YouTube titles and channel names. The bytes are
present verbatim in the `iliad` WeeChat logs. glibc correctly reports both as
zero columns.

The existing headless differential corpus included the exact live line and
passed. That was misleading: the harness compared xterm.js buffer cells, not
browser pixels. With Holdfast's width provider, xterm.js attaches the opening
isolate to the preceding cell (usually a space) and the closing isolate to the
last visible character. Its renderer then paints each cell in a separate
Canvas `fillText` call. A paired FSI/PDI sequence therefore reaches the browser
as two independent, unbalanced strings and cannot perform its Unicode bidi
function. Browser/font combinations may show a box or otherwise mispaint the
cell even though the headless buffer geometry is correct.

Implementing the Unicode Bidirectional Algorithm over a mutable terminal grid
is a distinct, much larger feature. It requires paragraph boundaries, shaping,
cursor mapping, selection mapping and redraw semantics; passing controls into
independent cell paints is not a partial implementation of it.

The terminal bidi working group's basic level-1 mode discards bidi controls.
That is also the least surprising behavior for Holdfast's current strictly
cell-ordered renderer: visible characters remain in the logical order emitted
by the application, and invisible controls cannot turn into glyphs or affect
cell measurement.

## Decision

- The web and desktop clients discard U+2066 LRI, U+2067 RLI, U+2068 FSI and
  U+2069 PDI immediately before bytes are written to xterm.js.
- The daemon continues forwarding the raw PTY bytes unchanged, and protocol
  frames are unchanged. The authoritative terminal model continues retaining
  the isolates in its cell state. This is a presentation policy, not a wire
  rewrite.
- The filter is streaming and retains at most two bytes, because protocol
  frames may split a three-byte UTF-8 encoding at either boundary. All
  non-matching and malformed bytes pass through unchanged.
- Snapshot, history and live output use the same filter. A reattach therefore
  cannot reintroduce the controls or diverge from the live presentation.
- This decision is deliberately limited to isolates. Embeddings, overrides,
  directional marks and general RTL shaping need their own evidence and
  decision rather than an unreviewed expansion of the filter.

## Verification

The exact live title-bot pattern and isolate-at-column-zero cases are in
`tools/render-diff/corpus.mjs`. Client unit tests exercise every split point,
byte-at-a-time delivery, false UTF-8 prefixes and filter reset:

```sh
cd web && npm test && npm run typecheck
cd desktop && npm test && npm run typecheck
node tools/render-diff/gen-corpus.mjs > /tmp/corpus.tsv
cargo run -p hf-terminal-model --example modelgrid < /tmp/corpus.tsv > /tmp/model.tsv
cd tools/render-diff && npx tsx xterm-diff.ts /tmp/corpus.tsv /tmp/model.tsv
```

The differential harness applies the client presentation filter to both raw
live output and server snapshot replay. Its model-text check removes the same
controls before comparison, while the model itself continues to preserve
them.
