# Render differential harness

Every rendering bug this project has shipped had the same shape: the screen
looked right while you watched it, and was wrong when you came back. That is
always a disagreement between the two halves of the render path —

- **server**: `hf-terminal-model` (vendored `avt`) builds the attach snapshot;
- **client**: `xterm.js` plus the generated `ServerWidthAddon`.

This harness renders the same bytes through both and diffs the resulting grids
cell by cell — characters, widths, colours and attributes — so a disagreement
is a test failure rather than something a user notices weeks later.

**What it structurally cannot see.** Those two sides are not independent on
width: both are generated from the same table (ADR 0026), so where that table
is wrong they agree with each other and are wrong together. That is exactly how
the 304-codepoint `wcwidth` gap survived a 100%-parity report — the third
party, the application laying out the screen with glibc, is not in this
comparison and cannot be added without a third measurement. The guard for that
class lives elsewhere: `cargo run -p hf-xterm-width-tables -- --check` in CI,
and `crates/terminal-model/tests/wcwidth_authority.rs`. The `wcwidth-*` corpus
cases here pin only the half this harness *can* prove — that the model and
xterm.js still agree on the codepoints that moved.

## Offline corpus

221 single-purpose cases covering Unicode width/composition, CSI/SGR, cursor
and scrolling, alternate screen, input-encoding modes, charsets, OSC/DCS
strings, raw mIRC formatting, and composite stress shapes. See `corpus.mjs`.

```bash
node tools/render-diff/gen-corpus.mjs > /tmp/corpus.tsv
cargo run -p hf-terminal-model --example modelgrid < /tmp/corpus.tsv > /tmp/model.tsv
cd tools/render-diff && npm install
npx tsx xterm-diff.ts /tmp/corpus.tsv /tmp/model.tsv
```

Set `ONLY=<regex>` to run a subset. Each case is checked four ways:

| check | question |
| --- | --- |
| grid | does the reattach snapshot render identically to the live bytes? |
| model-text | does the model's own view match what the client shows? |
| chunk-boundary | does the snapshot change if bytes arrive one at a time? |
| resize-grow / resize-shrink | after roaming to 100×30 or 60×20, does the snapshot still match? |

## Current results

`pass 208  fail 13  bounded 7` over 228 cases at 80×24 (plus the 100×30 and
60×20 roaming checks), re-measured 2026-08-11 after ADR 0026 regenerated the
width tables. Note that the 13 failures are **not** all resize checks, as an
earlier note claimed: `hyperlink-osc8`, `hyperlink-osc8-with-id` and
`tab-stops` differ at the attach size too. The two hyperlink cases are the
model not tracking OSC 8 at all, so the snapshot drops the attribute.

Fixed off the back of this harness, each with a regression test in
`crates/terminal-model/tests/render_parity.rs`:

- truecolor was dumped as `38:2:R:G:B`, which a spec-following parser reads
  with R as the colour-space id — every 24-bit colour changed on reattach;
- narrowing the terminal **destroyed** text: reflow overflow was neither kept
  on screen nor pushed to history, and content that still fitted was scrolled
  off the top instead of absorbed into the blank rows below the cursor;
- SGR 58's operands were left unconsumed, so underlined text came back
  blinking; colon-form underline styles and SGR 8 were dropped entirely;
- invalid UTF-8 became U+FFFD (one column) where xterm.js drops it — a column
  shift on every bad byte;
- combining marks were capped at three per cell, truncating subdivision-flag
  tag sequences and stacked diacritics;
- legacy (`31`) and indexed (`38;5;1`) palette colours were collapsed into one
  representation, though xterm.js renders them differently under bold.

Known remaining divergences, all reported by the harness rather than hidden.
**Every one of the 13 is a resize check** — `resize-grow` or `resize-shrink`,
often both. At the attach size the two emulators now agree on the whole
corpus: no case fails `grid`, `model-text` or `chunk-boundary`. The remaining
disagreement is entirely about reflow.

- **reflow scroll offset** (11 cases): when re-wrapped content cannot fit, the
  model and xterm.js disagree by a row about how far the screen scrolls.
  Content is intact on both sides; only the anchor differs. The decision on
  how to close it — re-render from a fresh server snapshot after a resize,
  rather than chasing xterm.js's `_reflowSmaller` — is ADR 0023; the client
  change it calls for is deliberately not part of this work. These are
  `wide-at-last-column`, `bg-colour-erase-to-eol`, `cursor-clamp-out-of-range`,
  `repeat-rep-after-combining`, `scroll-region-with-colour`, `tab-stops`
  (the snapshot restores stops portably via TBC/HTS; what remains shows up
  only after a reflow), `decaln`, `scroll-past-screen`,
  `scroll-past-screen-coloured`, `full-screen-redraw` and
  `weechat-like-layout`.
- **OSC 8 hyperlinks** (2 cases): the model does not track hyperlinks, so
  reattaching drops them. Needs per-cell hyperlink state in avt. Visible here
  only through the resize checks, which re-diff the reattached grid.

## Live weechat probe

Drives a *real* weechat under a live `holdfastd`, so the bytes under test are
genuine application output rather than hand-written sequences. `fake-ircd.py`
is a minimal IRC server that pushes a formatting torture corpus (mIRC colour
and attribute codes, emoji and ZWJ sequences, bidi, invalid UTF-8) at the
client; `run-weechat.sh` starts both against a throwaway weechat config
directory so an operator's own session is never touched.

Stage on the server, then run the probe from this box:

```bash
ssh user@<host> mkdir -p /tmp/hf-render
scp tools/render-diff/fake-ircd.py user@<host>:/tmp/hf-render/
scp tools/render-diff/run-weechat.sh user@<host>:/tmp/hf-render/run.sh
ssh user@<host> chmod +x /tmp/hf-render/run.sh

cargo run -p hf-client-core --example ircprobe -- \
    https://<host> <user> ~/.ssh/id_ed25519 /tmp/live
cd tools/render-diff && npx tsx xterm-diff.ts /tmp/live-corpus.tsv /tmp/live-model.tsv
```

The probe captures every live output byte, roams (detach → reattach), captures
the snapshot, and writes both in the corpus format so the same differ consumes
them. Leave ~60s between runs: the daemon's auth rate limiter will otherwise
reject the login.
