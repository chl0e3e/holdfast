# ADR 0026: the deployment's glibc `wcwidth` is the width authority

- Status: accepted
- Date: 2026-08-11
- Relates to ADRs 0004 (avt as the terminal model), 0023 (reflow parity with
  xterm.js)
- Supersedes the "one width authority end to end" framing in
  `tools/xterm-width-tables`, which counted two parties where there are three
- No wire change, no protocol change

## Context

A terminal has no way to ask what a character looks like. Every participant
independently *computes* how many cells a codepoint occupies, and if any two
disagree the screen shears: a row is laid out at one width and painted at
another, and everything after the disagreeing glyph is displaced.

The project has always framed this as a two-party problem — the server model
(vendored avt) must equal the client (xterm.js via the generated
`ServerWidthAddon`) — and closed it by generating the client's table from the
same `unicode-width` crate avt measures with. Those two do agree.

**There is a third party, and it is the one that actually lays out the
screen.** The application inside the shell — weechat, and everything else built
on ncurses — decides where to wrap and how wide to pad by calling the C
library's `wcwidth(3)`. Holdfast then draws those bytes with a table generated
from a Rust crate. Nothing has ever compared the two.

Measured exhaustively on 2026-08-11 (glibc 2.41, `C.UTF-8`, U+0020..U+10FFFF,
against the committed `unicode-width` 0.1.14 table):

| class | count | examples |
| --- | --- | --- |
| glibc 2, crate 1 | 206 | contiguous from U+2630 (trigrams) — symbols/dingbats |
| glibc 1, crate 0 | 58 | U+00AD SOFT HYPHEN |
| glibc 0, crate 1 | 37 | U+0897, U+2D7F |
| glibc 2, crate 0 | 2 | U+302E, U+302F (Hangul tone marks) |
| glibc 1, crate 2 | 1 | U+17A4 |
| **total** | **304** | |

Separately, glibc returns -1 ("not printable in this locale") for 819,568
codepoints that both emulators place as a one-cell glyph.

Two facts make this worth acting on rather than noting. First, the disagreeing
set is not exotic: U+00AD arrives from any web paste, and the 206-codepoint
symbol block is exactly the range IRC channel art draws from. Second, this is
invisible to `tools/render-diff` **by construction** — both of its sides are
generated from the same table, so they agree with each other and disagree with
the application together. The harness reporting 100% parity was never evidence
about this bug.

## Decision

**Generate every width table from a committed dump of glibc's `wcwidth(3)`.**

`tools/xterm-width-tables/data/wcwidth-glibc-2.41-C.UTF-8.txt` is the
authority: one measured character per codepoint, with a provenance header. The
generator reads it and emits all three consumers — `web/src/client/`
`server-width.ts`, `desktop/src/server-width.ts`, and `vendor/avt/src/`
`widths.rs` for the model. `unicode-width` is no longer consulted by anything
that draws; the crate stays only so `--example uwdump` can show what it *would*
have said, which is how the dump gets audited.

### The trade-off this accepts

`wcwidth` is a property of a machine, not of Unicode. Before this change,
`cargo run -p hf-xterm-width-tables` was reproducible anywhere and its output
was a pure function of `Cargo.lock`. Now it is a function of a dump measured on
one host, and **a deployment on a different glibc is out of parity by design.**

That is accepted because the alternative is worse in practice: the current
table is not host-independent-and-correct, it is host-independent-and-wrong
everywhere. A declared, versioned host dependence beats an undeclared universal
mismatch. Two things bound the risk:

- The fleet is homogeneous and was verified so, not assumed: odysseus and iliad
  both run Debian glibc 2.41-12+deb13u3 and produce byte-identical sweeps of
  all 1,112,032 codepoints (same SHA-256).
- The measurement is locale-independent within UTF-8. `en_US.UTF-8` agrees with
  `C.UTF-8` on every codepoint, so the locale a shell happens to inherit does
  not change the answer. `crates/pty` guarantees at least `C.UTF-8`.

A glibc upgrade is therefore a deliberate act: regenerate the dump, review the
diff, and commit it. `cargo run -p hf-xterm-width-tables -- --check` in CI
fails loudly if the generated files and the dump ever disagree.

### glibc's -1 maps to width 1

This is the one place the authority is deliberately overridden. Following the
measurement literally would give width 0 to 819,568 codepoints that both
emulators currently render, swallowing them and desynchronising the cursor
across a set 2,700× larger than the bug being fixed. Mapping -1 to 1 preserves
today's behaviour for exactly those codepoints and keeps this change scoped to
the 304 that genuinely shear.

The override is applied in the generator, not in the dump, so the raw glibc
answer stays visible and auditable in the committed artifact.

### The model gets a generated Rust table, not an injected one

`vendor/avt/src/widths.rs` is generated into the vendored fork, symmetrically
with the two TypeScript copies, and the fork's two width call sites
(`line.rs::char_display_width` and the zero-width gate in `terminal.rs::print`)
consult it. Threading a table through `Builder → Terminal → Line` instead would
keep the data out of the vendored tree, but it adds indirection on a per-glyph
hot path and a larger fork diff for no benefit while the table is static. If
the table ever becomes per-deployment (see below), that is the point to
revisit.

## Consequences

- `tools/render-diff` still cannot see this class of bug, and no change here
  makes it able to: it would need a third measurement. What it gains instead is
  corpus coverage of the disagreement set, so model↔client agreement on exactly
  these codepoints is pinned.
- `crates/terminal-model/tests/wcwidth_authority.rs` is the model-side
  statement of the fix, one test per disagreement class. All five fail against
  the pre-0026 table; a sixth (`ascii_is_unaffected`) passes under both and is
  the control.
- `web/src/client/server-width.test.ts` gains a pin per class. Every pre-0026
  assertion in that file passes under *both* authorities — verified — so
  without the new pins the suite could not tell them apart. It also now asserts
  the two generated copies are byte-identical, which nothing checked before.
- CI gains two gates that did not exist: the `--check` drift gate, and `npm
  test` in the web job, which was never run at all.
- A client built against one dump and a daemon built against another are
  silently mismatched for the 304 codepoints. There is no handshake on the
  table. This is tolerable while the table ships inside both artifacts from one
  repo, and is the first thing that breaks if that stops being true.

## Alternatives considered

**Keep `unicode-width`.** Zero cost, and defensible only if the disagreeing
codepoints are unreachable in practice. U+00AD and the symbol block say
otherwise.

**Negotiate the table at runtime.** The daemon dumps its own libc at startup
and ships the table to clients as a capability in `ServerHello`; the model uses
the same table. This is the only option correct for every deployment
simultaneously, including hosts we do not control. It was not chosen now
because it costs a wire change, a multi-KiB handshake payload, a fallback path
for old clients, and it would make `tools/render-diff` depend on a live daemon
— but the dumper written for this ADR is deliberately the same code path such a
daemon would run, so the option stays open.

**Adopt a Unicode version the application also uses.** Chasing glibc's Unicode
data with a crate version is guesswork about someone else's build, and it would
still not match a host whose glibc is patched. Measuring the actual deployment
is both simpler and exact.
