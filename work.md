# Work in progress — handoff notes

Rewritten 2026-08-11. Working tree is **clean**. Everything below is committed
on `main`. This file is untracked and not in `.gitignore` — delete it or ignore
it before committing anything else.

---

## Where things stand

Yesterday's four commits (`78dc184`, `4bb5ea8`, `a6fda98`, `56561fb`) are
**pushed**. Four more landed today:

| Commit | What |
| --- | --- |
| `63d6f4d` | Web keepalive fits inside an un-raised peer's idle limit twice over |
| `0e9976b` | The width authority is the deployment's glibc wcwidth, not a Rust crate (ADR 0026) |
| `0c91317` | The terminal model tracks OSC 8, so reattaching keeps hyperlinks |
| `e013536` | Web client: stop losing running shells, and dropped output, across a reattach |

**These four are NOT pushed and NOT deployed.** See "Deployment" below.

### `0e9976b` — the width authority (ADR 0026)

The big one. Width parity was always framed as two parties — server model vs
xterm.js — and both were generated from `unicode-width`. There is a third, and
it lays out the screen: the application, measuring with glibc `wcwidth(3)`.
**304 codepoints disagreed** (not 305; the earlier note's U+17D8 does not
reproduce). All three tables — both clients and `vendor/avt/src/widths.rs` —
now generate from a committed glibc dump in `tools/xterm-width-tables/data/`.

Read the ADR before touching this. The trade-off it accepts is that the table
is now **host-dependent**; that was justified by measuring, not assuming, that
odysseus and iliad produce byte-identical sweeps. Re-verify before adding a
host on a different glibc.

`cargo run -p hf-xterm-width-tables -- --check` is now a CI gate, as is
`npm test` in the web job, which had **never been run in CI** — so even the
pre-existing width pins were unenforced.

### `0c91317` — OSC 8

Needs no protocol change: the snapshot is an escape-sequence redraw carried as
opaque bytes, so tracking links in the fork is enough. Two traps, both silent
if missed and both now tested: a link-only pen change produced an empty `Sgr`,
which dumps as bare `CSI m` (a full attribute reset); and the link bled into
every blank an erase touched, making erased regions clickable.

Bounds are chosen against the **16 KiB negotiable frame floor**, not the
256 KiB default, because a snapshot too large for one frame fails attach
outright rather than degrading.

---

## Corrections to the previous handoff

Two things the old notes asserted that turned out to be false. Both were found
by re-measuring rather than re-reading, which is worth repeating.

- **"Every one of the 13 harness failures is a resize check."** Not true.
  `tab-stops` and `repeat-rep-after-combining` also fail `grid` and
  `model-text` at the attach size. They are now listed separately in
  `tools/render-diff/README.md` because they are not reflow and want their own
  investigation.
- **"305 codepoints" for the wcwidth gap.** It is 304.

Current harness baseline, re-measured today: **`pass 210 fail 11 bounded 7`
over 228 cases** (was 201/13/7 over 221).

---

## Deployment

**odysseus and iliad both run `56561fb`** — i.e. yesterday's work including
YubiKey. Today's four commits are **not deployed anywhere**.

Verified live on both after deploying, not inferred from timestamps:

| | odysseus | iliad |
| --- | --- | --- |
| binary | sha `965c838f…`, user-presence string present | same sha |
| served-shell `CapBnd` | `000001ffffffffff` | `000001fffffeffff` |
| `sudo` | `uid=0(root)` | clean password prompt |

iliad's one missing bit is `CAP_SYS_MODULE`, from `ProtectKernelModules=yes` on
line 33 of its unit — deliberate hardening, inherited only because iliad still
forks shells in-process. Irrelevant to `apt`.

**iliad had the ADR 0024 capability bug live** (`CapBnd 00000000000004e4`,
`sudo: unable to send audit message`). Fixed by commenting out line 11's
`CapabilityBoundingSet=` in `/etc/systemd/system/holdfastd.service`. iliad has
no spawner: porting the ADR 0024 split there is still open.

### Gotchas corrected

- **A mosh session is not a served shell.** The old note said restarting
  `holdfastd` kills Claude's own shell. It does not if you are on `mosh`
  (`ulimit -u` 514370, parented to PID 1, not to the daemon) — check before
  contorting into a detached restart. It *does* kill everyone else's shells.
- **odysseus has passwordless sudo.** iliad does not.
- Rollback points: `/usr/local/bin/holdfastd.bak-20260811` on both;
  `/etc/systemd/system/holdfastd.service.bak-20260811` on iliad.

---

## Open threads

### ADR 0023's client change — still deferred, now unblocked

The prerequisites landed in `e013536`; the re-render-from-snapshot work itself
did not. Three things to know before picking it up:

1. **It will not turn the harness green.** The harness diffs the model against
   xterm.js's reflow directly. Re-rendering from a snapshot changes the
   product, not the comparison. The 9 reflow cases stay red; they stop being a
   question *about the product*. Decide what those checks should assert.
2. **It needs a real browser and a live daemon** — drag behaviour, whether a
   full repaint per settle reads as "snapped into place" or "flashed", and
   whether a stream whose recv side finished still counts against
   `max_concurrent_bidi_streams(64)`.
3. **Three server-side bounds nobody currently hits** come into play once
   resize drives re-attach: `max_attachments_per_shell: 4` (the 5th
   un-detached re-attach returns ERR_LIMIT_EXCEEDED, which the web client does
   not handle), the 64-stream cap, and a daemon writer table that never
   releases send halves (`webtransport.rs:502-518`).

Open decisions: fresh channel + server-side teardown vs channel reuse; whether
re-attach preserves scroll position and fetched history.

### Client OSC 8 link policy — a decision, not a bug

`links.ts` claimed "OSC 8 stays inert — an escape sequence must not be able to
relabel a destination" (T9). **That was never true of the running client.**
xterm.js's core registers its own `OscLinkProvider` unconditionally and neither
client sets a `linkHandler`, so OSC 8 links have always been clickable via
xterm's own `confirm()` + `window.open`, bypassing the `LinkPopover` that
exists so the user always sees the true destination.

xterm's dialog does disclose the real URL, so the property is not lost — but it
is xterm's mitigation, not the project's. The comment is now corrected to say
so. **Whether to route OSC 8 through `LinkPopover` via `linkHandler` is an open
decision.** `0c91317` deliberately changed no client link behaviour.

### Unverified

- **The YubiKey hardware test has never been run.** Deployed on both hosts, and
  covered by a software authenticator, but the real round trip needs a physical
  key and two touches:
  ```bash
  HOLDFAST_SECURITY_KEY_TEST=1 cargo test -p hf-auth --test security_key_cli -- --ignored --nocapture
  ```
- **`e013536`'s three fixes are not browser-verified** — typecheck, web suite
  and bundle build only.

### Worth a look

- **`tab-stops` and `repeat-rep-after-combining` fail at the attach size**, not
  just on resize. Newly identified; nobody has looked at why.
- **The orphan zero-width column steal** in xterm.js (needs column 0, no
  preceding cell) — happens with xterm's own providers, so the width addon
  cannot fix it.
- **Porting the ADR 0024 spawner split to iliad.**
- **File upload / drag-a-screenshot-to-`/tmp`.** Discussed, not built. Needs no
  file browser: the WebTransport session already multiplexes streams as
  protocol channels, so a third channel kind is the natural fit, and the ADR
  0024 spawner is the natural place to open the destination fd as the target
  user. It is a new *write primitive into a user's filesystem*, so it wants an
  ADR covering destination policy, bounds, and audit.

---

## Gotchas

- **This box's process ceiling breaks builds in a way that reads as a compiler
  bug** — but only *inside a served shell* (`ulimit -u` 512). Two concurrent
  cargo jobs exhaust it and rustc dies with `could not exec the linker cc`.
  Re-run serially with `-j 4`. A mosh session is not affected.
- **Review subagents will edit your working tree.** Spawn them read-only.
  To audit: source mtimes, not `git diff` — restored files compare identical.
- **Don't pipe `cargo test` through `tail`.** The pipeline's exit status is
  `tail`'s, which is always 0 — a failing suite reads as green. Redirect to a
  file and check `$?`.
- **`vendor/avt` is a separate crate** (excluded from the workspace, wired via
  `[patch.crates-io]`). `cargo test --workspace` and `cargo clippy --workspace`
  do **not** cover it; run them in `vendor/avt` too.

## Re-running the render harness

```bash
node tools/render-diff/gen-corpus.mjs > /tmp/corpus.tsv
cargo run -p hf-terminal-model --example modelgrid < /tmp/corpus.tsv > /tmp/model.tsv
cd tools/render-diff && npm install
npx tsx xterm-diff.ts /tmp/corpus.tsv /tmp/model.tsv
```

Current: `pass 210  fail 11  bounded 7` over 228 cases. Re-measure rather than
trusting this line — it has been stale twice now.
