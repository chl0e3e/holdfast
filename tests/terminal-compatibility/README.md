# Terminal compatibility coverage

Terminal correctness is split across three layers:

- `hf-pty` verifies interactive I/O, resize, backpressure, and clean child exit;
- `hf-terminal-model` verifies UTF-8 boundaries, alternate screen, snapshots,
  bounded scrollback, hostile escapes, degenerate sizes, and deterministic fuzz
  input; and
- `hf-ssh-adapter` launches a real `/usr/bin/ssh` client against a
  Holdfast-backed PTY while rejecting unauthorized keys and remote exec.

```bash
cargo test -p hf-pty
cargo test -p hf-terminal-model
cargo test -p hf-ssh-adapter --test openssh -- --nocapture
```

A fourth layer compares the two halves of the render path directly:
`tools/render-diff` feeds one corpus to both the server model and xterm.js and
diffs the resulting grids, including after a roaming resize. It also carries a
live probe that drives a real weechat under a running daemon. See
`tools/render-diff/README.md` for the corpus, the checks and the commands.

```bash
node tools/render-diff/gen-corpus.mjs > /tmp/corpus.tsv
cargo run -p hf-terminal-model --example modelgrid < /tmp/corpus.tsv > /tmp/model.tsv
(cd tools/render-diff && npm install && npx tsx xterm-diff.ts /tmp/corpus.tsv /tmp/model.tsv)
```

Before a broad release, manually exercise full-screen applications (`vim` or
`neovim`, `less`, `top`, `watch`, and nested `tmux`) plus wide Unicode,
combining characters, emoji, rapid resize, and long output in both the browser
and native client. Those subjective rendering checks complement, rather than
replace, the deterministic automated corpus.
