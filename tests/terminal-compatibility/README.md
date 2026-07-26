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

Before a broad release, manually exercise full-screen applications (`vim` or
`neovim`, `less`, `top`, `watch`, and nested `tmux`) plus wide Unicode,
combining characters, emoji, rapid resize, and long output in both the browser
and native client. Those subjective rendering checks complement, rather than
replace, the deterministic automated corpus.
