# Multiple-shell coverage

One authenticated connection may own multiple persistent shells and temporary
attachments. Browser tabs map to shells, while each WebTransport bidirectional
stream or WebSocket logical channel maps to an attachment.

`crates/daemon/tests/ws.rs::browser_reload_reattaches_two_shells_with_screen_and_scrollback`
opens two independent PTYs, writes distinct output, drops the browser-style
connection, and restores both screens and histories. Session-core tests also
enforce per-user shell and attachment caps; the WebTransport suite caps
concurrent bidirectional streams at 64.

```bash
cargo test -p hf-daemon --test ws browser_reload_reattaches_two_shells_with_screen_and_scrollback
cargo test -p hf-session-core --test lifecycle shell_and_attachment_limits_are_enforced
cargo test -p hf-daemon --test webtransport concurrent_bidi_streams_are_capped
```
