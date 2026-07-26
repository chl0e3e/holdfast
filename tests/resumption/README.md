# Shell resumption tests

A shell is persistent state owned by `hf-session-core`; an attachment is a
temporary transport binding. Resume tokens rotate after every successful
attachment, stale tokens fail, and an authenticated owner check remains
mandatory even when a token is valid.

Automated coverage:

- `crates/session-core/tests/lifecycle.rs` — detach/reattach, token rotation,
  replay rejection, owner isolation, retained screen/history, and termination;
- `crates/daemon/tests/ws.rs` — browser-style reload reattaches two shells;
- `crates/daemon/tests/webtransport.rs` — reconnect from a new QUIC endpoint
  and cross-transport WebTransport→WebSocket reattachment;
- `crates/native-client/tests/client.rs` — native reconnect with persisted
  rotated token; and
- `crates/native-client/tests/netem.rs` — blackhole, reconnect, and retained
  state under real network shaping.

Run:

```bash
cargo test -p hf-session-core --test lifecycle
cargo test -p hf-daemon --test ws --test webtransport
cargo test -p hf-native-client --test client
tests/packet-loss/run.sh blackhole
```
