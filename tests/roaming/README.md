# Roaming and adverse-network coverage

Holdfast has two recovery layers:

1. QUIC may migrate a live connection when the client implementation permits.
2. Application-level resume always treats the shell independently from the
   connection and opens a fresh attachment with a rotating token.

The portable, tested guarantee is the second layer. A fresh client UDP endpoint
reattaches the same shell in
`crates/daemon/tests/webtransport.rs::address_change_resume_over_webtransport`.
Latency, jitter, loss, reordering, and a temporary 100% blackhole are exercised
inside a private network namespace by `tests/packet-loss/run.sh`.

```bash
cargo test -p hf-daemon --test webtransport address_change_resume_over_webtransport
tests/packet-loss/run.sh
```

Browser reload is an application reconnect, not assumed QUIC migration; it is
covered separately in `tests/resumption/`.
