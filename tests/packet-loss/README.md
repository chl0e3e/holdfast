# Adverse-network tests (netem)

Exercises the protocol over real WebTransport/QUIC while `tc netem` shapes the
loopback link. Every protocol channel is a reliable, ordered QUIC stream, so
these assert two distinct behaviours:

- **Impairment is masked.** Under latency+jitter, packet loss, and reordering,
  a large ordered output burst still arrives complete and in order, and its
  scrollback is intact — QUIC retransmits and re-sequences beneath us.
- **A sustained blackhole triggers resume.** 100% loss severs the QUIC
  connection; the daemon detaches but keeps the shell running. Once the
  blackhole clears, the client reconnects from a fresh endpoint with the
  rotated token and finds screen + scrollback intact and the shell still
  interactive (the application-level resume path).

## Running

```bash
tests/packet-loss/run.sh            # all scenarios
tests/packet-loss/run.sh blackhole  # scenarios matching a filter
```

The scenarios live in `crates/native-client/tests/netem.rs` and are
`#[ignore]`d, so a normal `cargo test` never runs them. `run.sh` builds the
test binary and runs it inside an **unprivileged user + network namespace**, so
no root is required — it relies on `kernel.unprivileged_userns_clone = 1` and
`tc` (iproute2). The test process holds `CAP_NET_ADMIN` over its private
loopback and drives `tc netem` directly, so it can shape the link mid-session
(e.g. raise a blackhole and later clear it). If namespaces or `tc` are
unavailable, both `run.sh` and a bare `cargo test -- --ignored` skip with a
message instead of failing.

## Scenarios

| Test | netem profile | Asserts |
|------|---------------|---------|
| `latency_and_jitter_are_masked` | `delay 40ms 15ms 25%` | ordered burst + history complete |
| `packet_loss_is_masked_by_retransmission` | `loss 15%` | ordered burst + history complete |
| `reordering_and_loss_are_masked` | `delay 10ms reorder 30% 50% loss 5%` | ordered burst + history complete |
| `blackhole_then_resume` | `loss 100%` then cleared | connection severed, then resume restores screen/scrollback and interactivity |

## Still deferred

- Client-address-change resume is covered separately over QUIC in
  `cargo test -p hf-daemon --test webtransport` (`address_change_resume_over_webtransport`).
- Slow-consumer flow-control pressure is covered by the bounded per-attachment
  queues in `hf-session-core` (a slow attachment is detached, never blocking the
  shell).
- Multi-hop / real-NIC (veth across two namespaces) shaping is not needed for
  these assertions; loopback netem exercises the same QUIC stack.
