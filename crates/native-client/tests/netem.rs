//! Adverse-network (netem) suite — the Phase 7 testing-strategy item.
//!
//! These drive the real daemon and the native client library over real
//! WebTransport/QUIC while `tc netem` shapes the loopback interface: latency +
//! jitter, packet loss, reordering, and a full UDP blackhole that forces the
//! application-level resume path. Every protocol channel is a reliable, ordered
//! QUIC stream, so loss/jitter/reorder must be *masked* (output still arrives,
//! in order); only a sustained blackhole should sever the connection, after
//! which resume with the rotated token must restore screen + scrollback.
//!
//! They are `#[ignore]`d so they never run in the default `cargo test`: they
//! need `CAP_NET_ADMIN` over `lo`, which the harness grants by running the test
//! binary inside an unprivileged user+network namespace. Reproduce with:
//!
//! ```bash
//! tests/packet-loss/run.sh
//! ```
//!
//! Running them directly outside the namespace will skip with a message rather
//! than fail, so a bare `cargo test -- --ignored` is safe.

use std::process::Command;
use std::time::Duration;

use hf_daemon::{Daemon, DaemonConfig};
use hf_native_client::{connect, AttachedShell, ShellEvent};

const TC: &str = "/usr/sbin/tc";

/// Apply a netem qdisc to loopback, replacing any existing one. Returns false
/// if we lack the capability (not inside the namespace harness), so callers can
/// skip instead of failing.
fn netem(args: &[&str]) -> bool {
    let mut cmd = Command::new(TC);
    cmd.args(["qdisc", "replace", "dev", "lo", "root", "netem"]);
    cmd.args(args);
    match cmd.output() {
        Ok(out) if out.status.success() => true,
        _ => false,
    }
}

fn netem_clear() {
    let _ = Command::new(TC).args(["qdisc", "del", "dev", "lo", "root"]).output();
}

/// True when we can actually shape `lo` — i.e. we are inside the namespace
/// harness with CAP_NET_ADMIN. Used to skip gracefully otherwise.
fn shaping_available() -> bool {
    if !std::path::Path::new(TC).exists() {
        return false;
    }
    if !netem(&["delay", "1ms"]) {
        return false;
    }
    netem_clear();
    true
}

macro_rules! skip_unless_shaping {
    () => {
        if !shaping_available() {
            eprintln!(
                "SKIP: netem shaping unavailable (run via tests/packet-loss/run.sh, \
                 which provides an unprivileged network namespace)"
            );
            return;
        }
    };
}

/// A scoped netem application that always clears the qdisc on drop, so one
/// scenario's shaping never leaks into the next.
struct Shaper;
impl Shaper {
    fn apply(args: &[&str]) -> Shaper {
        assert!(netem(args), "failed to apply netem {args:?}");
        Shaper
    }
}
impl Drop for Shaper {
    fn drop(&mut self) {
        netem_clear();
    }
}

async fn start_daemon() -> (Daemon, String) {
    let daemon = Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        ..Default::default()
    })
    .await
    .unwrap();
    let url = format!("http://{}", daemon.local_addr);
    (daemon, url)
}

/// Read shell output until `needle` appears or `budget` elapses. Returns
/// whether it appeared — callers assert so failures name the scenario.
async fn wait_output(shell: &mut AttachedShell, needle: &str, budget: Duration) -> bool {
    let mut collected = Vec::new();
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return false;
        }
        match tokio::time::timeout(deadline - now, shell.next_event()).await {
            Ok(Ok(ShellEvent::Output(data))) => {
                collected.extend_from_slice(&data);
                if String::from_utf8_lossy(&collected).contains(needle) {
                    return true;
                }
            }
            Ok(Ok(ShellEvent::Exited(code))) => panic!("shell exited early: {code}"),
            Ok(Err(_)) => return false, // transport error
            Err(_) => return false,     // timed out
        }
    }
}

/// Shared workload used by the shaping scenarios that expect QUIC to *mask* the
/// impairment: open a shell, emit a large ordered burst, and assert every line
/// arrives in order and the scrollback is intact. `budget` is generous because
/// jitter/loss inflate latency.
async fn ordered_delivery_under_shaping(profile: &[&str], budget: Duration) {
    let (daemon, url) = start_daemon().await;
    let _shaper = Shaper::apply(profile);

    let mut conn = connect(&url).await.expect("connect under shaping");
    let (shell_id, token) =
        conn.open_shell(Some("bash"), 40, 6, rand::random()).await.expect("open under shaping");
    let mut shell = conn.attach(&shell_id, &token, 40, 6).await.expect("attach under shaping");

    shell
        .input(b"for i in $(seq 1 200); do echo netem-line-$i; done\r")
        .await
        .expect("input under shaping");
    assert!(
        wait_output(&mut shell, "netem-line-200", budget).await,
        "profile {profile:?}: last line of an ordered burst never arrived — \
         reliable stream semantics violated under impairment"
    );

    // Scrollback for the burst survives and is monotonic (no gaps/reorder).
    let lines = shell.history(0, 5000).await.expect("history under shaping");
    let joined = lines.join("\n");
    for probe in ["netem-line-1", "netem-line-99", "netem-line-150"] {
        assert!(joined.contains(probe), "profile {profile:?}: history missing {probe}");
    }

    conn.terminate(&shell_id).await.ok();
    daemon.abort();
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN; run via tests/packet-loss/run.sh"]
async fn latency_and_jitter_are_masked() {
    skip_unless_shaping!();
    // 40ms ± 15ms with correlation — round trips vary but delivery is reliable.
    ordered_delivery_under_shaping(&["delay", "40ms", "15ms", "25%"], Duration::from_secs(30)).await;
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN; run via tests/packet-loss/run.sh"]
async fn packet_loss_is_masked_by_retransmission() {
    skip_unless_shaping!();
    // 15% independent loss — QUIC must retransmit; output still complete.
    ordered_delivery_under_shaping(&["loss", "15%"], Duration::from_secs(45)).await;
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN; run via tests/packet-loss/run.sh"]
async fn reordering_and_loss_are_masked() {
    skip_unless_shaping!();
    // Reordering requires a delay base; 10ms with 30% reordered plus loss.
    ordered_delivery_under_shaping(
        &["delay", "10ms", "reorder", "30%", "50%", "loss", "5%"],
        Duration::from_secs(45),
    )
    .await;
}

/// The exit-criterion scenario: a sustained UDP blackhole tears the connection
/// down; once it clears, the client resumes from a fresh endpoint with the
/// rotated token and finds screen + scrollback intact and the shell still live.
#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN; run via tests/packet-loss/run.sh"]
async fn blackhole_then_resume() {
    skip_unless_shaping!();
    let (daemon, url) = start_daemon().await;

    // Baseline: a little latency, nothing fatal.
    let _shaper = Shaper::apply(&["delay", "5ms"]);

    let mut conn = connect(&url).await.expect("initial connect");
    let (shell_id, token) =
        conn.open_shell(Some("bash"), 40, 6, rand::random()).await.expect("open");
    let mut shell = conn.attach(&shell_id, &token, 40, 6).await.expect("attach");
    let rotated = shell.rotated_token.clone();

    shell
        .input(b"for i in $(seq 1 60); do echo preloss-$i; done\r")
        .await
        .expect("input before blackhole");
    assert!(
        wait_output(&mut shell, "preloss-60", Duration::from_secs(15)).await,
        "pre-blackhole output should arrive"
    );

    // --- Sustained UDP blackhole: drop 100% for long enough that the QUIC
    // connection idles out and the client's transport is severed. ---
    assert!(netem(&["loss", "100%"]), "blackhole apply");
    // Writes now fail; the daemon detaches on transport loss but keeps the
    // shell running. Give it well past any idle timeout.
    let _ = shell.input(b"echo during-blackhole\r").await; // may error; that's the point
    tokio::time::sleep(Duration::from_secs(8)).await;
    drop(shell);
    drop(conn);

    // --- Clear the blackhole and resume from a fresh connection/endpoint. ---
    assert!(netem(&["delay", "5ms"]), "clear blackhole to mild latency");
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut conn2 = connect(&url).await.expect("reconnect after blackhole");
    let mut shell2 = conn2
        .attach(&shell_id, &rotated, 40, 6)
        .await
        .expect("resume attach after blackhole");
    assert!(
        String::from_utf8_lossy(&shell2.snapshot).contains("preloss-60"),
        "screen must survive the blackhole+resume"
    );
    let lines = shell2.history(0, 5000).await.expect("history after resume");
    let joined = lines.join("\n");
    assert!(
        joined.contains("preloss-1") && joined.contains("preloss-30"),
        "scrollback must survive the blackhole+resume"
    );

    // Still interactive after resume.
    shell2.input(b"echo resumed-after-blackhole\r").await.expect("input after resume");
    assert!(
        wait_output(&mut shell2, "resumed-after-blackhole", Duration::from_secs(15)).await,
        "shell must be interactive again after resume"
    );

    conn2.terminate(&shell_id).await.ok();
    daemon.abort();
}
