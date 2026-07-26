//! Hostile escape-sequence corpus for hf-terminal-model (threat model T9).
//!
//! The model sits on the server and parses attacker-controlled PTY output
//! (e.g. `cat`ing a malicious file), so every entry here must be survivable:
//! no panic, no hang, history bounds respected, and the model still renders
//! ordinary output afterwards. Reproduce with:
//! `cargo test -p hf-terminal-model --test hostile`

use hf_terminal_model::{TerminalModel, TerminalModelConfig};

fn model(cols: u16, rows: u16) -> TerminalModel {
    TerminalModel::new(TerminalModelConfig {
        cols,
        rows,
        max_history_lines: 200,
        max_history_bytes: 64 * 1024,
    })
}

/// Feed one corpus entry, then prove the model is still alive: a plain marker
/// line must render, the snapshot must replay into a fresh emulator, and the
/// history ring must respect its configured bounds.
fn assert_survives(name: &str, payload: &[u8]) {
    let mut m = model(40, 6);
    m.feed(payload);

    // Escape any in-flight string sequence (OSC/DCS/SOS/PM/APC) with CAN and
    // ST so the marker is interpreted as ordinary text, then leave the alt
    // screen in case the payload switched to it.
    m.feed(b"\x18\x1b\\\x1b[?1049l\x1b[0m\r\nMARKER-ALIVE\r\n");
    let on_screen = m.visible_lines().iter().any(|l| l.contains("MARKER-ALIVE"));
    let in_history = m
        .history_range(0, 1000, 1 << 20)
        .lines
        .iter()
        .any(|l| l.contains("MARKER-ALIVE"));
    assert!(
        on_screen || in_history,
        "{name}: model unusable after payload"
    );

    let range = m.history_range(0, 10_000, 10 << 20);
    assert!(
        range.lines.len() <= 200,
        "{name}: history line bound violated"
    );

    let mut replica = model(40, 6);
    replica.feed(&m.snapshot());
    assert_eq!(
        m.visible_lines(),
        replica.visible_lines(),
        "{name}: snapshot replay diverged"
    );
}

/// Named corpus of hostile sequences. Kept as (name, bytes) so a failure
/// message identifies the offending entry.
fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    let mut c: Vec<(&'static str, Vec<u8>)> = vec![
        // --- String sequences that never terminate ---
        ("unterminated-osc-title", {
            let mut v = b"\x1b]0;".to_vec();
            v.extend(std::iter::repeat(b'A').take(1 << 20));
            v
        }),
        ("unterminated-dcs", {
            let mut v = b"\x1bPq".to_vec();
            v.extend(std::iter::repeat(b'#').take(1 << 20));
            v
        }),
        ("unterminated-apc", {
            let mut v = b"\x1b_G".to_vec(); // kitty-graphics-style APC
            v.extend(std::iter::repeat(b'B').take(1 << 20));
            v
        }),
        ("osc52-huge-clipboard", {
            let mut v = b"\x1b]52;c;".to_vec();
            v.extend(std::iter::repeat(b'Q').take(1 << 20));
            v.extend_from_slice(b"\x07");
            v
        }),
        ("sos-pm-noise", b"\x1bXsos-junk\x1b\\\x1b^pm-junk\x1b\\\x1b_apc\x1b\\ok".to_vec()),
        // --- Parameter abuse ---
        ("csi-huge-params", b"\x1b[4294967295;4294967295H\x1b[999999999;1;0;;;42m".to_vec()),
        ("csi-insert-lines-flood", b"\x1b[999999999L\x1b[999999999M\x1b[999999999@\x1b[999999999P".to_vec()),
        ("csi-repeat-flood", b"x\x1b[2147483647b".to_vec()),
        ("csi-many-params", {
            let mut v = b"\x1b[".to_vec();
            for _ in 0..10_000 {
                v.extend_from_slice(b"38;5;196;");
            }
            v.extend_from_slice(b"m");
            v
        }),
        ("sgr-kilometre", {
            let mut v = Vec::new();
            for i in 0..5_000 {
                v.extend_from_slice(format!("\x1b[{}m", i % 108).as_bytes());
            }
            v
        }),
        ("scroll-region-inverted", b"\x1b[10;2r\x1b[999;999H scrolled \r\n".to_vec()),
        ("cursor-off-screen", b"\x1b[9999;9999H\x1b[9999A\x1b[9999B\x1b[9999C\x1b[9999D*".to_vec()),
        // --- Mode and screen abuse ---
        ("alt-screen-storm", {
            let mut v = Vec::new();
            for _ in 0..500 {
                v.extend_from_slice(b"\x1b[?1049h\x1b[?1049l");
            }
            v
        }),
        ("alt-screen-flood-no-exit", {
            let mut v = b"\x1b[?1049h".to_vec();
            for i in 0..2_000 {
                v.extend_from_slice(format!("alt-{i}\r\n").as_bytes());
            }
            v
        }),
        ("mode-soup", b"\x1b[?2004h\x1b[?1000h\x1b[?1002h\x1b[?1003h\x1b[?1006h\x1b[?25l\x1b[?7l\x1b[?6h".to_vec()),
        ("decset-param-kilometre", {
            // Mode tracker must stay bounded: one DECSET with a 1 MiB param.
            let mut v = b"\x1b[?".to_vec();
            v.extend(std::iter::repeat(b'9').take(1 << 20));
            v.extend_from_slice(b"h");
            v
        }),
        ("decset-flood", {
            let mut v = Vec::new();
            for i in 0..50_000u32 {
                v.extend_from_slice(format!("\x1b[?{}h", i % 3000).as_bytes());
            }
            v
        }),
        ("decset-aborted-mid-sequence", b"\x1b[?1000\x18\x1b[?10\x1b[?1002;\x1b]0;t\x07ok".to_vec()),
        ("full-reset-mid-line", b"half-a-line\x1bc\x1b[2J\x1b[3J".to_vec()),
        // --- Answerback / query sequences (model must swallow, never reply) ---
        ("query-soup", b"\x05\x1b[c\x1b[>c\x1b[=c\x1b[6n\x1b[?6n\x1b[5n\x1b]21;?\x07\x1bP$qm\x1b\\\x1b[14t\x1b[18t\x1b[21t".to_vec()),
        // --- Encoding abuse ---
        ("invalid-utf8-flood", {
            let mut v = Vec::new();
            for _ in 0..10_000 {
                v.extend_from_slice(&[0xff, 0xfe, 0xc0, 0xaf, 0xe0, 0x80, 0x80]);
            }
            v
        }),
        ("c1-controls-raw", vec![0x9b, b'3', b'1', b'm', 0x90, 0x9d, 0x98, 0x84, 0x8d, b'o', b'k']),
        ("truncated-utf8-then-escape", b"caf\xc3\x1b[31mred".to_vec()),
        ("nul-del-flood", {
            let mut v = Vec::new();
            for _ in 0..50_000 {
                v.push(0x00);
                v.push(0x7f);
            }
            v
        }),
        ("bel-flood", std::iter::repeat(b'\x07').take(100_000).collect()),
        // --- Combining/width abuse ---
        ("combining-char-pileup", {
            let mut v = b"a".to_vec();
            for _ in 0..10_000 {
                v.extend_from_slice("\u{0301}".as_bytes()); // combining acute
            }
            v
        }),
        ("wide-chars-at-margin", {
            let mut v = Vec::new();
            for _ in 0..500 {
                v.extend_from_slice("🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀🦀\r\n".as_bytes());
            }
            v
        }),
        ("tab-stop-abuse", b"\x1b[3g\x1bH\x1bH\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\tend".to_vec()),
    ];
    // Every printable C0 escape intro byte pair, to poke unhandled branches.
    let mut esc_soup = Vec::new();
    for b in 0x20u8..=0x7e {
        esc_soup.push(0x1b);
        esc_soup.push(b);
    }
    c.push(("esc-intro-sweep", esc_soup));
    c
}

#[test]
fn every_corpus_entry_is_survivable() {
    for (name, payload) in corpus() {
        assert_survives(name, &payload);
    }
}

#[test]
fn corpus_survives_byte_at_a_time_feeding() {
    // Split every escape sequence across feed boundaries: state must carry
    // over chunk edges exactly as if fed whole.
    for (name, payload) in corpus() {
        // Cap per-entry size so the O(bytes) loop stays fast.
        let slice = &payload[..payload.len().min(4096)];
        let mut m = model(40, 6);
        for b in slice {
            m.feed(std::slice::from_ref(b));
        }
        m.feed(b"\x18\x1b\\\x1b[?1049l\r\nMARKER-ALIVE\r\n");
        let alive = m.visible_lines().iter().any(|l| l.contains("MARKER-ALIVE"))
            || m.history_range(0, 1000, 1 << 20)
                .lines
                .iter()
                .any(|l| l.contains("MARKER-ALIVE"));
        assert!(alive, "{name}: model unusable after byte-at-a-time feed");
    }
}

#[test]
fn deterministic_fuzz_random_bytes() {
    // Seeded LCG so failures reproduce; no Date/random dependency.
    let mut state: u64 = 0x5DEECE66D;
    let mut next = move || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as u8
    };
    let mut m = model(80, 24);
    let mut chunk = [0u8; 4096];
    for _ in 0..64 {
        for b in chunk.iter_mut() {
            *b = next();
        }
        m.feed(&chunk);
    }
    m.feed(b"\x18\x1b\\\x1b[?1049l\r\nMARKER-ALIVE\r\n");
    let alive = m.visible_lines().iter().any(|l| l.contains("MARKER-ALIVE"))
        || m.history_range(0, 1000, 1 << 20)
            .lines
            .iter()
            .any(|l| l.contains("MARKER-ALIVE"));
    assert!(alive, "model unusable after random fuzz");
}

#[test]
fn deterministic_fuzz_escape_biased() {
    // Random bytes with a heavy bias toward escape-sequence structure, which
    // reaches far deeper into the parser than uniform noise.
    let mut state: u64 = 0xB5297A4D;
    let mut next = move || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as u32
    };
    let structural: &[u8] = b"\x1b[]P;?0123456789hlmHJKrcnqt\x07\x9b\\_^X";
    let mut m = model(80, 24);
    let mut buf = Vec::with_capacity(4096);
    for _ in 0..64 {
        buf.clear();
        for _ in 0..4096 {
            let r = next();
            let b = if r % 4 == 0 {
                (r >> 8) as u8 // 25% raw noise
            } else {
                structural[(r as usize >> 8) % structural.len()]
            };
            buf.push(b);
        }
        m.feed(&buf);
    }
    m.feed(b"\x18\x1b\\\x1b[?1049l\r\nMARKER-ALIVE\r\n");
    let alive = m.visible_lines().iter().any(|l| l.contains("MARKER-ALIVE"))
        || m.history_range(0, 1000, 1 << 20)
            .lines
            .iter()
            .any(|l| l.contains("MARKER-ALIVE"));
    assert!(alive, "model unusable after escape-biased fuzz");
}

#[test]
fn resize_storm_during_hostile_input() {
    let mut m = model(80, 24);
    let sizes = [(1u16, 1u16), (400, 100), (2, 200), (300, 1), (80, 24)];
    for (i, payload) in corpus().into_iter().enumerate() {
        let (cols, rows) = sizes[i % sizes.len()];
        m.resize(cols, rows);
        m.feed(&payload.1[..payload.1.len().min(8192)]);
    }
    m.resize(80, 24);
    m.feed(b"\x18\x1b\\\x1b[?1049l\r\nMARKER-ALIVE\r\n");
    let alive = m.visible_lines().iter().any(|l| l.contains("MARKER-ALIVE"))
        || m.history_range(0, 1000, 1 << 20)
            .lines
            .iter()
            .any(|l| l.contains("MARKER-ALIVE"));
    assert!(alive, "model unusable after resize storm");
}

#[test]
fn degenerate_resize_dimensions_are_clamped_not_fatal() {
    // avt 0.18 hangs at 0 columns and panics when a 1-column resize splits a
    // wide glyph or when rows hit 0. The model must clamp all of these.
    let mut m = model(40, 6);
    m.feed("🦀🦀🦀🦀🦀wide and dangerous\r\n".as_bytes());
    for &(c, r) in &[(0u16, 6u16), (1, 6), (40, 0), (0, 0), (1, 1), (2, 1)] {
        m.resize(c, r);
        let (gc, gr) = m.size();
        assert!(
            gc >= 2 && gr >= 1,
            "resize({c},{r}) left unsafe size ({gc},{gr})"
        );
        // Still usable after each degenerate resize.
        m.feed(b"ok\r\n");
    }
    m.resize(40, 6);
    m.feed(b"MARKER-ALIVE\r\n");
    assert!(m.visible_lines().iter().any(|l| l.contains("MARKER-ALIVE")));
}

#[test]
fn construction_with_zero_dimensions_is_clamped() {
    let mut m = TerminalModel::new(TerminalModelConfig {
        cols: 0,
        rows: 0,
        max_history_lines: 100,
        max_history_bytes: 4096,
    });
    let (c, r) = m.size();
    assert!(
        c >= 2 && r >= 1,
        "zero-dim construction left unsafe size ({c},{r})"
    );
    // Feeding a wide glyph into the clamped emulator must not panic; then a
    // resize to a normal size leaves it fully usable.
    m.feed("🦀🦀🦀".as_bytes());
    m.resize(40, 6);
    m.feed(b"\r\nMARKER-ALIVE\r\n");
    let alive = m.visible_lines().iter().any(|l| l.contains("MARKER-ALIVE"))
        || m.history_range(0, 100, 1 << 20)
            .lines
            .iter()
            .any(|l| l.contains("MARKER-ALIVE"));
    assert!(alive);
}

#[test]
fn history_bounds_hold_under_line_flood() {
    let mut m = TerminalModel::new(TerminalModelConfig {
        cols: 20,
        rows: 4,
        max_history_lines: 50,
        max_history_bytes: 2048,
    });
    for i in 0..20_000 {
        m.feed(format!("flood-line-{i}\r\n").as_bytes());
    }
    let range = m.history_range(0, 10_000, 10 << 20);
    assert!(
        range.lines.len() <= 50,
        "line bound violated: {}",
        range.lines.len()
    );
    let total: usize = range.lines.iter().map(|l| l.len()).sum();
    assert!(total <= 2048, "byte bound violated: {total}");
    assert!(range.truncated_by_eviction);
    assert!(m.oldest_line_id() > 1);
}
