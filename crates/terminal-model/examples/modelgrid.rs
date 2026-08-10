//! Server side of the render differential harness (`tools/render-diff`).
//!
//! Reads the corpus TSV on stdin and, for every case, replays it through a
//! fresh [`TerminalModel`] exactly as the daemon would, emitting:
//!
//! * `snapshot` — the attach payload a reattaching client replays;
//! * `visible`  — the model's own view of the screen, as text;
//! * `chunked`  — the snapshot produced when the same bytes arrive one byte at
//!   a time, which is what a PTY under load actually does. Any difference
//!   between `snapshot` and `chunked` is a parser state bug across chunk
//!   boundaries.
//!
//! ```text
//! node tools/render-diff/gen-corpus.mjs > corpus.tsv
//! cargo run -p hf-terminal-model --example modelgrid < corpus.tsv > model.tsv
//! ```

use std::io::{BufWriter, Read, Write};

use hf_terminal_model::{TerminalModel, TerminalModelConfig};

const COLS: u16 = 80;
const ROWS: u16 = 24;
/// Reattach sizes for the roaming checks (a wider desktop, a narrower phone).
const WIDE_COLS: u16 = 100;
const WIDE_ROWS: u16 = 30;
const NARROW_COLS: u16 = 60;
const NARROW_ROWS: u16 = 20;

fn main() -> std::io::Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    for line in input.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut fields = line.split('\t');
        let (Some(name), Some(_category), Some(_flags), Some(hex)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            eprintln!("malformed corpus line: {line:?}");
            std::process::exit(2);
        };
        let bytes = unhex(hex);

        let mut whole = model();
        whole.feed(&bytes);

        let mut chunked = model();
        for byte in &bytes {
            chunked.feed(std::slice::from_ref(byte));
        }

        // Roaming between devices reattaches at a different size. Each grows
        // and shrinks from a fresh replay so the two are independent.
        let mut grown = model();
        grown.feed(&bytes);
        grown.resize(WIDE_COLS, WIDE_ROWS);
        let mut shrunk = model();
        shrunk.feed(&bytes);
        shrunk.resize(NARROW_COLS, NARROW_ROWS);

        writeln!(
            out,
            "{name}\t{}\t{}\t{}\t{}\t{}",
            tohex(&whole.snapshot()),
            tohex(whole.visible_lines().join("\n").as_bytes()),
            tohex(&chunked.snapshot()),
            tohex(&grown.snapshot()),
            tohex(&shrunk.snapshot()),
        )?;
    }
    out.flush()
}

fn model() -> TerminalModel {
    TerminalModel::new(TerminalModelConfig {
        cols: COLS,
        rows: ROWS,
        ..TerminalModelConfig::default()
    })
}

fn unhex(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    assert!(bytes.len() % 2 == 0, "odd-length hex field");
    bytes
        .chunks_exact(2)
        .map(|pair| {
            let digit = |b: u8| match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => panic!("bad hex digit {b:?}"),
            };
            digit(pair[0]) << 4 | digit(pair[1])
        })
        .collect()
}

fn tohex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
