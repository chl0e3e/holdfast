//! Server-side VT state, screen revisions and bounded scrollback (spec §10).
//!
//! Wraps `avt` (ADR 0004) without leaking its types: avt owns VT semantics
//! (parsing, alternate screen, reflow); this crate owns the bounded history
//! ring with stable line IDs, screen revisions, and UTF-8 chunk handling.
//! No HTTP or QUIC imports, ever (enforced dependency direction).

mod history;
mod utf8;

pub use history::{HistoryRange, HistoryRing};

/// Smallest column count we hand to `avt`. Below this the emulator is both
/// useless and unsafe: `avt` 0.18 enters an infinite loop at 0 columns and
/// panics (subtract-with-overflow) when a resize to 1 column splits a
/// double-width cell. A terminal narrower than one wide glyph is degenerate
/// anyway, so every dimension is clamped to this floor (threat model T9 —
/// resize dimensions are attacker-controlled).
pub const MIN_COLS: u16 = 2;
/// Smallest row count we hand to `avt`; 0 rows panics on resize.
pub const MIN_ROWS: u16 = 1;

/// Bounds and initial dimensions for one shell's terminal model.
#[derive(Debug, Clone)]
pub struct TerminalModelConfig {
    pub cols: u16,
    pub rows: u16,
    /// Spec §8 defaults: 100_000 lines / 64 MiB, first limit hit wins.
    pub max_history_lines: usize,
    pub max_history_bytes: usize,
}

impl Default for TerminalModelConfig {
    fn default() -> TerminalModelConfig {
        TerminalModelConfig {
            cols: 80,
            rows: 24,
            max_history_lines: 100_000,
            max_history_bytes: 64 * 1024 * 1024,
        }
    }
}

/// One shell's authoritative terminal state.
pub struct TerminalModel {
    vt: avt::Vt,
    utf8: utf8::IncrementalUtf8,
    history: HistoryRing,
    /// Monotonic screen revision; 0 is reserved for "none" (spec §1), so the
    /// model starts at 1.
    revision: u64,
    cols: u16,
    rows: u16,
}

impl TerminalModel {
    pub fn new(config: TerminalModelConfig) -> TerminalModel {
        let cols = config.cols.max(MIN_COLS);
        let rows = config.rows.max(MIN_ROWS);
        TerminalModel {
            // scrollback_limit(0): avt evicts every scrolled-off primary line
            // immediately and hands it to us (ADR 0004); we own the ring.
            vt: avt::Vt::builder()
                .size(cols as usize, rows as usize)
                .scrollback_limit(0)
                .build(),
            utf8: utf8::IncrementalUtf8::new(),
            history: HistoryRing::new(config.max_history_lines, config.max_history_bytes),
            revision: 1,
            cols,
            rows,
        }
    }

    /// Feed raw PTY output bytes. Multi-byte UTF-8 sequences may be split
    /// across calls; invalid bytes become U+FFFD. Returns the new revision.
    pub fn feed(&mut self, bytes: &[u8]) -> u64 {
        let text = self.utf8.push(bytes);
        if !text.is_empty() {
            let changes = self.vt.feed_str(&text);
            let evicted: Vec<String> =
                changes.scrollback.map(|l| l.text().trim_end().to_string()).collect();
            for line in evicted {
                self.history.push(line);
            }
            self.revision += 1;
        }
        self.revision
    }

    /// Resize the model (the caller must also resize the PTY). History keeps
    /// its original wrapping (spec §10 v0 reflow decision); the visible
    /// screen is reflowed by avt.
    /// Resize the emulator. `cols`/`rows` are clamped to [`MIN_COLS`]/
    /// [`MIN_ROWS`] first, so hostile or degenerate client dimensions (0, or a
    /// 1-column split of a wide glyph) can never reach `avt`'s panicking/hanging
    /// paths. Returns the (possibly unchanged) revision.
    pub fn resize(&mut self, cols: u16, rows: u16) -> u64 {
        let cols = cols.max(MIN_COLS);
        let rows = rows.max(MIN_ROWS);
        if (cols, rows) != (self.cols, self.rows) {
            self.vt.resize(cols as usize, rows as usize);
            self.cols = cols;
            self.rows = rows;
            self.revision += 1;
        }
        self.revision
    }

    /// Byte sequence that reconstructs the current screen (including the
    /// alternate screen and cursor) in a fresh emulator — the attach
    /// `ScreenSnapshot` payload.
    pub fn snapshot(&self) -> Vec<u8> {
        self.vt.dump().into_bytes()
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn size(&self) -> (u16, u16) {
        (self.cols, self.rows)
    }

    /// Visible screen as plain text lines (for tests and diagnostics).
    pub fn visible_lines(&self) -> Vec<String> {
        self.vt.view().map(|l| l.text().trim_end().to_string()).collect()
    }

    /// Oldest retained history line ID; 0 when no history is retained.
    pub fn oldest_line_id(&self) -> u64 {
        self.history.oldest_id()
    }

    /// Newest committed history line ID; 0 when no history was ever committed.
    pub fn newest_line_id(&self) -> u64 {
        self.history.newest_id()
    }

    /// Range read for `RequestHistory` (spec §10).
    pub fn history_range(
        &self,
        before_line_id: u64,
        maximum_lines: u32,
        maximum_bytes: u32,
    ) -> HistoryRange {
        self.history.range(before_line_id, maximum_lines, maximum_bytes)
    }
}
