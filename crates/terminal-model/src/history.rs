//! Bounded scrollback ring with stable, monotonically increasing line IDs
//! (spec §10). IDs are 1-based (0 is the reserved "none" value), never reused
//! and never renumbered by eviction.

use std::collections::VecDeque;

#[derive(Debug)]
pub struct HistoryRing {
    lines: VecDeque<String>,
    /// ID of `lines[0]`; meaningful only when `lines` is non-empty.
    first_id: u64,
    /// ID the next committed line will receive.
    next_id: u64,
    bytes: usize,
    max_lines: usize,
    max_bytes: usize,
}

/// Result of a range read. `lines[i]` has ID `first_line_id + i`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryRange {
    pub first_line_id: u64,
    pub lines: Vec<String>,
    /// True when the requested range reaches below the oldest retained line —
    /// i.e. part of what was asked for is gone forever (spec §10).
    pub truncated_by_eviction: bool,
}

impl HistoryRing {
    pub fn new(max_lines: usize, max_bytes: usize) -> HistoryRing {
        HistoryRing {
            lines: VecDeque::new(),
            first_id: 1,
            next_id: 1,
            bytes: 0,
            max_lines: max_lines.max(1),
            max_bytes: max_bytes.max(1),
        }
    }

    /// Commit one scrolled-off line, evicting from the front while over
    /// either bound (first limit hit wins, spec §8).
    pub fn push(&mut self, line: String) {
        self.bytes += line.len();
        self.lines.push_back(line);
        self.next_id += 1;
        while self.lines.len() > self.max_lines || self.bytes > self.max_bytes {
            // The line just pushed may itself exceed max_bytes; keep at least
            // one line so newest history is always retrievable.
            if self.lines.len() == 1 {
                break;
            }
            let evicted = self.lines.pop_front().expect("non-empty");
            self.bytes -= evicted.len();
            self.first_id += 1;
        }
    }

    pub fn oldest_id(&self) -> u64 {
        if self.lines.is_empty() {
            0
        } else {
            self.first_id
        }
    }

    pub fn newest_id(&self) -> u64 {
        self.next_id - 1 // 0 when nothing was ever committed
    }

    /// Lines strictly before `before_line_id` (0 = "from the newest"),
    /// newest-bounded, walking backwards until either limit. Always returns
    /// at least one line when any line in range is retained, even if that
    /// line alone exceeds `maximum_bytes` — otherwise a client with a small
    /// budget could never make progress.
    pub fn range(
        &self,
        before_line_id: u64,
        maximum_lines: u32,
        maximum_bytes: u32,
    ) -> HistoryRange {
        let newest = self.newest_id();
        let upper = if before_line_id == 0 {
            newest
        } else {
            (before_line_id - 1).min(newest)
        };

        if self.lines.is_empty() || upper == 0 || upper < self.first_id {
            return HistoryRange {
                first_line_id: 0,
                lines: Vec::new(),
                // Empty because evicted (not because nothing exists there):
                truncated_by_eviction: upper != 0 && self.newest_id() != 0 && upper < self.first_id,
            };
        }

        let mut collected: Vec<&String> = Vec::new();
        let mut bytes = 0usize;
        let mut id = upper;
        loop {
            let line = &self.lines[(id - self.first_id) as usize];
            if !collected.is_empty()
                && (collected.len() as u32 >= maximum_lines
                    || bytes + line.len() > maximum_bytes as usize)
            {
                break;
            }
            bytes += line.len();
            collected.push(line);
            if id == self.first_id || collected.len() as u32 >= maximum_lines {
                break;
            }
            id -= 1;
        }

        let first_line_id = upper + 1 - collected.len() as u64;
        collected.reverse();
        HistoryRange {
            first_line_id,
            lines: collected.into_iter().cloned().collect(),
            // Truncated if the range the client could still want (below what
            // we returned) has been evicted.
            truncated_by_eviction: first_line_id == self.first_id && self.first_id > 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring_with(n: usize) -> HistoryRing {
        let mut r = HistoryRing::new(1000, 1 << 20);
        for i in 1..=n {
            r.push(format!("line-{i}"));
        }
        r
    }

    #[test]
    fn ids_are_stable_and_one_based() {
        let r = ring_with(3);
        assert_eq!((r.oldest_id(), r.newest_id()), (1, 3));
        let range = r.range(0, 10, 1 << 20);
        assert_eq!(range.first_line_id, 1);
        assert_eq!(range.lines, vec!["line-1", "line-2", "line-3"]);
        assert!(!range.truncated_by_eviction);
    }

    #[test]
    fn line_limit_evicts_from_front_without_renumbering() {
        let mut r = HistoryRing::new(5, 1 << 20);
        for i in 1..=8 {
            r.push(format!("line-{i}"));
        }
        assert_eq!((r.oldest_id(), r.newest_id()), (4, 8));
        let range = r.range(0, 100, 1 << 20);
        assert_eq!(range.first_line_id, 4);
        assert_eq!(range.lines.first().unwrap(), "line-4");
        assert!(range.truncated_by_eviction, "older lines were evicted");
    }

    #[test]
    fn byte_limit_evicts_first_hit_wins() {
        let mut r = HistoryRing::new(1000, 25);
        r.push("aaaaaaaaaa".into()); // 10 bytes, id 1
        r.push("bbbbbbbbbb".into()); // 10 bytes, id 2
        r.push("cccccccccc".into()); // 10 bytes, id 3 → 30 > 25, evict id 1
        assert_eq!((r.oldest_id(), r.newest_id()), (2, 3));
    }

    #[test]
    fn oversized_single_line_is_still_retained_and_returned() {
        let mut r = HistoryRing::new(1000, 8);
        r.push("way-more-than-eight-bytes".into());
        assert_eq!(r.oldest_id(), 1);
        let range = r.range(0, 10, 4); // byte budget smaller than the line
        assert_eq!(range.lines.len(), 1, "always progress by at least one line");
    }

    #[test]
    fn paging_backwards_with_before_line_id() {
        let r = ring_with(10);
        let newest = r.range(0, 4, 1 << 20);
        assert_eq!(newest.first_line_id, 7);
        assert_eq!(newest.lines, vec!["line-7", "line-8", "line-9", "line-10"]);

        let older = r.range(newest.first_line_id, 4, 1 << 20);
        assert_eq!(older.first_line_id, 3);
        assert_eq!(older.lines, vec!["line-3", "line-4", "line-5", "line-6"]);

        let oldest = r.range(older.first_line_id, 4, 1 << 20);
        assert_eq!(oldest.first_line_id, 1);
        assert_eq!(oldest.lines, vec!["line-1", "line-2"]);
        assert!(!oldest.truncated_by_eviction, "nothing was evicted");
    }

    #[test]
    fn fully_evicted_request_reports_truncation() {
        let mut r = HistoryRing::new(3, 1 << 20);
        for i in 1..=10 {
            r.push(format!("line-{i}"));
        }
        // ids 1..=7 evicted; ask for lines before id 5.
        let range = r.range(5, 10, 1 << 20);
        assert!(range.lines.is_empty());
        assert!(range.truncated_by_eviction);
    }

    #[test]
    fn byte_budget_limits_a_page() {
        let r = ring_with(10); // each line 6-7 bytes
        let range = r.range(0, 100, 14);
        assert_eq!(
            range.lines,
            vec!["line-9", "line-10"],
            "two lines fit in 14 bytes"
        );
    }

    #[test]
    fn empty_ring_returns_empty_untruncated() {
        let r = HistoryRing::new(10, 100);
        let range = r.range(0, 10, 100);
        assert!(range.lines.is_empty());
        assert!(!range.truncated_by_eviction);
        assert_eq!((r.oldest_id(), r.newest_id()), (0, 0));
    }
}
