use crate::pen::Pen;

/// Maximum zero-width characters (combining marks, ZWJ, variation
/// selectors) retained per cell. The input stream is untrusted, so this
/// is a hard bound: extras beyond the cap are dropped, which never
/// changes geometry — their display width is zero either way.
///
/// Sized to cover every legitimate cluster rather than the shortest one that
/// fit: an emoji TAG sequence (a subdivision flag such as
/// U+1F3F4 + 6 tag characters + U+E007F) needs seven on a single cell, and at
/// the previous cap of three those flags — and any text with more than three
/// stacked diacritics — came back truncated after a reattach. xterm.js keeps
/// clusters unbounded; deliberately diverging past this cap is the bounded
/// trade (project rule: every buffer has a chosen bound).
pub(crate) const MAX_ZERO_WIDTH: usize = 8;

const NO_ZERO_WIDTH: [char; MAX_ZERO_WIDTH] = ['\0'; MAX_ZERO_WIDTH];

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Cell(char, Occupancy, Pen, [char; MAX_ZERO_WIDTH]);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum Occupancy {
    Single,
    WideHead,
    WideTail,
}

impl Occupancy {
    pub(crate) fn width(&self) -> u8 {
        match self {
            Occupancy::Single => 1,
            Occupancy::WideHead => 2,
            Occupancy::WideTail => 0,
        }
    }
}

impl Cell {
    pub(crate) fn new(ch: char, occupancy: Occupancy, pen: Pen) -> Self {
        Cell(ch, occupancy, pen, NO_ZERO_WIDTH)
    }

    pub(crate) fn blank(pen: Pen) -> Self {
        Cell(' ', Occupancy::Single, pen, NO_ZERO_WIDTH)
    }

    pub fn is_default(&self) -> bool {
        self.0 == ' ' && self.1 == Occupancy::Single && self.2.is_default() && self.3[0] == '\0'
    }

    pub fn char(&self) -> char {
        self.0
    }

    pub(crate) fn occupancy(&self) -> Occupancy {
        self.1
    }

    pub fn width(&self) -> u8 {
        self.1.width()
    }

    pub fn pen(&self) -> &Pen {
        &self.2
    }

    pub(crate) fn set(&mut self, ch: char, occupancy: Occupancy, pen: Pen) {
        self.0 = ch;
        self.1 = occupancy;
        self.2 = pen;
        self.3 = NO_ZERO_WIDTH;
    }

    /// Append a zero-width character (combining mark, ZWJ, variation
    /// selector) to this cell. Extras beyond [`MAX_ZERO_WIDTH`] are dropped.
    pub(crate) fn push_zero_width(&mut self, ch: char) {
        if let Some(slot) = self.3.iter_mut().find(|c| **c == '\0') {
            *slot = ch;
        }
    }

    /// Zero-width characters appended to this cell, in arrival order.
    pub fn zero_width(&self) -> &[char] {
        let len = self.3.iter().position(|&c| c == '\0').unwrap_or(MAX_ZERO_WIDTH);
        &self.3[..len]
    }

    pub(crate) fn has_zero_width(&self) -> bool {
        self.3[0] != '\0'
    }
}

impl Default for Cell {
    fn default() -> Self {
        Self::blank(Pen::default())
    }
}
