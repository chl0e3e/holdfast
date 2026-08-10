use rgb::RGB8;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Color {
    /// A legacy SGR 30-37 / 40-47 / 90-97 / 100-107 colour. Kept distinct from
    /// [`Color::Indexed`] even though both name a palette slot: xterm.js
    /// records the two as different colour *modes* and renders them
    /// differently (it brightens the legacy 0-7 under bold, but never the
    /// indexed form), so collapsing them made a reattach change how coloured
    /// text looked.
    Ansi(u8),
    /// An SGR 38;5;n / 48;5;n palette colour.
    Indexed(u8),
    RGB(RGB8),
}

impl Color {
    pub fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self::RGB(RGB8::new(r, g, b))
    }
}
