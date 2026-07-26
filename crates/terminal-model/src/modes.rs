//! Input-relevant DEC private mode tracking for snapshots.
//!
//! `avt`'s `dump()` reconstructs screen *contents* (buffers, cursor, pen,
//! alternate screen) but ignores modes that only change how the client
//! encodes *input*: mouse tracking, application cursor keys, bracketed
//! paste. Without them a reattaching client renders the screen correctly
//! but has lost the app's input contract — e.g. weechat with `/mouse
//! enable` stops receiving wheel events after a page reload, and xterm.js
//! falls back to converting the wheel into arrow keys. This scanner watches
//! the same decoded text avt sees and replays the active modes after the
//! dump.
//!
//! The stream is attacker-controlled (threat model T9), so all state here
//! is bounded: a fixed mode set and a capped parameter buffer.

/// DEC private modes replayed by the snapshot, in replay order. Modes that
/// affect the rendered screen (1049 &c.) stay with avt.
const TRACKED: [u16; 11] = [
    1,    // DECCKM: application cursor keys
    9,    // X10 mouse
    1000, // normal mouse tracking
    1002, // button-event mouse tracking
    1003, // any-event mouse tracking
    1004, // focus in/out events
    1005, // UTF-8 mouse encoding
    1006, // SGR mouse encoding
    1007, // alternate scroll (wheel -> arrow keys in alt screen)
    1015, // urxvt mouse encoding
    2004, // bracketed paste
];

/// Mouse protocol modes are mutually exclusive (xterm semantics): enabling
/// one implicitly disables the others.
const MOUSE_PROTOCOLS: [u16; 4] = [9, 1000, 1002, 1003];

/// Longest CSI parameter section we buffer (`1000;1002;1006` style lists).
/// Anything longer cannot be a plausible mode list and the sequence is
/// ignored as a whole.
const MAX_PARAMS: usize = 32;

#[derive(Debug, Default, Clone, Copy)]
struct CsiFrame {
    /// Sequence started with `?` (DEC private).
    private: bool,
    /// Saw the `!` intermediate (DECSTR is `CSI ! p`).
    bang: bool,
    /// Params overflowed [`MAX_PARAMS`] or contained bytes we don't model;
    /// the sequence still consumes input but is never applied.
    invalid: bool,
    params_len: usize,
}

#[derive(Debug, Clone, Copy)]
enum State {
    Ground,
    /// Saw ESC.
    Escape,
    Csi(CsiFrame),
    /// Inside OSC/DCS/SOS/PM/APC payload; skip until BEL or ST.
    StringBody,
    /// Saw ESC inside a string payload (possible ST).
    StringEscape,
}

#[derive(Debug)]
pub(crate) struct ModeTracker {
    state: State,
    params: [u8; MAX_PARAMS],
    active: [bool; TRACKED.len()],
}

impl ModeTracker {
    pub(crate) fn new() -> ModeTracker {
        ModeTracker {
            state: State::Ground,
            params: [0; MAX_PARAMS],
            active: [false; TRACKED.len()],
        }
    }

    /// Scan decoded PTY output text. Sequences may be split across calls.
    pub(crate) fn scan(&mut self, text: &str) {
        for ch in text.chars() {
            self.step(ch);
        }
    }

    /// Escape-sequence suffix that restores the active modes in a fresh
    /// emulator; empty when every tracked mode is off (the reset default).
    pub(crate) fn restore_sequence(&self) -> String {
        let mut out = String::new();
        for (i, code) in TRACKED.iter().enumerate() {
            if self.active[i] {
                out.push_str(&format!("\x1b[?{code}h"));
            }
        }
        out
    }

    fn step(&mut self, ch: char) {
        self.state = match self.state {
            State::Ground => match ch {
                '\u{1b}' => State::Escape,
                '\u{9b}' => State::Csi(CsiFrame::default()),
                _ => State::Ground,
            },
            State::Escape => match ch {
                '[' => State::Csi(CsiFrame::default()),
                ']' | 'P' | 'X' | '^' | '_' => State::StringBody,
                'c' => {
                    // RIS: full reset clears every tracked mode.
                    self.active = [false; TRACKED.len()];
                    State::Ground
                }
                '\u{1b}' => State::Escape,
                _ => State::Ground,
            },
            State::Csi(mut frame) => match ch {
                '?' if frame.params_len == 0 && !frame.private => {
                    frame.private = true;
                    State::Csi(frame)
                }
                '0'..='9' | ';' => {
                    if frame.params_len < MAX_PARAMS {
                        self.params[frame.params_len] = ch as u8;
                        frame.params_len += 1;
                    } else {
                        frame.invalid = true;
                    }
                    State::Csi(frame)
                }
                // Param bytes we accept but don't model.
                ':' | '<' | '=' | '>' | '?' => {
                    frame.invalid = true;
                    State::Csi(frame)
                }
                '!' => {
                    frame.bang = true;
                    State::Csi(frame)
                }
                // Other intermediates: not a sequence we track.
                '\u{20}'..='\u{2f}' => {
                    frame.invalid = true;
                    State::Csi(frame)
                }
                '\u{40}'..='\u{7e}' => {
                    self.finish_csi(frame, ch);
                    State::Ground
                }
                '\u{1b}' => State::Escape,
                '\u{18}' | '\u{1a}' => State::Ground, // CAN / SUB abort
                '\u{00}'..='\u{1f}' => State::Csi(frame), // other C0: ignore
                _ => State::Ground,
            },
            State::StringBody => match ch {
                '\u{07}' | '\u{9c}' => State::Ground, // BEL / ST
                '\u{18}' | '\u{1a}' => State::Ground, // CAN / SUB abort
                '\u{1b}' => State::StringEscape,
                _ => State::StringBody,
            },
            State::StringEscape => match ch {
                '\\' => State::Ground, // ESC \ = ST
                '\u{1b}' => State::StringEscape,
                _ => State::StringBody,
            },
        };
    }

    fn finish_csi(&mut self, frame: CsiFrame, final_byte: char) {
        if frame.invalid {
            return;
        }
        if frame.bang && final_byte == 'p' {
            // DECSTR soft reset returns the tracked modes to their defaults.
            self.active = [false; TRACKED.len()];
            return;
        }
        if !frame.private || (final_byte != 'h' && final_byte != 'l') {
            return;
        }
        let set = final_byte == 'h';
        let params = self.params;
        let params = std::str::from_utf8(&params[..frame.params_len])
            .expect("params are ASCII digits and semicolons");
        for part in params.split(';') {
            if let Ok(code) = part.parse::<u16>() {
                self.apply(code, set);
            }
        }
    }

    fn apply(&mut self, code: u16, set: bool) {
        let Some(index) = TRACKED.iter().position(|&c| c == code) else {
            return;
        };
        if set && MOUSE_PROTOCOLS.contains(&code) {
            for other in MOUSE_PROTOCOLS {
                if other != code {
                    self.active[TRACKED.iter().position(|&c| c == other).unwrap()] = false;
                }
            }
        }
        self.active[index] = set;
    }
}
