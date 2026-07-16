//! Incremental UTF-8 decoding for PTY output chunks (spec §11 unit-test
//! requirement: multi-byte sequences split across reads must render
//! correctly). Invalid sequences become U+FFFD; an incomplete trailing
//! sequence is buffered (at most 3 bytes) until the next chunk.

#[derive(Debug, Default)]
pub struct IncrementalUtf8 {
    pending: Vec<u8>,
}

impl IncrementalUtf8 {
    pub fn new() -> IncrementalUtf8 {
        IncrementalUtf8::default()
    }

    pub fn push(&mut self, input: &[u8]) -> String {
        let mut data = std::mem::take(&mut self.pending);
        data.extend_from_slice(input);

        let mut out = String::with_capacity(data.len());
        let mut rest: &[u8] = &data;
        loop {
            match std::str::from_utf8(rest) {
                Ok(s) => {
                    out.push_str(s);
                    break;
                }
                Err(e) => {
                    let valid = e.valid_up_to();
                    // Safety not needed: re-slice through the checked API.
                    out.push_str(std::str::from_utf8(&rest[..valid]).unwrap());
                    match e.error_len() {
                        // Invalid sequence of known length: replace, continue.
                        Some(len) => {
                            out.push(char::REPLACEMENT_CHARACTER);
                            rest = &rest[valid + len..];
                        }
                        // Incomplete trailing sequence: keep for next chunk.
                        None => {
                            self.pending = rest[valid..].to_vec();
                            break;
                        }
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multibyte_split_at_every_position() {
        let text = "héllo 🦀 wörld";
        let bytes = text.as_bytes();
        for split in 0..=bytes.len() {
            let mut dec = IncrementalUtf8::new();
            let mut got = dec.push(&bytes[..split]);
            got.push_str(&dec.push(&bytes[split..]));
            assert_eq!(got, text, "split at byte {split}");
        }
    }

    #[test]
    fn four_byte_emoji_fed_one_byte_at_a_time() {
        let mut dec = IncrementalUtf8::new();
        let mut got = String::new();
        for b in "🦀".as_bytes() {
            got.push_str(&dec.push(&[*b]));
        }
        assert_eq!(got, "🦀");
    }

    #[test]
    fn invalid_bytes_become_replacement_chars() {
        let mut dec = IncrementalUtf8::new();
        assert_eq!(dec.push(b"ok\xff\xfeok"), "ok\u{FFFD}\u{FFFD}ok");
    }

    #[test]
    fn truncated_sequence_then_invalid_continuation() {
        let mut dec = IncrementalUtf8::new();
        // 0xE2 0x82 starts a 3-byte sequence; 'A' is an invalid continuation.
        let first = dec.push(&[0xE2, 0x82]);
        assert_eq!(first, "", "incomplete tail buffered");
        assert_eq!(dec.push(b"A"), "\u{FFFD}A");
    }
}
