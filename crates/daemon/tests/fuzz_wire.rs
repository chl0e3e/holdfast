//! Robustness harness for the WebSocket wire mapping (varint channel prefix +
//! frame). Random and adversarial messages must never panic the decoder.
//! Reproduce with: `cargo test -p hf-daemon --test fuzz_wire`

use hf_daemon::wire;

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }
    fn range(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const MAX_FRAME: u32 = 64 * 1024;

#[test]
fn random_messages_never_panic() {
    for seed in 1..=500u64 {
        let mut rng = XorShift(seed.wrapping_mul(0x2545F4914F6CDD1D) | 1);
        let len = rng.range(1024);
        let data: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        // Any Err is acceptable; a panic is not.
        let _ = wire::decode_message(&data, MAX_FRAME);
    }
}

#[test]
fn multibyte_varint_prefixes_are_handled() {
    // Exercise valid and truncated varint channel prefixes.
    let cases: Vec<Vec<u8>> = vec![
        vec![0x00u8], // channel 0, then a frame
        vec![0x80],   // truncated varint
        vec![0xff, 0xff, 0xff, 0x0f],
        vec![0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80], // overlong
    ];
    for prefix in &cases {
        let mut msg = prefix.clone();
        msg.extend_from_slice(&4u32.to_be_bytes());
        msg.extend_from_slice(&[0u8; 4]);
        // Either parses to a (channel, envelope) or errors — never panics.
        let _ = wire::decode_message(&msg, MAX_FRAME);
    }
}

#[test]
fn oversized_declared_frame_rejected() {
    // channel 0 varint, then a length prefix above the maximum.
    let mut msg = vec![0x00];
    msg.extend_from_slice(&(MAX_FRAME + 1).to_be_bytes());
    msg.extend_from_slice(&[0u8; 16]);
    assert!(wire::decode_message(&msg, MAX_FRAME).is_err());
}
