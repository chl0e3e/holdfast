//! Robustness harness for the untrusted parsers (threat model T5). No external
//! fuzzer or nightly: a deterministic xorshift PRNG drives adversarial inputs;
//! every case must return an error or a value, never panic, hang, or allocate
//! unboundedly. Reproduce with: `cargo test -p hf-protocol --test fuzz_framing`

use hf_protocol::framing::FrameDecoder;

/// Tiny deterministic PRNG (seeds are fixed so failures reproduce exactly).
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
fn random_bytes_never_panic_and_stay_bounded() {
    for seed in 1..=200u64 {
        let mut rng = XorShift(seed.wrapping_mul(0x9E3779B97F4A7C15));
        let mut dec = FrameDecoder::new(MAX_FRAME);

        // Feed many random chunks in arbitrary sizes.
        for _ in 0..64 {
            let len = rng.range(2048);
            let chunk: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
            match dec.extend(&chunk) {
                Ok(()) => {
                    // Drain whatever parses; errors are fine, panics are not.
                    loop {
                        match dec.next_frame() {
                            Ok(Some(_)) => {}
                            Ok(None) => break,
                            Err(_) => break,
                        }
                    }
                    // Buffered data must never exceed the max frame + one chunk:
                    // the length check rejects oversized headers before buffering
                    // a whole frame (spec §3).
                    assert!(
                        dec.buffered() <= MAX_FRAME as usize + 2048,
                        "seed {seed}: unbounded buffering ({} bytes)",
                        dec.buffered()
                    );
                }
                Err(_) => break, // fatal frame error: decoder is discarded
            }
        }
    }
}

#[test]
fn oversized_length_headers_are_always_rejected_pre_alloc() {
    // Any length prefix above the maximum must be rejected without buffering
    // the claimed payload, for every byte pattern of the header.
    for high in [0x40u8, 0x7f, 0x80, 0xff] {
        let mut dec = FrameDecoder::new(MAX_FRAME);
        let header = [high, 0x00, 0x00, 0x01]; // >= 1 GiB when high bit set
        let result = dec.extend(&header);
        if u32::from_be_bytes(header) > MAX_FRAME {
            assert!(result.is_err(), "header {header:?} should be rejected");
            assert!(dec.buffered() <= 4, "payload must not be buffered");
        }
    }
}

#[test]
fn truncated_frames_yield_none_not_panic() {
    // A valid length prefix followed by fewer bytes than promised must simply
    // wait (Ok(None)), never over-read.
    let mut dec = FrameDecoder::new(MAX_FRAME);
    dec.extend(&100u32.to_be_bytes()).unwrap();
    dec.extend(&[0u8; 30]).unwrap();
    assert!(matches!(dec.next_frame(), Ok(None)));
    assert_eq!(dec.buffered(), 34);
}

#[test]
fn interleaved_valid_and_garbage_frames() {
    use hf_protocol::framing::encode_frame;
    use hf_protocol::pb::{envelope, Envelope, Ping};

    let good = encode_frame(
        &Envelope {
            request_id: 1,
            server_id: vec![],
            shell_id: vec![],
            message: Some(envelope::Message::Ping(Ping { nonce: 1 })),
        },
        MAX_FRAME,
    )
    .unwrap();

    let mut rng = XorShift(0xDEADBEEF);
    for _ in 0..500 {
        let mut dec = FrameDecoder::new(MAX_FRAME);
        // A good frame, then a garbage frame of random declared length.
        let _ = dec.extend(&good);
        let _ = dec.next_frame();
        let len = rng.range(200) as u32;
        let mut garbage = len.to_be_bytes().to_vec();
        garbage.extend((0..len).map(|_| rng.byte()));
        if dec.extend(&garbage).is_ok() {
            // Decoding may error on invalid protobuf — must not panic.
            let _ = dec.next_frame();
        }
    }
}
