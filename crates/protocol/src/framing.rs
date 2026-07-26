//! Reliable-stream framing (spec §3): `u32 big-endian length | Envelope`.
//!
//! The decoder rejects a frame the moment its length header exceeds the
//! negotiated maximum — before the payload is buffered or any allocation
//! sized by the untrusted length occurs.

use bytes::{Buf, BufMut, BytesMut};
use prost::Message;

use crate::pb::{AgentEnvelope, Envelope};

pub const LENGTH_PREFIX_BYTES: usize = 4;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame of {len} bytes exceeds negotiated maximum {max}")]
    TooLarge { len: u32, max: u32 },
    #[error("frame payload is not a valid Envelope: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("envelope does not fit the negotiated maximum {max}")]
    EncodeTooLarge { max: u32 },
}

/// Encode one envelope as a length-prefixed frame.
pub fn encode_frame(envelope: &Envelope, max_frame_bytes: u32) -> Result<Vec<u8>, FrameError> {
    encode_delimited(envelope, max_frame_bytes)
}

/// Encode one managed-agent control envelope with the same explicit length
/// delimiter used by reliable client streams (spec §16).
pub fn encode_agent_frame(
    envelope: &AgentEnvelope,
    max_frame_bytes: u32,
) -> Result<Vec<u8>, FrameError> {
    encode_delimited(envelope, max_frame_bytes)
}

/// Decode an already-delimited managed-agent payload. Transport code must
/// check its u32 header against the maximum before allocating this slice.
pub fn decode_agent_payload(payload: &[u8]) -> Result<AgentEnvelope, FrameError> {
    Ok(AgentEnvelope::decode(payload)?)
}

/// Validate an untrusted length prefix before allocating its payload buffer.
pub fn checked_payload_len(
    header: [u8; LENGTH_PREFIX_BYTES],
    maximum: u32,
) -> Result<usize, FrameError> {
    let len = u32::from_be_bytes(header);
    if len > maximum {
        return Err(FrameError::TooLarge { len, max: maximum });
    }
    Ok(len as usize)
}

fn encode_delimited(message: &impl Message, max_frame_bytes: u32) -> Result<Vec<u8>, FrameError> {
    let len = message.encoded_len();
    if len > max_frame_bytes as usize {
        return Err(FrameError::EncodeTooLarge {
            max: max_frame_bytes,
        });
    }
    let mut out = Vec::with_capacity(LENGTH_PREFIX_BYTES + len);
    out.put_u32(len as u32);
    message.encode(&mut out).expect("Vec<u8> write cannot fail");
    Ok(out)
}

/// Incremental frame decoder. Feed transport bytes with [`FrameDecoder::extend`],
/// then drain complete envelopes with [`FrameDecoder::next_frame`]. A
/// [`FrameError`] is fatal for the stream (spec §3): discard the decoder and
/// close with the mapped error code.
#[derive(Debug)]
pub struct FrameDecoder {
    max_frame_bytes: u32,
    buf: BytesMut,
}

impl FrameDecoder {
    pub fn new(max_frame_bytes: u32) -> FrameDecoder {
        FrameDecoder {
            max_frame_bytes,
            buf: BytesMut::new(),
        }
    }

    /// Append transport bytes. Fails fast if the pending frame header already
    /// exceeds the maximum, without buffering the rest of that frame.
    pub fn extend(&mut self, bytes: &[u8]) -> Result<(), FrameError> {
        // If this call completes a split header, inspect those four bytes
        // before copying payload supplied in the same transport read.
        if self.buf.len() < LENGTH_PREFIX_BYTES {
            let header_bytes = (LENGTH_PREFIX_BYTES - self.buf.len()).min(bytes.len());
            self.buf.extend_from_slice(&bytes[..header_bytes]);
            self.check_header()?;
            self.buf.extend_from_slice(&bytes[header_bytes..]);
        } else {
            self.check_header()?;
            self.buf.extend_from_slice(bytes);
        }
        self.check_header()
    }

    /// Pop the next complete envelope, if one is fully buffered.
    pub fn next_frame(&mut self) -> Result<Option<Envelope>, FrameError> {
        self.check_header()?;
        if self.buf.len() < LENGTH_PREFIX_BYTES {
            return Ok(None);
        }
        let len = u32::from_be_bytes(self.buf[..LENGTH_PREFIX_BYTES].try_into().unwrap()) as usize;
        if self.buf.len() < LENGTH_PREFIX_BYTES + len {
            return Ok(None);
        }
        self.buf.advance(LENGTH_PREFIX_BYTES);
        let payload = self.buf.split_to(len);
        Ok(Some(Envelope::decode(payload.freeze())?))
    }

    /// Bytes currently buffered (bounded by max_frame_bytes + prefix + one
    /// transport read, since oversized headers fail in `extend`).
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    fn check_header(&self) -> Result<(), FrameError> {
        if self.buf.len() >= LENGTH_PREFIX_BYTES {
            let len = u32::from_be_bytes(self.buf[..LENGTH_PREFIX_BYTES].try_into().unwrap());
            if len > self.max_frame_bytes {
                return Err(FrameError::TooLarge {
                    len,
                    max: self.max_frame_bytes,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pb::{envelope, Envelope, Ping};

    fn ping(nonce: u64) -> Envelope {
        Envelope {
            request_id: nonce,
            server_id: vec![],
            shell_id: vec![],
            message: Some(envelope::Message::Ping(Ping { nonce })),
        }
    }

    #[test]
    fn roundtrip_single_frame() {
        let frame = encode_frame(&ping(42), 1024).unwrap();
        let mut dec = FrameDecoder::new(1024);
        dec.extend(&frame).unwrap();
        let env = dec.next_frame().unwrap().expect("one frame");
        assert!(matches!(
            env.message,
            Some(envelope::Message::Ping(Ping { nonce: 42 }))
        ));
        assert!(dec.next_frame().unwrap().is_none());
        assert_eq!(dec.buffered(), 0);
    }

    #[test]
    fn multiple_frames_split_across_arbitrary_chunks() {
        let mut wire = Vec::new();
        for n in 0..5 {
            wire.extend(encode_frame(&ping(n), 1024).unwrap());
        }
        // Feed one byte at a time — worst-case fragmentation.
        let mut dec = FrameDecoder::new(1024);
        let mut got = Vec::new();
        for b in wire {
            dec.extend(&[b]).unwrap();
            while let Some(env) = dec.next_frame().unwrap() {
                got.push(env.request_id);
            }
        }
        assert_eq!(got, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn oversized_header_rejected_before_payload_arrives() {
        let mut dec = FrameDecoder::new(1024);
        // Header claims 1 MiB; only the 4 header bytes are ever buffered.
        let err = dec.extend(&(1_048_576u32).to_be_bytes()).unwrap_err();
        assert!(matches!(
            err,
            FrameError::TooLarge {
                len: 1_048_576,
                max: 1024
            }
        ));
        assert_eq!(dec.buffered(), 4, "payload must not be buffered");
    }

    #[test]
    fn oversized_header_rejects_payload_from_the_same_read_before_buffering_it() {
        let mut dec = FrameDecoder::new(1024);
        let mut hostile_read = (1_048_576u32).to_be_bytes().to_vec();
        hostile_read.resize(1_048_580, 0xAA);
        let err = dec.extend(&hostile_read).unwrap_err();
        assert!(matches!(
            err,
            FrameError::TooLarge {
                len: 1_048_576,
                max: 1024
            }
        ));
        assert_eq!(dec.buffered(), 4, "untrusted payload must never be copied");
    }

    #[test]
    fn checked_payload_length_rejects_before_callers_allocate() {
        assert_eq!(
            checked_payload_len(512u32.to_be_bytes(), 1024).unwrap(),
            512
        );
        assert!(matches!(
            checked_payload_len(1025u32.to_be_bytes(), 1024),
            Err(FrameError::TooLarge {
                len: 1025,
                max: 1024
            })
        ));
    }

    #[test]
    fn malformed_payload_is_a_decode_error() {
        let mut dec = FrameDecoder::new(1024);
        let mut wire = 3u32.to_be_bytes().to_vec();
        wire.extend(b"\xff\xff\xff"); // invalid protobuf
        dec.extend(&wire).unwrap();
        assert!(matches!(dec.next_frame(), Err(FrameError::Decode(_))));
    }

    #[test]
    fn encode_respects_negotiated_maximum() {
        let big = Envelope {
            request_id: 1,
            server_id: vec![],
            shell_id: vec![],
            message: Some(envelope::Message::TerminalOutput(
                crate::pb::TerminalOutput {
                    data: vec![0u8; 2048],
                },
            )),
        };
        assert!(matches!(
            encode_frame(&big, 1024),
            Err(FrameError::EncodeTooLarge { max: 1024 })
        ));
    }

    #[test]
    fn zero_length_frame_is_an_empty_envelope() {
        let mut dec = FrameDecoder::new(1024);
        dec.extend(&0u32.to_be_bytes()).unwrap();
        let env = dec.next_frame().unwrap().expect("empty envelope decodes");
        assert!(
            env.message.is_none(),
            "spec §3: unset oneof is a protocol error upstream"
        );
    }

    #[test]
    fn agent_frame_roundtrip_uses_explicit_protobuf_schema() {
        use crate::pb::{agent_envelope, AgentEnvelope, AgentPing};

        let envelope = AgentEnvelope {
            request_id: 0,
            server_id: vec![7; 16],
            shell_id: vec![],
            message: Some(agent_envelope::Message::AgentPing(AgentPing { nonce: 7 })),
        };
        let frame = encode_agent_frame(&envelope, 1024).unwrap();
        let payload_len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        let decoded = decode_agent_payload(&frame[4..4 + payload_len]).unwrap();
        assert!(matches!(
            decoded.message,
            Some(agent_envelope::Message::AgentPing(AgentPing { nonce: 7 }))
        ));
    }

    #[test]
    fn agent_attachment_ceiling_rejects_before_allocation() {
        let maximum = crate::AGENT_ATTACHMENT_FRAME_BYTES_MAX;
        assert!(matches!(
            checked_payload_len(maximum.saturating_add(1).to_be_bytes(), maximum),
            Err(FrameError::TooLarge { len, max })
                if len == maximum + 1 && max == maximum
        ));
    }
}
