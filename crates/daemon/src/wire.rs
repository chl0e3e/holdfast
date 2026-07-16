//! WebSocket wire mapping (spec §2): each binary message is an
//! unsigned-LEB128 varint `channel_id` followed by exactly one §3 frame.

use hf_protocol::framing::{encode_frame, FrameDecoder, FrameError};
use hf_protocol::pb::Envelope;

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("truncated or oversized varint channel prefix")]
    BadVarint,
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("websocket message did not contain exactly one frame")]
    NotExactlyOneFrame,
}

pub fn encode_varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            out.push(byte | 0x80);
        } else {
            out.push(byte);
            break;
        }
    }
}

pub fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for (i, byte) in buf.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
    }
    None
}

/// Build one WebSocket binary message.
pub fn encode_message(
    channel: u64,
    envelope: &Envelope,
    max_frame_bytes: u32,
) -> Result<Vec<u8>, WireError> {
    let frame = encode_frame(envelope, max_frame_bytes)?;
    let mut out = Vec::with_capacity(frame.len() + 10);
    encode_varint(channel, &mut out);
    out.extend_from_slice(&frame);
    Ok(out)
}

/// Parse one WebSocket binary message into (channel, envelope).
pub fn decode_message(data: &[u8], max_frame_bytes: u32) -> Result<(u64, Envelope), WireError> {
    let (channel, used) = decode_varint(data).ok_or(WireError::BadVarint)?;
    let mut decoder = FrameDecoder::new(max_frame_bytes);
    decoder.extend(&data[used..])?;
    let envelope = decoder.next_frame()?.ok_or(WireError::NotExactlyOneFrame)?;
    if decoder.buffered() != 0 {
        return Err(WireError::NotExactlyOneFrame);
    }
    Ok((channel, envelope))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hf_protocol::pb::{envelope, Ping};

    #[test]
    fn varint_roundtrip() {
        for v in [0u64, 1, 127, 128, 300, u32::MAX as u64, u64::MAX] {
            let mut buf = Vec::new();
            encode_varint(v, &mut buf);
            assert_eq!(decode_varint(&buf), Some((v, buf.len())));
        }
        assert_eq!(decode_varint(&[]), None);
        assert_eq!(decode_varint(&[0x80]), None, "unterminated varint");
    }

    #[test]
    fn message_roundtrip() {
        let env = Envelope {
            request_id: 9,
            server_id: vec![],
            shell_id: vec![],
            message: Some(envelope::Message::Ping(Ping { nonce: 9 })),
        };
        let msg = encode_message(3, &env, 1024).unwrap();
        let (ch, back) = decode_message(&msg, 1024).unwrap();
        assert_eq!(ch, 3);
        assert_eq!(back.request_id, 9);
    }

    #[test]
    fn trailing_bytes_rejected() {
        let env = Envelope { request_id: 1, server_id: vec![], shell_id: vec![], message: None };
        let mut msg = encode_message(1, &env, 1024).unwrap();
        msg.push(0);
        assert!(matches!(decode_message(&msg, 1024), Err(WireError::NotExactlyOneFrame)));
    }
}
