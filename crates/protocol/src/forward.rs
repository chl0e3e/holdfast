//! Validation shared by the SOCKS client and daemon; no network I/O.

pub fn valid_destination(host: &str, port: u32) -> bool {
    if host.is_empty() || host.len() > 255 || !(1..=65535).contains(&port) {
        return false;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    host.strip_suffix('.')
        .unwrap_or(host)
        .split('.')
        .all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        framing::{encode_frame, FrameDecoder},
        negotiate::negotiate_server,
        pb::*,
        FRAME_BYTES_DEFAULT,
    };

    #[test]
    fn destinations_and_minor_gate() {
        for host in ["localhost", "example.com.", "127.0.0.1", "::1"] {
            assert!(valid_destination(host, 443));
        }
        for host in [
            "",
            "a/b",
            "user@host",
            "a\0b",
            "-host",
            "a..b",
            "[::1]",
            "héllo",
        ] {
            assert!(!valid_destination(host, 443));
        }
        assert!(!valid_destination(&"a".repeat(256), 443));
        assert!(!valid_destination("localhost", 0));
        assert!(!valid_destination("localhost", 65536));
        for minor in [0, 1, 2, 3] {
            let hello = ClientHello {
                protocol_minor: minor,
                capabilities: vec![Capability::TcpForward as i32],
                encodings: vec![Encoding::Utf8 as i32],
                max_frame_bytes: FRAME_BYTES_DEFAULT,
                ..Default::default()
            };
            let negotiated = negotiate_server(
                &hello,
                &[Capability::TcpForward],
                FRAME_BYTES_DEFAULT,
                0,
                false,
            )
            .unwrap();
            assert_eq!(
                negotiated.capabilities.contains(&Capability::TcpForward),
                minor >= 3
            );
        }
    }

    #[test]
    fn forwarding_schema_round_trips() {
        for message in [
            envelope::Message::OpenTcpForward(OpenTcpForward {
                host: "::1".into(),
                port: 443,
            }),
            envelope::Message::TcpForwardOpened(TcpForwardOpened {
                bound_ip: "::1".into(),
                bound_port: 1234,
            }),
            envelope::Message::TcpForwardData(TcpForwardData {
                data: vec![42; crate::FORWARD_DATA_BYTES_MAX],
            }),
            envelope::Message::TcpForwardEof(TcpForwardEof {}),
            envelope::Message::TcpForwardAck(TcpForwardAck {}),
        ] {
            let envelope = Envelope {
                message: Some(message),
                ..Default::default()
            };
            let bytes = encode_frame(&envelope, crate::FRAME_BYTES_FLOOR).unwrap();
            let mut decoder = FrameDecoder::new(crate::FRAME_BYTES_FLOOR);
            decoder.extend(&bytes).unwrap();
            assert_eq!(decoder.next_frame().unwrap(), Some(envelope));
        }
    }
}
