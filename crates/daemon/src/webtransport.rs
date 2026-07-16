//! WebTransport transport (spec §2): every bidirectional stream is a
//! channel; the first client-opened stream is the control channel (0); each
//! further stream is an attachment channel. Frames are the plain §3
//! length-prefixed encoding — no varint prefix (streams delimit channels).
//!
//! Phase 3 uses a fresh self-signed identity per daemon start (≤14 days, the
//! `serverCertificateHashes` ceiling); the browser pins its SHA-256 obtained
//! from `/webtransport-info`. Production replaces this with an ACME
//! certificate on a real hostname (plan: deployment section).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use hf_protocol::framing::FrameDecoder;
use hf_protocol::pb::Envelope;
use wtransport::endpoint::endpoint_side::Server;
use wtransport::endpoint::IncomingSession;
use wtransport::{Endpoint, Identity, ServerConfig};

use crate::conn::{Conn, OUTGOING_QUEUE};
use crate::AppState;

pub struct WtListener {
    pub local_addr: SocketAddr,
    /// SHA-256 of the certificate, base64 (for serverCertificateHashes).
    pub cert_hash_base64: String,
    endpoint: Arc<Endpoint<Server>>,
}

impl WtListener {
    pub fn bind(bind: SocketAddr) -> anyhow::Result<WtListener> {
        let identity = Identity::self_signed(["localhost", "127.0.0.1", "::1"])?;
        let hash = identity
            .certificate_chain()
            .as_slice()
            .first()
            .expect("self-signed identity has one certificate")
            .hash();
        // Standard (padded) base64 of the raw digest bytes.
        let cert_hash_base64 = base64_encode(hash.as_ref());

        let config = ServerConfig::builder()
            .with_bind_address(bind)
            .with_identity(identity)
            .build();
        let endpoint = Arc::new(Endpoint::server(config)?);
        let local_addr = endpoint.local_addr()?;
        Ok(WtListener { local_addr, cert_hash_base64, endpoint })
    }

    pub fn spawn_accept_loop(&self, state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
        let endpoint = Arc::clone(&self.endpoint);
        tokio::spawn(async move {
            loop {
                let incoming = endpoint.accept().await;
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = handle_session(incoming, state).await {
                        tracing::debug!("webtransport session ended: {e:#}");
                    }
                });
            }
        })
    }
}

enum WriterMsg {
    Register(u64, wtransport::SendStream),
    Frame(u64, Envelope),
}

async fn handle_session(incoming: IncomingSession, state: Arc<AppState>) -> anyhow::Result<()> {
    let request = incoming.await?;
    let connection = Arc::new(request.accept().await?);

    // Writer: owns all send-halves, serializes frames per channel.
    let (writer_tx, mut writer_rx) = tokio::sync::mpsc::channel::<WriterMsg>(OUTGOING_QUEUE);
    let writer = tokio::spawn(async move {
        let mut streams: HashMap<u64, wtransport::SendStream> = HashMap::new();
        while let Some(msg) = writer_rx.recv().await {
            match msg {
                WriterMsg::Register(channel, stream) => {
                    streams.insert(channel, stream);
                }
                WriterMsg::Frame(channel, envelope) => {
                    let Some(stream) = streams.get_mut(&channel) else { continue };
                    match hf_protocol::framing::encode_frame(
                        &envelope,
                        hf_protocol::FRAME_BYTES_DEFAULT,
                    ) {
                        Ok(bytes) => {
                            if stream.write_all(&bytes).await.is_err() {
                                streams.remove(&channel);
                            }
                        }
                        Err(e) => tracing::warn!("dropping unencodable frame: {e}"),
                    }
                }
            }
        }
    });

    // Adapter: Conn's transport-neutral (channel, envelope) → WriterMsg.
    // Registration always precedes the channel's first outgoing frame because
    // Register is enqueued before the reader dispatches anything.
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<(u64, Envelope)>(OUTGOING_QUEUE);
    let adapter_writer_tx = writer_tx.clone();
    tokio::spawn(async move {
        while let Some((channel, envelope)) = out_rx.recv().await {
            if adapter_writer_tx.send(WriterMsg::Frame(channel, envelope)).await.is_err() {
                break;
            }
        }
    });

    let peer_ip = connection.remote_address().ip();
    let conn =
        Arc::new(tokio::sync::Mutex::new(Conn::new(Arc::clone(&state), peer_ip, out_tx, true)));
    let mut next_channel: u64 = 0;

    loop {
        let (send, mut recv) = match connection.accept_bi().await {
            Ok(pair) => pair,
            Err(_) => break, // connection closed
        };
        let channel = next_channel;
        next_channel += 1;
        if writer_tx.send(WriterMsg::Register(channel, send)).await.is_err() {
            break;
        }

        let conn = Arc::clone(&conn);
        let connection = Arc::clone(&connection);
        tokio::spawn(async move {
            let mut decoder = FrameDecoder::new(hf_protocol::FRAME_BYTES_DEFAULT);
            let mut buf = vec![0u8; 16 * 1024];
            'read: while let Ok(Some(n)) = recv.read(&mut buf).await {
                if decoder.extend(&buf[..n]).is_err() {
                    connection.close(0u32.into(), b"frame too large");
                    break;
                }
                loop {
                    match decoder.next_frame() {
                        Ok(Some(envelope)) => {
                            if !conn.lock().await.dispatch(channel, envelope).await {
                                connection.close(0u32.into(), b"closed");
                                break 'read;
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            tracing::warn!("protocol error on stream: {e}");
                            connection.close(0u32.into(), b"protocol error");
                            break 'read;
                        }
                    }
                }
            }
            // Stream finished: control stream ends the session; an
            // attachment stream just detaches (spec §11).
            if channel == 0 {
                connection.close(0u32.into(), b"control stream closed");
            } else {
                conn.lock().await.channel_closed(channel);
            }
        });
    }

    conn.lock().await.detach_all();
    writer.abort();
    Ok(())
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[n as usize & 63] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn base64_matches_reference() {
        assert_eq!(super::base64_encode(b""), "");
        assert_eq!(super::base64_encode(b"f"), "Zg==");
        assert_eq!(super::base64_encode(b"fo"), "Zm8=");
        assert_eq!(super::base64_encode(b"foo"), "Zm9v");
        assert_eq!(super::base64_encode(&[0xfb, 0xff, 0x00]), "+/8A");
    }
}
