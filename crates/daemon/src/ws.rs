//! WebSocket transport loop (spec §2 fallback mapping): varint channel
//! prefix + one frame per binary message. Datagrams unsupported.

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use hf_protocol::pb::{Envelope, ErrorCode};

use crate::conn::{Conn, OUTGOING_QUEUE};
use crate::wire;
use crate::AppState;

pub(crate) async fn handle_connection(socket: WebSocket, state: Arc<AppState>, peer_ip: IpAddr) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<(u64, Envelope)>(OUTGOING_QUEUE);

    let writer = tokio::spawn(async move {
        while let Some((channel, envelope)) = out_rx.recv().await {
            match wire::encode_message(channel, &envelope, hf_protocol::FRAME_BYTES_DEFAULT) {
                Ok(bytes) => {
                    if ws_tx.send(Message::Binary(bytes.into())).await.is_err() {
                        break;
                    }
                }
                Err(e) => tracing::warn!("dropping unencodable outgoing frame: {e}"),
            }
        }
        let _ = ws_tx.close().await;
    });

    // No TLS channel binding on the WebSocket path (nginx terminates TLS; the
    // daemon cannot see the client's certificate) — ADR 0008 documents this as
    // relying on the operator's TLS/PKI. Empty binding = unbound signature.
    let mut conn = Conn::new(state, peer_ip, out_tx, false, Vec::new());

    while let Some(Ok(message)) = ws_rx.next().await {
        let data = match message {
            Message::Binary(b) => b,
            Message::Close(_) => break,
            // Text/sub-protocol pings are not part of the wire mapping.
            _ => continue,
        };
        match wire::decode_message(&data, conn.max_frame_bytes()) {
            Ok((channel, envelope)) => {
                if !conn.dispatch(channel, envelope).await {
                    break;
                }
            }
            Err(e) => {
                tracing::warn!("protocol error, closing: {e}");
                let _ = conn
                    .send_error(0, ErrorCode::ErrFrameTooLarge, &e.to_string())
                    .await;
                break;
            }
        }
    }

    conn.detach_all();
    writer.abort();
}
