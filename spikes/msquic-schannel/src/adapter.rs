//! An `h3::quic` transport adapter over `msquic-async`.
//!
//! This replaces `msquic-h3`. The reason is narrow and specific: WebTransport
//! stream payload is opaque and must not be wrapped in H3 DATA frames, so
//! writing it requires [`h3::quic::SendStreamUnframed`] — and `msquic-h3` does
//! not implement it. Adding it there meant threading a new input through
//! `H3SendStream`'s reducer state machine (terminal publication, the SF-2
//! non-consuming finish guard, MF-2 provisional cancellation), which is a poor
//! thing to own in someone else's crate. `msquic-async` exposes
//! `poll_write(cx, &[u8], fin)` directly, so here the same trait is a handful
//! of lines.
//!
//! Only the client subset is implemented. `poll_accept_bidi`/`poll_accept_recv`
//! are wired because h3 needs them for the server's control and QPACK streams,
//! but nothing here supports being a server.
//!
//! The one patch to vendored `msquic-async` is `Connection::msquic_handle`,
//! because the ADR 0008 channel binding needs `GetParam` on the live handle and
//! upstream keeps it private.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Buf;
use h3::quic::{ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf};
use msquic_async as ma;

// Debug, not Display: msquic-async's Display for `ConnectionLost` is the bare
// string "connection lost" and drops the wrapped `ConnectionError`, which is
// the only part that says *why*.
fn conn_err(origin: &str, e: impl std::fmt::Debug) -> ConnectionErrorIncoming {
    ConnectionErrorIncoming::InternalError(format!("{origin}: {e:?}"))
}

fn stream_err(origin: &str, e: impl std::fmt::Debug) -> StreamErrorIncoming {
    StreamErrorIncoming::ConnectionErrorIncoming {
        connection_error: conn_err(origin, e),
    }
}

/// msquic gives stream ids as `Option<u64>` (None before the stream starts).
/// h3 wants an infallible `StreamId`; every stream h3 asks about has started.
fn stream_id(id: Option<u64>) -> StreamId {
    StreamId::try_from(id.unwrap_or(0)).unwrap_or_else(|_| StreamId::try_from(0).unwrap())
}

type OpenFut = Pin<Box<dyn Future<Output = Result<ma::Stream, ma::StreamStartError>> + Send>>;

/// h3-facing wrapper around a connected `msquic_async::Connection`.
pub struct Connection {
    conn: Arc<ma::Connection>,
    /// Persistent opener backing the `OpenStreams` impl on `Connection`
    /// itself. It MUST outlive individual polls: an in-flight open is a boxed
    /// future, and building a fresh `Opener` per poll would drop and restart it
    /// every time, so it could never complete. h3 opens its control stream
    /// through this path, so that mistake stalls the whole handshake until the
    /// connection dies of QUIC_STATUS_CONNECTION_IDLE.
    opener: Opener,
}

impl Connection {
    pub fn new(conn: Arc<ma::Connection>) -> Self {
        Self {
            opener: Opener {
                conn: conn.clone(),
                bidi: None,
                uni: None,
            },
            conn,
        }
    }

    /// The underlying connection, for the Schannel `GetParam` channel binding.
    pub fn inner(&self) -> &Arc<ma::Connection> {
        &self.conn
    }
}

/// Opens outgoing streams. `msquic-async` only offers a borrowing future for
/// opening, so each open is driven as a boxed `'static` future that owns an
/// `Arc` clone of the connection.
pub struct Opener {
    conn: Arc<ma::Connection>,
    bidi: Option<OpenFut>,
    uni: Option<OpenFut>,
}

impl Opener {
    fn poll_open(
        conn: &Arc<ma::Connection>,
        slot: &mut Option<OpenFut>,
        kind: ma::StreamType,
        origin: &str,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ma::Stream, StreamErrorIncoming>> {
        let fut = slot.get_or_insert_with(|| {
            let conn = conn.clone();
            Box::pin(async move { conn.open_outbound_stream(kind, false).await })
        });
        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                *slot = None;
                Poll::Ready(result.map_err(|e| stream_err(origin, e)))
            }
        }
    }
}

impl<B: Buf> h3::quic::OpenStreams<B> for Opener {
    type BidiStream = Bidi<B>;
    type SendStream = SendHalf<B>;

    fn poll_open_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<Bidi<B>, StreamErrorIncoming>> {
        let stream = std::task::ready!(Self::poll_open(
            &self.conn,
            &mut self.bidi,
            ma::StreamType::Bidirectional,
            "poll_open_bidi",
            cx
        ))?;
        Poll::Ready(Ok(Bidi::from_stream(stream)))
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<SendHalf<B>, StreamErrorIncoming>> {
        let stream = std::task::ready!(Self::poll_open(
            &self.conn,
            &mut self.uni,
            ma::StreamType::Unidirectional,
            "poll_open_send",
            cx
        ))?;
        // A unidirectional stream has no read half, so this must NOT go through
        // Bidi::from_stream - that expects both and would panic here.
        let id = stream.id();
        let (_read, write) = stream.split();
        Poll::Ready(Ok(SendHalf {
            write: write.expect("outbound uni stream has a send half"),
            id,
            pending: None,
        }))
    }

    fn close(&mut self, code: h3::error::Code, _reason: &[u8]) {
        let _ = self.conn.shutdown(code.value());
    }
}

impl<B: Buf> h3::quic::OpenStreams<B> for Connection {
    type BidiStream = Bidi<B>;
    type SendStream = SendHalf<B>;

    fn poll_open_bidi(&mut self, cx: &mut Context<'_>) -> Poll<Result<Bidi<B>, StreamErrorIncoming>> {
        h3::quic::OpenStreams::<B>::poll_open_bidi(&mut self.opener, cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<SendHalf<B>, StreamErrorIncoming>> {
        h3::quic::OpenStreams::<B>::poll_open_send(&mut self.opener, cx)
    }

    fn close(&mut self, code: h3::error::Code, _reason: &[u8]) {
        let _ = self.conn.shutdown(code.value());
    }
}

impl<B: Buf> h3::quic::Connection<B> for Connection {
    type RecvStream = RecvHalf;
    type OpenStreams = Opener;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<RecvHalf, ConnectionErrorIncoming>> {
        match self.conn.poll_accept_inbound_uni_stream(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(read)) => Poll::Ready(Ok(RecvHalf { read })),
            Poll::Ready(Err(e)) => Poll::Ready(Err(conn_err("poll_accept_recv", e))),
        }
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Bidi<B>, ConnectionErrorIncoming>> {
        match self.conn.poll_accept_inbound_stream(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(stream)) => Poll::Ready(Ok(Bidi::from_stream(stream))),
            Poll::Ready(Err(e)) => Poll::Ready(Err(conn_err("poll_accept_bidi", e))),
        }
    }

    fn opener(&self) -> Opener {
        Opener {
            conn: self.conn.clone(),
            bidi: None,
            uni: None,
        }
    }
}

/// A bidirectional stream, held pre-split so `split()` is free.
pub struct Bidi<B> {
    send: SendHalf<B>,
    recv: RecvHalf,
}

impl<B: Buf> Bidi<B> {
    fn from_stream(stream: ma::Stream) -> Self {
        let id = stream.id();
        let (read, write) = stream.split();
        Self {
            send: SendHalf {
                write: write.expect("bidi stream has a send half"),
                id,
                pending: None,
            },
            recv: RecvHalf {
                read: read.expect("bidi stream has a recv half"),
            },
        }
    }
}

/// Send half. `pending` holds the one `WriteBuf` h3 may have queued via
/// `send_data`; h3's contract is `poll_ready` before each `send_data`, so at
/// most one is outstanding.
pub struct SendHalf<B> {
    write: ma::WriteStream,
    id: Option<u64>,
    pending: Option<WriteBuf<B>>,
}

impl<B: Buf> SendHalf<B> {
    /// Drain `pending` into the stream. msquic may accept a partial write, so
    /// this loops until the buffer is empty or the stream blocks.
    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        while let Some(buf) = self.pending.as_mut() {
            if !buf.has_remaining() {
                self.pending = None;
                break;
            }
            let chunk = buf.chunk();
            match self.write.poll_write(cx, chunk, false) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(stream_err("poll_flush", e))),
                Poll::Ready(Ok(n)) => {
                    buf.advance(n);
                    if n == 0 {
                        return Poll::Pending;
                    }
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<B: Buf> h3::quic::SendStream<B> for SendHalf<B> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.poll_flush(cx)
    }

    fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        // h3 always calls poll_ready first, so pending is drained by here.
        self.pending = Some(data.into());
        Ok(())
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        std::task::ready!(self.poll_flush(cx))?;
        self.write.poll_finish_write(cx).map_err(|e| stream_err("poll_finish", e))
    }

    fn reset(&mut self, reset_code: u64) {
        let _ = self.write.abort_write(reset_code);
    }

    fn send_id(&self) -> StreamId {
        stream_id(self.id)
    }
}

impl<B: Buf> h3::quic::SendStreamUnframed<B> for SendHalf<B> {
    /// The whole reason this adapter exists: raw, unframed bytes, which is what
    /// WebTransport stream payload must be.
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        std::task::ready!(self.poll_flush(cx))?;
        if !buf.has_remaining() {
            return Poll::Ready(Ok(0));
        }
        match self.write.poll_write(cx, buf.chunk(), false) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(stream_err("poll_send", e))),
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(n))
            }
        }
    }
}

/// Receive half.
pub struct RecvHalf {
    read: ma::ReadStream,
}

impl h3::quic::RecvStream for RecvHalf {
    type Buf = ma::StreamRecvBuffer;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        match self.read.poll_read_chunk(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(chunk)) => Poll::Ready(Ok(chunk)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(stream_err("poll_data", e))),
        }
    }

    fn stop_sending(&mut self, error_code: u64) {
        let _ = self.read.abort_read(error_code);
    }

    fn recv_id(&self) -> StreamId {
        stream_id(self.read.id())
    }
}

impl<B: Buf> h3::quic::SendStream<B> for Bidi<B> {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        h3::quic::SendStream::<B>::poll_ready(&mut self.send, cx)
    }

    fn send_data<T: Into<WriteBuf<B>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        h3::quic::SendStream::<B>::send_data(&mut self.send, data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        h3::quic::SendStream::<B>::poll_finish(&mut self.send, cx)
    }

    fn reset(&mut self, reset_code: u64) {
        h3::quic::SendStream::<B>::reset(&mut self.send, reset_code)
    }

    fn send_id(&self) -> StreamId {
        h3::quic::SendStream::<B>::send_id(&self.send)
    }
}

impl<B: Buf> h3::quic::SendStreamUnframed<B> for Bidi<B> {
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        h3::quic::SendStreamUnframed::<B>::poll_send(&mut self.send, cx, buf)
    }
}

impl<B: Buf> h3::quic::RecvStream for Bidi<B> {
    type Buf = ma::StreamRecvBuffer;

    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
        h3::quic::RecvStream::poll_data(&mut self.recv, cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        h3::quic::RecvStream::stop_sending(&mut self.recv, error_code)
    }

    fn recv_id(&self) -> StreamId {
        h3::quic::RecvStream::recv_id(&self.recv)
    }
}

impl<B: Buf> h3::quic::BidiStream<B> for Bidi<B> {
    type SendStream = SendHalf<B>;
    type RecvStream = RecvHalf;

    fn split(self) -> (SendHalf<B>, RecvHalf) {
        (self.send, self.recv)
    }
}
