//! Client-side WebTransport backend.
//!
//! Windows uses MsQuic/Schannel (ADR 0022); other platforms retain the
//! wtransport/quinn/rustls implementation.  The rest of the native client sees
//! one deliberately small stream API, so TLS/QUIC implementation types do not
//! leak into shell, attachment, or protocol handling.

fn endpoint_url(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("https://[{host}]:{port}/")
    } else {
        format!("https://{host}:{port}/")
    }
}

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;
    use std::future::poll_fn;
    use std::ptr;
    use std::sync::Arc;

    use anyhow::{anyhow, bail, Context, Result};
    use bytes::{Buf, Bytes};
    use h3::quic::{BidiStream as _, OpenStreams as _, RecvStream as _, SendStreamUnframed as _};
    use h3::stream::BidiStreamHeader;
    use msquic::{BufferRef, CredentialConfig, CredentialFlags, RegistrationConfig, Settings};
    use msquic_async as ma;
    use sha2::{Digest, Sha256};
    use tokio::sync::watch;
    use windows_sys::Win32::Security::Cryptography::{CertFreeCertificateContext, CERT_CONTEXT};

    use super::endpoint_url;
    use crate::schannel_adapter as adapter;

    const ALPN: &str = "h3";
    const MAX_PEER_BIDI_STREAMS: u16 = 64;
    const MAX_PEER_UNI_STREAMS: u16 = 16;
    const STREAM_RECV_WINDOW: u32 = 256 * 1024;
    const CONNECTION_FLOW_WINDOW: u32 = 16 * 1024 * 1024;
    const IDLE_TIMEOUT_MS: u64 = 60_000;
    const SECPKG_ATTR_REMOTE_CERT_CONTEXT: u32 = 0x53;

    /// A Schannel-backed WebTransport session.
    #[derive(Clone)]
    pub struct Connection {
        inner: Arc<Inner>,
    }

    struct Inner {
        conn: Arc<ma::Connection>,
        session_id: h3::webtransport::SessionId,
        cancel: watch::Sender<bool>,
        _lifetime: Arc<TransportLifetime>,
    }

    // MsQuic requires both objects to outlive every connection created from
    // them, including clones held briefly by the HTTP/3 background tasks.
    struct TransportLifetime {
        _configuration: msquic::Configuration,
        _registration: msquic::Registration,
    }

    impl Drop for Inner {
        fn drop(&mut self) {
            let _ = self.cancel.send(true);
            let _ = self.conn.shutdown(0);
        }
    }

    pub struct SendStream {
        inner: adapter::SendHalf<Bytes>,
    }

    pub struct RecvStream {
        inner: adapter::RecvHalf,
        current: Option<ma::StreamRecvBuffer>,
    }

    /// Connect with normal Schannel/WebPKI validation when `expected_hash` is
    /// absent, or with an exact development certificate pin when it is set.
    pub async fn connect_webtransport(
        host: &str,
        port: u16,
        expected_hash: Option<[u8; 32]>,
    ) -> Result<(Connection, [u8; 32])> {
        // MsQuic's setup-only ALPN and credential wrappers contain raw
        // pointers and intentionally are not Send. Keep them in a synchronous
        // scope so the async state machine contains only the long-lived,
        // thread-safe handles before its first await.
        let (registration, configuration, conn) = {
            let registration = msquic::Registration::new(&RegistrationConfig::default())
                .map_err(|status| anyhow!("open MsQuic registration: {status:?}"))?;
            let alpn = [BufferRef::from(ALPN)];
            let settings = Settings::new()
                .set_IdleTimeoutMs(IDLE_TIMEOUT_MS)
                .set_StreamRecvWindowDefault(STREAM_RECV_WINDOW)
                .set_ConnFlowControlWindow(CONNECTION_FLOW_WINDOW)
                .set_PeerBidiStreamCount(MAX_PEER_BIDI_STREAMS)
                .set_PeerUnidiStreamCount(MAX_PEER_UNI_STREAMS)
                .set_DatagramReceiveEnabled();
            let configuration = msquic::Configuration::open(&registration, &alpn, Some(&settings))
                .map_err(|status| anyhow!("open MsQuic configuration: {status:?}"))?;

            let credentials = if expected_hash.is_some() {
                // Development `http://` bootstrap publishes a self-signed
                // leaf hash, checked below before application bytes are sent.
                CredentialConfig::new_client()
                    .set_credential_flags(CredentialFlags::NO_CERTIFICATE_VALIDATION)
            } else {
                // Production: Schannel performs hostname, chain, time, and
                // trust validation against the Windows certificate stores.
                CredentialConfig::new_client()
            };
            configuration
                .load_credential(&credentials)
                .map_err(|status| anyhow!("load Schannel credentials: {status:?}"))?;

            let conn = Arc::new(
                ma::Connection::new(&registration)
                    .map_err(|error| anyhow!("open MsQuic connection: {error:?}"))?,
            );
            (registration, configuration, conn)
        };
        conn.start(&configuration, host, port)
            .await
            .map_err(|error| anyhow!("Schannel QUIC connect: {error:?}"))?;

        let leaf = schannel_peer_leaf(&conn).context("read Schannel peer certificate")?;
        let observed: [u8; 32] = Sha256::digest(&leaf).into();
        if let Some(expected) = expected_hash {
            if observed != expected {
                let _ = conn.shutdown(0);
                bail!("server certificate does not match /webtransport-info pin");
            }
        }

        let lifetime = Arc::new(TransportLifetime {
            _configuration: configuration,
            _registration: registration,
        });

        let adapted = adapter::Connection::new(Arc::clone(&conn));
        let mut builder = h3::client::builder();
        builder.enable_extended_connect(true);
        builder.enable_webtransport(true);
        builder.enable_datagram(true);
        let (mut driver, mut requests) = builder
            .build::<_, _, Bytes>(adapted)
            .await
            .map_err(|error| anyhow!("HTTP/3 handshake: {error}"))?;

        let (cancel, mut driver_cancel) = watch::channel(false);
        let driver_lifetime = Arc::clone(&lifetime);
        tokio::spawn(async move {
            let _lifetime = driver_lifetime;
            tokio::select! {
                _ = poll_fn(|cx| driver.poll_close(cx)) => {}
                _ = driver_cancel.changed() => {}
            }
        });

        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(endpoint_url(host, port))
            .extension(h3::ext::Protocol::WEB_TRANSPORT)
            .body(())
            .context("build WebTransport CONNECT")?;
        let mut connect = requests
            .send_request(request)
            .await
            .map_err(|error| anyhow!("send WebTransport CONNECT: {error}"))?;
        let response = connect
            .recv_response()
            .await
            .map_err(|error| anyhow!("receive WebTransport CONNECT: {error}"))?;
        if !response.status().is_success() {
            bail!("server refused WebTransport with {}", response.status());
        }
        let session_id = connect.id().into();

        // The CONNECT request stream owns the WebTransport session. Keep it
        // alive until the last Connection clone drops, without retaining an
        // Arc back to Inner (which would form a leak cycle).
        let mut session_cancel = cancel.subscribe();
        let session_lifetime = Arc::clone(&lifetime);
        tokio::spawn(async move {
            let _lifetime = session_lifetime;
            let _connect = connect;
            let _ = session_cancel.changed().await;
        });

        Ok((
            Connection {
                inner: Arc::new(Inner {
                    conn,
                    session_id,
                    cancel,
                    _lifetime: lifetime,
                }),
            },
            observed,
        ))
    }

    impl Connection {
        pub async fn open_bi(&self) -> Result<(SendStream, RecvStream)> {
            // One opener per call permits concurrent attachment-stream opens;
            // the opener itself remains alive for the whole in-flight future.
            let adapted = adapter::Connection::new(Arc::clone(&self.inner.conn));
            let mut opener = <adapter::Connection as h3::quic::Connection<Bytes>>::opener(&adapted);
            let mut stream = poll_fn(|cx| opener.poll_open_bidi(cx))
                .await
                .map_err(|error| anyhow!("open WebTransport stream: {error:?}"))?;
            h3::quic::SendStream::<Bytes>::send_data(
                &mut stream,
                BidiStreamHeader::WebTransportBidi(self.inner.session_id),
            )
            .map_err(|error| anyhow!("queue WebTransport stream header: {error:?}"))?;
            poll_fn(|cx| h3::quic::SendStream::<Bytes>::poll_ready(&mut stream, cx))
                .await
                .map_err(|error| anyhow!("write WebTransport stream header: {error:?}"))?;
            let (send, recv) = stream.split();
            Ok((
                SendStream { inner: send },
                RecvStream {
                    inner: recv,
                    current: None,
                },
            ))
        }
    }

    impl SendStream {
        pub async fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
            let mut bytes = Bytes::copy_from_slice(bytes);
            while bytes.has_remaining() {
                let written = poll_fn(|cx| self.inner.poll_send(cx, &mut bytes))
                    .await
                    .map_err(|error| anyhow!("write WebTransport stream: {error:?}"))?;
                if written == 0 {
                    bail!("WebTransport stream accepted zero bytes");
                }
            }
            Ok(())
        }
    }

    impl RecvStream {
        pub async fn read(&mut self, output: &mut [u8]) -> Result<Option<usize>> {
            if output.is_empty() {
                return Ok(Some(0));
            }
            loop {
                if let Some(chunk) = self.current.as_mut() {
                    if chunk.has_remaining() {
                        let len = chunk.remaining().min(output.len());
                        chunk.copy_to_slice(&mut output[..len]);
                        return Ok(Some(len));
                    }
                    self.current = None;
                }
                self.current = poll_fn(|cx| self.inner.poll_data(cx))
                    .await
                    .map_err(|error| anyhow!("read WebTransport stream: {error:?}"))?;
                if self.current.is_none() {
                    return Ok(None);
                }
            }
        }
    }

    /// Read the authenticated remote leaf from Schannel and free the returned
    /// certificate context after copying its bounded DER bytes.
    fn schannel_peer_leaf(conn: &ma::Connection) -> Result<Vec<u8>> {
        #[repr(C)]
        struct SchannelContextAttribute {
            attribute: u32,
            buffer: *mut c_void,
        }

        let mut cert: *const CERT_CONTEXT = ptr::null();
        let mut attribute = SchannelContextAttribute {
            attribute: SECPKG_ATTR_REMOTE_CERT_CONTEXT,
            buffer: &mut cert as *mut _ as *mut c_void,
        };
        let len = std::mem::size_of::<SchannelContextAttribute>() as u32;
        // SAFETY: the connection owns a live HQUIC for this call and the
        // buffer layout is QUIC_SCHANNEL_CONTEXT_ATTRIBUTE_W.
        unsafe {
            msquic::Api::get_param(
                conn.msquic_handle(),
                msquic::PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_W,
                &len,
                &mut attribute as *mut _ as *mut c_void,
            )
            .map_err(|status| anyhow!("query Schannel certificate: {status:?}"))?;
        }
        if cert.is_null() {
            bail!("Schannel returned no peer certificate");
        }
        // A certificate leaf is far below the protocol frame ceiling. Keep a
        // defensive cap before allocating in case a provider returns garbage.
        const MAX_CERT_DER_BYTES: usize = 1024 * 1024;
        // SAFETY: Schannel returned a non-null CERT_CONTEXT. We copy before
        // releasing it with CertFreeCertificateContext below.
        let result = unsafe {
            let context = &*cert;
            let len = context.cbCertEncoded as usize;
            if context.pbCertEncoded.is_null() || len == 0 || len > MAX_CERT_DER_BYTES {
                Err(anyhow!(
                    "Schannel peer certificate has invalid length {len}"
                ))
            } else {
                Ok(std::slice::from_raw_parts(context.pbCertEncoded, len).to_vec())
            }
        };
        // SAFETY: ownership of the context returned by QueryContextAttributes
        // transfers to the caller and must be released with this function.
        unsafe { CertFreeCertificateContext(cert) };
        result
    }
}

#[cfg(not(windows))]
mod platform {
    use anyhow::{anyhow, Context, Result};
    use wtransport::tls::Sha256Digest;
    use wtransport::{ClientConfig, Endpoint};

    use super::endpoint_url;

    pub struct Connection {
        inner: wtransport::Connection,
    }

    pub struct SendStream {
        inner: wtransport::SendStream,
    }

    pub struct RecvStream {
        inner: wtransport::RecvStream,
    }

    pub async fn connect_webtransport(
        host: &str,
        port: u16,
        expected_hash: Option<[u8; 32]>,
    ) -> Result<(Connection, [u8; 32])> {
        let config = match expected_hash {
            Some(hash) => ClientConfig::builder()
                .with_bind_default()
                .with_server_certificate_hashes([Sha256Digest::new(hash)])
                .build(),
            None => ClientConfig::builder()
                .with_bind_default()
                .with_native_certs()
                .build(),
        };
        let endpoint = Endpoint::client(config)?;
        let inner = endpoint
            .connect(endpoint_url(host, port))
            .await
            .context("webtransport connect")?;
        let digest = inner
            .peer_identity()
            .and_then(|chain| chain.as_slice().first().map(|cert| cert.hash()))
            .ok_or_else(|| anyhow!("server presented no certificate"))?;
        let observed = *digest.as_ref();
        Ok((Connection { inner }, observed))
    }

    impl Connection {
        pub async fn open_bi(&self) -> Result<(SendStream, RecvStream)> {
            let (send, recv) = self.inner.open_bi().await?.await?;
            Ok((SendStream { inner: send }, RecvStream { inner: recv }))
        }
    }

    impl SendStream {
        pub async fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
            self.inner.write_all(bytes).await?;
            Ok(())
        }
    }

    impl RecvStream {
        pub async fn read(&mut self, output: &mut [u8]) -> Result<Option<usize>> {
            Ok(self.inner.read(output).await?)
        }
    }
}

pub use platform::{connect_webtransport, Connection, RecvStream, SendStream};
