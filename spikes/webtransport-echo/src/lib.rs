//! Phase 0 spike: minimal secure WebTransport echo over real QUIC/UDP.
//!
//! Proves: certificate setup, session accept, bidirectional streams and
//! datagrams with the `wtransport` (quinn-based) stack. Disposable code —
//! production crates must not import this.

use anyhow::Result;
use wtransport::endpoint::{endpoint_side::Server, IncomingSession};
use wtransport::{Endpoint, Identity, ServerConfig};

pub struct EchoServer {
    pub endpoint: Endpoint<Server>,
    /// SHA-256 digest of the self-signed certificate, for certificate pinning
    /// (`serverCertificateHashes` in the browser, and the Rust client test).
    pub cert_hash: wtransport::tls::Sha256Digest,
    /// The same digest formatted as a JS byte array for browser-echo.html.
    pub cert_hash_js: String,
}

impl EchoServer {
    /// Bind on the given UDP port (0 = ephemeral) with a fresh self-signed
    /// certificate valid for localhost use.
    pub fn bind(port: u16) -> Result<EchoServer> {
        let identity = Identity::self_signed(["localhost", "127.0.0.1", "::1"])?;
        let cert_hash = identity
            .certificate_chain()
            .as_slice()
            .first()
            .expect("self-signed identity has one certificate")
            .hash();
        let cert_hash_js = cert_hash.fmt(wtransport::tls::Sha256DigestFmt::BytesArray);

        let config = ServerConfig::builder()
            .with_bind_default(port)
            .with_identity(identity)
            .build();

        let endpoint = Endpoint::server(config)?;
        Ok(EchoServer {
            endpoint,
            cert_hash,
            cert_hash_js,
        })
    }

    /// Accept sessions forever, echoing on every bidi stream and datagram.
    pub async fn serve(&self) {
        loop {
            let incoming = self.endpoint.accept().await;
            tokio::spawn(async move {
                if let Err(e) = handle_session(incoming).await {
                    tracing::warn!("session ended with error: {e:#}");
                }
            });
        }
    }
}

async fn handle_session(incoming: IncomingSession) -> Result<()> {
    let request = incoming.await?;
    tracing::info!(
        authority = request.authority(),
        path = request.path(),
        "session request"
    );
    let connection = request.accept().await?;

    loop {
        tokio::select! {
            stream = connection.accept_bi() => {
                let (mut send, mut recv) = stream?;
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 64 * 1024];
                    while let Ok(Some(n)) = recv.read(&mut buf).await {
                        if send.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
            datagram = connection.receive_datagram() => {
                let datagram = datagram?;
                connection.send_datagram(datagram.payload())?;
            }
        }
    }
}
