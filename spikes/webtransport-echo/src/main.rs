//! Run the echo server for manual browser verification:
//!
//! ```bash
//! cargo run -p spike-webtransport-echo            # listens on UDP 4433
//! cd spikes/webtransport-echo && python3 -m http.server 8080
//! # open http://localhost:8080/browser-echo.html and paste the printed hash
//! ```

use spike_webtransport_echo::EchoServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let server = EchoServer::bind(4433)?;
    println!("WebTransport echo listening on UDP {}", server.endpoint.local_addr()?);
    println!("serverCertificateHashes value (paste into browser-echo.html):");
    println!("{}", server.cert_hash_js);
    server.serve().await;
    Ok(())
}
