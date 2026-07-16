//! End-to-end echo test over real QUIC/UDP on loopback: a wtransport client
//! connects to the in-process echo server, exercising bidirectional streams
//! and datagrams. This is the automated half of the Phase 0 exit criterion;
//! browser verification uses browser-echo.html manually.

use spike_webtransport_echo::EchoServer;
use wtransport::{ClientConfig, Endpoint};

#[tokio::test]
async fn stream_and_datagram_echo() {
    let server = EchoServer::bind(0).expect("bind echo server");
    let port = server.endpoint.local_addr().unwrap().port();
    // Pin the self-signed cert by SHA-256 hash, mirroring the browser's
    // serverCertificateHashes mechanism.
    let cert_hash = server.cert_hash.clone();
    tokio::spawn(async move { server.serve().await });

    let client = Endpoint::client(
        ClientConfig::builder()
            .with_bind_default()
            .with_server_certificate_hashes([cert_hash])
            .build(),
    )
    .expect("client endpoint");

    let connection = client
        .connect(format!("https://127.0.0.1:{port}/echo"))
        .await
        .expect("webtransport session established");

    // Reliable bidirectional stream echo.
    let (mut send, mut recv) = connection.open_bi().await.unwrap().await.unwrap();
    let payload = b"holdfast phase-0 echo \xf0\x9f\xa6\x80";
    send.write_all(payload).await.unwrap();

    let mut got = vec![0u8; payload.len()];
    let mut filled = 0;
    while filled < got.len() {
        let n = recv.read(&mut got[filled..]).await.unwrap().expect("stream open");
        filled += n;
    }
    assert_eq!(&got, payload, "stream echo must return exact bytes");

    // Unreliable datagram echo (loopback: loss is not expected; retry a few
    // times anyway so the test cannot flake on a genuinely dropped datagram).
    let mut datagram_ok = false;
    for _ in 0..5 {
        connection.send_datagram(b"datagram-ping").unwrap();
        match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            connection.receive_datagram(),
        )
        .await
        {
            Ok(Ok(d)) if d.payload().as_ref() == b"datagram-ping" => {
                datagram_ok = true;
                break;
            }
            _ => continue,
        }
    }
    assert!(datagram_ok, "datagram echo must round-trip on loopback");
}
