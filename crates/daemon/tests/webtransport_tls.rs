//! Production WebTransport TLS configuration tests.
//!
//! Reproduce with: `cargo test -p hf-daemon --test webtransport_tls`

use std::path::PathBuf;

use base64::Engine;
use hf_daemon::{AuthConfig, Daemon, DaemonConfig, WebTransportCertificateMode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wtransport::tls::Sha256Digest;
use wtransport::{ClientConfig, Endpoint};

struct TestIdentity {
    dir: PathBuf,
    certificate: PathBuf,
    private_key: PathBuf,
}

impl Drop for TestIdentity {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn identity() -> TestIdentity {
    let dir = std::env::temp_dir().join(format!(
        "holdfast-webtransport-tls-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&dir).unwrap();
    let certificate = dir.join("fullchain.pem");
    let private_key = dir.join("privkey.pem");
    let generated = wtransport::Identity::self_signed(["localhost", "127.0.0.1"]).unwrap();
    generated
        .certificate_chain()
        .store_pemfile(&certificate)
        .await
        .unwrap();
    generated
        .private_key()
        .store_secret_pemfile(&private_key)
        .await
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&private_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    TestIdentity {
        dir,
        certificate,
        private_key,
    }
}

#[tokio::test]
async fn configured_pem_identity_serves_real_webtransport() {
    let identity = identity().await;
    let daemon = Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        webtransport_bind: Some("127.0.0.1:0".parse().unwrap()),
        webtransport_certificate: Some(identity.certificate.clone()),
        webtransport_private_key: Some(identity.private_key.clone()),
        ..Default::default()
    })
    .await
    .unwrap();
    assert_eq!(
        daemon.webtransport_certificate_mode,
        Some(WebTransportCertificateMode::WebPki)
    );
    let mut info = tokio::net::TcpStream::connect(daemon.local_addr)
        .await
        .unwrap();
    info.write_all(
        b"GET /webtransport-info HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();
    let mut response = Vec::new();
    info.read_to_end(&mut response).await.unwrap();
    assert!(
        String::from_utf8_lossy(&response).contains(r#""certificateMode":"webpki""#),
        "browser negotiation must select WebPKI"
    );

    // The generated test certificate is not in system WebPKI, so this test
    // pins its hash. Production browsers omit the hash and validate the same
    // configured chain through WebPKI.
    let hash: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(daemon.webtransport_cert_hash_base64.as_ref().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let endpoint = Endpoint::client(
        ClientConfig::builder()
            .with_bind_default()
            .with_server_certificate_hashes([Sha256Digest::new(hash)])
            .build(),
    )
    .unwrap();
    endpoint
        .connect(format!(
            "https://127.0.0.1:{}/",
            daemon.webtransport_addr.unwrap().port()
        ))
        .await
        .expect("configured certificate completes WebTransport handshake");
    daemon.abort();
}

#[tokio::test]
async fn tls_pair_is_atomic_and_self_signed_is_loopback_only() {
    let identity = identity().await;
    let incomplete = match Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        webtransport_certificate: Some(identity.certificate.clone()),
        webtransport_private_key: None,
        ..Default::default()
    })
    .await
    {
        Ok(_) => panic!("incomplete WebTransport TLS pair unexpectedly started"),
        Err(error) => error,
    };
    assert!(incomplete
        .to_string()
        .contains("both certificate and private-key"));

    let exposed = match Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        webtransport_bind: Some("0.0.0.0:0".parse().unwrap()),
        auth: AuthConfig::SshKeys {
            users: Default::default(),
        },
        ..Default::default()
    })
    .await
    {
        Ok(_) => panic!("non-loopback self-signed WebTransport unexpectedly started"),
        Err(error) => error,
    };
    assert!(exposed.to_string().contains("self-signed WebTransport"));
}

#[cfg(unix)]
#[tokio::test]
async fn configured_private_key_permissions_fail_closed() {
    use std::os::unix::fs::PermissionsExt;

    let identity = identity().await;
    std::fs::set_permissions(
        &identity.private_key,
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let error = match Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        webtransport_certificate: Some(identity.certificate.clone()),
        webtransport_private_key: Some(identity.private_key.clone()),
        ..Default::default()
    })
    .await
    {
        Ok(_) => panic!("publicly readable WebTransport private key unexpectedly loaded"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("mode 0600"));
}
