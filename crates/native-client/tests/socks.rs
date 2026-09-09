#![cfg(unix)]
use hf_daemon::{Daemon, DaemonConfig};
use hf_native_client::{connect, socks::SocksProxy};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{timeout, Duration},
};

async fn handshake(proxy: &SocksProxy, address: Vec<u8>, port: u16) -> TcpStream {
    let mut socket = TcpStream::connect(proxy.address).await.unwrap();
    for byte in [5, 1, 0] {
        socket.write_all(&[byte]).await.unwrap();
    }
    let mut method = [0; 2];
    socket.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let mut req = vec![5, 1, 0];
    req.extend(address);
    req.extend(port.to_be_bytes());
    socket.write_all(&req).await.unwrap();
    let mut reply = [0; 4];
    socket.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..3], &[5, 0, 0]);
    let mut bound = [0; 18];
    let n = if reply[3] == 4 { 18 } else { 6 };
    socket.read_exact(&mut bound[..n]).await.unwrap();
    socket
}

#[tokio::test]
async fn socks_over_real_quic_streams_large_data_dns_and_half_close() {
    let daemon = Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        tcp_forward_users: ["dev".into()].into(),
        ..Default::default()
    })
    .await
    .unwrap();
    let conn = connect(&format!("http://{}", daemon.local_addr))
        .await
        .unwrap();
    assert!(conn
        .hello
        .capabilities
        .contains(&(hf_protocol::pb::Capability::TcpForward as i32)));
    assert!(
        SocksProxy::start(conn.connection.clone(), "0.0.0.0:0".parse().unwrap())
            .await
            .is_err()
    );
    let proxy = SocksProxy::start(conn.connection.clone(), "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    for (bind, address) in [
        ("127.0.0.1:0", vec![1, 127, 0, 0, 1]),
        ("127.0.0.1:0", [vec![3, 9], b"localhost".to_vec()].concat()),
        (
            "[::1]:0",
            [vec![4], std::net::Ipv6Addr::LOCALHOST.octets().to_vec()].concat(),
        ),
    ] {
        let target = TcpListener::bind(bind).await.unwrap();
        let port = target.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = target.accept().await.unwrap();
            let mut buffer = [0; 8192];
            let mut total = 0;
            loop {
                let n = socket.read(&mut buffer).await.unwrap();
                if n == 0 {
                    break;
                }
                assert!(buffer[..n].iter().all(|b| *b == 42));
                total += n;
            }
            assert_eq!(total, 257 * 1024);
            socket.write_all(b"after EOF").await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let mut socket = timeout(Duration::from_secs(5), handshake(&proxy, address, port))
            .await
            .unwrap();
        timeout(Duration::from_secs(10), async {
            socket.write_all(&vec![42; 257 * 1024]).await.unwrap();
            socket.shutdown().await.unwrap();
            let mut response = [0; 9];
            socket.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"after EOF");
            let mut end = [0];
            assert_eq!(socket.read(&mut end).await.unwrap(), 0);
            server.await.unwrap();
        })
        .await
        .unwrap();
    }
    let address = proxy.address;
    drop(proxy);
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(TcpStream::connect(address).await.is_err());
    daemon.abort();
}

#[tokio::test]
async fn socks_rejects_unsupported_commands_and_stop_closes_active_sockets() {
    let daemon = Daemon::start(DaemonConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        tcp_forward_users: ["dev".into()].into(),
        ..Default::default()
    })
    .await
    .unwrap();
    let conn = connect(&format!("http://{}", daemon.local_addr))
        .await
        .unwrap();
    let proxy = SocksProxy::start(conn.connection.clone(), "127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    for cmd in [2, 3] {
        let mut socket = TcpStream::connect(proxy.address).await.unwrap();
        socket
            .write_all(&[5, 1, 0, 5, cmd, 0, 1, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        let mut response = [0; 12];
        socket.read_exact(&mut response).await.unwrap();
        assert_eq!(&response[..4], &[5, 0, 5, 7]);
    }
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut socket = handshake(
        &proxy,
        vec![1, 127, 0, 0, 1],
        target.local_addr().unwrap().port(),
    )
    .await;
    let (mut remote, _) = target.accept().await.unwrap();
    drop(proxy);
    timeout(Duration::from_secs(3), async {
        let mut byte = [0];
        assert_eq!(socket.read(&mut byte).await.unwrap(), 0);
        assert_eq!(remote.read(&mut byte).await.unwrap(), 0);
    })
    .await
    .unwrap();
    daemon.abort();
}
