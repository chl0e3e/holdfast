#![cfg(feature = "agent-mode")]

use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use hf_agent::{mtls_client_config, AgentConnector, ReconnectPolicy, RegistrationRequest};
use hf_auth::{GrantClaims, GrantSigner};
use hf_daemon::agent_mode::{AgentDaemon, AgentDaemonConfig};
use hf_gateway::{
    mtls_server_config, AgentAttachment, AgentAttachmentEvent, AgentAttachmentRequest,
    AgentGateway, AgentShellRequest, CertificateRegistry, GatewayError,
};
use hf_protocol::{ids::ServerId, pb::ErrorCode};
use hf_session_core::{SessionCoreConfig, ShellState};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

const LOOPBACK: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

struct Authority {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

impl Authority {
    fn new(common_name: &str) -> Self {
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        Self {
            issuer: CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap(),
        }
    }

    fn roots(&self) -> rustls::RootCertStore {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.issuer.der().clone()).unwrap();
        roots
    }

    fn issue(&self, dns_name: &str, usage: ExtendedKeyUsagePurpose) -> Leaf {
        let mut params = CertificateParams::new(vec![dns_name.to_owned()]).unwrap();
        params.extended_key_usages = vec![usage];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        Leaf {
            cert: cert.der().clone(),
            key: PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        }
    }
}

struct Leaf {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

async fn read_output_until(attachment: &mut AgentAttachment, needle: &str) -> String {
    let mut output = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let AgentAttachmentEvent::Output(chunk) = attachment.next_event().await.unwrap() {
                output.extend_from_slice(&chunk);
                if String::from_utf8_lossy(&output).contains(needle) {
                    break;
                }
            }
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "timed out waiting for {needle:?}; got {:?}",
            String::from_utf8_lossy(&output)
        )
    });
    String::from_utf8_lossy(&output).into_owned()
}

async fn read_history(attachment: &mut AgentAttachment, request_id: u64) -> Vec<String> {
    let mut lines = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match attachment.next_event().await.unwrap() {
                AgentAttachmentEvent::HistoryChunk {
                    request_id: response_id,
                    chunk,
                } if response_id == request_id => lines.extend(chunk.lines),
                AgentAttachmentEvent::HistoryEnd {
                    request_id: response_id,
                    ..
                } if response_id == request_id => break,
                AgentAttachmentEvent::Output(_) => {}
                other => panic!("unexpected attachment event while reading history: {other:?}"),
            }
        }
    })
    .await
    .expect("history response timed out");
    lines
}

#[tokio::test]
async fn agent_mode_enforces_local_policy_and_keeps_shell_across_gateway_reconnect() {
    let agent_ca = Authority::new("agent test CA");
    let gateway_ca = Authority::new("gateway test CA");
    let agent_leaf = agent_ca.issue("agent.test", ExtendedKeyUsagePurpose::ClientAuth);
    let gateway_leaf = gateway_ca.issue("gateway.test", ExtendedKeyUsagePurpose::ServerAuth);
    let server_id = ServerId([0x61; 16]);

    let registry = Arc::new(CertificateRegistry::new(8, 2).unwrap());
    registry
        .authorize_leaf(server_id, agent_leaf.cert.as_ref())
        .unwrap();
    let server_config =
        mtls_server_config(agent_ca.roots(), vec![gateway_leaf.cert], gateway_leaf.key).unwrap();
    let gateway = Arc::new(AgentGateway::bind(LOOPBACK, server_config, registry).unwrap());

    let client_config =
        mtls_client_config(gateway_ca.roots(), vec![agent_leaf.cert], agent_leaf.key).unwrap();
    let connector = AgentConnector::bind(
        LOOPBACK,
        gateway.local_addr().unwrap(),
        "gateway.test",
        client_config,
        RegistrationRequest::new(server_id, "holdfastd-agent-test").unwrap(),
    )
    .unwrap();

    let first_accept = tokio::spawn({
        let gateway = Arc::clone(&gateway);
        async move { gateway.accept_registration().await }
    });
    let mut policy = BTreeMap::new();
    policy.insert("alice".to_owned(), vec!["allowed".to_owned()]);
    let signer = GrantSigner::generate();
    let daemon = AgentDaemon::start(AgentDaemonConfig {
        connector,
        reconnect: ReconnectPolicy {
            initial_delay: Duration::from_millis(20),
            maximum_delay: Duration::from_millis(50),
        },
        grant_verifier: signer.verifier(),
        grant_audience: "gateway.test".to_owned(),
        account_policy: Some(policy),
        session: SessionCoreConfig::default(),
    })
    .unwrap();
    let mut first = tokio::time::timeout(Duration::from_secs(3), first_accept)
        .await
        .expect("first registration timed out")
        .unwrap()
        .unwrap();

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let claims = GrantClaims {
        sub: "alice".to_owned(),
        aud: "gateway.test".to_owned(),
        servers: vec![server_id.to_string()],
        ops: vec!["open".to_owned(), "attach".to_owned()],
        iat_ms: now_ms - 1_000,
        exp_ms: now_ms + 60_000,
        jti: "agent-open-test".to_owned(),
    };
    let grant = signer.issue(&claims);

    let forged_grant = GrantSigner::generate().issue(&claims);
    let forged = AgentShellRequest::new(
        "alice",
        forged_grant.as_bytes().to_vec(),
        Some("allowed".to_owned()),
        None,
        80,
        24,
        [0; 16],
    )
    .unwrap();
    assert!(matches!(
        first.open_shell(&forged).await,
        Err(GatewayError::Remote { code, .. })
            if code == ErrorCode::ErrUnauthenticated as i32
    ));

    let denied = AgentShellRequest::new(
        "alice",
        grant.as_bytes().to_vec(),
        Some("denied".to_owned()),
        None,
        80,
        24,
        [1; 16],
    )
    .unwrap();
    assert!(matches!(
        first.open_shell(&denied).await,
        Err(GatewayError::Remote { code, .. }) if code == ErrorCode::ErrForbidden as i32
    ));

    let open = AgentShellRequest::new(
        "alice",
        grant.as_bytes().to_vec(),
        Some("allowed".to_owned()),
        None,
        80,
        24,
        [2; 16],
    )
    .unwrap();
    let opened = first.open_shell(&open).await.unwrap();
    assert!(!opened.reused);
    let info = daemon.shell_info(&opened.shell_id).unwrap();
    assert_eq!(info.state, ShellState::Running);
    assert_eq!(info.owner, "alice");
    assert_eq!(info.account.as_deref(), Some("allowed"));

    let forged_attach =
        AgentAttachmentRequest::new("alice", forged_grant.as_bytes().to_vec(), 80, 24).unwrap();
    assert!(matches!(
        first.attach_shell(opened.shell_id, &forged_attach).await,
        Err(GatewayError::Remote { code, .. })
            if code == ErrorCode::ErrUnauthenticated as i32
    ));

    let bob_claims = GrantClaims {
        sub: "bob".to_owned(),
        aud: "gateway.test".to_owned(),
        servers: vec![server_id.to_string()],
        ops: vec!["attach".to_owned()],
        iat_ms: now_ms - 1_000,
        exp_ms: now_ms + 60_000,
        jti: "agent-attach-bob-test".to_owned(),
    };
    let bob_grant = signer.issue(&bob_claims);
    let bob_attach =
        AgentAttachmentRequest::new("bob", bob_grant.as_bytes().to_vec(), 80, 24).unwrap();
    assert!(matches!(
        first.attach_shell(opened.shell_id, &bob_attach).await,
        Err(GatewayError::Remote { code, .. }) if code == ErrorCode::ErrForbidden as i32
    ));

    let attach_request =
        AgentAttachmentRequest::new("alice", grant.as_bytes().to_vec(), 80, 24).unwrap();
    let mut attachment = first
        .attach_shell(opened.shell_id, &attach_request)
        .await
        .unwrap();
    assert!(attachment.attached.screen_revision > 0);
    attachment.resize(100, 30).await.unwrap();
    attachment
        .send_input(b"printf 'agent-live-marker\\n'; stty size\r")
        .await
        .unwrap();
    let live = read_output_until(&mut attachment, "30 100").await;
    assert!(live.contains("agent-live-marker"));
    attachment
        .send_input(b"for i in $(seq 1 50); do echo agent-history-$i; done\r")
        .await
        .unwrap();
    read_output_until(&mut attachment, "agent-history-50").await;
    let history_request = attachment
        .request_history(0, 1_000, 128 * 1024)
        .await
        .unwrap();
    let history = read_history(&mut attachment, history_request).await;
    assert!(
        history.iter().any(|line| line.contains("agent-history-1")),
        "history response did not contain early terminal output: {history:?}"
    );
    attachment.detach().await.unwrap();

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if daemon
                .shell_info(&opened.shell_id)
                .unwrap()
                .attachment_count
                == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("agent did not detach the backend attachment");

    // Leave a second attachment live when the gateway connection is forcibly
    // closed. Link loss must detach it locally without ending the shell.
    let link_loss_attachment = first
        .attach_shell(opened.shell_id, &attach_request)
        .await
        .unwrap();
    assert_eq!(
        daemon
            .shell_info(&opened.shell_id)
            .unwrap()
            .attachment_count,
        1
    );

    first.close();
    drop(first);
    drop(link_loss_attachment);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if daemon
                .shell_info(&opened.shell_id)
                .unwrap()
                .attachment_count
                == 0
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("gateway loss did not detach its backend attachment");
    let second_accept = tokio::spawn({
        let gateway = Arc::clone(&gateway);
        async move { gateway.accept_registration().await }
    });
    let mut second = tokio::time::timeout(Duration::from_secs(3), second_accept)
        .await
        .expect("agent did not reconnect")
        .unwrap()
        .unwrap();

    let recovered = second.open_shell(&open).await.unwrap();
    assert!(recovered.reused);
    assert_eq!(recovered.shell_id, opened.shell_id);
    assert_eq!(
        daemon.shell_info(&recovered.shell_id).unwrap().state,
        ShellState::Running
    );
    assert!(daemon.status().registrations >= 2);

    let mut recovered_attachment = second
        .attach_shell(recovered.shell_id, &attach_request)
        .await
        .unwrap();
    let recovered_history_request = recovered_attachment
        .request_history(0, 1_000, 128 * 1024)
        .await
        .unwrap();
    let recovered_history =
        read_history(&mut recovered_attachment, recovered_history_request).await;
    assert!(
        recovered_history
            .iter()
            .any(|line| line.contains("agent-history-1")),
        "scrollback did not survive gateway reconnect: {recovered_history:?}"
    );
    recovered_attachment
        .send_input(b"echo agent-after-reconnect\r")
        .await
        .unwrap();
    read_output_until(&mut recovered_attachment, "agent-after-reconnect").await;
    recovered_attachment.detach().await.unwrap();

    daemon.terminate_shell(&recovered.shell_id).unwrap();
    daemon.abort();
}
