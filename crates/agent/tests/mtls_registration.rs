use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use hf_agent::{mtls_client_config, AgentConnector, AgentError, RegistrationRequest};
use hf_gateway::{mtls_server_config, AgentGateway, CertificateRegistry, GatewayError};
use hf_protocol::ids::ServerId;
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
        let key = KeyPair::generate().unwrap();
        let issuer = CertifiedIssuer::self_signed(params, key).unwrap();
        Self { issuer }
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

fn connector(
    gateway_addr: SocketAddr,
    server_id: ServerId,
    gateway_ca: &Authority,
    agent: Leaf,
) -> AgentConnector {
    let config = mtls_client_config(gateway_ca.roots(), vec![agent.cert], agent.key).unwrap();
    AgentConnector::bind(
        LOOPBACK,
        gateway_addr,
        "gateway.test",
        config,
        RegistrationRequest::new(server_id, "holdfastd-test").unwrap(),
    )
    .unwrap()
}

fn gateway(
    agent_ca: &Authority,
    gateway_ca: &Authority,
    registry: Arc<CertificateRegistry>,
) -> Arc<AgentGateway> {
    let leaf = gateway_ca.issue("gateway.test", ExtendedKeyUsagePurpose::ServerAuth);
    let config = mtls_server_config(agent_ca.roots(), vec![leaf.cert], leaf.key).unwrap();
    Arc::new(AgentGateway::bind(LOOPBACK, config, registry).unwrap())
}

#[tokio::test]
async fn trusted_certificate_registers_exact_stable_server_identity() {
    let agent_ca = Authority::new("agent test CA");
    let gateway_ca = Authority::new("gateway test CA");
    let agent_leaf = agent_ca.issue("agent.test", ExtendedKeyUsagePurpose::ClientAuth);
    let server_id = ServerId([0x11; 16]);
    let registry = Arc::new(CertificateRegistry::new(8, 4).unwrap());
    registry
        .authorize_leaf(server_id, agent_leaf.cert.as_ref())
        .unwrap();
    let gateway = gateway(&agent_ca, &gateway_ca, Arc::clone(&registry));
    let connector = connector(
        gateway.local_addr().unwrap(),
        server_id,
        &gateway_ca,
        agent_leaf,
    );

    let accept = tokio::spawn({
        let gateway = Arc::clone(&gateway);
        async move { gateway.accept_registration().await }
    });
    let mut link = connector.connect().await.unwrap();
    let mut accepted = accept.await.unwrap().unwrap();

    assert_eq!(link.server_id(), server_id);
    assert_eq!(accepted.server_id(), server_id);
    assert_eq!(registry.active_count().unwrap(), 1);
    let ping = tokio::spawn(async move {
        assert_eq!(accepted.answer_ping().await.unwrap(), 0xA55A);
        accepted
    });
    link.ping(0xA55A).await.unwrap();
    let accepted = ping.await.unwrap();
    drop(accepted);
    assert_eq!(registry.active_count().unwrap(), 0);
}

#[tokio::test]
async fn certificate_cannot_claim_a_different_server_id() {
    let agent_ca = Authority::new("agent test CA");
    let gateway_ca = Authority::new("gateway test CA");
    let agent_leaf = agent_ca.issue("agent.test", ExtendedKeyUsagePurpose::ClientAuth);
    let authorized_id = ServerId([0x21; 16]);
    let claimed_id = ServerId([0x22; 16]);
    let registry = Arc::new(CertificateRegistry::new(8, 4).unwrap());
    registry
        .authorize_leaf(authorized_id, agent_leaf.cert.as_ref())
        .unwrap();
    let gateway = gateway(&agent_ca, &gateway_ca, registry);
    let connector = connector(
        gateway.local_addr().unwrap(),
        claimed_id,
        &gateway_ca,
        agent_leaf,
    );

    let accept = tokio::spawn({
        let gateway = Arc::clone(&gateway);
        async move { gateway.accept_registration().await }
    });
    let client_result = connector.connect().await;
    let gateway_result = accept.await.unwrap();

    assert!(matches!(
        gateway_result,
        Err(GatewayError::Rejected("certificate identity mismatch"))
    ));
    assert!(matches!(
        client_result,
        Err(AgentError::Rejected(reason)) if reason == "certificate identity mismatch"
    ));
}

#[tokio::test]
async fn rotation_overlap_accepts_old_and_next_certificates_for_one_server() {
    let agent_ca = Authority::new("agent test CA");
    let gateway_ca = Authority::new("gateway test CA");
    let old_leaf = agent_ca.issue("old-agent.test", ExtendedKeyUsagePurpose::ClientAuth);
    let next_leaf = agent_ca.issue("next-agent.test", ExtendedKeyUsagePurpose::ClientAuth);
    let server_id = ServerId([0x31; 16]);
    let registry = Arc::new(CertificateRegistry::new(8, 4).unwrap());
    registry
        .authorize_leaf(server_id, old_leaf.cert.as_ref())
        .unwrap();
    registry
        .authorize_leaf(server_id, next_leaf.cert.as_ref())
        .unwrap();
    assert_eq!(registry.identity_count().unwrap(), 2);
    let gateway = gateway(&agent_ca, &gateway_ca, Arc::clone(&registry));

    for leaf in [old_leaf, next_leaf] {
        let connector = connector(gateway.local_addr().unwrap(), server_id, &gateway_ca, leaf);
        let accept = tokio::spawn({
            let gateway = Arc::clone(&gateway);
            async move { gateway.accept_registration().await }
        });
        let link = connector.connect().await.unwrap();
        let accepted = accept.await.unwrap().unwrap();
        assert_eq!(link.server_id(), server_id);
        drop(accepted);
        drop(link);
        assert_eq!(registry.active_count().unwrap(), 0);
    }
}

#[tokio::test]
async fn connector_reregisters_after_gateway_link_loss_with_identity_unchanged() {
    let agent_ca = Authority::new("agent test CA");
    let gateway_ca = Authority::new("gateway test CA");
    let agent_leaf = agent_ca.issue("agent.test", ExtendedKeyUsagePurpose::ClientAuth);
    let server_id = ServerId([0x41; 16]);
    let registry = Arc::new(CertificateRegistry::new(8, 4).unwrap());
    registry
        .authorize_leaf(server_id, agent_leaf.cert.as_ref())
        .unwrap();
    let gateway = gateway(&agent_ca, &gateway_ca, Arc::clone(&registry));
    let connector = connector(
        gateway.local_addr().unwrap(),
        server_id,
        &gateway_ca,
        agent_leaf,
    );

    for generation in 1..=2 {
        let accept = tokio::spawn({
            let gateway = Arc::clone(&gateway);
            async move { gateway.accept_registration().await }
        });
        let link = connector.connect().await.unwrap();
        let accepted = accept.await.unwrap().unwrap();
        assert_eq!(
            accepted.server_id(),
            server_id,
            "registration generation {generation}"
        );

        accepted.close();
        drop(accepted);
        drop(link);
        assert_eq!(registry.active_count().unwrap(), 0);
    }
    assert_eq!(registry.identity_count().unwrap(), 1);
}

#[tokio::test]
async fn certificate_from_untrusted_ca_fails_during_mtls() {
    let trusted_agent_ca = Authority::new("trusted agent CA");
    let rogue_agent_ca = Authority::new("rogue agent CA");
    let gateway_ca = Authority::new("gateway test CA");
    let rogue_leaf = rogue_agent_ca.issue("rogue.test", ExtendedKeyUsagePurpose::ClientAuth);
    let server_id = ServerId([0x51; 16]);
    let registry = Arc::new(CertificateRegistry::new(8, 4).unwrap());
    registry
        .authorize_leaf(server_id, rogue_leaf.cert.as_ref())
        .unwrap();
    let gateway = gateway(&trusted_agent_ca, &gateway_ca, registry);
    let connector = connector(
        gateway.local_addr().unwrap(),
        server_id,
        &gateway_ca,
        rogue_leaf,
    );

    let accept = tokio::spawn({
        let gateway = Arc::clone(&gateway);
        async move { gateway.accept_registration().await }
    });
    assert!(connector.connect().await.is_err());
    assert!(accept.await.unwrap().is_err());
}
