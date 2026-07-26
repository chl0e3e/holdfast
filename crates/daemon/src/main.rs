//! holdfastd — standalone Holdfast daemon.
//!
//! ```bash
//! cargo run -p hf-daemon -- --bind 127.0.0.1:8080 --web-root web/dist
//! ```
//!
//! holdfastd CLI: HTTP/3-only daemon (ADR 0014) + browser client serving
//! (loopback only). WebTransport/QUIC arrive in Phase 3.

use hf_daemon::{AuthConfig, Daemon, DaemonConfig};

#[cfg(feature = "agent-mode")]
use hf_agent::{mtls_client_config, AgentConnector, ReconnectPolicy, RegistrationRequest};
#[cfg(feature = "agent-mode")]
use hf_daemon::agent_mode::{AgentDaemon, AgentDaemonConfig};

#[cfg(feature = "agent-mode")]
#[derive(Default)]
struct AgentCli {
    enabled: bool,
    gateway: Option<std::net::SocketAddr>,
    gateway_name: Option<String>,
    ca_path: Option<std::path::PathBuf>,
    cert_path: Option<std::path::PathBuf>,
    key_path: Option<std::path::PathBuf>,
    grant_verify_key_path: Option<std::path::PathBuf>,
    grant_audience: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut config = DaemonConfig::default();
    let mut password_users = std::collections::BTreeSet::new();
    let mut pam_service: Option<String> = None;
    #[cfg(feature = "agent-mode")]
    let mut agent = AgentCli::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" => {
                config.bind = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--bind needs an address"))?
                    .parse()?;
            }
            "--web-root" => {
                config.web_root =
                    Some(args.next().ok_or_else(|| anyhow::anyhow!("--web-root needs a path"))?.into());
            }
            "--ssh-auth" => {
                // --ssh-auth <username> <authorized_keys_path>
                let user = args.next().ok_or_else(|| anyhow::anyhow!("--ssh-auth needs a username"))?;
                let path =
                    args.next().ok_or_else(|| anyhow::anyhow!("--ssh-auth needs an authorized_keys path"))?;
                let keys = std::fs::read_to_string(&path)
                    .map_err(|e| anyhow::anyhow!("read {path}: {e}"))?;
                let users = match &mut config.auth {
                    AuthConfig::SshKeys { users } => users,
                    _ => {
                        config.auth = AuthConfig::SshKeys { users: Default::default() };
                        match &mut config.auth {
                            AuthConfig::SshKeys { users } => users,
                            _ => unreachable!(),
                        }
                    }
                };
                users.insert(user, keys);
            }
            "--password-auth" => {
                // --password-auth <username>  (repeatable; ADR 0016)
                // Allowlists a user for password login via PAM. Requires a
                // real auth mode: combine with --ssh-auth, or password-only
                // deployments still switch the mode off dev-auth below.
                let user = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--password-auth needs a username"))?;
                password_users.insert(user);
            }
            "--pam-service" => {
                pam_service = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--pam-service needs a service name"))?,
                );
            }
            "--wt-bind" => {
                config.webtransport_bind = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--wt-bind needs a UDP address"))?
                        .parse()?,
                );
            }
            "--wt-cert" => {
                config.webtransport_certificate = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--wt-cert needs a PEM path"))?
                        .into(),
                );
            }
            "--wt-key" => {
                config.webtransport_private_key = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--wt-key needs a PEM path"))?
                        .into(),
                );
            }
            "--no-webtransport" => config.webtransport_bind = None,
            "--grant-key" => {
                // Persistent 32-byte grant-signing seed (hex file). Grants —
                // and therefore stored client logins — survive daemon
                // restarts, which matter with short-lived TLS certificates
                // (renewal restarts the daemon every few days). Generated
                // 0600 on first start if absent.
                let path: std::path::PathBuf = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--grant-key needs a path"))?
                    .into();
                config.grant_signing_key = Some(load_or_create_grant_key(&path)?);
            }
            "--allowed-origin" => {
                let origin =
                    args.next().ok_or_else(|| anyhow::anyhow!("--allowed-origin needs a value"))?;
                config.allowed_origins.get_or_insert_with(Vec::new).push(origin);
            }
            "--account" => {
                // --account <username> <account1,account2,...>
                // Restricts which Unix accounts an authenticated user may run a
                // shell under (threat model T12). First account listed is their
                // default. Presence of any --account switches the policy from
                // permissive (AllowAll) to a StaticPolicy allowlist.
                let user = args.next().ok_or_else(|| anyhow::anyhow!("--account needs a username"))?;
                let accounts = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--account needs a comma-separated account list"))?;
                let list: Vec<String> = accounts
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
                if list.is_empty() {
                    anyhow::bail!("--account {user}: account list is empty");
                }
                config.account_policy.get_or_insert_with(Default::default).insert(user, list);
            }
            "--drop-privileges" => {
                // Launch each shell under its resolved Unix account (ADR 0007).
                // The daemon must run with enough privilege to switch (root, or
                // AmbientCapabilities=CAP_SETUID CAP_SETGID).
                config.session.privilege_drop = true;
            }
            "--shell-max-processes" => {
                let value: u64 = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--shell-max-processes needs a value"))?
                    .parse()?;
                if value == 0 {
                    anyhow::bail!("--shell-max-processes must be greater than zero");
                }
                config.session.shell_resource_limits.max_processes = value;
            }
            "--shell-max-open-files" => {
                let value: u64 = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--shell-max-open-files needs a value"))?
                    .parse()?;
                if value == 0 {
                    anyhow::bail!("--shell-max-open-files must be greater than zero");
                }
                config.session.shell_resource_limits.max_open_files = value;
            }
            "--shell-max-core-bytes" => {
                config.session.shell_resource_limits.max_core_bytes = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--shell-max-core-bytes needs a value"))?
                    .parse()?;
            }
            "--shell-idle-ttl" => {
                // Opt-in expiry (ADR 0021): reap shells left detached this
                // many seconds. Off when absent — clients are designed to
                // keep shells alive across long absences.
                let seconds: u64 = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--shell-idle-ttl needs seconds"))?
                    .parse()?;
                if seconds == 0 {
                    anyhow::bail!("--shell-idle-ttl must be > 0 (omit the flag to disable)");
                }
                config.session.idle_shell_ttl = Some(std::time::Duration::from_secs(seconds));
            }
            #[cfg(feature = "agent-mode")]
            "--agent" => agent.enabled = true,
            #[cfg(not(feature = "agent-mode"))]
            "--agent" => anyhow::bail!(
                "agent mode is not compiled in; rebuild with `--features agent-mode`"
            ),
            #[cfg(feature = "agent-mode")]
            "--gateway" => {
                agent.gateway = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--gateway needs an address"))?
                        .parse()?,
                );
            }
            #[cfg(feature = "agent-mode")]
            "--gateway-name" => {
                agent.gateway_name = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--gateway-name needs a TLS DNS name"))?,
                );
            }
            "--server-id" => {
                // Stable identity (standalone: grant audience; agent mode:
                // gateway registration). Standalone deployments usually get
                // this implicitly from --grant-key instead (ADR 0017).
                config.server_id = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--server-id needs srv_<hex>"))?
                        .parse()?,
                );
            }
            #[cfg(feature = "agent-mode")]
            "--agent-ca" => {
                agent.ca_path = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--agent-ca needs a PEM path"))?
                        .into(),
                );
            }
            #[cfg(feature = "agent-mode")]
            "--agent-cert" => {
                agent.cert_path = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--agent-cert needs a PEM path"))?
                        .into(),
                );
            }
            #[cfg(feature = "agent-mode")]
            "--agent-key" => {
                agent.key_path = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--agent-key needs a PEM path"))?
                        .into(),
                );
            }
            #[cfg(feature = "agent-mode")]
            "--grant-verify-key" => {
                agent.grant_verify_key_path = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--grant-verify-key needs a path"))?
                        .into(),
                );
            }
            #[cfg(feature = "agent-mode")]
            "--grant-audience" => {
                agent.grant_audience = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--grant-audience needs a value"))?,
                );
            }
            other => anyhow::bail!(
                "unknown argument: {other} (supported: --bind, --web-root, --ssh-auth <user> <keys>, --password-auth <user>, --pam-service <name>, --account <user> <accts>, --allowed-origin <origin>, --drop-privileges, --shell-max-processes <n>, --shell-max-open-files <n>, --shell-max-core-bytes <bytes>, --shell-idle-ttl <seconds>, --wt-bind, --wt-cert, --wt-key, --no-webtransport, --grant-key <path>, --server-id <srv_hex>)"
            ),
        }
    }
    if config.webtransport_bind == DaemonConfig::default().webtransport_bind {
        // Stable default for interactive use (tests pass port 0 explicitly).
        config.webtransport_bind = Some("127.0.0.1:4433".parse().unwrap());
    }

    if pam_service.is_some() && password_users.is_empty() {
        anyhow::bail!("--pam-service requires at least one --password-auth <user>");
    }
    if !password_users.is_empty() {
        // Password-only deployments still leave dev-auth: an empty SshKeys
        // user map authenticates nobody by key but enables the real issuer.
        if matches!(config.auth, AuthConfig::DevInsecure) {
            config.auth = AuthConfig::SshKeys {
                users: Default::default(),
            };
        }
        let service = pam_service.unwrap_or_else(|| hf_auth::pam::DEFAULT_PAM_SERVICE.to_string());
        config.password_auth = Some(hf_daemon::PasswordAuthConfig {
            users: password_users,
            verifier: std::sync::Arc::new(hf_auth::pam::PamVerifier::new(service)?),
        });
    }

    // Fail closed: privilege drop with no account policy would fall back to the
    // permissive AllowAll, letting any authenticated user request any Unix
    // account — the opposite of what --drop-privileges is for (threat model
    // T12). Require an explicit --account allowlist.
    if config.session.privilege_drop && config.account_policy.is_none() {
        anyhow::bail!(
            "--drop-privileges requires at least one --account <user> <accounts> mapping \
             (otherwise any authenticated user could run a shell as any account)"
        );
    }

    #[cfg(feature = "agent-mode")]
    if agent.enabled {
        let gateway = agent
            .gateway
            .ok_or_else(|| anyhow::anyhow!("--agent requires --gateway <address>"))?;
        let gateway_name = agent
            .gateway_name
            .ok_or_else(|| anyhow::anyhow!("--agent requires --gateway-name <TLS DNS name>"))?;
        let server_id = config
            .server_id
            .ok_or_else(|| anyhow::anyhow!("--agent requires --server-id <srv_hex>"))?;
        let ca_path = agent
            .ca_path
            .ok_or_else(|| anyhow::anyhow!("--agent requires --agent-ca <PEM>"))?;
        let cert_path = agent
            .cert_path
            .ok_or_else(|| anyhow::anyhow!("--agent requires --agent-cert <PEM>"))?;
        let key_path = agent
            .key_path
            .ok_or_else(|| anyhow::anyhow!("--agent requires --agent-key <PEM>"))?;
        let grant_verify_key_path = agent.grant_verify_key_path.ok_or_else(|| {
            anyhow::anyhow!("--agent requires --grant-verify-key <32-byte-hex file>")
        })?;
        let grant_audience = agent
            .grant_audience
            .ok_or_else(|| anyhow::anyhow!("--agent requires --grant-audience <value>"))?;
        let tls = load_agent_tls(&ca_path, &cert_path, &key_path)?;
        let grant_verifier = load_grant_verifier(&grant_verify_key_path)?;
        let bind = if gateway.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let connector = AgentConnector::bind(
            bind,
            gateway,
            gateway_name,
            tls,
            RegistrationRequest::new(server_id, env!("CARGO_PKG_VERSION"))?,
        )?;
        let daemon = AgentDaemon::start(AgentDaemonConfig {
            connector,
            reconnect: ReconnectPolicy::default(),
            grant_verifier,
            grant_audience,
            account_policy: config.account_policy.clone(),
            session: config.session.clone(),
        })?;
        println!("holdfastd agent {server_id} connecting outbound to {gateway}");
        tokio::signal::ctrl_c().await?;
        daemon.abort();
        return Ok(());
    }

    let daemon = Daemon::start(config.clone()).await?;
    println!("holdfastd listening on http://{}", daemon.local_addr);
    if let Some(root) = &config.web_root {
        println!("serving browser client from {}", root.display());
    }
    if let Some(wt) = daemon.webtransport_addr {
        println!("HTTP/3 endpoint (page + WebTransport): https://{wt} (UDP/QUIC)");
    }

    tokio::signal::ctrl_c().await?;
    daemon.abort();
    Ok(())
}

/// Read (or generate on first start) the 32-byte grant-signing seed: a 64-char
/// hex file, created 0600. Refuses group/world-readable files.
fn load_or_create_grant_key(path: &std::path::Path) -> anyhow::Result<[u8; 32]> {
    if !path.exists() {
        let seed: [u8; 32] = rand::random();
        let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(path, hex)
            .map_err(|e| anyhow::anyhow!("write grant key {}: {e}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        return Ok(seed);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            anyhow::bail!("grant key {} must be mode 0600 or stricter", path.display());
        }
    }
    let text = std::fs::read_to_string(path)?;
    let text = text.trim();
    if text.len() != 64 || !text.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("grant key {} must be 64 hex characters", path.display());
    }
    let mut seed = [0u8; 32];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16)?;
    }
    Ok(seed)
}

#[cfg(feature = "agent-mode")]
fn load_grant_verifier(path: &std::path::Path) -> anyhow::Result<hf_auth::GrantVerifier> {
    let value = std::fs::read_to_string(path)?;
    let hex = value.trim();
    if hex.len() != 64 {
        anyhow::bail!(
            "{} must contain exactly 64 hexadecimal characters",
            path.display()
        );
    }
    let mut bytes = [0u8; 32];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| anyhow::anyhow!("{} contains invalid hexadecimal", path.display()))?;
    }
    Ok(hf_auth::GrantVerifier::from_public_bytes(&bytes)?)
}

#[cfg(feature = "agent-mode")]
fn load_agent_tls(
    ca_path: &std::path::Path,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> anyhow::Result<hf_agent::AgentClientConfig> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(key_path)?.permissions().mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "{} must not be readable or writable by group/other (expected mode 0600 or stricter)",
                key_path.display()
            );
        }
    }
    let mut roots = rustls::RootCertStore::empty();
    let mut ca_reader = std::io::BufReader::new(std::fs::File::open(ca_path)?);
    let mut ca_count = 0usize;
    for cert in rustls_pemfile::certs(&mut ca_reader) {
        roots.add(cert?)?;
        ca_count += 1;
    }
    if ca_count == 0 {
        anyhow::bail!("{} contains no CA certificates", ca_path.display());
    }

    let mut cert_reader = std::io::BufReader::new(std::fs::File::open(cert_path)?);
    let chain: Vec<_> = rustls_pemfile::certs(&mut cert_reader).collect::<Result<_, _>>()?;
    if chain.is_empty() {
        anyhow::bail!("{} contains no agent certificate", cert_path.display());
    }
    let mut key_reader = std::io::BufReader::new(std::fs::File::open(key_path)?);
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow::anyhow!("{} contains no private key", key_path.display()))?;
    Ok(mtls_client_config(roots, chain, key)?)
}
