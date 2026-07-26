//! `hf-ssh-adapter`: loopback OpenSSH compatibility for Holdfast.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use hf_native_client::AuthMethod;
use hf_ssh_adapter::{
    load_authorized_keys, load_host_key, AdapterConfig, PasswordVerifier, DEFAULT_LISTEN,
    DEFAULT_MAX_CONNECTIONS,
};
use tracing_subscriber::EnvFilter;

struct Options {
    listen: SocketAddr,
    remote_url: String,
    local_user: String,
    authorized_keys: PathBuf,
    host_key: PathBuf,
    remote_auth: AuthMethod,
    password_auth: Option<Arc<dyn PasswordVerifier>>,
    max_connections: usize,
}

fn usage() -> &'static str {
    "hf-ssh-adapter \
  --local-user USER --authorized-keys PATH --host-key PATH \
  [--listen 127.0.0.1:2222] [--url http://127.0.0.1:8080] \
  (--dev-auth | --remote-user USER --remote-key PATH) \
  [--password-auth [--pam-service holdfast-ssh]] \
  [--max-connections 16]"
}

fn parse_options() -> Result<Options> {
    let mut listen: SocketAddr = DEFAULT_LISTEN
        .parse()
        .expect("valid default listen address");
    let mut remote_url = "http://127.0.0.1:8080".to_string();
    let mut local_user = None;
    let mut authorized_keys = None;
    let mut host_key = None;
    let mut remote_user = None;
    let mut remote_key = None;
    let mut dev_auth = false;
    let mut password_auth = false;
    let mut pam_service = None;
    let mut max_connections = DEFAULT_MAX_CONNECTIONS;

    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| anyhow!("{flag} needs a value"));
        match flag.as_str() {
            "--listen" => listen = value()?.parse().context("parse --listen")?,
            "--url" => remote_url = value()?,
            "--local-user" => local_user = Some(value()?),
            "--authorized-keys" => authorized_keys = Some(PathBuf::from(value()?)),
            "--host-key" => host_key = Some(PathBuf::from(value()?)),
            "--remote-user" => remote_user = Some(value()?),
            "--remote-key" => remote_key = Some(PathBuf::from(value()?)),
            "--max-connections" => {
                max_connections = value()?.parse().context("parse --max-connections")?
            }
            "--dev-auth" => dev_auth = true,
            "--password-auth" => password_auth = true,
            "--pam-service" => pam_service = Some(value()?),
            "-h" | "--help" => {
                println!("{}", usage());
                std::process::exit(0);
            }
            _ => bail!("unknown option {flag}\n{}", usage()),
        }
    }

    let remote_auth = match (dev_auth, remote_user, remote_key) {
        (true, None, None) => AuthMethod::Dev,
        (false, Some(username), Some(private_key_path)) => {
            AuthMethod::SshKey { username, private_key_path }
        }
        _ => bail!("choose exactly one remote auth mode: --dev-auth or both --remote-user and --remote-key"),
    };

    let password_auth = match (password_auth, pam_service) {
        (false, Some(_)) => bail!("--pam-service requires --password-auth"),
        (false, None) => None,
        #[cfg(unix)]
        (true, service) => {
            let service =
                service.unwrap_or_else(|| hf_ssh_adapter::pam::DEFAULT_PAM_SERVICE.to_string());
            Some(Arc::new(hf_ssh_adapter::pam::PamVerifier::new(service)?)
                as Arc<dyn PasswordVerifier>)
        }
        #[cfg(not(unix))]
        (true, _) => bail!("--password-auth requires PAM and is only supported on Unix"),
    };

    Ok(Options {
        listen,
        remote_url,
        local_user: local_user.ok_or_else(|| anyhow!("--local-user is required"))?,
        authorized_keys: authorized_keys.ok_or_else(|| anyhow!("--authorized-keys is required"))?,
        host_key: host_key.ok_or_else(|| anyhow!("--host-key is required"))?,
        remote_auth,
        password_auth,
        max_connections,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let options = parse_options()?;
    let config = AdapterConfig {
        listen: options.listen,
        remote_url: options.remote_url,
        remote_auth: options.remote_auth,
        local_user: options.local_user,
        authorized_keys: load_authorized_keys(&options.authorized_keys)?,
        password_auth: options.password_auth,
        host_key: load_host_key(&options.host_key)?,
        max_connections: options.max_connections,
    };
    config.validate()?;
    tracing::info!(
        listen = %config.listen,
        remote = %config.remote_url,
        password_auth = config.password_auth.is_some(),
        "starting SSH compatibility adapter"
    );
    hf_ssh_adapter::serve(config).await
}
