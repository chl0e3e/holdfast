//! holdfastd — standalone Holdfast daemon.
//!
//! ```bash
//! cargo run -p hf-daemon -- --bind 127.0.0.1:8080 --web-root web/dist
//! ```
//!
//! Phase 2: WebSocket transport + browser client serving, dev-mode auth
//! (loopback only). WebTransport/QUIC arrive in Phase 3.

use hf_daemon::{AuthConfig, Daemon, DaemonConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut config = DaemonConfig::default();
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
            "--wt-bind" => {
                config.webtransport_bind = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--wt-bind needs a UDP address"))?
                        .parse()?,
                );
            }
            "--no-webtransport" => config.webtransport_bind = None,
            "--allowed-origin" => {
                let origin =
                    args.next().ok_or_else(|| anyhow::anyhow!("--allowed-origin needs a value"))?;
                config.allowed_origins.get_or_insert_with(Vec::new).push(origin);
            }
            other => anyhow::bail!(
                "unknown argument: {other} (supported: --bind, --web-root, --ssh-auth <user> <keys>, --allowed-origin <origin>, --wt-bind, --no-webtransport)"
            ),
        }
    }
    if config.webtransport_bind == DaemonConfig::default().webtransport_bind {
        // Stable default for interactive use (tests pass port 0 explicitly).
        config.webtransport_bind = Some("127.0.0.1:4433".parse().unwrap());
    }

    let daemon = Daemon::start(config.clone()).await?;
    println!("holdfastd listening on http://{}", daemon.local_addr);
    if let Some(root) = &config.web_root {
        println!("serving browser client from {}", root.display());
    }
    println!("WebSocket endpoint:     ws://{}/terminal/ws", daemon.local_addr);
    if let Some(wt) = daemon.webtransport_addr {
        println!("WebTransport endpoint:  https://{wt} (UDP/QUIC)");
    }

    tokio::signal::ctrl_c().await?;
    daemon.abort();
    Ok(())
}
