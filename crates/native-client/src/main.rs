//! hf — the Holdfast native terminal client.
//!
//! ```text
//! hf [--url http://127.0.0.1:8080] list
//! hf [--url ...] open [command]      # open a shell and attach
//! hf [--url ...] attach <id-prefix>  # reattach a stored shell
//! hf [--url ...] terminate <id-prefix>
//! ```
//!
//! Inside a session: Ctrl-] detaches (the shell keeps running). Reconnection
//! with application-level resume is automatic when the connection drops.

use std::io::{Read, Write};

use anyhow::{anyhow, bail, Result};
use hf_native_client::state::{self, hex, unhex, ShellEntry};
use hf_native_client::{connect_with, AuthMethod, AttachedShell, ServerConn, ShellEvent};

/// Connection options shared by every command (global flags).
#[derive(Clone)]
struct Opts {
    url: String,
    user: Option<String>,
    key: Option<std::path::PathBuf>,
}

impl Opts {
    /// Choose an auth method: a stored grant first (cheap reconnect), then SSH
    /// key if configured, else dev. Persists any newly issued grant.
    async fn connect(&self) -> Result<ServerConn> {
        // Reuse a stored grant if present.
        if let Some(grant) = state::load()?.grants.get(&self.url).cloned() {
            if let Ok(bytes) = base64_decode(&grant) {
                if let Ok(conn) = connect_with(&self.url, AuthMethod::Grant(bytes)).await {
                    self.persist_grant(&conn)?;
                    return Ok(conn);
                }
                // Stale/expired grant: fall through to full auth.
            }
        }
        let method = match (&self.user, &self.key) {
            (Some(user), Some(key)) => {
                AuthMethod::SshKey { username: user.clone(), private_key_path: key.clone() }
            }
            _ => AuthMethod::Dev,
        };
        let conn = connect_with(&self.url, method).await?;
        self.persist_grant(&conn)?;
        Ok(conn)
    }

    fn persist_grant(&self, conn: &ServerConn) -> Result<()> {
        use base64::Engine;
        if conn.grant.is_empty() {
            return Ok(());
        }
        let mut stored = state::load()?;
        stored.grants.insert(
            self.url.clone(),
            base64::engine::general_purpose::STANDARD.encode(&conn.grant),
        );
        state::save(&stored)
    }
}

fn terminal_size() -> (u16, u16) {
    let mut ws = libc::winsize { ws_row: 0, ws_col: 0, ws_xpixel: 0, ws_ypixel: 0 };
    let ok = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) } == 0;
    if ok && ws.ws_col > 0 && ws.ws_row > 0 {
        (ws.ws_col, ws.ws_row)
    } else {
        (80, 24)
    }
}

/// Puts the local terminal into raw mode; restores on drop.
struct RawGuard {
    original: nix::sys::termios::Termios,
}

impl RawGuard {
    fn new() -> Result<RawGuard> {
        let stdin = std::io::stdin();
        let original = nix::sys::termios::tcgetattr(&stdin)?;
        let mut raw = original.clone();
        nix::sys::termios::cfmakeraw(&mut raw);
        nix::sys::termios::tcsetattr(&stdin, nix::sys::termios::SetArg::TCSANOW, &raw)?;
        Ok(RawGuard { original })
    }
}

impl Drop for RawGuard {
    fn drop(&mut self) {
        let stdin = std::io::stdin();
        let _ = nix::sys::termios::tcsetattr(
            &stdin,
            nix::sys::termios::SetArg::TCSANOW,
            &self.original,
        );
    }
}

const DETACH_KEY: u8 = 0x1d; // Ctrl-]

#[tokio::main]
async fn main() -> Result<()> {
    let mut opts = Opts { url: "http://127.0.0.1:8080".into(), user: None, key: None };
    let mut args = std::env::args().skip(1).peekable();
    // Global flags may precede the subcommand.
    while let Some(flag) = args.peek().cloned() {
        match flag.as_str() {
            "--url" => {
                args.next();
                opts.url = args.next().ok_or_else(|| anyhow!("--url needs a value"))?;
            }
            "--user" => {
                args.next();
                opts.user = Some(args.next().ok_or_else(|| anyhow!("--user needs a value"))?);
            }
            "--key" => {
                args.next();
                opts.key = Some(args.next().ok_or_else(|| anyhow!("--key needs a path"))?.into());
            }
            _ => break,
        }
    }
    let command = args.next().unwrap_or_else(|| "list".into());

    match command.as_str() {
        "list" => cmd_list(&opts).await,
        "open" => cmd_open(&opts, args.next()).await,
        "attach" => {
            let prefix = args.next().ok_or_else(|| anyhow!("attach needs a shell id prefix"))?;
            cmd_attach(&opts, &prefix).await
        }
        "terminate" => {
            let prefix =
                args.next().ok_or_else(|| anyhow!("terminate needs a shell id prefix"))?;
            cmd_terminate(&opts, &prefix).await
        }
        other => bail!(
            "unknown command {other} (list | open [cmd] | attach <id> | terminate <id>); \
             global flags: --url --user --key"
        ),
    }
}

async fn cmd_list(opts: &Opts) -> Result<()> {
    let mut conn = opts.connect().await?;
    let stored = state::load()?;
    let known = stored.servers.get(&opts.url);
    let shells = conn.list_shells().await?;
    if shells.is_empty() {
        println!("no shells on {}", opts.url);
        return Ok(());
    }
    println!("{:<34} {:<12} {:<8} shell", "ID", "STATE", "TOKEN?");
    for shell in shells {
        let id = hex(&shell.shell_id);
        let has_token = known.and_then(|m| m.get(&id)).is_some();
        let state_name = match shell.state {
            2 => "running",
            3 => "exited",
            4 => "terminating",
            _ => "unknown",
        };
        println!(
            "{:<34} {:<12} {:<8} {}",
            &id[..32.min(id.len())],
            state_name,
            if has_token { "yes" } else { "no" },
            known.and_then(|m| m.get(&id)).map(|e| e.name.as_str()).unwrap_or("-"),
        );
    }
    Ok(())
}

async fn cmd_open(opts: &Opts, command: Option<String>) -> Result<()> {
    let mut conn = opts.connect().await?;
    let (cols, rows) = terminal_size();
    let (shell_id, token) = conn
        .open_shell(command.as_deref(), cols, rows, rand::random())
        .await?;
    let id_hex = hex(&shell_id);
    let name = command.clone().unwrap_or_else(|| "shell".into());
    persist_token(&opts.url, &id_hex, &token, &name)?;
    eprintln!("opened shell {} — Ctrl-] detaches", &id_hex[..16]);
    run_session(opts, conn, shell_id, token, name).await
}

async fn cmd_attach(opts: &Opts, prefix: &str) -> Result<()> {
    let stored = state::load()?;
    let shells = stored
        .servers
        .get(&opts.url)
        .ok_or_else(|| anyhow!("no stored shells for {}", opts.url))?;
    let matches: Vec<(&String, &ShellEntry)> =
        shells.iter().filter(|(id, _)| id.starts_with(prefix)).collect();
    match matches.as_slice() {
        [] => bail!("no stored shell matches {prefix:?} (try `hf list`)"),
        [(id, entry)] => {
            let shell_id = unhex(id).ok_or_else(|| anyhow!("corrupt state file"))?;
            let token = base64_decode(&entry.token)?;
            let name = entry.name.clone();
            let conn = opts.connect().await?;
            run_session(opts, conn, shell_id, token, name).await
        }
        multiple => bail!(
            "ambiguous prefix {prefix:?}: {}",
            multiple.iter().map(|(id, _)| &id[..16]).collect::<Vec<_>>().join(", ")
        ),
    }
}

async fn cmd_terminate(opts: &Opts, prefix: &str) -> Result<()> {
    let mut conn = opts.connect().await?;
    let shells = conn.list_shells().await?;
    let matches: Vec<&Vec<u8>> = shells
        .iter()
        .map(|s| &s.shell_id)
        .filter(|id| hex(id).starts_with(prefix))
        .collect();
    match matches.as_slice() {
        [] => bail!("no shell matches {prefix:?}"),
        [id] => {
            let code = conn.terminate(id).await?;
            forget_token(&opts.url, &hex(id))?;
            println!("terminated (exit code {code})");
            Ok(())
        }
        _ => bail!("ambiguous prefix {prefix:?}"),
    }
}

/// Interactive session: raw mode, stdin→shell, shell→stdout, SIGWINCH
/// resize, Ctrl-] detach, automatic reconnect + resume on transport loss.
async fn run_session(
    opts: &Opts,
    first_conn: ServerConn,
    shell_id: Vec<u8>,
    mut token: Vec<u8>,
    name: String,
) -> Result<()> {
    let url = &opts.url;
    let _raw = RawGuard::new();
    let mut stdout = std::io::stdout();

    // Blocking stdin reader thread feeding the async loop.
    let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 4096];
        while let Ok(n) = stdin.read(&mut buf) {
            if n == 0 || stdin_tx.blocking_send(buf[..n].to_vec()).is_err() {
                break;
            }
        }
    });
    let mut winch = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())?;

    let mut conn = Some(first_conn);
    let mut backoff = std::time::Duration::from_secs(1);

    'sessions: loop {
        // (Re)connect if needed, then attach with the newest token.
        let session = match conn.take() {
            Some(c) => c,
            None => match opts.connect().await {
                Ok(c) => c,
                Err(_) => {
                    eprint!("\r\n[holdfast: reconnecting in {}s]\r\n", backoff.as_secs());
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(std::time::Duration::from_secs(15));
                    continue;
                }
            },
        };
        let (cols, rows) = terminal_size();
        let mut shell: AttachedShell = match session.attach(&shell_id, &token, cols, rows).await {
            Ok(s) => s,
            Err(e) => {
                eprint!("\r\n[holdfast: cannot reattach: {e}]\r\n");
                forget_token(url, &hex(&shell_id))?;
                return Err(e);
            }
        };
        token = shell.rotated_token.clone();
        persist_token(url, &hex(&shell_id), &token, &name)?;
        backoff = std::time::Duration::from_secs(1);

        // Restore the screen.
        stdout.write_all(&shell.snapshot)?;
        stdout.flush()?;

        loop {
            tokio::select! {
                event = shell.next_event() => match event {
                    Ok(ShellEvent::Output(data)) => {
                        stdout.write_all(&data)?;
                        stdout.flush()?;
                    }
                    Ok(ShellEvent::Exited(code)) => {
                        eprint!("\r\n[holdfast: shell exited with code {code}]\r\n");
                        forget_token(url, &hex(&shell_id))?;
                        return Ok(());
                    }
                    Err(_) => {
                        eprint!("\r\n[holdfast: connection lost — resuming]\r\n");
                        continue 'sessions;
                    }
                },
                Some(bytes) = stdin_rx.recv() => {
                    if let Some(pos) = bytes.iter().position(|b| *b == DETACH_KEY) {
                        if pos > 0 {
                            let _ = shell.input(&bytes[..pos]).await;
                        }
                        let _ = shell.detach().await;
                        eprint!("\r\n[holdfast: detached — shell {} keeps running]\r\n",
                            &hex(&shell_id)[..16]);
                        return Ok(());
                    }
                    if shell.input(&bytes).await.is_err() {
                        eprint!("\r\n[holdfast: connection lost — resuming]\r\n");
                        continue 'sessions;
                    }
                },
                _ = winch.recv() => {
                    let (cols, rows) = terminal_size();
                    let _ = shell.resize(cols, rows).await;
                },
            }
        }
    }
}

fn persist_token(url: &str, id_hex: &str, token: &[u8], name: &str) -> Result<()> {
    use base64::Engine;
    let mut stored = state::load()?;
    stored.servers.entry(url.to_string()).or_default().insert(
        id_hex.to_string(),
        ShellEntry {
            token: base64::engine::general_purpose::STANDARD.encode(token),
            name: name.to_string(),
        },
    );
    state::save(&stored)
}

fn forget_token(url: &str, id_hex: &str) -> Result<()> {
    let mut stored = state::load()?;
    if let Some(shells) = stored.servers.get_mut(url) {
        shells.remove(id_hex);
    }
    state::save(&stored)
}

fn base64_decode(text: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.decode(text)?)
}
