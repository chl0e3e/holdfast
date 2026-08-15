//! Local handoff to an already-running DockerWM desktop application.
//!
//! DockerWM publishes a short-lived, mode-0600 descriptor containing a random
//! bearer token and a loopback port. This deliberately avoids a custom URI
//! handler: URI activation starts a closed application and cannot report a
//! reliable failure for Holdfast's existing remote fallback.

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

const DESCRIPTOR_BYTES_MAX: u64 = 4096;
const RESPONSE_BYTES_MAX: usize = 4096;
const URL_BYTES_MAX: usize = 2048;
const TOKEN_HEX_BYTES: usize = 64;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(350);
const IO_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Deserialize)]
struct Descriptor {
    version: u8,
    address: String,
    port: u16,
    token: String,
    #[allow(dead_code)]
    pid: u32,
}

fn descriptor_path() -> Result<PathBuf> {
    dirs::config_dir()
        .map(|base| base.join("dockerwm").join("link-bridge-v1.json"))
        .ok_or_else(|| anyhow!("the per-user application-data directory is unavailable"))
}

fn checked_url(url: &str) -> Result<()> {
    if url.len() > URL_BYTES_MAX {
        return Err(anyhow!("URL is too long"));
    }
    let lower = url.to_ascii_lowercase();
    if !(lower.starts_with("https://") || lower.starts_with("http://")) {
        return Err(anyhow!("only http(s) URLs can be opened"));
    }
    Ok(())
}

fn read_descriptor(path: &Path) -> Result<Option<Descriptor>> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("read DockerWM bridge metadata"),
    };
    if !metadata.is_file() || metadata.len() > DESCRIPTOR_BYTES_MAX {
        return Err(anyhow!(
            "DockerWM bridge descriptor is not a bounded regular file"
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(anyhow!(
                "DockerWM bridge descriptor permissions are too broad"
            ));
        }
    }
    let raw = fs::read_to_string(path).context("read DockerWM bridge")?;
    let descriptor: Descriptor =
        serde_json::from_str(&raw).context("parse DockerWM bridge descriptor")?;
    if descriptor.version != 1
        || descriptor.address != "127.0.0.1"
        || descriptor.port == 0
        || descriptor.token.len() != TOKEN_HEX_BYTES
        || !descriptor
            .token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(anyhow!("DockerWM bridge descriptor is invalid"));
    }
    Ok(Some(descriptor))
}

fn open_at(path: &Path, url: &str) -> Result<bool> {
    checked_url(url)?;
    let Some(descriptor) = read_descriptor(path)? else {
        return Ok(false);
    };
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, descriptor.port).into();
    let mut stream = match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
        Ok(stream) => stream,
        // A stale descriptor simply means DockerWM is no longer running.
        Err(_) => return Ok(false),
    };
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    let body = serde_json::to_vec(&serde_json::json!({ "url": url }))?;
    let request = format!(
        "POST /v1/open HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        descriptor.port,
        descriptor.token,
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.write_all(&body)?;
    stream.flush()?;

    let mut response = Vec::with_capacity(512);
    let mut chunk = [0_u8; 512];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        if response.len() + read > RESPONSE_BYTES_MAX {
            return Err(anyhow!("DockerWM bridge response is too large"));
        }
        response.extend_from_slice(&chunk[..read]);
    }
    let status = response
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .unwrap_or_default();
    if status.starts_with("HTTP/1.1 200 ") || status.starts_with("HTTP/1.0 200 ") {
        Ok(true)
    } else {
        Err(anyhow!(
            "DockerWM desktop rejected the link ({})",
            status.trim_end_matches('\r')
        ))
    }
}

/// Open an http(s) URL in DockerWM Desktop if an authenticated local bridge
/// is currently reachable. `false` means callers should use their remote
/// DockerWM fallback; a reachable bridge rejection is returned as an error.
pub fn open_in_running_desktop(url: &str) -> Result<bool> {
    open_at(&descriptor_path()?, url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_directory() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("holdfast-dockerwm-{nonce}-{}", std::process::id()));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn missing_descriptor_means_local_app_is_unavailable() {
        let directory = temporary_directory();
        assert!(!open_at(&directory.join("missing.json"), "https://example.com").unwrap());
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn authenticated_request_opens_in_running_bridge() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let token = "a".repeat(TOKEN_HEX_BYTES);
        let expected_token = token.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 512];
            loop {
                let read = stream.read(&mut chunk).unwrap();
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|part| part == b"\r\n\r\n")
                    && request.last() == Some(&b'}')
                {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.contains(&format!("Authorization: Bearer {expected_token}")));
            assert!(request.contains("{\"url\":\"https://example.com/path\"}"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}")
                .unwrap();
        });

        let directory = temporary_directory();
        let path = directory.join("bridge.json");
        fs::write(
            &path,
            serde_json::json!({
                "version": 1,
                "address": "127.0.0.1",
                "port": port,
                "token": token,
                "pid": std::process::id(),
            })
            .to_string(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }

        assert!(open_at(&path, "https://example.com/path").unwrap());
        server.join().unwrap();
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
