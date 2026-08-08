//! Stage 1 of the MsQuic/Schannel port spike: can a Schannel-backed QUIC
//! client reproduce the ADR 0008 channel binding?
//!
//! Holdfast signs the SSH auth challenge over a channel binding that *is* the
//! SHA-256 of the server's leaf certificate (`hf-native-client`'s
//! `connect_with`, and `channel_bound_message`). Any replacement transport
//! must arrive at byte-identical bytes or auth silently changes meaning.
//! wtransport gets them two ways:
//!
//! - `http://` bootstrap — `/webtransport-info` publishes `certHashBase64` and
//!   the client pins it via `with_server_certificate_hashes`.
//! - `https://` production — WebPKI validates, then the hash is read back off
//!   the live connection via `peer_identity()`.
//!
//! MsQuic has no `peer_identity()`. It hands the peer certificate to a
//! connection callback as an opaque `*mut QUIC_CERTIFICATE`, whose meaning
//! depends on the TLS provider — an `X509*` on quictls, a `PCCERT_CONTEXT` on
//! Schannel. `QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES` is documented to
//! normalise that to a `QUIC_BUFFER` of DER regardless of provider. Whether
//! Schannel actually honours it is the open question, and it is the reason
//! this spike exists rather than the port.
//!
//! Run it against a live daemon:
//!
//! ```powershell
//! # dev bootstrap: the oracle comes from the daemon itself
//! certprobe.exe http://host:8080
//! # production: supply the hash the wtransport client pins
//! certprobe.exe https://host:443 --expect <base64-sha256>
//! ```
//!
//! PASS means the DER MsQuic surfaced hashes to the value holdfast pins. That
//! is the whole criterion; the process exits non-zero on anything else.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use msquic::{
    BufferRef, Configuration, Connection, ConnectionEvent, ConnectionRef, CredentialConfig,
    CredentialFlags, Registration, RegistrationConfig, Settings, Status,
};
use sha2::{Digest, Sha256};

/// The daemon's HTTP/3 endpoint negotiates `h3` and nothing else
/// (`tls_server_config` in crates/daemon/src/webtransport.rs).
const ALPN: &str = "h3";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

fn main() -> Result<()> {
    let target = Target::from_args()?;
    println!("target      {}:{}", target.host, target.port);
    match &target.expected {
        Some(hash) => println!("expecting   {}", hex(hash)),
        None => println!("expecting   (none supplied - will report observed hash only)"),
    }

    let der = probe(&target.host, target.port)?;
    println!("leaf DER    {} bytes", der.len());
    let observed: [u8; 32] = Sha256::digest(&der).into();
    println!("observed    {}", hex(&observed));

    match target.expected {
        Some(expected) if expected == observed => {
            println!("\nPASS - Schannel surfaced a leaf certificate matching the pinned hash.");
            println!("ADR 0008 channel binding is reproducible on MsQuic. Proceed to stage 2.");
            Ok(())
        }
        Some(_) => {
            bail!(
                "FAIL - hash mismatch. The bytes MsQuic surfaced are not the leaf certificate \
                 holdfast pins, so the signed challenge would differ. Check whether \
                 USE_PORTABLE_CERTIFICATES was honoured before concluding the port is blocked."
            )
        }
        None => {
            println!("\nINCONCLUSIVE - no expected hash supplied; nothing was verified.");
            println!("Re-run against an http:// base, or pass --expect <base64-sha256>.");
            bail!("no oracle to compare against")
        }
    }
}

struct Target {
    host: String,
    port: u16,
    expected: Option<[u8; 32]>,
}

impl Target {
    /// Mirrors the two URL forms `connect_with` accepts (ADR 0014).
    fn from_args() -> Result<Self> {
        let mut args = std::env::args().skip(1);
        let url = args
            .next()
            .ok_or_else(|| anyhow!("usage: certprobe <http[s]://host[:port]> [--expect <base64>]"))?;

        let mut expected = None;
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--expect" => {
                    let value = args
                        .next()
                        .ok_or_else(|| anyhow!("--expect needs a base64 SHA-256"))?;
                    expected = Some(decode_hash(&value)?);
                }
                other => bail!("unexpected argument: {other}"),
            }
        }

        if let Some(rest) = url.strip_prefix("https://") {
            let rest = rest.trim_end_matches('/');
            let (host, port) = split_authority(rest, 443);
            Ok(Self {
                host,
                port,
                expected,
            })
        } else if url.starts_with("http://") {
            // Dev bootstrap: the daemon publishes both the QUIC port and the
            // hash the wtransport client would pin, so it is its own oracle.
            let info: serde_json::Value = serde_json::from_str(&http_get(&url, "/webtransport-info")?)
                .context("parse /webtransport-info")?;
            let port = info["port"]
                .as_u64()
                .ok_or_else(|| anyhow!("info missing port"))? as u16;
            let published = info["certHashBase64"]
                .as_str()
                .ok_or_else(|| anyhow!("info missing certHashBase64"))?;
            let published = decode_hash(published)?;
            if let Some(supplied) = expected {
                if supplied != published {
                    bail!("--expect disagrees with /webtransport-info; refusing to guess");
                }
            }
            let authority = url.trim_start_matches("http://").trim_end_matches('/');
            let (host, _) = split_authority(authority, 80);
            Ok(Self {
                host,
                port,
                expected: Some(published),
            })
        } else {
            bail!("server URL must start with https:// or http:// (got {url})")
        }
    }
}

/// Connect far enough to see the certificate, then stop. Deliberately below
/// HTTP/3: extended CONNECT is stage 2, and folding it in here would let an
/// unrelated h3 failure masquerade as a channel-binding failure.
fn probe(host: &str, port: u16) -> Result<Vec<u8>> {
    let registration = Registration::new(&RegistrationConfig::default())
        .map_err(|s| status("open registration", s))?;
    let alpn = [BufferRef::from(ALPN)];
    let settings = Settings::new().set_IdleTimeoutMs(HANDSHAKE_TIMEOUT.as_millis() as u64);
    let configuration = Configuration::open(&registration, &alpn, Some(&settings))
        .map_err(|s| status("open configuration", s))?;

    // NO_CERTIFICATE_VALIDATION is the msquic analogue of wtransport's
    // `with_server_certificate_hashes`: the self-signed dev identity has no
    // chain to build, so validation is off and the pin *is* the hash check we
    // perform ourselves. USE_PORTABLE_CERTIFICATES is the flag under test.
    let credential = CredentialConfig::new_client().set_credential_flags(
        CredentialFlags::NO_CERTIFICATE_VALIDATION
            | CredentialFlags::INDICATE_CERTIFICATE_RECEIVED
            | CredentialFlags::USE_PORTABLE_CERTIFICATES,
    );
    configuration
        .load_credential(&credential)
        .map_err(|s| status("load client credential", s))?;

    let (tx, rx) = mpsc::channel::<Probe>();
    let handler = move |_conn: ConnectionRef, event: ConnectionEvent| {
        let message = match event {
            ConnectionEvent::PeerCertificateReceived { certificate, .. } => {
                Some(Probe::Certificate(unsafe { portable_der(certificate) }))
            }
            ConnectionEvent::Connected { .. } => Some(Probe::Connected),
            ConnectionEvent::ShutdownInitiatedByTransport { status, .. } => {
                Some(Probe::Failed(format!("transport shutdown: {status:?}")))
            }
            ConnectionEvent::ShutdownInitiatedByPeer { error_code } => {
                Some(Probe::Failed(format!("peer shutdown: code {error_code}")))
            }
            ConnectionEvent::ShutdownComplete { .. } => Some(Probe::Closed),
            _ => None,
        };
        if let Some(message) = message {
            // The receiver may already be gone once we have what we came for.
            let _ = tx.send(message);
        }
        Ok::<(), Status>(())
    };

    let connection =
        Connection::open(&registration, handler).map_err(|s| status("open connection", s))?;
    connection
        .start(&configuration, host, port)
        .map_err(|s| status("start connection", s))?;

    // PEER_CERTIFICATE_RECEIVED fires during the handshake, before Connected.
    let mut failure: Option<String> = None;
    loop {
        match rx.recv_timeout(HANDSHAKE_TIMEOUT) {
            Ok(Probe::Certificate(Some(der))) => return Ok(der),
            Ok(Probe::Certificate(None)) => bail!(
                "MsQuic reported PEER_CERTIFICATE_RECEIVED but the QUIC_CERTIFICATE was not a \
                 readable DER buffer - USE_PORTABLE_CERTIFICATES was almost certainly ignored on \
                 this TLS provider. This is the blocking outcome; see README."
            ),
            Ok(Probe::Connected) => {
                bail!(
                    "handshake completed without ever indicating the peer certificate - \
                     INDICATE_CERTIFICATE_RECEIVED had no effect"
                )
            }
            Ok(Probe::Failed(why)) => failure = Some(why),
            Ok(Probe::Closed) => {
                bail!(
                    "connection closed before the certificate was indicated{}",
                    failure.map(|w| format!(" ({w})")).unwrap_or_default()
                )
            }
            Err(_) => bail!("timed out after {:?} waiting for the handshake", HANDSHAKE_TIMEOUT),
        }
    }
}

enum Probe {
    Certificate(Option<Vec<u8>>),
    Connected,
    Failed(String),
    Closed,
}

/// Read the leaf certificate as DER.
///
/// # Safety
/// Only sound when the credential was loaded with `USE_PORTABLE_CERTIFICATES`,
/// which makes MsQuic pass a `QUIC_BUFFER` here instead of a provider-native
/// handle (`PCCERT_CONTEXT` on Schannel, `X509*` on quictls). Reading a
/// provider-native handle as a buffer would be undefined; the flag is set in
/// `probe` and must not be removed without changing this function.
unsafe fn portable_der(certificate: *mut msquic::ffi::QUIC_CERTIFICATE) -> Option<Vec<u8>> {
    if certificate.is_null() {
        return None;
    }
    let buffer = &*(certificate as *const msquic::ffi::QUIC_BUFFER);
    if buffer.Buffer.is_null() || buffer.Length == 0 {
        return None;
    }
    Some(std::slice::from_raw_parts(buffer.Buffer, buffer.Length as usize).to_vec())
}

/// Blocking twin of `hf-native-client`'s `http_get`, kept deliberately close to
/// it so the bootstrap this spike tests is the one the client actually uses.
fn http_get(base: &str, path: &str) -> Result<String> {
    let host_port = base
        .strip_prefix("http://")
        .ok_or_else(|| anyhow!("bootstrap URL must start with http:// (got {base})"))?
        .trim_end_matches('/');
    let mut stream = TcpStream::connect(host_port).with_context(|| format!("connect {host_port}"))?;
    let host = host_port.split(':').next().unwrap_or(host_port);
    stream.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let text = String::from_utf8_lossy(&response);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow!("malformed HTTP response"))?;
    if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
        bail!(
            "GET {path}: {}",
            head.lines().next().unwrap_or("unknown status")
        );
    }
    Ok(body.to_string())
}

fn split_authority(authority: &str, default_port: u16) -> (String, u16) {
    match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() => {
            (host.to_string(), port.parse().unwrap_or(default_port))
        }
        _ => (authority.to_string(), default_port),
    }
}

fn decode_hash(value: &str) -> Result<[u8; 32]> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .context("decode base64 hash")?
        .try_into()
        .map_err(|_| anyhow!("certificate hash must be 32 bytes"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn status(what: &str, status: Status) -> anyhow::Error {
    anyhow!("{what} failed: {status:?}")
}
