//! Phase 0 encoding spike: prove the protobuf schema round-trips between
//! prost (Rust) and @bufbuild/protobuf (TypeScript).
//!
//! Full interop check: `spikes/encoding-spike/run-interop.sh`

use anyhow::{bail, ensure, Context, Result};
use prost::Message;

#[allow(dead_code)]
mod pb {
    include!(concat!(env!("OUT_DIR"), "/holdfast.v0.rs"));
}

/// The reference envelope both languages must agree on.
fn reference_envelope() -> pb::Envelope {
    pb::Envelope {
        request_id: 7,
        server_id: vec![0xAB; 16],
        shell_id: vec![],
        message: Some(pb::envelope::Message::ClientHello(pb::ClientHello {
            protocol_major: 0,
            protocol_minor: 1,
            client_kind: pb::ClientKind::NativeQuic as i32,
            client_build: "holdfast-encoding-spike ünïcode 🦀".to_string(),
            capabilities: vec![
                pb::Capability::Datagrams as i32,
                pb::Capability::Clipboard as i32,
            ],
            max_frame_bytes: 256 * 1024,
            max_datagram_bytes: 1200,
            encodings: vec![pb::Encoding::Utf8 as i32],
        })),
    }
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let (cmd, path) = (args.next(), args.next());
    match (cmd.as_deref(), path) {
        (Some("encode"), Some(path)) => {
            if let Some(dir) = std::path::Path::new(&path).parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(&path, reference_envelope().encode_to_vec())
                .with_context(|| format!("write {path}"))?;
            println!("rust: encoded reference envelope -> {path}");
        }
        (Some("verify"), Some(path)) => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {path}"))?;
            let decoded = pb::Envelope::decode(bytes.as_slice()).context("decode envelope")?;
            ensure!(
                decoded == reference_envelope(),
                "decoded envelope differs from reference:\n{decoded:#?}"
            );
            println!("rust: verified envelope from {path} matches the reference");
        }
        _ => bail!("usage: spike-encoding <encode|verify> <path>"),
    }
    Ok(())
}
