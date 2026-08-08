# ADR 0022: Windows desktop transport uses MsQuic with Schannel

- Status: accepted
- Date: 2026-08-08
- Relates to ADRs 0005, 0008, 0019; threat model T1, T11
- No wire change

## Context

The desktop client was portable Rust but its QUIC/TLS stack was always
Quinn/rustls. Windows is the first shipping desktop target, and the requested
platform posture is native Schannel certificate validation and trust stores.
The Rust `schannel` crate cannot provide this: it wraps stream TLS over SSPI,
not QUIC. `wtransport` also accepts a concrete `rustls::ClientConfig`, so its
custom-TLS hook cannot substitute Schannel.

Microsoft's supported Windows user-mode QUIC library is MsQuic; its normal
Windows TLS provider is Schannel and applications package `msquic.dll` with
their binary:

- https://microsoft.github.io/msquic/msquicdocs/docs/Platforms.html
- https://microsoft.github.io/msquic/msquicdocs/docs/Release.html

The disposable `spikes/msquic-schannel` work proved three facts against a live
holdfastd on Windows: Schannel exposes the authenticated peer leaf required by
ADR 0008, an HTTP/3 extended CONNECT establishes the WebTransport session, and
a WebTransport bidirectional stream carries the real Holdfast
ClientHello/ServerHello wire exchange.

## Decision

On Windows only, `hf-native-client` uses:

```text
Holdfast protocol framing
        ↓
WebTransport streams / HTTP/3 h3 0.0.8
        ↓
small h3::quic adapter over msquic-async 0.4.1
        ↓
MsQuic 2.5.3 user-mode DLL
        ↓
Schannel
```

Other platforms retain wtransport/Quinn/rustls. The daemon remains unchanged.
The native-client public API wraps the platform connection and stream types, so
client-core, shell lifecycle, authentication, and protocol framing are shared.

Production `https://` connections use Schannel's hostname, chain, validity,
and Windows trust-store checks. Development `http://` bootstrap connections
use the existing `/webtransport-info` exact leaf hash: certificate validation
is deferred only for the QUIC handshake, then the live Schannel leaf is
compared before HTTP/3 or Holdfast bytes are sent. In both cases the SHA-256 of
that live leaf remains the ADR 0008 SSH challenge channel binding.

All transport resource dimensions are explicit: 64 peer bidirectional streams,
16 peer unidirectional streams, a 256 KiB stream receive window, a 16 MiB
connection flow-control window, and a one MiB defensive peer-certificate cap.
Protocol framing retains its separate negotiated 256 KiB default/one MiB hard
ceiling and rejects lengths before payload allocation.

## Upstream and packaging surface

Only two vendored patches remain:

1. `h3` adds the missing client-builder `enable_webtransport` setter. Without
   it, the client advertises `SETTINGS_ENABLE_WEBTRANSPORT=0` and holdfastd
   correctly refuses the session.
2. `msquic-async` exposes its live HQUIC handle for the Schannel
   `SECPKG_ATTR_REMOTE_CERT_CONTEXT` query and disables the crate's broken
   source-build default in favour of the official prebuilt library.

The spike's `msquic-h3` fork and earlier probe generations are not imported.

`desktop/scripts/prepare-msquic.ps1` downloads Microsoft's official
`Microsoft.Native.Quic.MsQuic.Schannel` 2.5.3 NuGet package and verifies pinned
package, DLL, and PDB SHA-256 values. Its x64 import library incorrectly names
`msquic.sys` even though the package ships the user-mode `msquic.dll`; the
script deterministically regenerates the two-export import library from a
small `.def` using MSVC `lib.exe`. The installer includes `msquic.dll` beside
the desktop executable. An `.sys`-named DLL alias is never shipped.

## Verification

Linux regression and frontend:

```bash
cargo test -p hf-native-client -p hf-client-core
cd desktop && npm ci && npm test && npm run typecheck && npm run build
```

Windows compile and import-name gate (PowerShell from repository root):

```powershell
./desktop/scripts/prepare-msquic.ps1
cargo check -p hf-native-client --lib --locked
cargo check -p hf-client-core --locked
cd desktop/src-tauri
cargo check --locked
```

The CI installer job additionally runs `dumpbin /dependents` against
`hf-desktop.exe` and requires `msquic.dll` while rejecting `msquic.sys`.

The live wire proof remains the disposable spike's `stage3` executable against
a configured holdfastd; it checks the Schannel leaf hash, HTTP/3 settings,
WebTransport CONNECT, and a real Holdfast ClientHello/ServerHello exchange.
The production Windows build and installer were reproduced in Dockur/Windows
with:

```powershell
cd desktop
npm ci
npm test
npm run build
cd src-tauri
cargo build --release --locked
cd ..
cargo tauri build
dumpbin /dependents src-tauri/target/release/hf-desktop.exe
```

The resulting PE imported `msquic.dll` and the unpacked NSIS installer
contained `hf-desktop.exe` plus the pinned 558,640-byte `msquic.dll`.
