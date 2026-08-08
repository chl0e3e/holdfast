# msquic-schannel spike

De-risking for the "switch the Windows desktop build to Schannel" work. Three
stages, **all passing** — everything the port needs is proven:

- **stage 1** (`certprobe`) — can Schannel surface the peer leaf certificate at
  all, so the ADR 0008 channel binding is reproducible? It exists as its own
  stage because a No here invalidates everything downstream.
- **stage 2** (`wtprobe`) — does that survive the HTTP/3 layer, and will the
  real daemon accept a WebTransport session from a non-wtransport client?
- **stage 3** (`stage3`) — over our own `h3::quic` adapter, does a WebTransport
  bidi stream carry holdfast's actual protocol? This is what `Chan::open` does,
  so it is the one that decides wire compatibility.

Disposable code. The production crates must not import any of it.

## Result: PASS (2026-08-07)

Schannel honours `USE_PORTABLE_CERTIFICATES`. `certprobe` connected to a live
`holdfastd` over Schannel-terminated QUIC, received the peer leaf as a 429-byte
DER buffer, and hashed it to
`d33e1b78cfdf676a15450dd02e85e85bdfec48cf9cb538cec2846b772af0bb27` — identical
to the value the daemon publishes and the `hf` wtransport client signs into the
ADR 0008 channel binding. **The port is not blocked.** Stage 2 (the
WebTransport client session) is the next question.

Run on the `~/windows-build` VM, MsQuic 2.5.3 Schannel build, against a daemon
on the Linux host with a supplied ECDSA P-256 certificate. The oracle was
confirmed three independent ways before the probe ran: OpenSSL over the leaf
DER, the daemon's own `/webtransport-info`, and a live `hf` client that
completed SSH auth against it.

One wart appeared in the spike and had to be fixed before the production port:
the linked
`certprobe.exe` imports **`msquic.sys`**, not `msquic.dll`. The round only ran
because a copy of `msquic.dll` was placed beside the exe under that name. The
cause is not the obvious ones — the box has exactly one `msquic.lib` (the
NuGet one), that lib's import descriptor names `msquic.dll`, the DLL's own
export name is `msquic.dll`, and the crate declares plain
`#[link(name = "msquic")]`. Neither the crate nor the DLL contains a `.sys`
string anywhere. Shipping an `msquic.sys` alias was not acceptable. The
production preparation script resolves it by deterministically regenerating
the two-export import library from the package DLL with MSVC `lib.exe`; the
desktop PE now imports only `msquic.dll` (ADR 0022).

## Why a spike and not the port

Schannel cannot be dropped into the current stack. `wtransport`'s TLS type is
`pub type TlsClientConfig = rustls::ClientConfig` — a concrete type, not a
trait — so even its `with_custom_tls()` escape hatch only accepts rustls. And
the Rust `schannel` crate is a stream-TLS (SSPI-over-TCP) wrapper with no QUIC
surface at all; the copy already in `Cargo.lock` is just `rustls-native-certs`
reading the Windows certificate store.

Schannel-backed QUIC therefore means MsQuic, which uses Schannel as its TLS
provider on Windows. The layering works out better than expected:

- `h3` 0.0.8 is generic over a transport (`h3/src/quic.rs` traits); `h3-quinn`
  is only ~650 lines of adapter.
- `msquic-h3` 0.0.7 already implements that adapter over MsQuic, and it pins
  **h3 0.0.8** — the same version the daemon speaks via `h3-quinn` 0.0.10. No
  vendoring needed.
- The daemon stays on quinn/rustls, untouched. Both ends speak the same
  HTTP/3 and WebTransport wire format.

The client's wtransport surface is also small: `Endpoint::client`, the
`ClientConfig` builder, `.connect(url)`, `.open_bi()`, `SendStream`/`RecvStream`.
No datagrams are ever sent or received — `Capability::Datagrams` is negotiated
in `crates/protocol/src/negotiate.rs` and then unused.

What is *not* solved is authentication.

## The question

Holdfast binds the SSH auth signature to the server's identity (ADR 0008). The
channel binding is the SHA-256 of the server's leaf certificate, and
`hf-native-client` obtains it two different ways:

| URL form | How the hash is obtained | MsQuic equivalent |
| --- | --- | --- |
| `http://` dev bootstrap | `/webtransport-info` publishes `certHashBase64`; pinned via `with_server_certificate_hashes` | none — pinning must be done by hand in the certificate callback |
| `https://` production | WebPKI validates, then `connection.peer_identity()` reads the leaf back off the live connection | none — there is no `peer_identity()` |

MsQuic instead hands the peer certificate to a connection callback as an opaque
`*mut QUIC_CERTIFICATE`. Its meaning is provider-dependent: `X509*` on
quictls, `PCCERT_CONTEXT` on Schannel.
`QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES` is documented to normalise it
to a `QUIC_BUFFER` of DER on any provider, and the flag is exposed by the Rust
bindings (`msquic::CredentialFlags::USE_PORTABLE_CERTIFICATES`).

**Whether Schannel honours that flag is the open question.** If it does not
yield bytes hashing to the same value, ADR 0008 cannot be reproduced, and the
port is blocked rather than merely expensive.

## Success criterion

One line, and nothing else counts:

> The SHA-256 of the DER MsQuic surfaces equals the hash the wtransport client
> pins for the same daemon.

`certprobe` exits `0` only on that. It stops below HTTP/3 on purpose —
extended CONNECT is stage 2, and folding it in here would let an unrelated h3
failure look like a channel-binding failure.

## Running it

Requires a Windows host: Schannel is the thing under test. Building on Linux
gets you quictls and proves nothing — do not be tempted.

**The `msquic` crate's default `src` feature cannot build from crates.io on
Windows.** `src/platform/CMakeLists.txt` unconditionally compiles
`datapath_raw_xdp_win.c` on x64 and adds
`submodules/xdp-for-windows/published/external` to the include path — a git
submodule the published `.crate` does not vendor. It fails with:

```
datapath_raw_xdp_win.c(16,1): fatal error C1083:
  Cannot open include file: 'xdp/wincommon.h'
```

Only `QUIC_UWP_BUILD`, `QUIC_GAMECORE_BUILD` or an arm/arm64 processor select
the `datapath_raw_dummy.c` path instead, and none of those are appropriate
here. So the spike uses the `find` feature, which links a prebuilt MsQuic.
Despite the name it does not need vcpkg — `try_vcpkg()` merely probes
`$VCPKG_ROOT/installed/x64-windows` for `bin/msquic.dll`, `bin/msquic.pdb` and
`lib/msquic.lib`. `spike.ps1` populates that layout from Microsoft's official
`Microsoft.Native.Quic.MsQuic.Schannel` NuGet package, pinned to 2.5.3 (the
closest stable to the crate's 2.5.1-beta bindings). That package *is* the
Schannel build, which is what keeps this an honest test.

This matters beyond the spike: a real port inherits the same constraint. It
would ship a prebuilt Schannel MsQuic DLL rather than building it, which is a
redistribution and update-cadence question the current all-static Rust binary
does not have.

```powershell
cargo run --bin certprobe -- http://<daemon-host>:8080
cargo run --bin certprobe -- https://<daemon-host>:443 --expect <base64-sha256>
```

Against an `http://` base the daemon is its own oracle — the probe fetches
`/webtransport-info` and compares against the hash published there, which is
exactly what the wtransport client would pin. The `https://` form has no
bootstrap endpoint, so pass `--expect` with the hash observed from the
wtransport client (`hf --url https://…` against the same host).

The build VM rig at `~/windows-build` is the fastest path. Re-read its notes
first — host→VM share propagation lags by minutes, and a rebuild triggered too
soon silently builds stale source.

## Stage 2: PASS (2026-08-07)

`wtprobe` connected to a live `holdfastd` over Schannel-terminated QUIC,
recovered the leaf via `GetParam` (same 429-byte DER, same hash), completed the
HTTP/3 handshake, and got **`200 OK`** to an extended CONNECT with
`:protocol: webtransport`. The daemon independently logged
`webtransport session ended: Connection error: Timeout` — a session that
existed and then idled out when the probe exited.

So the full mechanism is proven: Schannel QUIC → channel binding → h3 →
WebTransport session, against the real server, with no wtransport anywhere on
the client side.

**Cost of that result: two vendored patches.**

| crate | patch | upstream prospects |
| --- | --- | --- |
| `msquic-h3` | one accessor exposing the inner `msquic::Connection` | community crate (`youyuanwu`), small ask |
| `h3` | `enable_webtransport` on the *client* builder | hyperium; arguably an upstream bug — the server knob exists, the client one does not |

The h3 patch is not optional and not a nicety: `h3-webtransport`'s server reads
the peer's settings and refuses with `H3_SETTINGS_ERROR`
("webtransport is not supported by client", `server.rs:90`) unless the client
advertises `ENABLE_WEBTRANSPORT`, and stock h3 gives a client no way to do so.
**A WebTransport client cannot exist on unpatched h3.** That is a strong
upstream PR candidate; landing it would shrink the permanent fork to one crate.

Note the h3 patch is wired as `[patch.crates-io]`, not a path dependency — the
vendored `msquic-h3` also depends on h3, and both must resolve to the same
crate instance or the `h3::quic` trait impls do not line up.

## Stage 3: PASS (2026-08-08)

`stage3` ran the whole client path over **our own `h3::quic` adapter** (`src/adapter.rs`,
over `msquic-async` — no `msquic-h3`):

```
connected   QUIC handshake complete (Schannel)
            channel binding matches
h3          SETTINGS exchanged
CONNECT     status 200 OK
wt stream   opened, header written (session SessionId(0))
sent        ClientHello
recv        ServerHello: protocol 0.1, max_frame_bytes 262144
```

The `ServerHello` was decoded with holdfast's own `hf-protocol`, so this is
wire compatibility with the live daemon rather than an approximation. The
daemon independently logged `webtransport session ended` when the probe exited.

**Everything the port needs is now proven.** Schannel-terminated QUIC, the
ADR 0008 channel binding, HTTP/3, WebTransport session establishment, and
WebTransport bidi streams carrying the real protocol.

Final fork surface — three patches, all small, none inside anyone's state
machine:

| crate | patch |
| --- | --- |
| `msquic-async` | one accessor, `Connection::msquic_handle`, for the `GetParam` channel binding |
| `msquic-async` (manifest) | `default-features = false, features = ["preview-api", "find"]` — see the feature trap below |
| `h3` | `enable_webtransport` on the client builder |

`msquic-h3` is no longer used; `wtprobe` and `vendor/msquic-h3` remain only as
the stage 2 artefact and can be deleted.

### Traps worth carrying into the port

- **Feature unification re-breaks the Windows build.** Any crate in the graph
  that takes `msquic` with default features turns `src` back on for everyone,
  regardless of what our own manifest says. That is what `msquic-async` did.
- **h3's backend modules are gated** behind
  `i-implement-a-third-party-backend-and-opt-into-breaking-changes`. Writing a
  transport is supported, but the name is h3's own warning: pin h3 exactly and
  re-check the adapter on every bump.
- **An `Opener` must outlive individual polls.** An in-flight stream open is a
  boxed future; rebuilding the opener per poll drops and restarts it forever,
  and the symptom is not an error but a silent stall ending in
  `QUIC_STATUS_CONNECTION_IDLE`.
- **Format msquic-async errors with `Debug`, never `Display`.** Its
  `ConnectionLost` is `#[error("connection lost")]` and discards the wrapped
  cause, which is the only part that says why.
- A unidirectional stream has no read half; `split()` returns `(None, Some(..))`.

## Superseded: why stage 3 looked blocked before the adapter

Stage 2 proved the *session* opens. What holdfast actually uses is
`connection.open_bi()` per channel (`Chan::open`), carrying 4-byte
big-endian length-prefixed protobuf (`crates/protocol/src/framing.rs`). So the
remaining proof is: open a WebTransport bidi stream, send `ClientHello`, read
`ServerHello`.

Most of that is available:

- `h3::stream::{WriteBuf, BidiStreamHeader::WebTransportBidi}` are public, so
  the stream header (frame type `WEBTRANSPORT_BI_STREAM` + session id) can be
  written without h3-webtransport.
- `h3::client::RequestStream::id()` gives the session id — the same value the
  server derives via `stream.send_id().into()`.
- `hf-protocol` compiles its `.proto` with `protox` (pure Rust, no `protoc`),
  so the spike can use holdfast's real encoder and prove true wire
  compatibility rather than a hand-rolled approximation.

**The blocker is the payload write.** After the stream header, WebTransport
payload is opaque — it must not be wrapped in H3 DATA frames. Writing raw bytes
requires `h3::quic::SendStreamUnframed::poll_send`, and `WriteBuf` has no
`From<B>` for raw payload (only `StreamType`, `UniStreamHeader`,
`BidiStreamHeader`, `Frame<B>`), so `send_data` cannot carry it either.
`msquic-h3` implements `SendStream`, `RecvStream` and `BidiStream` — **but not
`SendStreamUnframed`.**

Adding it is not another accessor. `H3SendStream`'s send path is a reducer
state machine (`transition`/`SendCommand`, terminal publication, the SF-2
non-consuming finish guard, MF-2 provisional cancellation). A new unframed-send
input has to be threaded through it correctly; getting it subtly wrong risks
hangs or lost terminal states, which is precisely what that machinery exists to
prevent.

This changes the trade-off that made option 1 attractive. If we must implement
a core trait inside someone else's concurrency state machine, `msquic-h3`'s
value as an off-the-shelf dependency drops a long way, and **option 3 — writing
our own `h3::quic` adapter over `msquic-async` — becomes materially more
competitive.** Worth re-deciding before more work goes in.

## How stage 2 got there (the layering problem it had to solve)

The plan was msquic + `msquic-h3` + `h3`, writing only the WebTransport client
session. The pieces line up better than expected: `msquic-h3` 0.0.7 depends on
exactly `h3` 0.0.8 and `msquic` 2.5.1-beta, implements
`h3::quic::Connection`/`OpenStreams`/`SendStream`/`RecvStream`/`BidiStream`,
has a client `Connection::connect`, and `h3`'s client can emit extended CONNECT
(`enable_extended_connect` on the builder; `:protocol` comes from
`Protocol::WEB_TRANSPORT` in the request extensions).

**But `msquic-h3` cannot give us the channel binding.** Its connection callback
handles only `Connected`, `PeerStreamStarted`, `ShutdownComplete`,
`ShutdownInitiatedByPeer` and `ShutdownInitiatedByTransport` — there is no
`PeerCertificateReceived` arm, it never sets `INDICATE_CERTIFICATE_RECEIVED` or
`USE_PORTABLE_CERTIFICATES`, and it exposes no way to reach the connection it
owns: `Connection.conn` is `pub(crate)`, and the `Deref` to
`msquic::Connection` is on the crate-private `ConnHandle`. So the exact
mechanism stage 1 proved works is unreachable through this layer.

Note also that `msquic-h3` and `msquic-async` are community crates (author
`youyuanwu@outlook.com`), not Microsoft's. Only `msquic` itself is Microsoft's.

Three ways out (option 1 was taken, spike-local):

1. **Patch/fork `msquic-h3`.** Cheapest by far, and there is repo precedent:
   `vendor/avt` is already a patched fork wired through `[patch.crates-io]`.
   The minimal patch is roughly three lines — make an accessor for the inner
   `msquic::Connection` public. We would then not even need the callback,
   because there is a Schannel-native route: `GetParam` with
   `PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_W` and
   `SECPKG_ATTR_REMOTE_CERT_CONTEXT` yields a `PCCERT_CONTEXT` whose
   `pbCertEncoded`/`cbCertEncoded` is the leaf DER. Cost: a second vendored
   fork to carry for the life of the product.
2. **Upstream it.** Same patch, no fork to maintain, but the port is then gated
   on a third party's release cadence.
3. **Write our own `h3::quic` adapter over `msquic-async`.** No fork, full
   control, but `msquic-h3` is ~15 modules — this is the expensive option.

Option 1 was taken, vendored inside the spike only. It then turned out that
`h3` needed a patch too (see the stage 2 result above), so the fork surface is
two crates rather than one.

## Reading the result

- **PASS** — the channel binding is reproducible. Stage 2 becomes: implement
  the WebTransport *client* session. `h3-webtransport` 0.1.2 ships only
  `lib.rs`, `server.rs`, `stream.rs`; there is no client session module in any
  crate outside wtransport, so that is ~400–600 lines (SETTINGS check, extended
  CONNECT with `:protocol: webtransport` via `h3`'s `Protocol::WEB_TRANSPORT`,
  session-ID stream framing) plus conformance testing against the live
  wtransport server.
- **`QUIC_CERTIFICATE` was not a readable DER buffer** — the blocking outcome.
  Before concluding the port is dead, try reading it as a `PCCERT_CONTEXT` and
  pulling `pbCertEncoded`/`cbCertEncoded` via `windows-sys`. That is
  Schannel-specific rather than portable, but it only has to work on Windows.
- **Hash mismatch with a readable buffer** — most likely the buffer is a chain
  or a re-encoding rather than the leaf as transmitted. Worth dumping the DER
  and diffing against the daemon's certificate before drawing conclusions.

## Known costs, whatever the result

- `msquic` is at `2.5.1-beta`. A beta C library underneath the client's only
  transport is a real risk to weigh.
- Schannel gives far less control over the TLS parameter set than rustls. The
  13-day self-signed dev identity has no chain to build, so it needs validation
  disabled plus the manual hash check this probe performs.
- `hf-native-client` would grow two transports behind a trait, with the unix
  `hf` CLI staying on quinn. That is a permanent maintenance fork, so the
  protocol conformance tests need to run against both backends.
