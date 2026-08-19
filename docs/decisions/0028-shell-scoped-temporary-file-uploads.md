# ADR 0028: shell-scoped temporary file uploads

- **Status:** Accepted; implemented
- **Date:** 2026-08-19
- **Scope:** standalone `holdfastd` and the Windows desktop client
- **Protocol capability:** `CAPABILITY_FILE_TRANSFER`, protocol minor 2

## Context

The Windows desktop client needs to copy a local file to the machine hosting an
active Holdfast shell and receive a path that can be used from that shell. The
original design anticipated optional file transfer and assigned it to reliable
streams, and the protobuf capability enum already reserves
`CAPABILITY_FILE_TRANSFER`, but there are no file-transfer messages or handlers.
Today the first client-opened bidirectional stream is the control channel and
every later stream is assumed to be a shell attachment.

This is not a terminal-byte feature. Upload bytes must never pass through the
PTY, terminal model, scrollback, or the control channel. It is also not an HTTP
form endpoint: reusing the authenticated protocol connection avoids a second
authorization surface and preserves the transport-independent WebTransport /
native QUIC / WebSocket channel model.

The difficult part is Unix ownership. In the single-user service, `holdfastd`
and its shells have the same uid and share the service's `PrivateTmp` namespace.
In the multi-user service, shells are launched by the socket-activated spawner
under an allowlisted target account. The network-facing daemon must not gain
`CAP_CHOWN`, `CAP_SETUID`, or arbitrary filesystem-write authority merely to
implement uploads.

## Decision

### Product scope

The first file-transfer version provides **one-file uploads to an active
shell's temporary area**:

1. The desktop user selects one regular local file.
2. The client opens a new reliable bidirectional protocol channel and binds the
   upload to the active shell ID.
3. The daemon verifies that the authenticated connection owns the running shell
   and that the grant permits `upload`.
4. The server chooses a non-guessable directory and safe stored basename under
   its configured upload root. The client never supplies a destination path.
5. Bytes stream to disk with transport backpressure and an incremental SHA-256.
6. Only after the declared length and digest match does the server return the
   absolute remote path.
7. The desktop shows progress and offers to copy or insert the returned path.

The initial version does **not** provide downloads, directory/archive upload,
multiple-file batches, overwrite, arbitrary destinations, upload resumption,
gateway/agent forwarding, or browser UI. Those require later decisions and
capabilities. Direct standalone daemons remain the primary product; the admin
overlay does not gain file-transfer messages in this change.

### Capability and compatibility

`CAPABILITY_FILE_TRANSFER` is valid from protocol minor 2. A capability is
negotiated only when both peers advertise it, the selected minor supports it,
and the daemon has uploads explicitly configured. Existing minor-1 clients and
servers continue without uploads. Advertising the reserved enum from a minor-1
client does not enable it.

The daemon defaults to uploads disabled. `--upload-root <absolute-path>` enables
the capability. A scoped connection grant must contain the `upload` operation;
the existing local-auth unrestricted grant remains unrestricted, but still
cannot upload unless the operator enabled an upload root.

### Wire protocol

One upload occupies one client-opened reliable channel. Its state machine is:

```text
opening
  client -> BeginUpload(shell_id, original_name, total_bytes, sha256)
  server -> UploadAccepted(upload_id, maximum_chunk_bytes)
streaming
  client -> UploadChunk(offset, data) ...
finishing
  client -> FinishUpload(upload_id)
  server -> UploadFinished(remote_path, bytes_written, sha256)
closed
```

`AbortUpload` is optional client intent; closing the channel has the same abort
semantics. The server removes an uncommitted partial file. Chunks must be
contiguous and exactly ordered even though the underlying stream is ordered;
the explicit offset detects client bugs and makes accounting auditable. The
server rejects data beyond the declared length before writing it.

Upload messages are added to `Envelope` and documented in
`protocol/specification.md` in the same change. They never appear in
`AgentEnvelope` during this phase.

### Fixed bounds

Every implementation layer uses explicit bounds:

| Resource | Initial default / ceiling |
|---|---:|
| File size | 256 MiB per upload |
| Chunk payload | 64 KiB protocol ceiling; server may select lower |
| Concurrent uploads | 2 per connection |
| Concurrent uploads | 4 per authenticated user |
| Concurrent uploads | 16 per daemon |
| Client-core pending upload commands | 8 per server supervisor |
| Progress notifications | coalesced to at most 10 per second |
| Inactivity timeout | 30 seconds between accepted chunks |
| Original filename | 255 UTF-8 bytes before sanitizing |
| Upload ID / directory entropy | 128 random bits |
| Temporary retention | 24 hours |

The per-file ceiling is configurable downward or upward only up to a hard
protocol ceiling of 4 GiB. Values are checked before opening or allocating the
destination. A server selects a chunk limit that, including protobuf overhead,
fits the negotiated frame ceiling. No queue
contains whole-file buffers: the client reads, hashes and sends one chunk at a
time; the server validates, hashes and writes one chunk at a time.

Retention is temporary, not durable storage. The deployment ships a
`tmpfiles.d` rule for the configured conventional root and documents the
equivalent rule for a custom root. In-process tests use an explicit reaper.
Partials are removed immediately on error, timeout, cancellation or connection
loss. A successful file may subsequently be changed by its owning shell; the
reported SHA-256 describes the committed upload bytes only.

### Paths and filesystem safety

The conventional root is `/tmp/holdfast-uploads`, but there is no implicit
default: the operator must pass it (or another absolute path) explicitly.
Server-selected paths have the form:

```text
<upload-root>/<32 lowercase hex upload id>/<sanitized basename>
```

The original name is display metadata only. The stored basename permits ASCII
letters, digits, `.`, `_`, and `-`; every other run becomes `_`. Empty names,
`.` and `..` become `upload`. It is capped below `NAME_MAX`. The server uses
directory-relative, no-follow, create-new operations and never joins an
unvalidated client path. It refuses symlinks, non-regular local source files,
and any existing destination.

Committed directories are mode `0700` and files mode `0600`, owned by the
shell's resolved Unix account. The returned absolute path is therefore usable
by that shell without being readable by unrelated local accounts.

### Privilege boundary

Single-user mode writes through a transport-neutral upload store owned by the
daemon account.

Multi-user mode extends the socket-activated spawner with a distinct upload
operation. The spawner repeats the existing peer-uid and account-allowlist
checks. It receives bounded chunks over its `SOCK_SEQPACKET` connection, writes
and hashes the partial while it is still recoverable, then atomically commits
it for the target account. Only the spawner receives the minimum additional
filesystem capability needed by the selected implementation; the daemon unit's
capabilities do not expand, and the launcher still clears all inherited and
ambient capabilities before running a shell.

The internal spawner request is explicitly tagged (`SpawnShell` versus
`ReceiveUpload`) and remains bounded by `MAX_MESSAGE_BYTES`. A failed or lost
spawner connection aborts the upload and never falls back to daemon-owned or
world-readable output.

### Desktop trust boundary

The webview must not be able to ask Rust to read an arbitrary local path. The
Rust/Tauri side owns the native file picker and retains the selected handle or
path internally for the upload command. File bytes do not cross Tauri IPC.
Only bounded progress records and the final remote path cross into the webview.

The UI binds Upload to the active shell. It disables the action when the server
did not negotiate file transfer, the shell is not running, or another upload
for that tab is active. Cancellation closes the upload channel and triggers
partial cleanup. Returned paths are rendered as text; inserting one into the
terminal uses POSIX shell quoting and remains an explicit user action.

### Observability

Audit records contain authenticated user, shell ID, stored basename, byte
count, outcome and duration. They do not contain file bytes, local source path,
digest preimages, or the full random remote path. Metrics count active uploads,
bytes, completions, cancellations, timeouts and rejected limits. Error messages
do not reveal another user's shell, account or upload path.

## Implementation plan and gates

Work proceeds in order; a later phase does not expose surface area before the
preceding phase's tests pass.

### U0 — decision record and threat model

- Accept this ADR and add upload threats: traversal/symlink attacks, local file
  disclosure, cross-user writes, disk exhaustion, partial-file leakage and
  maliciously slow streams.
- Record exact reproduction commands alongside each later phase.

**Gate:** documentation review; no runtime capability advertised.

### U1 — protocol contract

- Raise protocol minor to 2.
- Add upload messages and required error codes to `messages.proto` and the
  message catalogue/semantics to `specification.md` in the same change.
- Teach negotiation that file transfer requires minor 2.
- Regenerate the browser TypeScript schema even though browser UI is deferred.
- Add encode/decode, version downgrade and oversized-chunk tests.

**Gate:** `cargo test -p hf-protocol --locked`; web schema generation and
typecheck; no server advertises file transfer.

### U2 — transport-neutral temporary store

- Add a focused core module/crate for filename sanitizing, bounds, incremental
  hashing, create-new partials, commit/abort and retention metadata.
- Keep it independent of HTTP, QUIC, Tauri, PTYs and terminal parsing.
- Implement the same-uid backend first with deterministic fault-injection tests.

**Gate:** traversal, symlink, collision, short/long data, checksum mismatch,
timeout and cleanup tests all pass; capability remains disabled.

### U3 — privileged multi-user writer

- Tag the spawner protocol and implement `ReceiveUpload` with independent
  peer/account validation.
- Stream bounded seqpacket chunks, abort on disconnect, and commit ownership
  only after length/hash verification.
- Update systemd capabilities and tmpfiles configuration narrowly, with an
  explicit deployment regression for target ownership and unrelated-user
  denial.

**Gate:** spawner unit/integration tests prove `0600` target ownership, partial
cleanup, root refusal, allowlist enforcement and no daemon capability increase.

### U4 — standalone daemon upload channels

- Generalize non-control channel classification by first message: attachment or
  upload.
- Add per-connection/user/global concurrency accounting, inactivity timeout,
  grant-operation checks, audit events and configuration.
- Route same-uid and spawner-backed writes through one interface.
- Advertise file transfer only when the configured backend is ready.

**Gate:** WebSocket and real-WebTransport tests cover success, backpressure,
oversize-before-write, cancellation, disconnect, cross-user denial and scoped
grant denial.

### U5 — native client and desktop core

- Add a native-client streaming API that reads one bounded chunk, updates
  SHA-256, sends it, and waits for the committed result.
- Add a bounded `Upload` supervisor command, cancellation token, reconnect
  semantics (fail and cleanly retry from byte zero; no hidden resumption), and
  coalesced progress events.
- Expose negotiated upload capability in the desktop bootstrap/status model.

**Gate:** client/server integration tests compare bytes and digest, exercise
cancel/transport loss, and show no whole-file allocation.

### U6 — Windows desktop UI

- Add a Rust-owned native picker, Upload action on the active shell, progress,
  cancel, and final copy/quoted-insert actions.
- Keep local paths and file bytes out of webview IPC.
- Verify keyboard focus, terminal resize, multiple tabs and server reconnects
  are unaffected.

**Gate:** frontend state tests plus a Windows manual regression using files at
0 B, 1 B, 64 KiB boundaries and the configured maximum.

### U7 — full verification and release readiness

- Run the workspace, protocol, daemon, native client, desktop, spawner,
  generated-width and audit gates.
- Verify both shipped systemd deployment modes and document enabling/disabling,
  cleanup, limits and exact commands.
- Keep gateway/agent capability absent and state that limitation in release
  notes.

**Gate:** all automated gates pass and a file selected on Windows is readable
only by the intended Linux shell account at the returned path.

## Implementation progress

As of 2026-08-19, U0 through U7 are complete for direct standalone daemon
connections and the Windows desktop client. File transfer remains absent from
the gateway/agent and browser surfaces, as decided above.

Exact reproduction commands:

```sh
cargo test -p hf-protocol --locked
cargo test -p hf-upload-store --locked
cargo test -p hf-spawner --locked
cargo test -p hf-daemon --test ws --test webtransport --test auth --locked
cargo test -p hf-native-client --test client --locked
cargo test -p hf-client-core --locked
cargo test --workspace --locked
cargo clippy -p hf-protocol -p hf-upload-store -p hf-spawner -p hf-daemon \
  -p hf-native-client -p hf-client-core --locked -- \
  -D warnings -A clippy::unnecessary-map-or
cargo run -p hf-xterm-width-tables --locked -- --check
cd web && npm run proto:generate && npm run typecheck
cd desktop && npm test && npm run typecheck && npm run build
# On Windows, after scripts/prepare-msquic.ps1:
cd desktop/src-tauri && cargo check --locked
```

## Consequences

- File upload uses the existing authenticated, multiplexed transport cleanly
  and does not couple the core daemon to a central service.
- The protocol and spawner gain new explicit state machines that require careful
  fuzzing and failure cleanup.
- Uploads are temporary convenience objects, not durable storage or a general
  SFTP replacement.
- Gateway/agent users will not see the capability until a later overlay-specific
  decision adds forwarding without weakening the agent's independent policy.
