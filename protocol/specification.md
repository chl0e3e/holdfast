# Holdfast protocol specification

```text
Protocol version: 0.1 (draft)
Status: Phase 0 draft — normative once Phase 1 begins; every change to this
        document must ship with the matching change to messages.proto
Last updated: 2026-07-16
```

This protocol is transport-independent. It runs over any transport that provides
the abstraction in [Transport model](#transport-model): native QUIC, WebTransport,
or a WebSocket fallback. Nothing in this document may depend on a specific QUIC
library or on WebTransport-only API behavior.

## 1. Terminology

Normative terms (see also the project plan's Terminology section):

- **Shell** — a persistent logical PTY process on a managed server. Identity is
  `(server_id, shell_id)`. A shell outlives any network connection.
- **Attachment** — a temporary binding of one client stream to one shell.
  Identity is `(connection, stream)` and is never persistent.
- **Session** — one authenticated client-to-gateway connection carrying a control
  channel and zero or more attachments. Never use "session" to mean "shell".
- **Screen revision** — monotonically increasing `u64` identifying a rendered
  terminal state for one shell. Revision `0` is reserved (means "none").
- **History line ID** — stable, monotonically increasing `u64` per shell,
  assigned when a line is committed to scrollback. Never reused, never renumbered
  on eviction.
- **Connection grant** — short-lived signed credential issued by the control
  plane authorizing a gateway session.
- **Resume token** — opaque, scoped, expiring credential authorizing
  reattachment to a specific shell. Distinct from the shell ID and from the
  connection grant.

Integers on the wire are protobuf varints unless stated otherwise. All text is
UTF-8. Terminal output bytes are opaque `bytes` (raw PTY output, not text).

## 2. Transport model

All clients and servers program against this abstraction:

```text
Transport:
    open_reliable_stream()   -> bidirectional ordered byte stream
    accept_reliable_stream() -> bidirectional ordered byte stream
    send_datagram(bytes)     -> may fail Unsupported
    receive_datagram()       -> may fail Unsupported
    close(code, reason)
```

Mappings:

- **Native QUIC / WebTransport**: streams map to QUIC/WebTransport bidirectional
  streams; datagrams map to QUIC/WebTransport datagrams.
- **WebSocket fallback**: exactly one WebSocket connection emulates all channels.
  Each frame defined in §3 is wrapped in a binary WebSocket message prefixed with
  an unsigned-LEB128 varint `channel_id`. Channel 0 is the control channel.
  Channels are allocated implicitly, mirroring QUIC stream opening: the client
  opens a channel by sending its first frame on an unused odd `channel_id`
  (1, 3, 5, …); even non-zero IDs are reserved for server-initiated channels
  (unused in v0). A frame on an unknown even channel, or a reused closed
  channel, is a protocol error. Datagram operations report Unsupported; the
  application stays on reliable screen updates. Logical protocol semantics,
  message types and IDs are identical.

Stream-open may fail at any time (browser or QUIC limits). Clients must treat
stream-open failure as a recoverable error, not a protocol violation. The
gateway enforces its own per-user limits (§8) regardless of transport limits.

### Channel roles

- **Control channel** — the first bidirectional stream opened by the client
  after transport establishment. Carries negotiation, authentication, shell
  lifecycle, and any message not bound to a live attachment.
- **Attachment stream** — one bidirectional stream per attached shell, opened by
  the client, beginning with `AttachShell`. Carries that shell's input, output,
  resize and history messages.
- **Datagrams (optional)** — screen snapshots/deltas and revision acks only
  (§7). Never input, never authentication, never history.

## 3. Framing

Every message on a reliable stream is framed as:

```text
frame = length | payload
length  : u32, big-endian, byte length of payload
payload : one protobuf-encoded Envelope message
```

- `MAX_FRAME_BYTES` is negotiated (§4); the protocol ceiling is 1 MiB, the
  default is 256 KiB. A receiver MUST reject a frame whose length exceeds the
  negotiated maximum *before allocating* the payload buffer, then close the
  stream (attachment streams) or connection (control channel) with
  `ERR_FRAME_TOO_LARGE`.
- Datagrams carry a single protobuf `DatagramEnvelope` with no length prefix
  (the transport delimits them). Maximum datagram size is negotiated and must
  respect the transport's datagram MTU.
- The `Envelope` contains a `oneof` of every message type plus common header
  fields (`request_id`, `server_id`, `shell_id` where applicable). Unknown
  fields are ignored (protobuf default). An `Envelope` whose `oneof` is unset
  or unrecognized is a protocol error: respond `Error{ERR_UNKNOWN_MESSAGE}` and
  close cleanly.

## 4. Version and capability negotiation

The first frame in each direction on the control channel:

```text
client -> ClientHello {
    protocol_major = 0, protocol_minor = 1
    client_kind    (BROWSER_WEBTRANSPORT | BROWSER_WEBSOCKET | NATIVE_QUIC | ADAPTER)
    client_build   (informational string)
    capabilities   (repeated enum: DATAGRAMS, CLIPBOARD, FILE_TRANSFER, ...)
    max_frame_bytes, max_datagram_bytes
    encodings      (repeated; must include UTF8)
}
server -> ServerHello {
    protocol_major, protocol_minor  (selected)
    capabilities                    (intersection actually enabled)
    max_frame_bytes, max_datagram_bytes  (final values = min of both sides, capped)
    keepalive_interval_ms
}
```

Rules:

- Different `protocol_major` → server sends `Error{ERR_VERSION}` then `Close`.
- Minor versions only add optional capabilities; both sides behave as the lower
  minor version.
- A capability is enabled only if both sides listed it. Datagram capability is
  additionally disabled if the transport reports datagrams Unsupported.
- Anything after `ServerHello` and before a successful `Authenticate` exchange
  other than `Authenticate`, `Ping`, `Pong`, `Close` is rejected with
  `ERR_UNAUTHENTICATED`.

## 5. Authentication and authorization

```text
client -> Authenticate { connection_grant }
server -> AuthenticationResult { ok, user_id, expires_at, error? }
```

- Connection grants come from a **pluggable grant issuer**; the terminal
  endpoint (standalone `holdfastd`, or a gateway in the admin overlay) only
  verifies signatures and never needs to call the issuer. Two issuers are
  defined:
  1. **Local issuer (core, default):** the daemon itself authenticates the user
     — initially SSH public-key challenge/response against the target account's
     `authorized_keys` — and issues a grant signed with its own key. This is
     what makes direct browser/native login to a single server work with zero
     central infrastructure.
  2. **Central issuer (admin overlay):** a control plane signs grants with its
     private key; daemons/gateways hold only the verification key. Claims per
     the plan's Connection grants section (subject, audience, allowed server
     IDs/policy, allowed operations, iat/exp, unique token ID).
  For the local issuer, the challenge/response exchange rides in `Authenticate`
  (a small sub-negotiation: request challenge → signed response → grant), so
  the message flow is identical for both issuers from the transport's view.
- Every shell-scoped request is authorized against the authenticated user and
  the grant's scope. Authorization failure is `ERR_FORBIDDEN` and MUST be
  indistinguishable from a nonexistent shell (`ERR_NOT_FOUND` is reserved for
  resources the user could otherwise see) to prevent shell-ID probing.
- When the grant expires, the session enters a drain state: existing attachments
  stay live for a bounded grace period (default 60 s) while the client obtains
  and presents a fresh grant via `Authenticate`; otherwise the server closes.

## 6. Message catalogue (v0)

All messages ride in `Envelope`. Requests carry a client-chosen `request_id`
(u64, unique per session); responses and errors echo it.

| Message | Channel | Direction | Notes |
|---|---|---|---|
| ClientHello / ServerHello | control | c→s / s→c | §4 |
| Authenticate / AuthenticationResult | control | c→s / s→c | §5 |
| ListServers / ServerList | control | c→s / s→c | servers visible under grant |
| ListShells / ShellList | control | c→s / s→c | user's shells, optionally per server |
| OpenShell / ShellOpened | control | c→s / s→c | requires `idempotency_key` (§9) |
| AttachShell / ShellAttached | attachment stream | c→s / s→c | first message on the stream |
| DetachShell | attachment stream | c→s | graceful detach; shell keeps running |
| TerminateShell / ShellExited | control | c→s / s→c | explicit kill; idempotent |
| ShellExited | control + attachment | s→c | also sent unsolicited on process exit |
| TerminalInput | attachment stream | c→s | raw bytes; reliable, ordered |
| TerminalOutput | attachment stream | s→c | raw PTY bytes; reliable, ordered |
| TerminalResize | attachment stream | c→s | cols, rows; coalescible (§9) |
| RequestHistory / HistoryChunk / HistoryEnd | attachment stream | c→s / s→c | §10 |
| ScreenSnapshot / ScreenDelta | datagram (or attachment stream if no datagrams) | s→c | §7 |
| AckScreenRevision | datagram (or attachment stream) | c→s | §7 |
| Ping / Pong | any | both | keepalive, RTT estimate |
| Error | any | both | code, message, echoed request_id |
| Close | control | both | code, reason; last message |

`OpenShell` returns the persistent identity and a resume token:

```text
OpenShell  { server_id, unix_account?, command?, initial_cols, initial_rows,
             idempotency_key }
ShellOpened{ server_id, shell_id, resume_token, expires_policy }
```

`AttachShell` supports both fresh attachments and resumption:

```text
AttachShell   { server_id, shell_id, resume_token, cols, rows,
                last_seen_revision?, last_history_line_id? }
ShellAttached { screen_snapshot, screen_revision, rotated_resume_token,
                oldest_history_line_id, newest_history_line_id }
```

## 7. Screen synchronization

v0 baseline is **reliable output only**: `TerminalOutput` frames on the
attachment stream carry raw PTY bytes; the client's xterm.js (or native
emulator) renders them. This is sufficient for Phases 1–2 and remains the
mandatory fallback forever.

When the DATAGRAMS capability is enabled (Phase 3+ experiment):

- The server may send `ScreenSnapshot { shell_id, revision, packed_screen }` and
  `ScreenDelta { shell_id, revision, base_revision, ops }` as datagrams.
- Clients discard any snapshot/delta whose `revision` ≤ last applied revision,
  and any delta whose `base_revision` ≠ last applied revision (then wait for a
  snapshot).
- Clients periodically send `AckScreenRevision`; the server sends a full
  snapshot at a bounded interval and whenever the acked revision lags too far.
- Losing an old update must never delay a newer one; the server never
  retransmits datagrams.

Datagram mode and reliable `TerminalOutput` are mutually exclusive per
attachment; the mode is fixed at `ShellAttached`.

## 8. Flow control, backpressure and limits

Absolute rule: no unbounded queue anywhere.

- Every per-attachment and per-shell queue has explicit byte AND message limits.
- History transfers rely on stream flow control plus `RequestHistory` paging;
  the server never pushes unrequested history.
- Obsolete `TerminalResize` messages are coalesced: only the newest pending size
  is applied.
- Ordered keyboard input is never dropped silently. If input queues exceed
  limits the server sends `Error{ERR_INPUT_OVERFLOW}` and closes the attachment
  (the shell survives; the client may reattach).
- Output backpressure: if a client cannot drain `TerminalOutput`, the server
  buffers up to the per-attachment bound, then detaches that attachment with
  `ERR_TOO_SLOW`. PTY reads continue into scrollback so the shell is never
  blocked by one slow client; PTY reads pause only when the scrollback writer
  itself is at its bound.
- Default limits (configurable; enforced server-side regardless of transport):

```text
max_shells_per_user            16
max_attachments_per_shell      4       (multi-client attach is an open question;
                                        v0 allows it, revisit in docs/decisions)
max_concurrent_streams/user    64
max_inflight_history_requests  2 per attachment
input queue                    256 KiB or 1024 messages
output queue                   1 MiB per attachment
scrollback ring                100_000 lines or 64 MiB per shell (first hit wins)
```

## 9. Ordering, idempotency and duplicates

- `TerminalInput` is reliable and ordered within its attachment stream.
- `OpenShell` carries a client-generated 128-bit `idempotency_key`. The server
  remembers keys for at least the shell-expiry window; a retry with the same key
  returns the original shell identity instead of creating a duplicate shell.
  The returned resume token is freshly rotated (the server stores only token
  hashes — §12 — so the original token cannot be re-issued); any prior token
  for that shell is thereby invalidated.
- `AttachShell` is safely retryable; a retry supersedes the previous attachment
  on the same stream identity.
- `TerminateShell` is idempotent: terminating an already-exited shell returns
  the recorded exit status.
- Datagrams may be lost, duplicated or reordered; §7 revision rules make this
  safe.

## 10. Scrollback and history

The server maintains, per shell: current visible screen, alternate screen, and
a bounded primary-screen scrollback ring with stable history line IDs.
Alternate-screen output (vim, less, top, tmux) never enters primary scrollback.

```text
RequestHistory { shell_id, before_line_id, maximum_lines, maximum_bytes }
HistoryChunk   { shell_id, first_line_id, lines[], truncated_by_eviction }
HistoryEnd     { shell_id, oldest_available_line_id }
```

- Requests are range-based and paged; the client fetches lazily as the user
  scrolls. Responses never exceed the requested byte/line bounds or the frame
  limit.
- If requested lines were evicted, the response says so explicitly
  (`truncated_by_eviction`) rather than silently returning less.
- v0 reflow policy: history keeps its original wrapping after resize; the
  stored line is the logical line as originally committed. (Recorded decision —
  see docs/decisions.)
- Scrollback lives in memory with the shell and dies with it. Durable recording
  is out of scope for v0 and must never be silently enabled.

## 11. State machines

Shell (server-side, authoritative):

```text
creating → running → { exited | terminating → exited } → expired/deleted
running → unavailable   (fatal agent/backend loss; may recover to running)
```

Attachment:

```text
authorizing → synchronizing → live → { detached | closed }
```

- In `synchronizing` the server sends the coherent screen snapshot + revision;
  client input received before `live` is buffered up to 4 KiB, beyond which it
  is rejected with `ERR_NOT_READY`.
- Detach (stream closes, `DetachShell`, network loss) NEVER kills the shell.
  Only `TerminateShell`, process exit, expiry policy, or admin action ends it.

## 12. Resume tokens

- Issued at `ShellOpened` and rotated at every successful `ShellAttached`.
- Scoped to (user, shell, attachment policy) with an expiry; opaque to clients.
- The server stores only a hash. Presenting an already-rotated token fails with
  `ERR_TOKEN_REPLAYED` and raises an audit event (possible theft).
- Resume tokens are never written to logs, metrics or crash dumps.

## 13. Errors and close codes

`Error { code, human_message, request_id?, retryable }`. Initial code space:

```text
ERR_VERSION, ERR_UNAUTHENTICATED, ERR_FORBIDDEN, ERR_NOT_FOUND,
ERR_FRAME_TOO_LARGE, ERR_UNKNOWN_MESSAGE, ERR_INPUT_OVERFLOW, ERR_TOO_SLOW,
ERR_NOT_READY, ERR_TOKEN_EXPIRED, ERR_TOKEN_REPLAYED, ERR_LIMIT_EXCEEDED,
ERR_SERVER_UNAVAILABLE, ERR_INTERNAL
```

`Close { code, reason }` terminates the session; the server sends it before
closing the transport whenever possible. Shells persist per their expiry policy.

## 14. Keepalive

`Ping`/`Pong` on the control channel at the negotiated interval. Three missed
pongs → the server treats the session as dead, detaches its attachments
(shells keep running) and reclaims connection resources.

## 15. Conformance notes for implementers

- Reject before allocating: length checks precede buffer allocation everywhere.
- The protobuf schema in `messages.proto` is the wire format; Rust structs are
  never serialized directly.
- All timestamps on the wire are Unix milliseconds UTC (`int64`).
- All IDs (`server_id`, `shell_id`, token IDs) are opaque 128-bit values,
  rendered as lowercase hex with a type prefix in logs/UI (`srv_…`, `sh_…`).
  Authorization keys are these opaque IDs, never display names.
