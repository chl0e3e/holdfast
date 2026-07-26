# Holdfast protocol specification

```text
Protocol version: 0.1 (draft)
Status: Phase 0 draft — normative once Phase 1 begins; every change to this
        document must ship with the matching change to messages.proto
Last updated: 2026-07-18
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
- The local issuer MAY additionally accept `Authenticate { password_request }`
  (ADR 0016): a single round trip carrying `username` + `password`, verified
  locally (PAM) and answered with the same issued grant as the SSH path.
  Password login is **off by default**, per-username allowlisted, and bounded
  (`MAX_USERNAME_BYTES` = 128, `MAX_PASSWORD_BYTES` = 1024; empty values
  rejected). Servers MUST NOT advertise or accept it in dev-insecure mode,
  MUST subject failures to the same rate limiting as other methods, and MUST
  never log or audit the password itself. It only ever rides the encrypted
  transport; whether it is offered is advertised to the browser client via
  `passwordAuth` in `/webtransport-info`.
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
- Expiry policy: an operator-configured idle TTL may reap shells that sit
  with zero attachments past the TTL (ADR 0021). Disabled by default; when a
  shell is reaped the server records a distinct expiry audit event.

## 12. Resume tokens

- Issued at `ShellOpened` and rotated at every successful `ShellAttached`.
- Scoped to (user, shell, attachment policy) with an expiry; opaque to clients.
- The server stores only a hash. Presenting an already-rotated token fails with
  `ERR_TOKEN_REPLAYED` and raises an audit event (possible theft). Replay
  detection covers the last 64 superseded tokens per shell (bounded ring);
  anything older — or never valid — reports `ERR_TOKEN_EXPIRED`.
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

## 16. Managed-server agent link (overlay extension)

The optional administration overlay connects a managed server to a gateway on
a **separate outbound raw-QUIC connection** using ALPN `holdfast-agent/0`. This
link is not a client session, is never accepted by standalone daemon listeners,
and does not change the core daemon's ability to operate without a gateway.

TLS is mutual. The gateway validates the agent certificate against its agent CA
and maps the SHA-256 fingerprint of the presented leaf certificate to exactly
one stable 128-bit `server_id` in its local registry. A certificate may never
answer for another server. Rotation is an overlap operation: the registry may
map a bounded set of old and next leaf fingerprints to the same `server_id`.

The agent opens the first bidirectional stream and sends one length-prefixed
protobuf `AgentEnvelope` containing:

```text
AgentRegister {
    protocol_major, protocol_minor
    server_id, agent_build, max_frame_bytes
}
```

The gateway compares `server_id` with the identity selected by the authenticated
leaf certificate. A mismatch or unregistered certificate is rejected and the
connection is closed. A successful response is:

```text
AgentRegistration {
    accepted = true, server_id
    max_frame_bytes, keepalive_interval_ms
}
```

Agent control framing is `u32 big-endian length | AgentEnvelope`, with a hard
16 KiB ceiling. The receiver rejects an oversized length before allocating the
payload. `agent_build` is informational UTF-8 and limited to 128 encoded bytes.
The valid range is 1–16 KiB; the negotiated frame maximum is the lower valid
peer value, never above 16 KiB.
`AgentPing`/`AgentPong` provide bounded link liveness. Terminal data never uses
this control stream.

After registration, the gateway may request a local shell on the same control
stream:

```text
AgentOpenShell {
    user_id, unix_account, command
    initial_cols, initial_rows, idempotency_key, connection_grant
}
AgentShellOpened { shell_id, reused }
```

The envelope carries the request ID and authenticated `server_id`; the agent
rejects any other server identity. `user_id` and `unix_account` are each capped
at 128 encoded bytes, `command` at 4 KiB, and `idempotency_key` is exactly 16
bytes. The agent passes the request through its local `AccessPolicy` and the
same bounded `ShellManager`/privileged launcher used by standalone mode. A
denial is an `agent_error` with `ERR_FORBIDDEN`; limits and launch failures use
their existing v0 error codes. Retrying the same owner/key after link recovery
returns the same live `shell_id` with `reused=true`. The gateway link never owns
the shell, so connection loss does not terminate it.

The connection grant is capped at 8 KiB and is verified by the agent, not
trusted merely because the gateway has mTLS access. Its signature/time window,
configured gateway audience (capped at 256 bytes), explicit `server_id` scope,
`open` operation, and `sub == user_id` must all pass before local account policy
is evaluated. Invalid signatures/expiry are `ERR_UNAUTHENTICATED`; subject,
operation, audience, or server-scope failures are `ERR_FORBIDDEN`. Thus a stolen
gateway certificate alone cannot invent a user or broaden a captured grant.

This control operation intentionally does not carry terminal bytes or a client
resume token.

For each live attachment, the gateway opens a new bidirectional QUIC stream.
The first frame is an `AgentEnvelope` scoped to the authenticated `server_id`
and requested `shell_id`:

```text
AgentAttachShell { user_id, connection_grant, cols, rows }
AgentShellAttached {
    screen_snapshot, screen_revision
    oldest_history_line_id, newest_history_line_id
}
```

The agent independently verifies signature/time, configured audience, explicit
server scope, `attach` operation and `sub == user_id`, then checks that the
local shell belongs to that user. Ownership mismatch is indistinguishable from
an unknown shell. The gateway never receives the managed daemon's local resume
token; the future client-facing gateway layer owns its own client resume-token
boundary. Grant expiry closes this attachment stream; the shell survives and a
fresh grant may create a new attachment.

After `AgentShellAttached`, the stream carries the existing explicit protobuf
messages `TerminalInput`, `TerminalOutput`, `TerminalResize`, `DetachShell`,
`RequestHistory`, `HistoryChunk`, `HistoryEnd`, `ShellExited`, and `Error`
inside `AgentEnvelope`. Every frame repeats the exact `server_id` and
`shell_id`; a mismatch closes only that attachment. Input and output remain
reliable and ordered. Stream EOF, reset, `DetachShell`, grant expiry, output
backpressure or protocol failure detaches without terminating the shell.

Agent attachment framing uses the same `u32 big-endian length | AgentEnvelope`
shape with a separate fixed 256 KiB ceiling. Length is rejected before payload
allocation. One connection permits at most 64 gateway-opened attachment
streams in addition to its agent-opened control stream. Per-stream QUIC receive
flow control is 256 KiB and the aggregate connection send/receive window is
16 MiB. Raw input is capped at
64 KiB per frame and processed directly without an application queue. PTY
output chunks remain capped at 8 KiB; the bridge into an async QUIC writer is
bounded to 64 messages / 512 KiB, in addition to session-core's bounded
per-attachment queue. History is sequential (one request in flight), capped at
10,000 lines and half the attachment frame limit in requested bytes, so its
response always fits. Multiple simultaneous attachments to one shell remain
bounded by `max_attachments_per_shell` (default 4); ADR 0012 records that v0
policy.
