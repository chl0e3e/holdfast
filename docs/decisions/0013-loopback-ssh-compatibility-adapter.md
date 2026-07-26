# ADR 0013: terminate a minimal SSH server in the loopback compatibility adapter

- Status: accepted
- Date: 2026-07-18
- Phase: 8

## Context

An unmodified OpenSSH client speaks SSH over TCP, while Holdfast exposes its
terminal protocol over WebTransport/QUIC. A byte-for-byte TCP-to-QUIC tunnel
would only help if the remote endpoint were an SSH server. `holdfastd` is not,
and making it one would duplicate authentication and channel semantics in the
core daemon. It would also hide PTY output from Holdfast if the encrypted SSH
stream continued to another `sshd`, preventing screen and scrollback recovery.

The adapter runs on the user's machine and is optional. It receives credentials
that can open remote Holdfast shells, so accepting unauthenticated local TCP
connections would let another local process use those credentials.

## Decision

`hf-ssh-adapter` terminates a small SSH server on a loopback TCP address and
translates one accepted SSH PTY shell channel into one Holdfast shell and
attachment. It is a compatibility edge component, not part of `holdfastd`.

The adapter:

- refuses non-loopback listen addresses;
- requires a persistent SSH host private key and a local `authorized_keys`
  allowlist;
- accepts public-key authentication only and requires the configured local
  username (**update 2026-07-21:** ADR 0015 adds an opt-in PAM password mode;
  the default remains public-key only);
- skips option-bearing `authorized_keys` entries because it cannot faithfully
  implement OpenSSH per-key restrictions;
- accepts at most one SSH session channel and one shell request per TCP
  connection;
- supports PTY allocation, interactive shell data and terminal resize only;
- rejects exec, subsystem/SFTP, environment, X11, agent and TCP/Unix forwarding
  requests;
- bounds concurrent TCP connections, SSH packets and windows, pending terminal
  input and internal event queues; and
- terminates the Holdfast shell when its owning local SSH connection ends. An
  SSH client has no Holdfast shell ID or resume token with which to manage an
  orphan later.

The adapter authenticates separately in both directions. The local OpenSSH key
authorizes use of the adapter; the adapter's configured Holdfast grant or SSH
key authorizes the remote account. Local usernames are not forwarded as Unix
account selections.

## Consequences

Existing `ssh -p <port> <local-user>@127.0.0.1` clients can use an interactive
Holdfast-backed terminal. Holdfast retains visibility of terminal output, so
its normal bounded screen and scrollback model still applies.

This is intentionally not a general SSH server. `scp`, SFTP, port forwarding,
X11 forwarding, agent forwarding and `ssh host command` are unsupported. The
local TCP connection itself cannot roam between client devices. A later adapter
revision may reconnect its backend attachment after transient QUIC failure, but
it must retain the same bounds and rotate the resume token on every successful
reattachment.

Keeping SSH parsing in the optional adapter preserves the core dependency
direction and keeps the standalone daemon's direct browser/native login model
independent of SSH compatibility.
