# Holdfast SSH compatibility adapter

`hf-ssh-adapter` is the optional Phase 8 edge adapter. It lets an unmodified
OpenSSH client open an interactive Holdfast shell through a loopback TCP port:

```text
ssh -> local minimal SSH server -> Holdfast WebTransport/QUIC -> holdfastd PTY
```

The adapter is separate from `holdfastd`. It requires local public-key
authentication because it holds credentials capable of opening remote
Holdfast shells. The configured SSH host key should be persistent so OpenSSH
can remember the adapter identity.

## Run locally

Start a development daemon, then prepare distinct adapter host and local-client
keys:

```bash
cargo run -p hf-daemon -- --bind 127.0.0.1:8080
ssh-keygen -q -t ed25519 -N '' -f /tmp/holdfast-adapter-host
ssh-keygen -q -t ed25519 -N '' -f /tmp/holdfast-adapter-client
cp /tmp/holdfast-adapter-client.pub /tmp/holdfast-adapter-authorized_keys
cargo run -p hf-ssh-adapter -- \
  --listen 127.0.0.1:2222 \
  --url http://127.0.0.1:8080 \
  --local-user adapter \
  --authorized-keys /tmp/holdfast-adapter-authorized_keys \
  --host-key /tmp/holdfast-adapter-host \
  --dev-auth
ssh -p 2222 -i /tmp/holdfast-adapter-client adapter@127.0.0.1
```

For a non-development daemon, replace `--dev-auth` with
`--remote-user USER --remote-key PATH`. The remote key authenticates the
adapter to Holdfast; it is separate from the key that authenticates the local
OpenSSH client to the adapter.

## Optional password authentication (PAM)

Local authentication is public-key only by default. `--password-auth` (ADR
0015) additionally lets the configured `--local-user` log in with their Unix
password, verified through PAM — authentication and account checks only,
never a PAM session:

```bash
sudo install -m 0644 deploy/pam/holdfast-ssh /etc/pam.d/holdfast-ssh
cargo run -p hf-ssh-adapter -- ... --password-auth   # [--pam-service holdfast-ssh]
```

Run the adapter as the same Unix account as `--local-user`: pam_unix verifies
the calling user's own password via `unix_chkpwd`, and any other arrangement
fails closed. Foreign usernames, empty and oversized passwords are rejected
before PAM runs, and every failed attempt pays a constant 1 s rejection delay
on top of the 3-attempts-per-connection limit. Threat model T13 records the
trade-off.

## Deliberate limitations

Only one PTY-backed interactive shell channel is supported per SSH connection.
Remote exec (`ssh host command`), SFTP/SCP, subsystems, environment injection,
port or Unix-socket forwarding, X11 and SSH-agent forwarding are rejected. The
adapter listens only on a loopback address. When the local SSH connection ends,
its Holdfast shell is terminated rather than left as an unmanageable orphan.

Packets, channel windows, internal event queues, pending terminal input,
terminal dimensions, key files and concurrent connections all have explicit
bounds in `src/lib.rs`.

## Verify

The integration suite launches `/usr/bin/ssh` against the adapter and a real
`holdfastd` test instance. It verifies interactive output, local-key rejection
and rejection of remote exec; the password suite drives negotiation, gating
and the full password-authenticated shell with an injected verifier:

```bash
cargo test -p hf-ssh-adapter --test openssh -- --nocapture
cargo test -p hf-ssh-adapter
```

The real shadow/pam_unix round trip needs root and a throwaway account, so it
is `#[ignore]`d and wrapped by:

```bash
tests/password-auth/run.sh
```
