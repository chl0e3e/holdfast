# systemd units

Two reference units, matching the two deployment models. Both run the
network-facing daemon as an unprivileged `holdfast` service account — the daemon
is **never** run as root outright.

| Unit | Shells run as | Privilege the daemon holds | Use when |
|------|---------------|----------------------------|----------|
| `holdfastd.service` | the `holdfast` service account | `CAP_NET_BIND_SERVICE` only | one administrator; the standalone case |
| `holdfastd-multiuser.service` | each authenticated user's own account | `CAP_SETUID` + `CAP_SETGID` (+ `CAP_DAC_READ_SEARCH`, `CAP_NET_BIND_SERVICE`) | multiple users with real Unix accounts |

Both units also provide aggregate resource containment (ADR 0009):
`TasksMax=2048`, `MemoryHigh=50%`, and `MemoryMax=75%`. Independently,
`holdfastd` wraps every shell in `/usr/bin/prlimit` with hard inherited defaults
of 512 processes per Unix uid, 1,024 open files per process, and zero-byte core
dumps. Tune the daemon flags and unit values together for the host's workload;
never remove both layers.

## WebTransport certificate

Both reference units expect a publicly trusted chain at
`/etc/holdfast/tls/fullchain.pem` and its private key at
`/etc/holdfast/tls/privkey.pem`. The private key must be readable by the
`holdfast` service account and mode 0600 or stricter; the directory should not
be writable by that account. Copy renewed ACME output into those paths
atomically and restart the service:

```bash
sudo systemctl restart holdfastd
```

The browser uses ordinary WebPKI for this configured identity. The generated
hash-pinned identity is deliberately restricted to loopback development.

## The privilege model (multi-user)

Privilege separation for T12 (ADR 0007) has an authorization half and a
mechanism half. The mechanism is `setpriv`: the daemon wraps each shell in
`setpriv --reuid <uid> --regid <gid> --init-groups --inh-caps -all
--ambient-caps -all --reset-env -- <shell>`.

The complete exec chain is `prlimit → setpriv → shell`, so resource limits
are installed before the account switch and remain in force afterward. Both
`prlimit` and `setpriv` are supplied by util-linux and referenced by absolute
path; a missing executable fails shell open rather than bypassing a boundary.

- The daemon does **not** run as root. It is granted `AmbientCapabilities=`
  `CAP_SETUID CAP_SETGID` — exactly enough to change uid/gid, nothing more.
- `--init-groups` gives the shell the target account's supplementary groups and
  none of the daemon's.
- **Capability leak prevention:** ambient capabilities normally survive a
  `setuid`, so a daemon holding `CAP_SETUID` would leak it into the dropped
  shell — which could then switch uid again. The launcher clears the
  inheritable and ambient sets (`--inh-caps -all --ambient-caps -all`) before
  exec, so the shell keeps none of the daemon's capabilities. The capability
  *bounding set* is left intact, so ordinary setuid-root programs (`sudo`,
  `ping`, `passwd`) still work exactly as in a normal SSH login.
- **Fail-closed at every layer:** `--drop-privileges` refuses to start without
  at least one `--account` mapping (otherwise the permissive `AllowAll` policy
  would let any authenticated user request any account). A requested account
  outside a user's allowlist is `ERR_FORBIDDEN`. If the daemon somehow cannot
  perform the switch, `setpriv` aborts before exec'ing the shell — the shell
  never runs under the daemon's identity.

## Why the sandboxing is deliberately modest

A terminal daemon exists to run arbitrary interactive shells, and those shells
are children of the unit — so any sandbox applied to the service also applies to
them. Aggressive systemd hardening that is correct for a typical network daemon
would break ordinary use here:

- **`NoNewPrivileges=yes`** blocks every setuid-root program. Fine for the
  single-user unit (its service account rarely needs `sudo`); **must be off**
  for the multi-user unit, where shells are real logins that expect `sudo`,
  `ping`, etc. — just like an `sshd` session, which also does not set it.
- **`ProtectHome=` / `ProtectSystem=strict`** would hide or freeze the very home
  directories and paths users' shells need. The multi-user unit omits them; host
  protection comes from the minimal capability set instead.
- **`MemoryDenyWriteExecute` / restrictive `SystemCallFilter`** break common
  interpreters and JITs a user may legitimately run.
- **`CapabilityBoundingSet=`** is inherited by every descendant and can never be
  widened again, so a bounding set on a unit that forks shells also applies to
  them: `sudo` still yields uid 0, but without
  `CAP_CHOWN`/`CAP_DAC_OVERRIDE`/`CAP_FOWNER`, so `apt`, `passwd`, `ping` and
  `mount` fail with `EPERM`, and the launcher cannot undo it — the ratchet is
  applied before the daemon ever runs. This is the constraint ADR 0024 removes
  by moving shell launching out of the daemon (see below), which is what lets
  the multi-user unit carry a bounding set again.

Each unit therefore keeps the hardening that does **not** interfere with
interactive shells (kernel-tunable/module protection, address-family and
realtime restriction) and drops the rest.

## The spawner split (ADR 0024)

`holdfastd` does not fork shells. It connects to `holdfast-spawner.socket`, and
systemd — PID 1 — forks one `holdfast-spawner@.service` per connection to do the
launch. Because that helper is a child of PID 1 rather than of the daemon, its
capability bounding set is independent:

| | `holdfastd.service` (multi-user) | `holdfast-spawner@.service` |
|---|---|---|
| Bounding set | `CAP_NET_BIND_SERVICE CAP_DAC_READ_SEARCH` | full (inherited by the shell) |
| Ambient | same two | `CAP_SETUID CAP_SETGID CAP_KILL` |
| Exposed to | the network | a `0600` socket owned by `holdfast` |

The network-facing process is therefore *more* restricted than before the split:
`CAP_SETUID`, `CAP_SETGID` and `CAP_KILL` are no longer in its ambient set at
all. `systemd-run` would have avoided the extra unit, but polkit denies it to an
unprivileged service account, and a polkit rule allowing it would grant more
than the capabilities it replaced.

Authorization is checked on both sides. The daemon applies its `--account`
policy; the spawner independently enforces its own `--allow-account` list,
verifies the peer's uid with `SO_PEERCRED`, and refuses uid 0 outright — so a
compromised daemon still cannot obtain a shell as an arbitrary account. **Keep
the spawner's `--allow-account` flags in step with the daemon's `--account`
mappings**, or shells for the missing accounts fail with `ERR_FORBIDDEN`.

Both units join `holdfast.slice`, which carries the aggregate `TasksMax=` and
memory ceilings (ADR 0009). Those must live on the slice now: the shells are no
longer in the daemon's cgroup, so a `TasksMax=` on the daemon unit would bound
only the daemon.

## Customizing

Replace the example `--ssh-auth`/`--account` pairs, the origin, and the bind
addresses. The daemon owns **UDP** 443 for WebTransport/QUIC; keep nginx (or
another TLS terminator) on **TCP** 443 for the WebSocket fallback and static
assets (see `../nginx/`). Validate a unit before enabling with
`systemd-analyze verify ./holdfastd-multiuser.service` and check the exposure
score with `systemd-analyze security holdfastd`.
