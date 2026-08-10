# ADR 0024: socket-activated shell spawner (shells escape the daemon's bounding set)

- Status: accepted
- Date: 2026-08-10
- Relates to ADRs 0007 (privilege drop), 0009 (containment), 0016 (password
  auth); threat model T12; spec §6
- No wire change; new deployment units and a new `--spawner-socket` flag

## Context

`holdfastd-multiuser.service` carried both
`AmbientCapabilities=CAP_SETUID CAP_SETGID CAP_KILL CAP_NET_BIND_SERVICE
CAP_DAC_READ_SEARCH` and an identical `CapabilityBoundingSet=`. The ambient set
is the daemon's actual privilege and is correct. The bounding set was not: it is
inherited by every descendant and can never be widened again, so it applied to
the shells too. `sudo` still produced uid 0, but a root without `CAP_CHOWN`,
`CAP_DAC_OVERRIDE`, `CAP_FOWNER` or `CAP_AUDIT_WRITE` — which is exactly the
failure reported on odysseus:

```
$ sudo apt-get update
sudo: unable to send audit message: Operation not permitted
... chown ...: Operation not permitted
... rename failed, Permission denied
```

The launcher cannot undo this. `setpriv --inh-caps -all --ambient-caps -all`
clears the inheritable and ambient sets, but nothing can raise a bounding set,
and it is applied by PID 1 before the daemon's first instruction runs. ADR 0007
and `hf-launch` both already state that the bounding set must be left intact so
ordinary setuid-root programs work as in a normal login shell.

That left an unpleasant choice: a working `sudo` **or** a bounded daemon. The
line was removed first (restoring working shells), which is what this ADR
replaces with a design that gives both.

Two options were rejected:

- **`systemd-run --uid=<acct> --pty`.** Forking from PID 1 is the right idea,
  but the daemon runs as the unprivileged `holdfast` account and polkit denies
  it: `Failed to start transient service unit: Interactive authentication
  required`. A polkit rule permitting it cannot be scoped to non-root uids at
  the `manage-units` action level, so it would grant *more* privilege than the
  `CAP_SETUID`/`CAP_SETGID` pair it was meant to replace.
- **A widened bounding set** listing what shells actually need. To keep `sudo`
  usable it must include `CAP_DAC_OVERRIDE`, `CAP_CHOWN` and `CAP_FOWNER`, which
  is near-root anyway; and dropping `CAP_SYS_ADMIN`/`CAP_NET_ADMIN`/
  `CAP_SYS_PTRACE` would break docker and debuggers on a development host.

## Decision

**Shells stop being descendants of the daemon.**

`holdfast-spawner.socket` is a `SOCK_SEQPACKET` unix socket with `Accept=yes`.
The daemon connects once per shell; systemd forks one
`holdfast-spawner@.service` instance per connection, with the accepted
connection as its stdin. Because PID 1 forks it, its capability bounding set
comes from its own unit and is unrelated to the daemon's.

- **`holdfastd.service`** keeps `CAP_NET_BIND_SERVICE` and
  `CAP_DAC_READ_SEARCH` in *both* the ambient and bounding sets. This is
  strictly tighter than before the split: `CAP_SETUID`, `CAP_SETGID` and
  `CAP_KILL` are gone from the network-facing process entirely.
- **`holdfast-spawner@.service`** has no `CapabilityBoundingSet=` (the shell
  inherits it, and it must stay full) and ambient
  `CAP_SETUID CAP_SETGID CAP_KILL`. `CAP_KILL` is required because being a
  shell's parent does not grant the right to signal it once it has changed uid.
- Both join **`holdfast.slice`**, which now carries the aggregate `TasksMax=`
  and memory ceilings. ADR 0009's containment was expressed as `TasksMax=` on
  the daemon unit; with shells in sibling cgroups that would have silently
  stopped bounding them.

### Protocol

One connection per shell, alive for the shell's lifetime. `SOCK_SEQPACKET` gives
datagram boundaries, so no length framing, and carries `SCM_RIGHTS`:

1. daemon → `SpawnRequest { account, command, args, cols, rows, limits }`
2. spawner → `SpawnReply::Spawned { pid }` **+ the PTY master fd**, or
   `SpawnReply::Error { message, forbidden }`
3. daemon → `DaemonMsg::Kill` (terminate)
4. spawner → `SpawnerMsg::Exited { success, exit_code }`, then exits

The daemon keeps the master fd and drives it exactly as before
(`PtyProcess::adopt`); only `wait`/`try_wait`/`kill` travel over the socket,
because the shell is no longer its child to reap.

**Losing the connection kills the shell.** Shell state lives in the daemon's
memory, so a daemon that died has already forgotten its shells; killing them
prevents a restart from stranding unreachable processes. This is a deliberate
change from the previous behaviour, where a dying daemon left orphans running.

### The spawner does not trust the daemon

Authorization is enforced twice. The daemon applies its `--account` policy as
before; the spawner independently:

- requires the account to appear in its own `--allow-account` list,
- verifies the peer's uid via `SO_PEERCRED` (`--peer-user holdfast`), on top of
  the socket's `0600` ownership,
- refuses uid 0 outright, even if root were allowlisted by mistake.

So a compromised daemon can still only reach accounts the deployment already
exposes over the network. `SpawnReply::Error { forbidden: true }` maps back onto
`SessionError::Forbidden`, keeping the T2 property that a client cannot
distinguish an absent account from an unauthorized one.

### Structure

`launch.rs` moved out of `hf-session-core` into its own `hf-launch` crate: the
daemon and the privileged helper build the same `setpriv`/`prlimit` argv, and
the helper must not pull in the PTY, terminal-model and networking dependencies
to do it.

`--spawner-socket <path>` selects the new path and **requires**
`--drop-privileges`; the daemon refuses to start otherwise rather than silently
falling back to in-process launching, which would hand every shell the daemon's
own tight bounding set. Without the flag, behaviour is unchanged — the
single-user unit and the whole test suite still fork shells in process.

## Consequences

- `sudo apt-get update` works from a served shell again, with the daemon bounded.
- One more privileged component to audit — though it is ~250 lines, reads only
  from a `0600` socket, and re-checks every authorization decision.
- A per-shell helper process (~1 MB RSS) for the shell's lifetime.
- Deployment gains three files (`holdfast.slice`, `holdfast-spawner.socket`,
  `holdfast-spawner@.service`) and one binary. The spawner's `--allow-account`
  list must be kept in step with the daemon's `--account` mappings.

## What this does not fix

On a host where a served account can reach root anyway, the bounding set is not
what stands between an attacker and the machine. odysseus is such a host:
`development` has `(ALL) NOPASSWD: ALL` in sudoers *and* is offered over
`--password-auth` on a public address, so a daemon compromise reaches root
through a legitimately requested shell no matter how tightly this unit is
bounded. The split is worth having — it shrinks what the network-facing process
can do on its own — but the sudoers configuration is the larger lever and is
tracked separately.
