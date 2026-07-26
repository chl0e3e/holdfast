# ADR 0009: Shell resource containment with prlimit + systemd cgroups

Date: 2026-07-18 · Status: accepted and implemented · Relates to threat
model T6

## Decision

Use two complementary Linux boundaries:

1. Every shell launch is wrapped by absolute `/usr/bin/prlimit` before any
   optional `setpriv` uid/gid drop. The hard limits are inherited by the shell
   and every descendant and cannot be raised from inside the shell:

   - `RLIMIT_NPROC=512` (Linux accounts this per real Unix uid),
   - `RLIMIT_NOFILE=1024` per process,
   - `RLIMIT_CORE=0` (no core dumps containing terminal/user secrets).

   The first two values are configurable through `SessionCoreConfig` and the
   daemon flags `--shell-max-processes` / `--shell-max-open-files`; core bytes
   are configurable through `--shell-max-core-bytes`. Process and file limits
   may never be zero. If `prlimit` is absent, opening fails before spawning a
   shell; there is no uncontained fallback.

2. The reference systemd units bound the aggregate daemon cgroup with
   `TasksMax=2048`, `MemoryHigh=50%`, and `MemoryMax=75%`. This contains actual
   aggregate memory and PID consumption, which POSIX rlimits cannot model well
   for an interactive process tree. Percentages scale with host RAM and are
   reference defaults operators may tune deliberately.

## Why this split

`portable-pty` still has no child `pre_exec` hook. A util-linux exec wrapper is
the same small, auditable integration pattern already accepted for privilege
drop in ADR 0007, and limits set outside `setpriv` survive the account switch.

`RLIMIT_NPROC` is deliberately an account boundary, not a shell boundary. A
fork bomb under one Unix account cannot consume unlimited PIDs or prevent a
different account from forking, but multiple Holdfast shells mapped to the
same account share the 512-process budget. This matches Unix authorization;
operators who map many identities to one account should raise the value or use
separate accounts. UID 0 is exempt from `RLIMIT_NPROC`, which is another reason
production units run the daemon unprivileged and drop multi-user shells.

We do **not** set `RLIMIT_AS`: modern runtimes reserve large sparse virtual
address ranges, and a per-process address-space ceiling both breaks legitimate
tools and fails to bound aggregate resident memory. The cgroup memory ceiling
is the correct host-protection mechanism.

## Verification

```bash
cargo test -p hf-session-core
tests/authorization/run.sh
systemd-analyze verify deploy/systemd/holdfastd.service
systemd-analyze verify deploy/systemd/holdfastd-multiuser.service
```

The `systemd-analyze` commands expect `/usr/local/bin/holdfastd` to have been
installed as described by `deploy/systemd/README.md`; on a development checkout
they otherwise report only that expected missing-executable warning.

Coverage includes pure wrapper/validation tests, an ordinary PTY observing the
hard limits through shell builtins, and the rooted uid-switch test confirming
that all three limits survive `prlimit → setpriv → shell`.
