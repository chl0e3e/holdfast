# Authorization and privileged-launch tests

This area verifies the deployment-sensitive half of account authorization:
the real `prlimit → setpriv → PTY` exec chain (ADRs 0007 and 0009).

`crates/session-core/tests/privilege_drop.rs` opens a shell as the secondary
`nobody` account and asserts:

- the PTY reports uid 65534 rather than the daemon/root uid;
- hard process, open-file, and core-dump limits survive the uid/gid switch;
- a shell without a requested account stays under the daemon's uid.

The test requires root and is ignored by normal Cargo runs. The wrapper builds
as the current user, then uses passwordless `sudo` only for the test binary:

```bash
tests/authorization/run.sh
```

If passwordless sudo or the secondary account is unavailable, the script skips
with an explicit message. Pure authorization, launcher construction, invalid
limit, and ordinary PTY limit tests always run with:

```bash
cargo test -p hf-session-core
```
