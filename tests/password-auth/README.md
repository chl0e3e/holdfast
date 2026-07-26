# PAM password-authentication tests

This area verifies the deployment-sensitive half of ADRs 0015/0016: the real
PAM round trip through shadow/pam_unix, using the same `PamVerifier` that the
SSH compatibility adapter and the daemon's local issuer (web password login)
run in production.

`crates/auth/src/pam.rs` (`real_account_round_trip`, `#[ignore]`d)
asserts, against a throwaway local account:

- the correct password authenticates;
- a wrong password and an empty password are rejected.

The wrapper builds as the current user, then uses passwordless `sudo` to
create the account, install `/etc/pam.d/holdfast-ssh` from `deploy/pam/` if
absent, run the test binary as root, and remove both again:

```bash
tests/password-auth/run.sh
```

If passwordless sudo is unavailable, the script skips with an explicit
message. Negotiation, gating, constant-delay rejection and the full
password-authenticated shell bridge run without root via injected verifiers,
alongside the PAM fail-closed unit tests:

```bash
cargo test -p hf-auth            # PAM fail-closed + service-name validation
cargo test -p hf-ssh-adapter     # adapter password path (ADR 0015)
cargo test -p hf-daemon --test auth  # web/daemon password login (ADR 0016)
```
