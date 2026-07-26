# ADR 0015: opt-in PAM password authentication in the SSH compatibility adapter

- Status: accepted
- Date: 2026-07-21
- Phase: 8 follow-on
- Relates to ADRs 0007, 0013; threat model T11, T13

## Context

Holdfast authentication is key-only by design: the core daemon and local
issuer verify SSH public-key challenges (ADR 0006), and the compatibility
adapter accepts public-key authentication only (ADR 0013). ADR 0007
additionally keeps the shell-launch path free of PAM so the privilege-drop
sequence stays small and auditable.

Password login was requested for the adapter regardless — for clients where
provisioning a local key is impractical. The question is how to add it without
weakening the rest of the design.

## Decision

The adapter gains an **opt-in** password method, disabled by default and
scoped entirely to `hf-ssh-adapter`:

- `AdapterConfig.password_auth` takes a `PasswordVerifier` (blocking, fail
  closed). Only when set is the SSH `password` method advertised; the default
  and the core daemon, issuer and grants remain key-only.
- The shipped verifier is PAM (`--password-auth [--pam-service NAME]`,
  default service `holdfast-ssh`, example stack in `deploy/pam/`).
  (**Update 2026-07-22:** the verifier now lives in `hf-auth`
  (`crates/auth/src/{password,pam}.rs`), shared with the daemon's web
  password login — ADR 0016.) It is a
  deliberately small hand-written binding over the stable libpam ABI —
  `pam_start → pam_authenticate → pam_acct_mgmt → pam_end` — rather than an
  unmaintained wrapper crate (T11). The conversation answers echo-off prompts
  with the client password and fails closed on any other prompt style, PAM
  error, unknown service (`/etc/pam.d/other` denies) or interior NUL.
- **PAM is used for authentication and account checks only.** No PAM session
  is opened, no credentials are installed, and the ADR 0007 launch path
  (`setpriv`, explicitly no PAM) is untouched.
- Guardrails, all before the verifier runs: the username must equal the
  configured `local_user`; passwords are bounded (`MAX_PASSWORD_BYTES`) and
  non-empty; `PAM_DISALLOW_NULL_AUTHTOK` is set; the PAM service name is
  restricted to a bounded path-safe character set. Every failed attempt —
  password or public-key, whatever the reason — pays russh's constant
  `auth_rejection_time` (`AUTH_REJECTION_DELAY`, 1 s), on top of the existing
  3-attempts-per-connection and bounded-concurrent-connections limits.
- Verification runs on a blocking thread, never on the connection task.

## Consequences

- A password is a weaker, phishable credential; the loopback-only listener
  (ADR 0013) confines the exposure to local processes, and the threat is
  recorded as T13. Deployments that do not pass `--password-auth` are
  byte-for-byte unaffected.
- pam_unix verifies the *calling* user's password via `unix_chkpwd`, so the
  adapter must run as the same Unix account as `--local-user` (the normal
  deployment) — otherwise verification fails closed rather than succeeding
  with lesser checks.
- Account lockout policy (e.g. `pam_faillock`) composes in the PAM stack
  without adapter changes.
- Tests: negotiation, gating and the full password → PTY bridge with an
  injected verifier (`tests/password.rs`); PAM fail-closed unit tests; the
  real shadow/pam_unix round trip needs root and a throwaway account, so it
  is `#[ignore]`d and run via `tests/password-auth/run.sh`.
