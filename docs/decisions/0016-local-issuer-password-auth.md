# ADR 0016: opt-in password login in the local issuer (web client)

- Status: accepted
- Date: 2026-07-22
- Relates to ADRs 0006, 0007, 0015; threat model T13
- Extends the spec §5 local issuer

## Context

ADR 0015 added opt-in PAM password authentication to the loopback SSH
compatibility adapter. The same capability was requested for the browser
client, whose only interactive login was the SSH challenge/response flow —
secure, but demanding: the user must hold a provisioned key and run
`ssh-keygen -Y sign` in a second terminal. The password in this flow crosses
the network (inside the encrypted transport), unlike the adapter's loopback
case, so it is a separate decision rather than a footnote to 0015.

## Decision

`Authenticate` gains a fourth method, `PasswordRequest { username, password }`
(single round trip; on success the `AuthenticationResult` carries an issued
grant exactly like the SSH challenge path, so everything downstream — grant
storage, reconnect, scoping, expiry — is unchanged).

Daemon side:

- **Off by default and explicitly allowlisted.** `DaemonConfig.password_auth`
  names the permitted users and carries a `PasswordVerifier`
  (`hf_auth::password`, shared with the adapter; PAM via `hf_auth::pam` in
  production — `--password-auth <user>` repeatable, `--pam-service NAME`).
  Refused in dev-insecure mode; enabling it without `--ssh-auth` switches the
  daemon onto the real issuer with an empty key set.
- Bounds and the allowlist run **before** the verifier (username ≤ 128 bytes,
  password 1..=1024 bytes), so no PAM work is spent on foreign or oversized
  input; every failure collapses into the same "authentication failed" reply
  and counts toward the per-source rate limiter (5 failures/min → 60 s
  lockout). Verification runs on a blocking thread. PAM use remains
  authentication + account checks only — no PAM session, no credentials; the
  ADR 0007 launch path stays PAM-free.
- The audit schema stays content-free: a new `AuthMethod::Password` label is
  recorded, never the password.

Client side: `/webtransport-info` advertises `passwordAuth`; the login dialog
shows a username/password form as the default when offered (the SSH-key flow
remains one click away, and is the only form otherwise). The password is sent
once over the WebTransport session (TLS 1.3 — WebPKI in production, the
hash-pinned development certificate otherwise) and cleared from the form; the
browser stores only the issued grant, as before.

## Privilege reality (deployment)

pam_unix verifies the **calling** user's password via `unix_chkpwd`. The
standalone single-user daemon (running as the account that logs in) therefore
works unprivileged. For a daemon serving password login to *other* users, the
service account needs read access to shadow (e.g. systemd
`SupplementaryGroups=shadow` on Debian) — a deliberate, documented widening;
without it verification fails closed rather than partially succeeding. See
`deploy/pam/README.md`.

## Consequences

- A password is phishable and reusable in ways a signed challenge is not, and
  unlike the SSH path it carries no ADR 0008 channel binding — the trade is
  recorded under threat model T13, and the feature stays opt-in per user.
- Grants issued by password and by key are indistinguishable downstream,
  which keeps the session/authorization layers untouched.
- Tests: end-to-end wire tests with injected verifiers
  (`crates/daemon/tests/auth.rs` — success + grant reconnect, fail-closed
  gating with verifier-call counting, refusal when not configured); the real
  shadow/pam_unix round trip stays under `tests/password-auth/run.sh`.
