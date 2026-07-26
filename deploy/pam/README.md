# PAM service for Holdfast password authentication

`holdfast-ssh` is the PAM stack consulted by both opt-in password features:
`hf-ssh-adapter --password-auth` (ADR 0015) and the daemon's web/native
password login (`holdfastd --password-auth <user>`, ADR 0016). Install it as:

```bash
sudo install -m 0644 deploy/pam/holdfast-ssh /etc/pam.d/holdfast-ssh
```

Both consumers perform PAM authentication and account checks only — they
never open a PAM session or install credentials, so `session`/`password`
lines are deliberately absent. The shipped file uses Debian-style `@include`
lines; a RHEL-family equivalent is noted inside it.

Notes:

- pam_unix verifies the **calling** user's own password via the
  `unix_chkpwd` helper. Run the adapter as the same Unix account as its
  `--local-user`; likewise the standalone single-user daemon works
  unprivileged when it runs as the account that logs in. A daemon serving
  password login for *other* users needs read access to shadow — on Debian,
  `SupplementaryGroups=shadow` in the systemd unit — a deliberate widening
  to make explicitly. In every other arrangement verification fails closed.
- Without this file, PAM falls back to `/etc/pam.d/other`, which denies —
  password logins fail closed until the service is installed.
- To lock accounts under repeated failure, add `pam_faillock` lines here; the
  adapter already imposes a constant 1 s delay per failed attempt, 3 attempts
  per connection and a bounded connection count, and the daemon rate-limits
  failures per source address with lockout (threat model T13).
- A different stack can be selected with `--pam-service NAME` (the name is
  restricted to a bounded path-safe character set).
