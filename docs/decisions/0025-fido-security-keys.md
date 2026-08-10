# ADR 0025: FIDO security keys authenticate through the existing SSH challenge

- Status: accepted
- Date: 2026-08-10
- Relates to ADRs 0006 (local SSH issuer), 0008 (channel binding), 0016
  (password auth); threat model T10
- No wire change, no new flag, no new dependency on the client

## Context

Holdfast's local issuer authenticates a user by having them sign a
channel-bound nonce with an `authorized_keys` key, as an `SshSig` under the
`holdfast-auth@v0` namespace (ADR 0006/0008). Every credential it accepts is
therefore a file on disk: anything that can read `~/.ssh/id_ed25519` can
authenticate as that user forever, and `--password-auth` deployments (ADR 0016)
are worse still, since the secret is replayable and typed into a browser.

A FIDO security key — a YubiKey — removes that: the private key lives on the
authenticator and cannot be exported, and each signature requires a physical
touch. OpenSSH has supported these as first-class key types since 8.2
(`sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com`).

## Decision

**Support them inside the existing flow rather than adding an authentication
method.** An `sk-*` key is an ordinary `authorized_keys` entry, `ssh-keygen -Y
sign` already drives the authenticator, and the signature is still an `SshSig`
under the same namespace. The wire protocol, the daemon's flags, the browser
login page and the resulting connection grant are all unchanged — nothing
distinguishes a hardware login until the moment of verification.

Three things had to change.

### The verifier enforces user presence

A security-key signature carries a trailer after the signature proper: the
authenticator's flags byte and its counter. The flags byte is folded into the
signed bytes (`sha256(application) || flags || counter || sha256(message)`), so
it cannot be edited after the fact — but `ssh-key` verifies the signature
without ever *looking* at it. That is the verifier's job, and sshd does it too.

`SshVerifier::verify_response` now requires the user-presence bit and returns
`SshError::UserPresenceMissing` without it. This is checked **after** the
cryptographic verification, because before that the flags are attacker-chosen
input.

Failing closed is the only coherent choice here given an existing decision:
OpenSSH spells "this key may sign without a touch" as the `no-touch-required`
option on the `authorized_keys` entry, and `from_authorized_keys` skips *every*
entry carrying options (ADR 0006 — Holdfast cannot honor OpenSSH's
restrictions, so it refuses to guess). A key that opts out of touch therefore
cannot authenticate at all, and every security key that reaches the presence
check is one whose owner intended a touch.

User *verification* (a PIN or biometric, `-O verify-required`) is recorded on
`VerifiedIdentity` and logged, but not required: whether to mandate it is a
per-deployment enrolment decision, not one this issuer can impose on keys it
did not create.

### sk-ecdsa needed a crate feature, not just code

`ssh-key`'s `"ecdsa"` feature brings the ECDSA key *format*; verifying the
NIST P-256 curve needs `"p256"`. Without it `sk-ecdsa-sha2-nistp256@openssh.com`
is rejected as an unsupported algorithm — silently, at the point of login. The
workspace now enables `"p256"`. This matters for reach rather than elegance:
`ed25519-sk` requires YubiKey firmware 5.2.3 or newer, while every FIDO2 key
can do `ecdsa-sk`.

### The native client shells out to sign

`hf` signed challenges in-process with `ssh-key`. It cannot do that for a
security key, whose "private key" file is only a credential handle — the secret
is on the device. For `sk-*` keys the client now runs `ssh-keygen -Y sign`,
which owns the libfido2 plumbing and emits exactly the `SSHSIG` PEM the
protocol already carries. Its stderr is inherited deliberately: that is where
"Confirm user presence for key ..." appears, and a silenced prompt is
indistinguishable from a hang while the daemon waits for a touch that the user
does not know to give.

The browser flow needed no change at all — it already instructs the user to run
`ssh-keygen -Y sign`, which handles security keys natively.

## Consequences

- A YubiKey login is phishing-resistant twice over: the credential cannot be
  copied off the device, and ADR 0008's channel binding is inside the bytes the
  authenticator signs, so a relayed signature still fails.
- Audit records now distinguish hardware from software logins, and note
  whether the human was verified rather than merely present (T10).
- `VerifiedIdentity` gained a field. It is constructed only inside `hf-auth`.
- The native client gained a runtime dependency on `ssh-keygen` — but only on
  the `sk-*` path, and only on the client side.
- Enforcing user presence is stricter than sshd's default, which honors
  `no-touch-required`. Since Holdfast honors no `authorized_keys` options at
  all, no key that works today starts failing.

## Testing

Hardware cannot be a test dependency, so the unit tests in `hf-auth` play the
part of the authenticator: they reproduce the `sk-ssh-ed25519` and `sk-ecdsa`
constructions exactly — including hand-assembling the `SSHSIG` container for
sk-ecdsa, because ssh-key 0.6's *encoder* mishandles that type and would not
survive its own decoder — and cover a touched key, an untouched one, a
user-verified one, channel binding, and a credential scoped to another
application. `crates/auth/tests/security_key_cli.rs` closes the loop against a
real YubiKey; it is opt-in (`HOLDFAST_SECURITY_KEY_TEST=1`) since it needs the
hardware and two touches.
