//! Privilege-drop launch construction (threat model T12, the *mechanism* half —
//! ADR 0007).
//!
//! Authorization (which account a user may request) lives in [`crate::policy`].
//! Once an account is resolved, this module builds the argv that actually
//! launches the shell under that account's uid/gid, by wrapping the command in
//! `setpriv(1)` (util-linux): it sets the gid, initializes the account's
//! supplementary groups, sets the uid, and resets the environment — the full,
//! well-audited drop sequence — with no PAM and no password.
//!
//! The drop is only attempted when [`SessionCoreConfig::privilege_drop`] is
//! enabled *and* the resolved account differs from the daemon's own user. When
//! enabled but the switch cannot be performed (account missing, or the daemon
//! lacks the privilege to switch), launching is a hard error — the shell is
//! never silently run under the wrong (more-privileged) account.
//!
//! [`SessionCoreConfig::privilege_drop`]: crate::SessionCoreConfig::privilege_drop

use crate::SessionError;

/// `setpriv` path. Absolute so a hostile `PATH` cannot substitute it.
const SETPRIV: &str = "/usr/bin/setpriv";
/// Fallback shell when the client did not specify a command and we are wrapping
/// (we cannot pass `None`/`$SHELL` through `setpriv`; `$SHELL` would be the
/// daemon user's shell anyway, not the target account's).
const DEFAULT_SHELL: &str = "/bin/bash";

/// A resolved Unix account: its numeric identifiers, kept together so the argv
/// builder cannot mix a uid from one account with a gid from another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountIds {
    pub uid: u32,
    pub gid: u32,
}

/// The concrete program + args to hand to the PTY layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    /// `None` preserves the existing "run the client's command, or `$SHELL`,
    /// as the daemon's own user" behavior; `Some` is a concrete program.
    pub program: Option<String>,
    pub args: Vec<String>,
}

/// Build the `setpriv` wrapper argv for a resolved account. Pure and
/// unit-testable: it never touches the host account database. `program` is the
/// shell/command to run under the target account.
fn setpriv_wrap(ids: AccountIds, program: &str, args: &[String]) -> Launch {
    let mut wrapped = vec![
        "--reuid".to_string(),
        ids.uid.to_string(),
        "--regid".to_string(),
        ids.gid.to_string(),
        // Initialize the target account's supplementary groups (initgroups),
        // so it gains exactly its groups and no others — in particular it does
        // NOT keep the daemon's groups.
        "--init-groups".to_string(),
        // Start from a clean environment for the dropped process.
        "--reset-env".to_string(),
        "--".to_string(),
        program.to_string(),
    ];
    wrapped.extend(args.iter().cloned());
    Launch { program: Some(SETPRIV.to_string()), args: wrapped }
}

/// Resolve a Unix account name to its uid/gid via the host account database
/// (`getpwnam`). Returns [`SessionError::Forbidden`] if the account does not
/// exist — the client must not learn whether an allowed-but-absent account is
/// missing versus merely unauthorized.
fn resolve_account_ids(name: &str) -> Result<AccountIds, SessionError> {
    match nix::unistd::User::from_name(name) {
        Ok(Some(user)) => Ok(AccountIds { uid: user.uid.as_raw(), gid: user.gid.as_raw() }),
        Ok(None) => Err(SessionError::Forbidden),
        Err(e) => Err(SessionError::Internal(format!("account lookup failed: {e}"))),
    }
}

/// The daemon's own effective uid — a switch to the same uid is a no-op we skip.
fn own_uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

/// Decide how to launch a shell for a resolved `account`.
///
/// - `privilege_drop` disabled, or `account` is `None`/self → run directly as
///   the daemon's user (unchanged behavior; the resolved account is still
///   recorded elsewhere for audit).
/// - enabled and the account resolves to a *different* uid → wrap with
///   `setpriv` so the shell runs under that account.
///
/// When wrapping, a missing `setpriv` binary is an [`SessionError::Internal`];
/// a missing account is [`SessionError::Forbidden`]. The caller must treat any
/// error as "do not open the shell" — there is no unprivileged fallback.
pub(crate) fn build_launch(
    privilege_drop: bool,
    account: Option<&str>,
    command: Option<&str>,
    args: &[String],
) -> Result<Launch, SessionError> {
    let account = account.filter(|a| !a.is_empty());
    let wants_switch = privilege_drop && account.is_some();

    if !wants_switch {
        // Direct launch: preserve `None` = `$SHELL` semantics.
        return Ok(Launch { program: command.map(str::to_string), args: args.to_vec() });
    }

    let name = account.unwrap();
    let ids = resolve_account_ids(name)?;
    if ids.uid == own_uid() {
        // Switching to ourselves is a no-op; run directly.
        return Ok(Launch { program: command.map(str::to_string), args: args.to_vec() });
    }

    if !std::path::Path::new(SETPRIV).exists() {
        return Err(SessionError::Internal(format!(
            "privilege drop requested for account {name:?} but {SETPRIV} is not present"
        )));
    }

    let program = command.filter(|c| !c.is_empty()).unwrap_or(DEFAULT_SHELL);
    Ok(setpriv_wrap(ids, program, args))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_launch_when_privilege_drop_disabled() {
        // Even with an account requested, a disabled flag never wraps.
        let l = build_launch(false, Some("someone"), Some("bash"), &["-l".into()]).unwrap();
        assert_eq!(l, Launch { program: Some("bash".into()), args: vec!["-l".into()] });
    }

    #[test]
    fn direct_launch_preserves_none_shell() {
        let l = build_launch(false, None, None, &[]).unwrap();
        assert_eq!(l, Launch { program: None, args: vec![] });
    }

    #[test]
    fn empty_account_is_treated_as_no_switch() {
        let l = build_launch(true, Some(""), Some("bash"), &[]).unwrap();
        assert_eq!(l, Launch { program: Some("bash".into()), args: vec![] });
    }

    #[test]
    fn setpriv_argv_shape_is_correct() {
        // The pure builder: numeric ids, init-groups, reset-env, then command.
        let l = setpriv_wrap(AccountIds { uid: 1001, gid: 2002 }, "/bin/bash", &["-c".into(), "id".into()]);
        assert_eq!(l.program.as_deref(), Some(SETPRIV));
        assert_eq!(
            l.args,
            vec![
                "--reuid", "1001",
                "--regid", "2002",
                "--init-groups",
                "--reset-env",
                "--",
                "/bin/bash",
                "-c", "id",
            ]
        );
    }

    #[test]
    fn setpriv_wrap_defaults_are_absolute_paths() {
        // Guard against a hostile PATH: both the wrapper and the reference to it
        // are absolute.
        assert!(SETPRIV.starts_with('/'));
        assert!(DEFAULT_SHELL.starts_with('/'));
    }

    #[test]
    fn resolve_root_is_zero_zero() {
        // `root` exists on every Unix host and is uid/gid 0 — a stable anchor
        // for the resolver without depending on this host's other accounts.
        assert_eq!(resolve_account_ids("root").unwrap(), AccountIds { uid: 0, gid: 0 });
    }

    #[test]
    fn resolve_missing_account_is_forbidden() {
        let err = resolve_account_ids("definitely-not-a-real-account-xyzzy").unwrap_err();
        assert!(matches!(err, SessionError::Forbidden));
    }

    #[test]
    fn switch_to_self_is_a_noop() {
        // Resolve the daemon's own account by uid and ask to switch to it: the
        // builder must run directly, not wrap.
        let me = nix::unistd::User::from_uid(nix::unistd::geteuid()).unwrap().unwrap();
        let l = build_launch(true, Some(&me.name), Some("bash"), &[]).unwrap();
        assert_eq!(l, Launch { program: Some("bash".into()), args: vec![] });
    }
}
