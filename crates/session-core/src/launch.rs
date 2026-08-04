//! Resource-limited and privilege-dropped launch construction (threat models
//! T6/T12; ADRs 0009 and 0007).
//!
//! Authorization (which account a user may request) lives in [`crate::policy`].
//! Once an account is resolved, this module builds the argv that actually
//! launches the shell under that account's uid/gid, by wrapping the command in
//! `setpriv(1)` (util-linux): it sets the gid, initializes the account's
//! supplementary groups, sets the uid, and resets the environment — the full,
//! well-audited drop sequence — with no PAM and no password.
//!
//! Every shell first receives hard process/file/core limits through
//! `/usr/bin/prlimit`. The uid/gid drop is only attempted when
//! [`SessionCoreConfig::privilege_drop`] is enabled *and* the resolved account
//! differs from the daemon's own user. It is fail-closed in two layers, so the
//! shell is never silently run under the wrong (more-privileged) account:
//!
//! - **At build time** (here): invalid limits, a missing account, or an absent
//!   `prlimit`/`setpriv` binary is an error before any process is spawned.
//! - **At exec time** (`setpriv` itself): if the daemon lacks the privilege to
//!   switch, `setpriv` performs the uid/gid change *before* exec'ing the shell
//!   and aborts with a non-zero status when it fails — it never execs the shell
//!   under the daemon's identity. The shell therefore fails to start rather
//!   than running unprivileged-fallback as the daemon's user.
//!
//! [`SessionCoreConfig::privilege_drop`]: crate::SessionCoreConfig::privilege_drop

use crate::{SessionError, ShellResourceLimits};

/// `setpriv` path. Absolute so a hostile `PATH` cannot substitute it.
const SETPRIV: &str = "/usr/bin/setpriv";
/// `prlimit` path (util-linux). Absolute for the same reason as `setpriv`.
const PRLIMIT: &str = "/usr/bin/prlimit";
/// `env` path (coreutils), used to re-establish a locale after
/// `setpriv --reset-env` scrubs the environment. Absolute like the others.
const ENV: &str = "/usr/bin/env";
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

/// Locale variables the dropped shell must keep. `setpriv --reset-env` scrubs
/// the environment down to TERM/HOME/SHELL/USER/LOGNAME/PATH — without a
/// locale the shell runs under POSIX/ASCII, and locale-aware programs replace
/// every non-ASCII character with `?` (e.g. `screen -x` opens an ASCII display
/// and transcodes a UTF-8 weechat to `?` per emoji). Forward the daemon's own
/// LANG/LC_ALL/LC_CTYPE; if it has none, fall back to C.UTF-8, which glibc
/// ships without locale generation.
fn locale_env() -> Vec<String> {
    let kept: Vec<String> = ["LANG", "LC_ALL", "LC_CTYPE"]
        .iter()
        .filter_map(|key| std::env::var(key).ok().map(|value| format!("{key}={value}")))
        .collect();
    if kept.is_empty() {
        vec!["LANG=C.UTF-8".to_string()]
    } else {
        kept
    }
}

/// Build the `setpriv` wrapper argv for a resolved account. Pure and
/// unit-testable: it never touches the host account database. `program` is the
/// shell/command to run under the target account; `locale` is the list of
/// `KEY=value` locale assignments re-injected via `env(1)` after the reset
/// (empty = no `env` wrapper).
fn setpriv_wrap(ids: AccountIds, locale: &[String], program: &str, args: &[String]) -> Launch {
    let mut wrapped = vec![
        "--reuid".to_string(),
        ids.uid.to_string(),
        "--regid".to_string(),
        ids.gid.to_string(),
        // Initialize the target account's supplementary groups (initgroups),
        // so it gains exactly its groups and no others — in particular it does
        // NOT keep the daemon's groups.
        "--init-groups".to_string(),
        // Clear inheritable and ambient capabilities before exec. This matters
        // in the recommended non-root deployment where the daemon itself holds
        // AmbientCapabilities=CAP_SETUID CAP_SETGID to perform the switch:
        // ambient capabilities survive setuid, so without this the dropped
        // shell would inherit CAP_SETUID and could switch back to another uid.
        // The capability *bounding set* is deliberately left intact so ordinary
        // setuid-root programs (sudo, ping, su) work as in a normal login shell.
        // When the daemon runs as root these sets are already empty, so this is
        // a harmless no-op there.
        "--inh-caps".to_string(),
        "-all".to_string(),
        "--ambient-caps".to_string(),
        "-all".to_string(),
        // Start from a clean environment for the dropped process.
        "--reset-env".to_string(),
        "--".to_string(),
    ];
    if !locale.is_empty() {
        wrapped.push(ENV.to_string());
        wrapped.extend(locale.iter().cloned());
    }
    wrapped.push(program.to_string());
    wrapped.extend(args.iter().cloned());
    Launch {
        program: Some(SETPRIV.to_string()),
        args: wrapped,
    }
}

/// Apply hard inherited limits to a concrete launch. `prlimit` runs before a
/// possible `setpriv`, so the limits survive the uid/gid switch and cannot be
/// raised by the shell or its descendants.
fn prlimit_wrap(limits: ShellResourceLimits, launch: Launch) -> Launch {
    let program = launch
        .program
        .expect("resource limiting requires a concrete program");
    let mut args = vec![
        format!("--nproc={0}:{0}", limits.max_processes),
        format!("--nofile={0}:{0}", limits.max_open_files),
        format!("--core={0}:{0}", limits.max_core_bytes),
        "--".to_string(),
        program,
    ];
    args.extend(launch.args);
    Launch {
        program: Some(PRLIMIT.to_string()),
        args,
    }
}

/// Resolve a Unix account name to its uid/gid via the host account database
/// (`getpwnam`). Returns [`SessionError::Forbidden`] if the account does not
/// exist — the client must not learn whether an allowed-but-absent account is
/// missing versus merely unauthorized.
fn resolve_account_ids(name: &str) -> Result<AccountIds, SessionError> {
    match nix::unistd::User::from_name(name) {
        Ok(Some(user)) => Ok(AccountIds {
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
        }),
        Ok(None) => Err(SessionError::Forbidden),
        Err(e) => Err(SessionError::Internal(format!(
            "account lookup failed: {e}"
        ))),
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
    limits: ShellResourceLimits,
    account: Option<&str>,
    command: Option<&str>,
    args: &[String],
) -> Result<Launch, SessionError> {
    if limits.max_processes == 0 || limits.max_open_files == 0 {
        return Err(SessionError::Internal(
            "shell process and open-file limits must be greater than zero".into(),
        ));
    }
    if !std::path::Path::new(PRLIMIT).exists() {
        return Err(SessionError::Internal(format!(
            "shell resource limits require {PRLIMIT}, but it is not present"
        )));
    }

    let account = account.filter(|a| !a.is_empty());
    let wants_switch = privilege_drop && account.is_some();

    if !wants_switch {
        let program = command
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or_else(|| std::env::var("SHELL").ok())
            .unwrap_or_else(|| DEFAULT_SHELL.to_string());
        return Ok(prlimit_wrap(
            limits,
            Launch {
                program: Some(program),
                args: args.to_vec(),
            },
        ));
    }

    let name = account.unwrap();
    let ids = resolve_account_ids(name)?;
    if ids.uid == own_uid() {
        // Switching to ourselves is a no-op, but resource limits still apply.
        let program = command
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or_else(|| std::env::var("SHELL").ok())
            .unwrap_or_else(|| DEFAULT_SHELL.to_string());
        return Ok(prlimit_wrap(
            limits,
            Launch {
                program: Some(program),
                args: args.to_vec(),
            },
        ));
    }

    if !std::path::Path::new(SETPRIV).exists() {
        return Err(SessionError::Internal(format!(
            "privilege drop requested for account {name:?} but {SETPRIV} is not present"
        )));
    }

    let program = command.filter(|c| !c.is_empty()).unwrap_or(DEFAULT_SHELL);
    // Missing env(1) only costs the locale re-injection, never the shell.
    let locale = if std::path::Path::new(ENV).exists() {
        locale_env()
    } else {
        Vec::new()
    };
    Ok(prlimit_wrap(limits, setpriv_wrap(ids, &locale, program, args)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> ShellResourceLimits {
        ShellResourceLimits {
            max_processes: 32,
            max_open_files: 64,
            max_core_bytes: 0,
        }
    }

    #[test]
    fn direct_launch_when_privilege_drop_disabled() {
        // Account switching is disabled, but the resource wrapper is mandatory.
        let l = build_launch(
            false,
            limits(),
            Some("someone"),
            Some("bash"),
            &["-l".into()],
        )
        .unwrap();
        assert_eq!(l.program.as_deref(), Some(PRLIMIT));
        assert_eq!(
            l.args,
            vec![
                "--nproc=32:32",
                "--nofile=64:64",
                "--core=0:0",
                "--",
                "bash",
                "-l"
            ]
        );
    }

    #[test]
    fn default_shell_is_concrete_inside_resource_wrapper() {
        let l = build_launch(false, limits(), None, None, &[]).unwrap();
        let expected = std::env::var("SHELL").unwrap_or_else(|_| DEFAULT_SHELL.to_string());
        assert_eq!(l.program.as_deref(), Some(PRLIMIT));
        assert_eq!(l.args.last(), Some(&expected));
    }

    #[test]
    fn empty_account_is_treated_as_no_switch() {
        let l = build_launch(true, limits(), Some(""), Some("bash"), &[]).unwrap();
        assert_eq!(l.program.as_deref(), Some(PRLIMIT));
        assert_eq!(l.args.last().map(String::as_str), Some("bash"));
    }

    #[test]
    fn setpriv_argv_shape_is_correct() {
        // The pure builder: numeric ids, init-groups, reset-env, then command.
        let l = setpriv_wrap(
            AccountIds {
                uid: 1001,
                gid: 2002,
            },
            &[],
            "/bin/bash",
            &["-c".into(), "id".into()],
        );
        assert_eq!(l.program.as_deref(), Some(SETPRIV));
        assert_eq!(
            l.args,
            vec![
                "--reuid",
                "1001",
                "--regid",
                "2002",
                "--init-groups",
                "--inh-caps",
                "-all",
                "--ambient-caps",
                "-all",
                "--reset-env",
                "--",
                "/bin/bash",
                "-c",
                "id",
            ]
        );
    }

    #[test]
    fn setpriv_reinjects_locale_via_env_wrapper() {
        // --reset-env scrubs LANG; the env(1) shim must restore it between the
        // `--` separator and the command so the shell is not left in the POSIX
        // (ASCII) locale, where screen/ncurses render non-ASCII as `?`.
        let l = setpriv_wrap(
            AccountIds {
                uid: 1001,
                gid: 2002,
            },
            &["LANG=C.UTF-8".to_string()],
            "/bin/bash",
            &[],
        );
        let args: Vec<&str> = l.args.iter().map(String::as_str).collect();
        let sep = args.iter().position(|a| *a == "--").unwrap();
        assert_eq!(&args[sep..], ["--", ENV, "LANG=C.UTF-8", "/bin/bash"]);
    }

    #[test]
    fn locale_env_never_empty() {
        // Whatever the daemon's own environment, the dropped shell always gets
        // at least one locale assignment (C.UTF-8 needs no locale generation).
        let vars = locale_env();
        assert!(!vars.is_empty());
        assert!(vars.iter().all(|v| {
            v.starts_with("LANG=") || v.starts_with("LC_ALL=") || v.starts_with("LC_CTYPE=")
        }));
    }

    #[test]
    fn setpriv_wrap_defaults_are_absolute_paths() {
        // Guard against a hostile PATH: both the wrapper and the reference to it
        // are absolute.
        assert!(SETPRIV.starts_with('/'));
        assert!(PRLIMIT.starts_with('/'));
        assert!(ENV.starts_with('/'));
        assert!(DEFAULT_SHELL.starts_with('/'));
    }

    #[test]
    fn zero_process_or_file_limit_is_rejected() {
        let mut invalid = limits();
        invalid.max_processes = 0;
        assert!(matches!(
            build_launch(false, invalid, None, Some("bash"), &[]),
            Err(SessionError::Internal(_))
        ));
        invalid = limits();
        invalid.max_open_files = 0;
        assert!(matches!(
            build_launch(false, invalid, None, Some("bash"), &[]),
            Err(SessionError::Internal(_))
        ));
    }

    #[test]
    fn resolve_root_is_zero_zero() {
        // `root` exists on every Unix host and is uid/gid 0 — a stable anchor
        // for the resolver without depending on this host's other accounts.
        assert_eq!(
            resolve_account_ids("root").unwrap(),
            AccountIds { uid: 0, gid: 0 }
        );
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
        let me = nix::unistd::User::from_uid(nix::unistd::geteuid())
            .unwrap()
            .unwrap();
        let l = build_launch(true, limits(), Some(&me.name), Some("bash"), &[]).unwrap();
        assert_eq!(l.program.as_deref(), Some(PRLIMIT));
        assert!(!l.args.iter().any(|arg| arg == SETPRIV));
        assert_eq!(l.args.last().map(String::as_str), Some("bash"));
    }
}
