//! Account-authorization enforcement (threat model T12, authorization half).
//! Reproduce with: `cargo test -p hf-session-core --test policy`

use std::collections::HashMap;
use std::sync::Arc;

use hf_session_core::{
    OpenShellRequest, SessionCoreConfig, SessionError, ShellManager, StaticPolicy,
};

fn req(user: &str, account: Option<&str>, key: u8) -> OpenShellRequest {
    OpenShellRequest {
        user: user.into(),
        requested_account: account.map(str::to_string),
        command: Some("bash".into()),
        args: vec!["--norc".into()],
        cols: 40,
        rows: 6,
        idempotency_key: [key; 16],
    }
}

fn manager() -> ShellManager {
    let mut allowed = HashMap::new();
    allowed.insert(
        "alice".to_string(),
        vec!["alice".to_string(), "deploy".to_string()],
    );
    ShellManager::with_policy(
        SessionCoreConfig::default(),
        Arc::new(StaticPolicy::new(allowed)),
    )
}

#[test]
fn allowed_account_is_recorded_on_the_shell() {
    let mgr = manager();
    let opened = mgr.open_shell(&req("alice", Some("deploy"), 1)).unwrap();
    let info = mgr.shell_info(&opened.shell_id).unwrap();
    assert_eq!(info.owner, "alice");
    assert_eq!(info.account.as_deref(), Some("deploy"));
    mgr.terminate(&opened.shell_id).unwrap();
}

#[test]
fn default_account_is_the_first_allowed() {
    let mgr = manager();
    let opened = mgr.open_shell(&req("alice", None, 2)).unwrap();
    let info = mgr.shell_info(&opened.shell_id).unwrap();
    assert_eq!(
        info.account.as_deref(),
        Some("alice"),
        "default = first listed"
    );
    mgr.terminate(&opened.shell_id).unwrap();
}

#[test]
fn disallowed_account_is_forbidden_and_spawns_nothing() {
    let mgr = manager();
    assert!(matches!(
        mgr.open_shell(&req("alice", Some("root"), 3)),
        Err(SessionError::Forbidden)
    ));
    // Nothing was created.
    assert!(mgr.list_shells().is_empty());
}

#[test]
fn unknown_user_is_forbidden() {
    let mgr = manager();
    assert!(matches!(
        mgr.open_shell(&req("mallory", Some("alice"), 4)),
        Err(SessionError::Forbidden)
    ));
    assert!(matches!(
        mgr.open_shell(&req("mallory", None, 5)),
        Err(SessionError::Forbidden)
    ));
}

#[test]
fn dev_default_allow_all_accepts_any_account() {
    // ShellManager::new uses the permissive AllowAll policy.
    let mgr = ShellManager::new(SessionCoreConfig::default());
    let opened = mgr.open_shell(&req("", Some("anything"), 6)).unwrap();
    assert_eq!(
        mgr.shell_info(&opened.shell_id).unwrap().account.as_deref(),
        Some("anything")
    );
    mgr.terminate(&opened.shell_id).unwrap();
}
