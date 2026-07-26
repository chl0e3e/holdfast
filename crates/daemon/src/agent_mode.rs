//! Outbound-only `holdfastd --agent` runtime.
//!
//! This module is behind the `agent-mode` Cargo feature. The default standalone
//! daemon build has no dependency on `hf-agent` and starts exactly as before.

use std::{collections::BTreeMap, sync::Arc};

use hf_agent::{AgentConnector, AgentStatus, AgentSupervisor, ReconnectPolicy};
use hf_auth::GrantVerifier;
use hf_protocol::ids::ShellId;
use hf_session_core::{SessionCoreConfig, SessionError, ShellInfo, ShellManager};

use crate::build_shell_manager;

pub struct AgentDaemonConfig {
    pub connector: AgentConnector,
    pub reconnect: ReconnectPolicy,
    pub grant_verifier: GrantVerifier,
    pub grant_audience: String,
    pub account_policy: Option<BTreeMap<String, Vec<String>>>,
    pub session: SessionCoreConfig,
}

/// Running outbound agent. The manager is owned independently from the
/// supervisor task so cancelling/restarting a link can never end a shell.
pub struct AgentDaemon {
    manager: Arc<ShellManager>,
    status: AgentStatus,
    supervisor: tokio::task::JoinHandle<()>,
}

impl AgentDaemon {
    pub fn start(config: AgentDaemonConfig) -> Result<Self, hf_agent::AgentError> {
        if config.account_policy.is_none() {
            return Err(hf_agent::AgentError::MissingAccountPolicy);
        }
        let manager = Arc::new(build_shell_manager(config.session, &config.account_policy));
        let supervisor = AgentSupervisor::new(
            config.connector,
            Arc::clone(&manager),
            config.reconnect,
            config.grant_verifier,
            config.grant_audience,
        )?;
        let status = supervisor.status();
        let supervisor = tokio::spawn(supervisor.run());
        Ok(Self {
            manager,
            status,
            supervisor,
        })
    }

    pub fn status(&self) -> hf_agent::AgentStatusSnapshot {
        self.status.snapshot()
    }

    pub fn shell_info(&self, shell_id: &ShellId) -> Result<ShellInfo, SessionError> {
        self.manager.shell_info(shell_id)
    }

    pub fn terminate_shell(&self, shell_id: &ShellId) -> Result<(), SessionError> {
        self.manager.terminate(shell_id).map(|_| ())
    }

    pub fn abort(&self) {
        self.supervisor.abort();
    }
}

impl Drop for AgentDaemon {
    fn drop(&mut self) {
        self.supervisor.abort();
    }
}
