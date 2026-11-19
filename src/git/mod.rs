pub mod credential;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the mirror step builds its remote from it")
)]
pub(crate) mod http;
#[cfg_attr(
    any(not(test), not(unix)),
    expect(
        dead_code,
        reason = "the public and personal mirror steps call it; ssh and https are tested on unix"
    )
)]
pub(crate) mod mirror;
pub mod ssh;
#[cfg(test)]
mod testcgi;

use crate::config::Transport;
use crate::platform;
use anyhow::{Context, Result, bail};
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

/// The environment that lets `git fetch` reach GitHub over the chosen transport.
pub(crate) struct Auth {
    env: Vec<(&'static str, OsString)>,
    /// The graphical session's display and agent, for the shim's ssh and its askpass.
    session: Vec<(String, String)>,
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The values can hold the token.
        f.debug_list()
            .entries(self.env.iter().map(|(k, _)| *k))
            .entries(self.session.iter().map(|(k, _)| k.as_str()))
            .finish()
    }
}

/// git hands a helper or ssh command with shell characters to sh; ours must be run directly.
fn shell_safe(path: &Path) -> Result<()> {
    if !path.to_str().is_some_and(|s| {
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'))
    }) {
        bail!(
            "{} has characters git would pass to a shell",
            path.display()
        );
    }
    Ok(())
}

impl Auth {
    /// Links this binary into the runtime dir under the name git will start it by.
    /// For https it also asks `gh` for the token, which then lives only in the fetch's environment.
    pub(crate) fn new(transport: Transport, runtime: &Path) -> Result<Self> {
        let dir = runtime.join("preserver");
        platform::private_dir_all(&dir).with_context(|| dir.display().to_string())?;
        let env = match transport {
            Transport::Ssh => {
                let shim = dir.join(ssh::SHIM);
                shell_safe(&shim)?;
                platform::link_self(&shim).with_context(|| shim.display().to_string())?;
                vec![
                    ("GIT_SSH", shim.clone().into()),
                    ("GIT_SSH_VARIANT", "ssh".into()),
                    // core.sshCommand from a git config file would win over GIT_SSH.
                    ("GIT_CONFIG_COUNT", "1".into()),
                    ("GIT_CONFIG_KEY_0", "core.sshCommand".into()),
                    ("GIT_CONFIG_VALUE_0", shim.into()),
                ]
            }
            Transport::Https => {
                let helper = dir.join(credential::HELPER);
                shell_safe(&helper)?;
                platform::link_self(&helper).with_context(|| helper.display().to_string())?;
                vec![
                    ("GIT_TERMINAL_PROMPT", "0".into()),
                    // An empty value first drops every helper from the user's git config.
                    ("GIT_CONFIG_COUNT", "2".into()),
                    ("GIT_CONFIG_KEY_0", "credential.helper".into()),
                    ("GIT_CONFIG_VALUE_0", OsString::new()),
                    ("GIT_CONFIG_KEY_1", "credential.helper".into()),
                    ("GIT_CONFIG_VALUE_1", helper.into()),
                    (credential::TOKEN_ENV, credential::token()?.into()),
                ]
            }
        };
        Ok(Self {
            env,
            session: Vec::new(),
        })
    }

    pub(crate) fn with_session(mut self, vars: Vec<(String, String)>) -> Self {
        self.session = vars;
        self
    }

    pub(crate) fn apply(&self, cmd: &mut Command) {
        // GIT_SSH_COMMAND would win over GIT_SSH and run through a shell.
        cmd.env_remove("GIT_SSH_COMMAND")
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .envs(self.session.iter().map(|(k, v)| (k, v)));
    }
}
