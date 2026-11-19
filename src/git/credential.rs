use anyhow::{Context, Result, bail};
use std::process::{Command, Stdio};

/// Asks the gh CLI for its token. It travels by pipe and memory only.
pub(crate) fn token() -> Result<String> {
    let out = Command::new("gh")
        .args(["auth", "token", "--hostname", "github.com"])
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .context("run gh")?;
    if !out.status.success() {
        bail!("gh auth token: {}", out.status);
    }
    let token = String::from_utf8(out.stdout)
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_graphic()))
        .context("gh auth token printed no usable token")?;
    Ok(token)
}
