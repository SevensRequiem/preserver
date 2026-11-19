pub(crate) mod credential;
pub(crate) mod http;
pub(crate) mod mirror;
pub mod ssh;
#[cfg(test)]
pub(crate) mod testcgi;

#[cfg(unix)]
use anyhow::{Result, bail};
#[cfg(unix)]
use std::path::Path;

#[cfg(unix)]
/// The shim path ends up in an ssh command line that must be run directly, never by a shell.
pub(crate) fn shell_safe(path: &Path) -> Result<()> {
    if !path.to_str().is_some_and(|s| {
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'))
    }) {
        bail!("{} has characters a shell would act on", path.display());
    }
    Ok(())
}
