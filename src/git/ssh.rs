use crate::platform;
use anyhow::anyhow;
use std::ffi::OsString;
use std::path::Path;

/// The file name under which git starts this binary as its ssh program (`GIT_SSH`).
pub const SHIM: &str = "preserver-ssh";

/// Becomes ssh with the connection-sharing options in front of git's arguments.
/// It returns only when ssh could not be started.
pub fn shim_main(args: impl Iterator<Item = OsString>) -> anyhow::Error {
    let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") else {
        return anyhow!("XDG_RUNTIME_DIR is not set");
    };
    let mut cmd = platform::ssh_command(Path::new(&runtime));
    cmd.args(args);
    anyhow!("start ssh: {}", platform::exec(cmd))
}
