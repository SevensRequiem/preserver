use crate::platform;
use anyhow::anyhow;
use std::ffi::OsString;
use std::path::Path;

/// The file name under which gix starts this binary as its ssh program.
pub const SHIM: &str = "preserver-ssh";

/// Becomes ssh as a mux client of the run's master, with its options in front of git's arguments.
/// It returns only when ssh could not be started.
pub fn shim_main(args: impl Iterator<Item = OsString>) -> anyhow::Error {
    let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") else {
        return anyhow!("XDG_RUNTIME_DIR is not set");
    };
    let mut cmd = platform::ssh_command(Path::new(platform::SSH), Path::new(&runtime), false);
    cmd.args(args);
    anyhow!("start ssh: {}", platform::exec(cmd))
}
