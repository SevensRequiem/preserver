mod fs;
mod notify;
mod tray;
mod udisks;

pub(crate) use fs::{
    disk_free, is_mounted, link_self, private_dir_all, private_dir_new, private_file,
    private_file_new, restrict_dir, set_mode, symlink, sync_dir, sync_fs,
};
pub(crate) use notify::notify;
pub(crate) use tray::run_tray;
pub(crate) use udisks::{list_filesystems, mount};

use anyhow::{Context, Result, bail};
use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

const ASKPASS: &str = "/usr/bin/ksshaskpass";

pub(crate) fn open_path(path: &Path) -> Result<()> {
    let status = Command::new("xdg-open")
        .arg(path)
        .status()
        .context("xdg-open")?;
    if !status.success() {
        bail!("xdg-open: {status}");
    }
    Ok(())
}

/// ssh with one multiplexed connection, so the security key is touched once for the whole run.
/// The options come first: everything the caller appends is git's.
pub(crate) fn ssh_command(runtime: &Path) -> Command {
    let mut control = OsString::from("ControlPath=");
    control.push(runtime.join("code-archive-ssh-%C"));
    let mut cmd = Command::new("/usr/bin/ssh");
    cmd.args(["-o", "ControlMaster=auto", "-o"])
        .arg(control)
        .args(["-o", "ControlPersist=60"]);
    // Backups run from the tray with no terminal, so the PIN and touch prompts go to a dialog.
    if Path::new(ASKPASS).exists() {
        cmd.env("SSH_ASKPASS", ASKPASS)
            .env("SSH_ASKPASS_REQUIRE", "force");
    }
    cmd
}

const GITHUB: &str = "git@github.com";

/// Opens the shared connection up front, so the key is touched here and nothing outlives the run.
/// `ControlPersist` only bounds the master if `ssh_master_stop` never gets to run.
pub(crate) fn ssh_master(runtime: &Path) -> Result<()> {
    let status = ssh_command(runtime)
        .args(["-fN", GITHUB])
        .status()
        .context("start ssh")?;
    if !status.success() {
        bail!("ssh connection to github.com: {status}");
    }
    Ok(())
}

pub(crate) fn ssh_master_stop(runtime: &Path) {
    let stopped = ssh_command(runtime)
        .args(["-O", "exit", GITHUB])
        .stderr(Stdio::null())
        .status();
    if !stopped.is_ok_and(|s| s.success()) {
        tracing::debug!("ssh master already gone");
    }
}

/// Replaces this process with `cmd`; it only returns when that failed.
pub(crate) fn exec(mut cmd: Command) -> std::io::Error {
    cmd.exec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_options_precede_the_callers_arguments() {
        let mut cmd = ssh_command(Path::new("/run/user/1000"));
        cmd.args(["-p", "22", "git@github.com", "git-upload-pack 'o/r.git'"]);
        assert_eq!(cmd.get_program(), "/usr/bin/ssh");
        let args: Vec<_> = cmd.get_args().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(
            args,
            [
                "-o",
                "ControlMaster=auto",
                "-o",
                "ControlPath=/run/user/1000/code-archive-ssh-%C",
                "-o",
                "ControlPersist=60",
                "-p",
                "22",
                "git@github.com",
                "git-upload-pack 'o/r.git'",
            ]
        );
    }
}
