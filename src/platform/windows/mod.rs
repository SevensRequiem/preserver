//! Windows arrives in phase 5. Until then every call that needs the OS reports that.

use crate::config::DriveId;
use crate::platform::FsInfo;
use anyhow::Result;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "not supported on Windows yet (phase 5)",
    )
}

pub(crate) fn list_filesystems() -> Result<Vec<FsInfo>> {
    Err(unsupported().into())
}

pub(crate) fn mount(_id: &DriveId) -> Result<PathBuf> {
    Err(unsupported().into())
}

pub(crate) fn is_mounted(_path: &Path) -> bool {
    false
}

pub(crate) fn sync_fs(_path: &Path) -> io::Result<()> {
    Err(unsupported())
}

pub(crate) fn private_file(path: &Path) -> io::Result<File> {
    File::create(path)
}

pub(crate) fn private_file_new(path: &Path) -> io::Result<File> {
    File::create_new(path)
}

pub(crate) fn private_dir_new(path: &Path) -> io::Result<()> {
    std::fs::create_dir(path)
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "same signature as the linux fn; ACLs come in phase 5"
)]
pub(crate) fn restrict_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "same signature as the linux fn; NTFS has no directory fsync"
)]
pub(crate) fn sync_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

pub(crate) fn ssh_master(_runtime: &Path) -> io::Result<()> {
    Err(unsupported())
}

pub(crate) fn ssh_master_stop(_runtime: &Path) {}

pub(crate) fn private_dir_all(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)
}

pub(crate) fn link_self(_link: &Path) -> io::Result<()> {
    Err(unsupported())
}

pub(crate) fn notify(_urgent: bool, _title: &str, _body: &str) {}

pub(crate) fn open_path(_path: &Path) -> Result<()> {
    Err(unsupported().into())
}

pub(crate) fn ssh_command(_runtime: &Path) -> Command {
    Command::new(r"C:\Windows\System32\OpenSSH\ssh.exe")
}

pub(crate) fn exec(mut cmd: Command) -> io::Error {
    match cmd.status() {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(e) => e,
    }
}
