//! Windows arrives in phase 5. Until then every call that needs the OS reports that.

use crate::config::DriveId;
use crate::platform::{DriveAt, DriveEvent, FsInfo};
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

pub(crate) fn locate(_id: &DriveId) -> DriveAt {
    DriveAt::Absent
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "same signature as the linux fn; drive events come in phase 5"
)]
pub(crate) fn mount_added(
    _object: &str,
    _wanted: &[DriveId],
) -> Result<Option<(DriveId, PathBuf)>> {
    Ok(None)
}

pub(crate) fn watch_drives(_on_event: impl Fn(DriveEvent) + Send + 'static) {
    tracing::warn!("drive events are not supported on Windows yet (phase 5)");
}

pub(crate) fn watch_queue(_dir: &Path, _on_change: impl Fn() + Send + 'static) {
    tracing::warn!("queue wake-ups are not supported on Windows yet (phase 5): 30 s tick");
}

pub(crate) fn session_env() -> Vec<(String, String)> {
    Vec::new()
}

pub(crate) fn is_mounted(_path: &Path) -> bool {
    false
}

pub(crate) fn sync_fs(_path: &Path) -> io::Result<()> {
    Err(unsupported())
}

pub(crate) fn disk_free(_path: &Path) -> io::Result<(u64, u64)> {
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

#[expect(
    clippy::unnecessary_wraps,
    reason = "same signature as the linux fn; NTFS modes come in phase 5"
)]
pub(crate) fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

pub(crate) fn symlink(_target: &Path, _link: &Path) -> io::Result<()> {
    Err(unsupported())
}

pub(crate) fn run_tray(_paths: &crate::paths::Paths) -> Result<()> {
    Err(unsupported().into())
}

pub(crate) const SSH: &str = r"C:\Windows\System32\OpenSSH\ssh.exe";

/// ssh.exe makes its own connection per repo and asks for the key itself.
#[expect(clippy::unnecessary_wraps, reason = "same signature as the Linux one")]
pub(crate) fn ssh_master(
    _program: &Path,
    _runtime: &Path,
    _session: &[(String, String)],
    _stop: &dyn Fn() -> bool,
) -> Result<()> {
    Ok(())
}

pub(crate) fn ssh_ensure_master(
    program: &Path,
    runtime: &Path,
    session: &[(String, String)],
    stop: &dyn Fn() -> bool,
) -> Result<()> {
    ssh_master(program, runtime, session, stop)
}

pub(crate) fn ssh_master_stop(_runtime: &Path) {}

pub(crate) fn private_dir_all(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)
}

pub(crate) fn notify(_urgent: bool, _title: &str, _body: &str) {}

pub(crate) fn open_path(_path: &Path) -> Result<()> {
    Err(unsupported().into())
}

pub(crate) fn ssh_command(program: &Path, _runtime: &Path, _master: bool) -> Command {
    Command::new(program)
}

pub(crate) fn exec(mut cmd: Command) -> io::Error {
    match cmd.status() {
        Ok(status) => std::process::exit(status.code().unwrap_or(1)),
        Err(e) => e,
    }
}

pub(crate) fn fs_type(_path: &Path) -> io::Result<String> {
    Err(unsupported())
}

pub(crate) fn block_size(_path: &Path) -> io::Result<u64> {
    Err(unsupported())
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "same signature as the linux fn; read-back on Windows comes in phase 5"
)]
pub(crate) fn drop_cache(_f: &File) -> io::Result<()> {
    Ok(())
}

pub(crate) fn open_nofollow(path: &Path) -> io::Result<File> {
    if std::fs::symlink_metadata(path)?.is_symlink() {
        return Err(io::Error::other("refusing a symlink"));
    }
    File::open(path)
}

pub(crate) fn open_regular(path: &Path) -> io::Result<File> {
    let f = open_nofollow(path)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    Ok(f)
}

pub(crate) fn open_rw_regular(path: &Path) -> io::Result<File> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if !m.is_file() => return Err(io::Error::other("not a regular file")),
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    Ok(f)
}

/// No atomic exchange here: the caller renames the old path aside, then the new one in.
#[expect(
    clippy::unnecessary_wraps,
    reason = "same signature as the linux fn, which can fail"
)]
pub(crate) fn exchange(_a: &Path, _b: &Path) -> io::Result<bool> {
    Ok(false)
}
