//! One module per OS with the same free functions; only one is ever compiled.

use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::*;

#[derive(Debug)]
pub(crate) struct FsInfo {
    pub device: String,
    pub id: String,
    pub label: String,
    pub fstype: String,
    pub size: u64,
    pub mount: Option<PathBuf>,
    pub removable: bool,
}

/// Where a drive is, as far as a lane may know: lanes locate drives and never mount them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    windows,
    allow(dead_code, reason = "Windows drive lookup arrives in phase 5")
)]
pub(crate) enum DriveAt {
    Absent,
    Unmounted,
    Mounted(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    windows,
    allow(dead_code, reason = "Windows drive events arrive in phase 5")
)]
pub(crate) enum DriveEvent {
    /// A filesystem appeared (a plug-in): its udisks object path.
    Added(String),
    /// A mount changed, or events may have been missed.
    Changed,
}

/// The security key prompt went unanswered, or ssh failed after `gh` had reached GitHub.
#[derive(Debug)]
pub(crate) struct TouchMissing(pub String);

impl std::fmt::Display for TouchMissing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the security key was not touched ({})", self.0)
    }
}

impl std::error::Error for TouchMissing {}

/// Writes an owner-only file through `<file>.tmp` and a rename, creating the parent directory.
pub(crate) fn write_private(file: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = file.parent() {
        private_dir_all(dir)?;
    }
    let mut tmp = file.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = Path::new(&tmp);
    match std::fs::remove_file(tmp) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    private_file_new(tmp)?.write_all(data)?;
    std::fs::rename(tmp, file)
}
