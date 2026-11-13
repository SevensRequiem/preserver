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
