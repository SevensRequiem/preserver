use std::fs::{DirBuilder, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// A mount point sits on a different device than its parent directory.
pub(crate) fn is_mounted(path: &Path) -> bool {
    let (Ok(here), Some(Ok(parent))) = (
        std::fs::metadata(path),
        path.parent().map(std::fs::metadata),
    ) else {
        return false;
    };
    here.dev() != parent.dev()
}

/// Flushes the filesystem that holds `path`.
pub(crate) fn sync_fs(path: &Path) -> io::Result<()> {
    Ok(rustix::fs::syncfs(File::open(path)?)?)
}

/// Opens an owner-only file, creating or truncating it; a symlink at `path` is refused.
pub(crate) fn private_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed())
        .open(path)
}

/// Creates an owner-only file that must not exist yet, so nothing planted there is followed or reused.
pub(crate) fn private_file_new(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Creates one owner-only directory that must not exist yet.
pub(crate) fn private_dir_new(path: &Path) -> io::Result<()> {
    DirBuilder::new().mode(0o700).create(path)
}

/// Makes an existing directory owner-only.
pub(crate) fn restrict_dir(path: &Path) -> io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

pub(crate) fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

pub(crate) fn symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

/// Flushes the directory entries of `dir`.
pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

pub(crate) fn private_dir_all(path: &Path) -> io::Result<()> {
    DirBuilder::new().recursive(true).mode(0o700).create(path)
}

/// Points `link` at the running binary, so git can start it under another name.
pub(crate) fn link_self(link: &Path) -> io::Result<()> {
    let exe = std::env::current_exe()?;
    if std::fs::read_link(link).is_ok_and(|target| target == exe) {
        return Ok(());
    }
    match std::fs::remove_file(link) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    std::os::unix::fs::symlink(exe, link)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    #[test]
    fn a_plain_directory_is_not_a_mount() {
        let tmp = TempDir::new();
        assert!(!is_mounted(tmp.path()));
        assert!(!is_mounted(&tmp.path().join("absent")));
        assert!(is_mounted(Path::new("/proc")));
    }

    #[test]
    fn private_files_and_dirs_are_owner_only() {
        let tmp = TempDir::new();
        let dir = tmp.path().join("a/b");
        private_dir_all(&dir).unwrap();
        private_file(&dir.join("f")).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("f")), 0o600);
    }

    #[test]
    fn link_self_replaces_a_stale_link() {
        let tmp = TempDir::new();
        let link = tmp.path().join("preserver-ssh");
        std::os::unix::fs::symlink("/nonexistent", &link).unwrap();
        link_self(&link).unwrap();
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            std::env::current_exe().unwrap()
        );
        link_self(&link).unwrap();
    }
}
