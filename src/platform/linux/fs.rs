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

/// Bytes an unprivileged user can still write, and the size, of the filesystem holding `path`.
pub(crate) fn disk_free(path: &Path) -> io::Result<(u64, u64)> {
    let st = rustix::fs::statvfs(path)?;
    Ok((
        st.f_bavail.saturating_mul(st.f_frsize),
        st.f_blocks.saturating_mul(st.f_frsize),
    ))
}

/// The filesystem type of `path`, from its superblock magic: `vfat`, `exfat`, `ntfs3`, or
/// `fuseblk` (ntfs-3g and other FUSE drivers, treated like NTFS), or `other` for the rest, which
/// all keep POSIX names and links. A drive target prefers the name udisks reports.
pub(crate) fn fs_type(path: &Path) -> io::Result<String> {
    let magic = u64::try_from(rustix::fs::statfs(path)?.f_type).unwrap_or_default();
    Ok(match magic {
        0x4d44 => "vfat",
        0x2011_bab0 => "exfat",
        0x7366_746e => "ntfs3",
        0x6573_5546 => "fuseblk",
        _ => "other",
    }
    .to_string())
}

/// The allocation unit: the cluster size on FAT and exFAT.
pub(crate) fn block_size(path: &Path) -> io::Result<u64> {
    Ok(rustix::fs::statvfs(path)?.f_bsize.max(512))
}

/// Evicts the file's clean pages, so the next read comes from the device, not the page cache.
pub(crate) fn drop_cache(f: &File) -> io::Result<()> {
    Ok(rustix::fs::fadvise(
        f,
        0,
        None,
        rustix::fs::Advice::DontNeed,
    )?)
}

/// Swaps two paths in one step (`RENAME_EXCHANGE`). `Ok(false)` when the filesystem cannot,
/// so the caller renames one aside instead.
pub(crate) fn exchange(a: &Path, b: &Path) -> io::Result<bool> {
    use rustix::io::Errno;
    match rustix::fs::renameat_with(
        rustix::fs::CWD,
        a,
        rustix::fs::CWD,
        b,
        rustix::fs::RenameFlags::EXCHANGE,
    ) {
        Ok(()) => Ok(true),
        Err(Errno::INVAL | Errno::NOSYS | Errno::OPNOTSUPP) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Opens a file for reading, refusing a symlink as the last component.
pub(crate) fn open_nofollow(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits().cast_signed())
        .open(path)
}

/// Opens a regular file for reading: no link as the last component, and a FIFO or device is
/// refused instead of waited on.
pub(crate) fn open_regular(path: &Path) -> io::Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK)
                .bits()
                .cast_signed(),
        )
        .open(path)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    Ok(f)
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
    fn exchange_swaps_a_file_and_a_directory() {
        let tmp = TempDir::new();
        let (a, b) = (tmp.path().join("a"), tmp.path().join("b"));
        std::fs::write(&a, b"file").unwrap();
        std::fs::create_dir(&b).unwrap();
        assert!(exchange(&a, &b).unwrap(), "tmpfs supports RENAME_EXCHANGE");
        assert!(a.is_dir());
        assert_eq!(std::fs::read(&b).unwrap(), b"file");
        assert!(exchange(&a, &tmp.path().join("absent")).is_err());
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
