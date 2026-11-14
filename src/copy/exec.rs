//! Writing a plan to the target. Both drives are untrusted: sources open without following
//! links, every directory written into is checked to be a plain one, files are created
//! exclusively as `<name>.copying` and renamed only once whole, synced and hashed, and nothing
//! is visible on the target before it read back right.

use super::plan::{Action, FileEnt, Have, SetStep};
use crate::platform;
use crate::public::versioned::{clear_other_stages, plain_dirs, read_set_file, version_dirs};
use crate::resolve::hex;
use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const CHUNK: usize = 1 << 20;

/// The stop flag tripped (pause or cancel).
#[derive(Debug)]
pub(crate) struct Halted;

impl std::fmt::Display for Halted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("stopped")
    }
}

impl std::error::Error for Halted {}

/// A source file went away mid-run: a public sync pruned the version being copied.
#[derive(Debug)]
pub(crate) struct Vanished(pub String);

impl std::fmt::Display for Vanished {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} vanished from the primary", self.0)
    }
}

impl std::error::Error for Vanished {}

/// Counters the lane shows as progress, and the stop flag it sets. Relaxed throughout: they
/// carry no data, and the lane joins the copy thread before it reads them for the record.
#[derive(Default)]
pub(crate) struct Prog {
    pub stop: AtomicBool,
    pub bytes: AtomicU64,
    pub files: AtomicU64,
    pub bytes_total: AtomicU64,
    pub files_total: AtomicU64,
}

pub(crate) struct Ctx<'a> {
    pub stop: &'a (dyn Fn() -> bool + Sync),
    pub prog: &'a Prog,
    pub free: &'a (dyn Fn(&Path) -> io::Result<(u64, u64)> + Sync),
    /// Free bytes never to go below.
    pub floor: u64,
    pub root: &'a Path,
}

/// A path relative to an archive, as SHA256SUMS lists it: plain names only.
pub(crate) fn safe_rel(rel: &str) -> bool {
    !rel.contains('\0')
        && !rel.contains('\\')
        && rel
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..")
}

/// Creates `base/rel` one directory at a time, refusing anything on the way that is not a
/// plain directory. `base` has been checked by the caller.
pub(crate) fn ensure_dir(base: &Path, rel: &str) -> Result<PathBuf> {
    let mut p = base.to_path_buf();
    for c in rel.split('/').filter(|c| !c.is_empty()) {
        p.push(c);
        match std::fs::symlink_metadata(&p) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => bail!(
                "{} is not a plain directory, refusing to write there",
                p.display()
            ),
            Err(e) if e.kind() == io::ErrorKind::NotFound => match std::fs::create_dir(&p) {
                Err(e) if e.kind() != io::ErrorKind::AlreadyExists => {
                    return Err(e).with_context(|| p.display().to_string());
                }
                _ => plain_dirs(&[&p])?,
            },
            Err(e) => return Err(e).with_context(|| p.display().to_string()),
        }
    }
    Ok(p)
}

fn copying(dst: &Path) -> PathBuf {
    let mut s = dst.as_os_str().to_owned();
    s.push(".copying");
    PathBuf::from(s)
}

fn remove_if_there(p: &Path) -> io::Result<()> {
    match std::fs::remove_file(p) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Copies one file and returns its SHA-256. With `expect`, a source that hashes otherwise is
/// refused: the primary's copy rotted. The bytes land in `<dst>.copying`, which is synced,
/// stamped with the source's mtime and renamed; on any failure it is deleted.
pub(crate) fn copy_file(ctx: &Ctx, src: &Path, dst: &Path, expect: &str) -> Result<String> {
    let mut from = match platform::open_nofollow(src) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(anyhow!(Vanished(src.display().to_string())));
        }
        r => r.with_context(|| src.display().to_string())?,
    };
    let meta = from.metadata()?;
    if !meta.is_file() {
        bail!("{} is not a regular file", src.display());
    }
    let (free, _) = (ctx.free)(ctx.root).with_context(|| ctx.root.display().to_string())?;
    if free < meta.len().saturating_add(ctx.floor) {
        bail!(
            "the target ran out of room ({} free, {} needed for {})",
            free,
            meta.len(),
            src.display()
        );
    }
    let tmp = copying(dst);
    remove_if_there(&tmp).with_context(|| tmp.display().to_string())?;
    let mut to = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .with_context(|| tmp.display().to_string())?;
    let written = (|| -> Result<String> {
        let mut h = Sha256::new();
        let mut buf = vec![0u8; CHUNK];
        loop {
            if (ctx.stop)() {
                return Err(anyhow!(Halted));
            }
            let n = from
                .read(&mut buf)
                .with_context(|| src.display().to_string())?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
            to.write_all(&buf[..n])
                .with_context(|| tmp.display().to_string())?;
            ctx.prog.bytes.fetch_add(n as u64, Ordering::Relaxed);
        }
        let got = hex(&h.finalize());
        if !expect.is_empty() && got != expect {
            bail!(
                "{} does not match its SHA256SUMS on the primary: the primary's copy is damaged, run 'preserver verify'",
                src.display()
            );
        }
        to.set_modified(meta.modified()?)?;
        to.sync_all()?;
        Ok(got)
    })();
    drop(to);
    match written {
        Ok(h) => {
            std::fs::rename(&tmp, dst).with_context(|| dst.display().to_string())?;
            ctx.prog.files.fetch_add(1, Ordering::Relaxed);
            Ok(h)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn hash_file(path: &Path) -> Result<String> {
    let mut f = platform::open_nofollow(path).with_context(|| path.display().to_string())?;
    platform::drop_cache(&f).with_context(|| path.display().to_string())?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = f
            .read(&mut buf)
            .with_context(|| path.display().to_string())?;
        if n == 0 {
            return Ok(hex(&h.finalize()));
        }
        h.update(&buf[..n]);
    }
}

/// Reads each file back from the device, its cached pages dropped first, so a stick that
/// lies about its size or loses writes shows up now and not on the day of the restore. A file
/// that does not match is deleted. Call after `sync_fs`: only clean pages can be dropped.
pub(crate) fn verify(files: &[(PathBuf, String)]) -> Result<()> {
    for (path, want) in files {
        if hash_file(path)? != *want {
            let _ = std::fs::remove_file(path);
            bail!(
                "read-back of {} does not match what was written: failing or fake-capacity media",
                path.display()
            );
        }
    }
    Ok(())
}

/// Personal files are only added and replaced, never deleted: the target may be the last
/// copy of something the primary has lost. Returns `(rel, sha256)` per file written.
pub(crate) fn copy_personal(
    ctx: &Ctx,
    src: &Path,
    dst: &Path,
    files: &[FileEnt],
) -> Result<Vec<(String, String)>> {
    let mut written = Vec::new();
    let mut check = Vec::new();
    for f in files {
        let parent = f.rel.rsplit_once('/').map_or("", |(p, _)| p);
        let to = ensure_dir(dst, parent)?.join(f.rel.rsplit('/').next().unwrap_or(&f.rel));
        let h = copy_file(ctx, &src.join(&f.rel), &to, "")?;
        check.push((to, h.clone()));
        written.push((f.rel.clone(), h));
    }
    if !check.is_empty() {
        platform::sync_fs(dst).with_context(|| dst.display().to_string())?;
        verify(&check)?;
    }
    Ok(written)
}

/// Moves a directory out of sight in one rename, then deletes it. std's `remove_dir_all`
/// does not follow links.
fn retire(dir: &Path, to: &Path) -> Result<()> {
    if std::fs::symlink_metadata(dir).is_err() {
        return Ok(());
    }
    if std::fs::symlink_metadata(to).is_ok() {
        std::fs::remove_dir_all(to).with_context(|| to.display().to_string())?;
    }
    std::fs::rename(dir, to).with_context(|| dir.display().to_string())?;
    std::fs::remove_dir_all(to).with_context(|| to.display().to_string())
}

/// Removes a set the plan dropped, in one rename first so no half-deleted version is seen.
pub(crate) fn delete_set(archive: &Path, name: &str) -> Result<()> {
    let dir = archive.join("public").join(name);
    plain_dirs(&[&dir])?;
    retire(
        &dir,
        &archive.join("public").join(format!(".removing~{name}")),
    )
}

pub(crate) fn delete_kit(archive: &Path) -> Result<()> {
    remove_if_there(&archive.join("kit.tar"))?;
    plain_dirs(&[&archive.join("kit")])?;
    retire(&archive.join("kit"), &archive.join(".kit-old"))
}

/// Copies one set version: staged under `.staging/<version>~<variant>`, read back, given its
/// own SET.toml and SHA256SUMS for the files it holds, and renamed into place. Files the
/// target already has are hard linked from the old version, or, for a replacement in place,
/// moved out of it once it is out of sight. A stage left by an interrupted run is resumed:
/// its whole files are read back instead of copied again.
pub(crate) fn copy_set(
    ctx: &Ctx,
    src: &Path,
    set_dir: &Path,
    step: &SetStep,
    have: Option<&Have>,
    links: bool,
) -> Result<()> {
    let stage_root = set_dir.join(".staging");
    plain_dirs(&[set_dir, &stage_root])?;
    if step.action == Action::Unchanged {
        clear_other_stages(&stage_root, "");
        return Ok(());
    }
    let stage_name = format!("{}~{}", step.version, step.variant);
    let stage = stage_root.join(&stage_name);
    let retired = stage_root.join(".retired");
    plain_dirs(&[&stage])?;
    clear_other_stages(&stage_root, &stage_name);
    ensure_dir(set_dir, &format!(".staging/{stage_name}"))?;

    let old = have.map(|h| set_dir.join(&h.version));
    let in_place = matches!(step.action, Action::Replace { in_place: true });
    let reuse_from = match &old {
        Some(o) if in_place => {
            plain_dirs(&[o])?;
            std::fs::rename(o, &retired).with_context(|| o.display().to_string())?;
            Some(retired.clone())
        }
        Some(o) if links => Some(o.clone()),
        _ => None,
    };
    let sums = have.map(|h| &h.sums);

    let mut check = Vec::new();
    for f in &step.files {
        let parent = f.rel.rsplit_once('/').map_or("", |(p, _)| p);
        let dst = ensure_dir(&stage, parent)?.join(f.rel.rsplit('/').next().unwrap_or(&f.rel));
        match std::fs::symlink_metadata(&dst) {
            Ok(m) if m.is_file() => {
                check.push((dst, f.sha256.clone()));
                continue;
            }
            Ok(_) => bail!("{} is not a regular file", dst.display()),
            Err(_) => {}
        }
        let reusable = sums.is_some_and(|s| s.get(&f.rel) == Some(&f.sha256));
        if let (Some(from), true) = (&reuse_from, reusable) {
            let from = from.join(&f.rel);
            let plain = std::fs::symlink_metadata(&from).is_ok_and(|m| m.is_file());
            let moved = plain
                && if in_place {
                    std::fs::rename(&from, &dst).is_ok()
                } else {
                    std::fs::hard_link(&from, &dst).is_ok()
                };
            if moved {
                continue;
            }
        }
        let h = copy_file(ctx, &src.join(&f.rel), &dst, &f.sha256)?;
        check.push((dst, h));
    }
    if in_place {
        std::fs::remove_dir_all(&retired).with_context(|| retired.display().to_string())?;
    }
    platform::sync_fs(&stage).with_context(|| stage.display().to_string())?;
    verify(&check)?;

    // The primary's SET.toml cut down to the variant's sources.
    let srcs: HashSet<&str> = step
        .files
        .iter()
        .filter_map(|f| f.rel.split('/').next())
        .collect();
    let mut sf = read_set_file(&src.join("SET.toml"));
    sf.entries.retain(|e| srcs.contains(e.source.as_str()));
    sf.sources.retain(|s| srcs.contains(s.name.as_str()));
    sf.variant.clone_from(&step.variant);
    sf.bytes = step.files.iter().map(|f| f.len).sum();
    let toml = toml::to_string(&sf)?;
    let mut files: Vec<&FileEnt> = step.files.iter().collect();
    files.sort_by(|a, b| a.rel.cmp(&b.rel));
    let mut sums = String::new();
    for f in files {
        let _ = writeln!(sums, "{}  {}", f.sha256, f.rel);
    }
    let _ = writeln!(sums, "{}  SET.toml", hex(&Sha256::digest(toml.as_bytes())));
    write_new(&stage.join("SET.toml"), toml.as_bytes())?;
    write_new(&stage.join("SHA256SUMS"), sums.as_bytes())?;
    platform::sync_fs(&stage).with_context(|| stage.display().to_string())?;
    verify(&[
        (
            stage.join("SET.toml"),
            hex(&Sha256::digest(toml.as_bytes())),
        ),
        (
            stage.join("SHA256SUMS"),
            hex(&Sha256::digest(sums.as_bytes())),
        ),
    ])?;

    let dest = set_dir.join(&step.version);
    retire(&dest, &stage_root.join(format!(".old~{}", step.version)))?;
    std::fs::rename(&stage, &dest).with_context(|| dest.display().to_string())?;
    platform::sync_dir(set_dir)?;
    for v in version_dirs(set_dir) {
        if v != step.version {
            retire(&set_dir.join(&v), &stage_root.join(format!(".old~{v}")))?;
        }
    }
    Ok(())
}

/// Replaces a small file the copy owns: created exclusively, so a planted link is never
/// followed.
pub(crate) fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    remove_if_there(path).with_context(|| path.display().to_string())?;
    let mut f = File::create_new(path).with_context(|| path.display().to_string())?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KitKind {
    Dir,
    File(u64),
    Link(PathBuf),
}

/// The kit as one `kit.tar`, hashed while it is written and read back against that hash.
pub(crate) fn copy_kit_tar(
    ctx: &Ctx,
    src: &Path,
    archive: &Path,
    entries: &[(String, KitKind)],
    in_place: bool,
) -> Result<()> {
    struct Hashing<'a> {
        f: File,
        h: Sha256,
        prog: &'a Prog,
    }
    impl Write for Hashing<'_> {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            let n = self.f.write(b)?;
            self.h.update(&b[..n]);
            self.prog.bytes.fetch_add(n as u64, Ordering::Relaxed);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.f.flush()
        }
    }
    let dst = archive.join("kit.tar");
    if in_place {
        remove_if_there(&dst)?;
    }
    let tmp = copying(&dst);
    remove_if_there(&tmp)?;
    let f = File::create_new(&tmp).with_context(|| tmp.display().to_string())?;
    let built = (|| -> Result<String> {
        let mut tar = tar::Builder::new(Hashing {
            f,
            h: Sha256::new(),
            prog: ctx.prog,
        });
        tar.follow_symlinks(false);
        for (rel, kind) in entries {
            if (ctx.stop)() {
                return Err(anyhow!(Halted));
            }
            let name = format!("kit/{rel}");
            let path = src.join(rel);
            match kind {
                KitKind::Dir => tar.append_dir(&name, &path)?,
                KitKind::File(_) => {
                    let mut f = platform::open_nofollow(&path)
                        .map_err(|_| anyhow!(Vanished(path.display().to_string())))?;
                    tar.append_file(&name, &mut f)
                        .with_context(|| path.display().to_string())?;
                }
                KitKind::Link(target) => {
                    let mut h = tar::Header::new_gnu();
                    h.set_entry_type(tar::EntryType::Symlink);
                    h.set_size(0);
                    h.set_mode(0o777);
                    tar.append_link(&mut h, &name, target)?;
                }
            }
            ctx.prog.files.fetch_add(1, Ordering::Relaxed);
        }
        let w = tar.into_inner()?;
        w.f.sync_all()?;
        Ok(hex(&w.h.finalize()))
    })();
    let h = match built {
        Ok(h) => h,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };
    std::fs::rename(&tmp, &dst).with_context(|| dst.display().to_string())?;
    platform::sync_fs(archive)?;
    verify(&[(dst, h)])?;
    plain_dirs(&[&archive.join("kit")])?;
    retire(&archive.join("kit"), &archive.join(".kit-old"))
}

/// The kit as a tree, for filesystems that keep links and names: staged, read back, swapped in.
pub(crate) fn copy_kit_tree(
    ctx: &Ctx,
    src: &Path,
    archive: &Path,
    entries: &[(String, KitKind)],
    in_place: bool,
) -> Result<()> {
    let stage = archive.join(".kit-staging");
    let live = archive.join("kit");
    plain_dirs(&[&stage, &live])?;
    if in_place {
        retire(&live, &archive.join(".kit-old"))?;
    }
    if std::fs::symlink_metadata(&stage).is_ok() {
        std::fs::remove_dir_all(&stage)?;
    }
    ensure_dir(archive, ".kit-staging")?;
    let mut check = Vec::new();
    for (rel, kind) in entries {
        let parent = rel.rsplit_once('/').map_or("", |(p, _)| p);
        let leaf = rel.rsplit('/').next().unwrap_or(rel);
        match kind {
            KitKind::Dir => {
                ensure_dir(&stage, rel)?;
            }
            KitKind::File(_) => {
                let dst = ensure_dir(&stage, parent)?.join(leaf);
                let h = copy_file(ctx, &src.join(rel), &dst, "")?;
                check.push((dst, h));
            }
            KitKind::Link(target) => {
                platform::symlink(target, &ensure_dir(&stage, parent)?.join(leaf))?;
            }
        }
    }
    platform::sync_fs(&stage)?;
    verify(&check)?;
    retire(&live, &archive.join(".kit-old"))?;
    std::fs::rename(&stage, &live).with_context(|| live.display().to_string())?;
    remove_if_there(&archive.join("kit.tar"))?;
    platform::sync_dir(archive)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    fn ctx<'a>(prog: &'a Prog, stop: &'a (dyn Fn() -> bool + Sync), root: &'a Path) -> Ctx<'a> {
        Ctx {
            stop,
            prog,
            free: &|_| Ok((u64::MAX / 2, u64::MAX / 2)),
            floor: 0,
            root,
        }
    }

    #[test]
    fn read_back_catches_a_corrupted_byte() {
        let tmp = TempDir::new();
        let prog = Prog::default();
        let c = ctx(&prog, &|| false, tmp.path());
        let src = tmp.path().join("src");
        std::fs::write(&src, b"some bytes worth keeping").unwrap();
        let dst = tmp.path().join("dst");
        let h = copy_file(&c, &src, &dst, "").unwrap();
        assert!(!copying(&dst).exists());
        verify(&[(dst.clone(), h.clone())]).unwrap();

        let mut bytes = std::fs::read(&dst).unwrap();
        bytes[5] ^= 0x01;
        std::fs::write(&dst, bytes).unwrap();
        let err = verify(&[(dst.clone(), h)]).unwrap_err().to_string();
        assert!(err.contains("failing or fake-capacity media"), "{err}");
        assert!(!dst.exists(), "a bad copy is never left behind");
    }

    #[test]
    fn copy_refuses_rot_links_and_cleans_up() {
        let tmp = TempDir::new();
        let prog = Prog::default();
        let c = ctx(&prog, &|| false, tmp.path());
        let src = tmp.path().join("src");
        std::fs::write(&src, b"abc").unwrap();
        let dst = tmp.path().join("dst");
        let err = copy_file(&c, &src, &dst, &"0".repeat(64))
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match its SHA256SUMS"), "{err}");
        assert!(!dst.exists() && !copying(&dst).exists());

        #[cfg(unix)]
        {
            let link = tmp.path().join("link");
            std::os::unix::fs::symlink(&src, &link).unwrap();
            assert!(
                copy_file(&c, &link, &dst, "").is_err(),
                "a source link is not followed"
            );
        }

        let stopped = ctx(&prog, &|| true, tmp.path());
        let err = copy_file(&stopped, &src, &dst, "").unwrap_err();
        assert!(err.is::<Halted>());
        assert!(!dst.exists() && !copying(&dst).exists());

        let gone = copy_file(&c, &tmp.path().join("nope"), &dst, "").unwrap_err();
        assert!(gone.is::<Vanished>());

        let full = Ctx {
            free: &|_| Ok((2, 100)),
            ..ctx(&prog, &|| false, tmp.path())
        };
        let err = copy_file(&full, &src, &dst, "").unwrap_err().to_string();
        assert!(err.contains("ran out of room"), "{err}");
    }

    #[test]
    fn rels_and_dirs() {
        for (rel, ok) in [
            ("a/b", true),
            ("a", true),
            ("", false),
            ("/a", false),
            ("a//b", false),
            ("a/../b", false),
            ("./a", false),
            ("a\\b", false),
        ] {
            assert_eq!(safe_rel(rel), ok, "{rel:?}");
        }
        let tmp = TempDir::new();
        let d = ensure_dir(tmp.path(), "x/y/z").unwrap();
        assert!(d.is_dir());
        std::fs::write(tmp.path().join("file"), b"").unwrap();
        assert!(ensure_dir(tmp.path(), "file/sub").is_err());
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(tmp.path().join("x"), tmp.path().join("ln")).unwrap();
            assert!(
                ensure_dir(tmp.path(), "ln/sub").is_err(),
                "a planted link is refused"
            );
        }
    }
}
