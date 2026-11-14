//! Local folders as encrypted `tar.zst` archives: a level 0 each month and daily differentials
//! against it. The first tar entry is the manifest, which lists every path present; that is what
//! lets a restore apply deletions, and the level 0's copy in the state dir is the index the
//! differentials compare against.

use crate::config::{Config, LocalFolder};
use crate::crypt::{self, Identities};
use crate::paths::Paths;
use crate::personal::restore::check_target;
use crate::personal::{Hooks, Stopped};
use crate::platform;
use age::x25519;
use anyhow::{Context, Result, anyhow, bail};
use ruzstd::decoding::StreamingDecoder;
use ruzstd::encoding::{CompressionLevel, FrameCompressor};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::{File, Metadata};
use std::io::{self, BufReader, BufWriter, ErrorKind, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MANIFEST: &str = ".preserver/manifest.tsv";
const MAGIC: &str = "preserver-manifest\t1\t";
/// A restore reads the manifest into memory before it trusts anything else in the archive.
const MANIFEST_LIMIT: u64 = 1 << 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
    Link,
}

/// What a differential compares against the level 0, and what a restore puts back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Meta {
    kind: Kind,
    mode: u32,
    size: u64,
    /// Nanoseconds since the epoch.
    mtime: i128,
    /// Catches what mtime misses: chmod, rename, a restored older copy. Zero where the OS has none.
    ctime: i128,
}

#[cfg(unix)]
fn mode_and_ctime(m: &Metadata) -> (u32, i128) {
    use std::os::unix::fs::MetadataExt;
    (
        m.mode() & 0o7777,
        i128::from(m.ctime()) * 1_000_000_000 + i128::from(m.ctime_nsec()),
    )
}

#[cfg(not(unix))]
fn mode_and_ctime(_m: &Metadata) -> (u32, i128) {
    (0, 0)
}

/// `None` for what is not archived: sockets, FIFOs and devices.
fn meta_of(m: &Metadata) -> Option<Meta> {
    let kind = if m.is_symlink() {
        Kind::Link
    } else if m.is_dir() {
        Kind::Dir
    } else if m.is_file() {
        Kind::File
    } else {
        return None;
    };
    let mtime = match m
        .modified()
        .unwrap_or(UNIX_EPOCH)
        .duration_since(UNIX_EPOCH)
    {
        Ok(d) => d.as_nanos().cast_signed(),
        Err(e) => -e.duration().as_nanos().cast_signed(),
    };
    let (mode, ctime) = mode_and_ctime(m);
    Some(Meta {
        kind,
        mode,
        // A directory's size is the filesystem's business and would only add noise.
        size: if kind == Kind::Dir { 0 } else { m.len() },
        mtime,
        ctime,
    })
}

/// One path under a folder: where it is, and its manifest key (`/`-separated bytes).
#[derive(Debug)]
struct Found {
    rel: PathBuf,
    key: Vec<u8>,
    meta: Meta,
}

/// Lists everything under `root` without following symlinks, parents before children.
fn walk(root: &Path) -> Result<Vec<Found>> {
    let mut out = Vec::new();
    let mut stack = vec![(PathBuf::new(), Vec::new())];
    while let Some((dir_rel, dir_key)) = stack.pop() {
        let dir = root.join(&dir_rel);
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            // Removed since its parent was listed.
            Err(e) if e.kind() == ErrorKind::NotFound && !dir_key.is_empty() => continue,
            Err(e) => return Err(e).with_context(|| dir.display().to_string()),
        };
        for entry in entries {
            let entry = entry.with_context(|| dir.display().to_string())?;
            let name = entry.file_name();
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(e) if e.kind() == ErrorKind::NotFound => continue,
                Err(e) => return Err(e).with_context(|| entry.path().display().to_string()),
            };
            let Some(meta) = meta_of(&meta) else {
                tracing::debug!(
                    "not a file, directory or symlink: {}",
                    entry.path().display()
                );
                continue;
            };
            let rel = dir_rel.join(&name);
            let mut key = dir_key.clone();
            if !key.is_empty() {
                key.push(b'/');
            }
            key.extend_from_slice(name.as_encoded_bytes());
            if meta.kind == Kind::Dir {
                stack.push((rel.clone(), key.clone()));
            }
            out.push(Found { rel, key, meta });
        }
    }
    out.sort_unstable_by(|a, b| a.key.cmp(&b.key));
    Ok(out)
}

#[derive(Debug)]
struct Manifest {
    id: String,
    /// The id of the level 0 a differential was taken against.
    base: Option<String>,
    entries: HashMap<Vec<u8>, Meta>,
}

/// One line per path: kind, mode, size, mtime, ctime, path. Tab, newline, CR and backslash in a
/// path are escaped, so a line is always one path.
fn manifest_bytes<'a>(
    id: &str,
    base: Option<&str>,
    entries: impl Iterator<Item = &'a Found>,
) -> Vec<u8> {
    let mut out = format!("{MAGIC}{id}\t{}\n", base.unwrap_or("-")).into_bytes();
    for f in entries {
        let m = &f.meta;
        let kind = match m.kind {
            Kind::File => 'f',
            Kind::Dir => 'd',
            Kind::Link => 'l',
        };
        out.extend_from_slice(
            format!(
                "{kind}\t{:o}\t{}\t{}\t{}\t",
                m.mode, m.size, m.mtime, m.ctime
            )
            .as_bytes(),
        );
        for &b in &f.key {
            match b {
                b'\\' => out.extend_from_slice(b"\\\\"),
                b'\t' => out.extend_from_slice(b"\\t"),
                b'\n' => out.extend_from_slice(b"\\n"),
                b'\r' => out.extend_from_slice(b"\\r"),
                _ => out.push(b),
            }
        }
        out.push(b'\n');
    }
    out
}

fn unescape(path: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(path.len());
    let mut bytes = path.iter();
    while let Some(&b) = bytes.next() {
        out.push(if b == b'\\' {
            match bytes.next() {
                Some(b'\\') => b'\\',
                Some(b't') => b'\t',
                Some(b'n') => b'\n',
                Some(b'r') => b'\r',
                _ => bail!("bad escape in a manifest path"),
            }
        } else {
            b
        });
    }
    Ok(out)
}

fn parse_manifest(data: &[u8]) -> Result<Manifest> {
    let mut lines = data.split(|b| *b == b'\n');
    let header = std::str::from_utf8(lines.next().unwrap_or_default())
        .ok()
        .and_then(|h| h.strip_prefix(MAGIC))
        .and_then(|h| h.split_once('\t'))
        .filter(|(id, base)| !id.is_empty() && !base.is_empty());
    let Some((id, base)) = header else {
        bail!("not a preserver manifest (or a newer version of it)");
    };
    let mut entries = HashMap::new();
    for line in lines.filter(|l| !l.is_empty()) {
        let entry = (|| {
            let mut fields = line.splitn(6, |b| *b == b'\t');
            let mut text = || std::str::from_utf8(fields.next()?).ok();
            let kind = match text()? {
                "f" => Kind::File,
                "d" => Kind::Dir,
                "l" => Kind::Link,
                _ => return None,
            };
            let meta = Meta {
                kind,
                mode: u32::from_str_radix(text()?, 8).ok()?,
                size: text()?.parse().ok()?,
                mtime: text()?.parse().ok()?,
                ctime: text()?.parse().ok()?,
            };
            Some((unescape(fields.next()?).ok()?, meta))
        })();
        let (path, meta) = entry.context("bad line in the manifest")?;
        entries.insert(path, meta);
    }
    Ok(Manifest {
        id: id.to_string(),
        base: (base != "-").then(|| base.to_string()),
        entries,
    })
}

fn tmp_name(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_owned();
    name.push(".tmp");
    name.into()
}

fn remove_stale(file: &Path) -> io::Result<()> {
    match std::fs::remove_file(file) {
        Err(e) if e.kind() != ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Adds one path to the tar. `false` means it vanished or changed type since the walk: it is
/// left out, and out of the index too, so the next differential picks it up.
fn append(tar: &mut tar::Builder<impl Write>, root: &Path, found: &Found) -> io::Result<bool> {
    let path = root.join(&found.rel);
    let gone = |e: &io::Error| e.kind() == ErrorKind::NotFound;
    let meta = match std::fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if gone(&e) => return Ok(false),
        Err(e) => return Err(e),
    };
    if meta_of(&meta).map(|m| m.kind) != Some(found.meta.kind) {
        return Ok(false);
    }
    let mut header = tar::Header::new_gnu();
    header.set_metadata_in_mode(&meta, tar::HeaderMode::Complete);
    match found.meta.kind {
        Kind::Dir => {
            header.set_size(0);
            tar.append_data(&mut header, &found.rel, io::empty())?;
        }
        Kind::Link => {
            let target = match std::fs::read_link(&path) {
                Ok(t) => t,
                Err(e) if gone(&e) => return Ok(false),
                Err(e) => return Err(e),
            };
            header.set_size(0);
            tar.append_link(&mut header, &found.rel, target)?;
        }
        Kind::File => {
            let file = match File::open(&path) {
                Ok(f) => f,
                Err(e) if gone(&e) => return Ok(false),
                Err(e) => return Err(e),
            };
            let meta = file.metadata()?;
            if !meta.is_file() {
                return Ok(false);
            }
            header.set_metadata_in_mode(&meta, tar::HeaderMode::Complete);
            let size = meta.len();
            // The header promises `size` bytes: a file that grows is cut there, and one that
            // shrinks is padded with zeros, as GNU tar does. Its mtime moved, so the next run
            // archives it again.
            let data = file.take(size).chain(io::repeat(0)).take(size);
            tar.append_data(&mut header, &found.rel, data)?;
        }
    }
    Ok(true)
}

/// Writes the tar stream and returns the indexes of the entries that were left out.
fn write_tar(
    out: impl Write,
    root: &Path,
    manifest: &[u8],
    entries: &[&Found],
) -> Result<Vec<usize>> {
    let mut tar = tar::Builder::new(out);
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o600);
    header.set_size(manifest.len() as u64);
    header.set_mtime(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
    );
    tar.append_data(&mut header, MANIFEST, manifest)?;
    let mut left_out = Vec::new();
    for (i, found) in entries.iter().enumerate() {
        if !append(&mut tar, root, found)
            .with_context(|| root.join(&found.rel).display().to_string())?
        {
            left_out.push(i);
        }
    }
    tar.into_inner()?.flush()?;
    Ok(left_out)
}

/// ruzstd's encoder unwraps every read and write. This keeps the first I/O error out of its
/// sight (the stream just ends), so a full or unplugged drive is an error, not a panic.
struct Held<'a, T> {
    inner: T,
    error: &'a RefCell<Option<io::Error>>,
}

impl<T: Read> Read for Held<'_, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.error.borrow().is_some() {
            return Ok(0);
        }
        loop {
            match self.inner.read(buf) {
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => {
                    *self.error.borrow_mut() = Some(e);
                    return Ok(0);
                }
                ok => return ok,
            }
        }
    }
}

impl<T: Write> Write for Held<'_, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.error.borrow().is_none()
            && let Err(e) = self.inner.write_all(buf)
        {
            *self.error.borrow_mut() = Some(e);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Streams tar -> zstd -> age into `tmp` and syncs it. The tar side runs on its own thread
/// because the zstd encoder pulls from a reader. Returns the indexes of the entries left out.
fn write_archive(
    recipients: &[x25519::Recipient],
    tmp: &Path,
    root: &Path,
    manifest: &[u8],
    entries: &[&Found],
) -> Result<Vec<usize>> {
    remove_stale(tmp)?;
    let mut sealed = crypt::encrypt(recipients, BufWriter::new(platform::private_file_new(tmp)?))?;
    let (reader, writer) = io::pipe()?;
    let error = RefCell::new(None);
    let tarred = std::thread::scope(|s| {
        let tar = s.spawn(move || write_tar(BufWriter::new(writer), root, manifest, entries));
        let mut zstd = FrameCompressor::new(CompressionLevel::Fastest);
        zstd.set_source(Held {
            inner: reader,
            error: &error,
        });
        zstd.set_drain(Held {
            inner: &mut sealed,
            error: &error,
        });
        zstd.compress();
        // This closes the pipe, which ends a tar thread that is still writing after an error.
        drop(zstd);
        tar.join().unwrap_or_else(|p| std::panic::resume_unwind(p))
    });
    if let Some(e) = error.into_inner() {
        return Err(e).context("write the archive");
    }
    // Checked before the archive is completed: a tar that stopped early still ends as a valid zstd frame.
    let left_out = tarred?;
    sealed
        .finish()?
        .into_inner()
        .map_err(io::IntoInnerError::into_error)?
        .sync_all()?;
    Ok(left_out)
}

/// Writes one archive of `entries` to `dest`, visible only once it is complete and synced.
/// `before_rename` runs in between, for state that must exist before the archive does.
fn publish(
    recipients: &[x25519::Recipient],
    dest: &Path,
    root: &Path,
    manifest: &[u8],
    entries: &[&Found],
    before_rename: impl FnOnce(&[usize]) -> Result<()>,
) -> Result<()> {
    let tmp = tmp_name(dest);
    let done = write_archive(recipients, &tmp, root, manifest, entries).and_then(|left_out| {
        before_rename(&left_out)?;
        std::fs::rename(&tmp, dest)?;
        if let Some(dir) = dest.parent() {
            platform::sync_dir(dir)?;
        }
        Ok(())
    });
    if done.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    done.with_context(|| dest.display().to_string())
}

/// The number for the next `Dnn` in `dir`: one past the highest there.
fn next_differential(dir: &Path) -> Result<u32> {
    let mut next = 1;
    for entry in std::fs::read_dir(dir)? {
        let name = entry?.file_name();
        let n = name
            .to_str()
            .and_then(|n| n.strip_prefix('D'))
            .and_then(|n| n.strip_suffix(".tar.zst.age"))
            .filter(|n| n.len() == 2)
            .and_then(|n| n.parse::<u32>().ok());
        if let Some(n) = n {
            next = next.max(n + 1);
        }
    }
    if next > 99 {
        bail!("more than 99 differentials this month");
    }
    Ok(next)
}

/// A level 0 is taken each month; every later run that month is a differential against it.
fn backup_folder(
    paths: &Paths,
    recipients: &[x25519::Recipient],
    folder: &LocalFolder,
    now: &jiff::Zoned,
) -> Result<()> {
    let month = now.strftime("%Y-%m").to_string();
    let dir = paths.local_dest().join(&folder.name).join(&month);
    let state = paths.local_state.join(&folder.name);
    platform::private_dir_all(&dir)?;
    platform::private_dir_all(&state)?;
    let l0 = dir.join("L0.tar.zst.age");
    let index = state.join(format!("{month}.L0.idx"));
    let found = walk(&folder.path)?;
    let all: Vec<&Found> = found.iter().collect();
    let id = now.timestamp().to_string();

    if !l0.exists() {
        let manifest = manifest_bytes(&id, None, found.iter());
        publish(recipients, &l0, &folder.path, &manifest, &all, |left_out| {
            // The index is written first and synced: a level 0 without it could never get a differential.
            let archived = found
                .iter()
                .enumerate()
                .filter(|(i, _)| !left_out.contains(i))
                .map(|(_, f)| f);
            let tmp = tmp_name(&index);
            remove_stale(&tmp)?;
            let mut file = platform::private_file_new(&tmp)?;
            file.write_all(&manifest_bytes(&id, None, archived))?;
            file.sync_all()?;
            std::fs::rename(&tmp, &index)?;
            platform::sync_dir(&state)?;
            Ok(())
        })?;
        for entry in std::fs::read_dir(&state)? {
            let old = entry?.path();
            if old != index && old.to_string_lossy().ends_with(".L0.idx") {
                let _ = std::fs::remove_file(old);
            }
        }
        return Ok(());
    }

    let base = match std::fs::read(&index) {
        Ok(data) => parse_manifest(&data).with_context(|| index.display().to_string())?,
        Err(e) if e.kind() == ErrorKind::NotFound => bail!(
            "level 0 exists but its index {} is gone; move {} aside to start a new level 0",
            index.display(),
            dir.display()
        ),
        Err(e) => return Err(e).with_context(|| index.display().to_string()),
    };
    let changed: Vec<&Found> = found
        .iter()
        .filter(|f| base.entries.get(&f.key) != Some(&f.meta))
        .collect();
    let dest = dir.join(format!("D{:02}.tar.zst.age", next_differential(&dir)?));
    let manifest = manifest_bytes(&id, Some(&base.id), found.iter());
    publish(recipients, &dest, &folder.path, &manifest, &changed, |_| {
        Ok(())
    })
}

/// Backs up every folder. One failing folder does not stop the rest; a stop does, between
/// folders.
fn backup_all(
    paths: &Paths,
    recipients: &[x25519::Recipient],
    folders: &[LocalFolder],
    now: &jiff::Zoned,
    hooks: &Hooks,
) -> Result<()> {
    let mut failed = Vec::new();
    let mut stopped = false;
    for (n, folder) in folders.iter().enumerate() {
        if (hooks.stop)() {
            stopped = true;
            break;
        }
        (hooks.on_item)(n, folders.len(), &folder.name);
        if let Err(e) = backup_folder(paths, recipients, folder, now) {
            tracing::error!(folder = folder.name, "local backup: {e:#}");
            failed.push(folder.name.as_str());
        }
    }
    let dest = paths.local_dest();
    platform::private_dir_all(&dest)?;
    platform::sync_fs(&dest).context("sync")?;
    if stopped {
        return Err(Stopped.into());
    }
    if !failed.is_empty() {
        bail!(
            "{} of {} folders failed: {}",
            failed.len(),
            folders.len(),
            failed.join(" ")
        );
    }
    Ok(())
}

/// `paths.mnt` is the primary the caller located.
pub(crate) fn run(paths: &Paths, cfg: &Config, hooks: &Hooks) -> Result<()> {
    if cfg.local.is_empty() {
        return Ok(());
    }
    let recipients = crypt::read_recipients(&paths.personal.join("recipient.txt"))?;
    backup_all(paths, &recipients, &cfg.local, &jiff::Zoned::now(), hooks)
}

type Entries<'a> = tar::Entries<'a, Box<dyn Read>>;

fn open(identities: &Identities, file: &Path) -> Result<tar::Archive<Box<dyn Read>>> {
    let sealed = File::open(file).with_context(|| file.display().to_string())?;
    let plain = crypt::decrypt(identities, BufReader::new(sealed))
        .context("decrypt (is this the key the backup was made for?)")?;
    let zstd = StreamingDecoder::new(plain)
        .map_err(|e| anyhow!("{}: not a zstd stream: {e}", file.display()))?;
    Ok(tar::Archive::new(Box::new(zstd)))
}

fn read_manifest(entries: &mut Entries) -> Result<Manifest> {
    let first = entries.next().context("the archive is empty")??;
    if first.path_bytes().as_ref() != MANIFEST.as_bytes() {
        bail!(
            "no manifest: an archive that preserver did not write is restored with \
             'age -d FILE | zstd -d | tar -x --listed-incremental=/dev/null -C DIR'"
        );
    }
    let mut data = Vec::new();
    first.take(MANIFEST_LIMIT + 1).read_to_end(&mut data)?;
    if data.len() as u64 > MANIFEST_LIMIT {
        bail!("the manifest is larger than 1 GiB");
    }
    parse_manifest(&data)
}

/// An archive path as a path below the restore directory: only plain names, so no `..`, no root.
/// `None` is the directory itself.
fn safe_rel(path: &Path) -> Result<Option<PathBuf>> {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Normal(name) => out.push(name),
            Component::CurDir => {}
            _ => bail!("unsafe path in the archive: {}", shown(path)),
        }
    }
    Ok((!out.as_os_str().is_empty()).then_some(out))
}

/// Creates the missing parents of `rel` and returns its full path. Every parent must be a real
/// directory: nothing is ever written through a symlink the archive (or anyone) put there.
fn prepare(dir: &Path, rel: &Path) -> Result<PathBuf> {
    let mut at = dir.to_path_buf();
    let mut names = rel.components().peekable();
    while let Some(name) = names.next() {
        at.push(name);
        if names.peek().is_none() {
            break;
        }
        match std::fs::symlink_metadata(&at) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => bail!("{} is in the way: not a directory", shown(&at)),
            Err(e) if e.kind() == ErrorKind::NotFound => platform::private_dir_new(&at)?,
            Err(e) => return Err(e).with_context(|| shown(&at)),
        }
    }
    Ok(at)
}

/// Removes whatever is at `path`, without following a symlink.
fn clear(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// A path from the archive, with control characters escaped so it cannot steer the terminal.
fn shown(path: &Path) -> String {
    path.display().to_string().escape_debug().to_string()
}

/// Whether a symlink at `rel` with this target points outside the restore directory. A `..` after
/// a plain name is refused: it resolves against whatever the name is (another link may lead out),
/// not against the text before it. Only a leading run of `..` no deeper than `rel` is allowed.
pub(crate) fn escapes(rel: &Path, target: &Path) -> bool {
    let mut up = rel.components().count() - 1;
    let mut leading = true;
    for c in target.components() {
        match c {
            Component::Normal(_) => leading = false,
            Component::CurDir => {}
            Component::ParentDir => match up.checked_sub(1) {
                Some(u) if leading => up = u,
                _ => return true,
            },
            Component::RootDir | Component::Prefix(_) => return true,
        }
    }
    false
}

/// Extracts the rest of an archive over `dir`, replacing what is there. Returns what was skipped,
/// with each path.
fn extract(entries: &mut Entries, dir: &Path) -> Result<Vec<(PathBuf, String)>> {
    let mut skipped = Vec::new();
    for entry in entries {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let Some(rel) = safe_rel(&path)? else {
            continue;
        };
        let dest = prepare(dir, &rel)?;
        let written = match entry.header().entry_type() {
            tar::EntryType::Directory => match std::fs::symlink_metadata(&dest) {
                Ok(m) if m.is_dir() => Ok(()),
                _ => clear(&dest).and_then(|()| platform::private_dir_new(&dest)),
            },
            tar::EntryType::Regular => clear(&dest)
                .and_then(|()| platform::private_file_new(&dest))
                .and_then(|mut file| io::copy(&mut entry, &mut file).map(drop)),
            tar::EntryType::Symlink => {
                let target = entry
                    .link_name()?
                    .with_context(|| format!("{}: symlink without a target", shown(&rel)))?;
                clear(&dest)?;
                if escapes(&rel, &target) {
                    let msg = format!(
                        "{} -> {} (points outside the restore directory)",
                        shown(&rel),
                        shown(&target)
                    );
                    skipped.push((rel, msg));
                    continue;
                }
                platform::symlink(&target, &dest)
            }
            other => {
                let msg = format!("{} (tar entry type {other:?})", shown(&rel));
                skipped.push((rel, msg));
                continue;
            }
        };
        written.with_context(|| shown(&dest))?;
    }
    Ok(skipped)
}

fn system_time(nanos: i128) -> SystemTime {
    let d = Duration::from_nanos(u64::try_from(nanos.unsigned_abs()).unwrap_or(u64::MAX));
    let t = if nanos < 0 {
        UNIX_EPOCH.checked_sub(d)
    } else {
        UNIX_EPOCH.checked_add(d)
    };
    t.unwrap_or(UNIX_EPOCH)
}

/// Restores a `.tar.zst.age` into `dir`, which must be empty or absent. A differential is applied
/// over its level 0 (`L0.tar.zst.age` next to it): what its manifest no longer lists is removed.
/// Returns the entries that were skipped.
pub(crate) fn restore(identities: &Identities, file: &Path, dir: &Path) -> Result<Vec<String>> {
    check_target(dir)?;
    let mut top = open(identities, file)?;
    let mut top_entries = top.entries()?;
    let manifest = read_manifest(&mut top_entries)?;
    std::fs::create_dir_all(dir).with_context(|| dir.display().to_string())?;

    let mut from_l0 = Vec::new();
    if let Some(base) = &manifest.base {
        let l0 = file.with_file_name("L0.tar.zst.age");
        let mut archive = open(identities, &l0).context("the level 0 of this differential")?;
        let mut entries = archive.entries()?;
        if read_manifest(&mut entries)?.id != *base {
            bail!(
                "{} is not the level 0 this differential was taken against",
                l0.display()
            );
        }
        from_l0 = extract(&mut entries, dir)?;
        for found in walk(dir)? {
            if !manifest.entries.contains_key(&found.key) {
                clear(&dir.join(&found.rel))?;
            }
        }
    }
    let mut skipped = extract(&mut top_entries, dir)?;
    // A level 0 skip is a loss only if the path is still wanted and the differential did not
    // bring it back (or skip it itself).
    let mut dropped: Vec<_> = from_l0
        .into_iter()
        .filter(|(rel, _)| {
            let key = rel
                .components()
                .map(|c| c.as_os_str().as_encoded_bytes())
                .collect::<Vec<_>>()
                .join(&b'/');
            manifest.entries.contains_key(&key)
                && std::fs::symlink_metadata(dir.join(rel)).is_err()
                && !skipped.iter().any(|(r, _)| r == rel)
        })
        .collect();
    dropped.append(&mut skipped);
    let skipped = dropped;

    // Modes and times come from the manifest, which has them for every path, changed or not.
    // Children go first: writing into a directory would move its mtime again.
    for found in walk(dir)?.iter().rev() {
        let Some(meta) = manifest.entries.get(&found.key) else {
            continue;
        };
        if meta.kind != found.meta.kind || meta.kind == Kind::Link {
            continue;
        }
        let path = dir.join(&found.rel);
        File::open(&path)
            .and_then(|f| f.set_modified(system_time(meta.mtime)))
            .and_then(|()| platform::set_mode(&path, meta.mode & 0o777))
            .with_context(|| shown(&path))?;
    }
    Ok(skipped.into_iter().map(|(_, msg)| msg).collect())
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, paths};
    use std::collections::BTreeMap;
    use std::os::unix::fs::{PermissionsExt, symlink};

    struct Setup {
        tmp: TempDir,
        paths: Paths,
        recipients: Vec<x25519::Recipient>,
        identities: Identities,
        folder: LocalFolder,
    }

    fn setup() -> Setup {
        let tmp = TempDir::new();
        let paths = paths(tmp.path());
        let id = x25519::Identity::generate();
        let folder = LocalFolder {
            name: "docs".to_string(),
            path: tmp.path().join("src"),
            origin: None,
        };
        std::fs::create_dir(&folder.path).unwrap();
        Setup {
            paths,
            recipients: vec![id.to_public()],
            identities: vec![Box::new(id)],
            folder,
            tmp,
        }
    }

    impl Setup {
        fn backup(&self, when: &str) {
            backup_folder(
                &self.paths,
                &self.recipients,
                &self.folder,
                &when.parse().unwrap(),
            )
            .unwrap();
        }

        fn archive(&self, month: &str, name: &str) -> PathBuf {
            self.paths
                .local_dest()
                .join("docs")
                .join(month)
                .join(format!("{name}.tar.zst.age"))
        }

        fn restore(&self, month: &str, name: &str) -> PathBuf {
            let out = self.tmp.path().join(format!("out-{month}-{name}"));
            let skipped = restore(&self.identities, &self.archive(month, name), &out).unwrap();
            assert_eq!(skipped, Vec::<String>::new());
            out
        }

        fn write(&self, rel: &str, content: &str, mtime: u64) {
            let path = self.folder.path.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, content).unwrap();
            set_mtime(&path, mtime);
        }
    }

    fn set_mtime(path: &Path, secs: u64) {
        File::open(path)
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::new(secs, 123_456_789))
            .unwrap();
    }

    /// Every path with its type, mode, mtime (files and dirs) and content or link target.
    fn tree(root: &Path) -> BTreeMap<String, String> {
        walk(root)
            .unwrap()
            .into_iter()
            .map(|f| {
                let path = root.join(&f.rel);
                let detail = match f.meta.kind {
                    Kind::File => format!(
                        "file {:o} {} {:?}",
                        f.meta.mode,
                        f.meta.mtime,
                        std::fs::read_to_string(&path).unwrap()
                    ),
                    Kind::Dir => format!("dir {:o} {}", f.meta.mode, f.meta.mtime),
                    Kind::Link => format!("link {}", std::fs::read_link(&path).unwrap().display()),
                };
                (String::from_utf8_lossy(&f.key).into_owned(), detail)
            })
            .collect()
    }

    const DAY1: &str = "2026-11-01T02:00:00+00:00[UTC]";
    const DAY2: &str = "2026-11-02T02:00:00+00:00[UTC]";
    const DAY3: &str = "2026-11-03T02:00:00+00:00[UTC]";

    fn populate(s: &Setup) {
        s.write("keep.txt", "same", 1_000);
        s.write("change.txt", "before", 1_000);
        s.write("same-size.txt", "aaaa", 1_000);
        s.write("delete.txt", "gone soon", 1_000);
        s.write("sub/deep/file.bin", "deep", 1_000);
        s.write("sub/removed-dir/x", "x", 1_000);
        s.write("ünï/файл 名前.txt", "unicode", 1_000);
        s.write("tab\tnew\nline\\back", "escaped", 1_000);
        s.write("to-dir", "a file that becomes a directory", 1_000);
        s.write("to-file/inner", "a directory that becomes a file", 1_000);
        s.write(&format!("long/{}/f", "n".repeat(150)), "long path", 1_000);
        s.write("empty-file", "", 1_000);
        std::fs::create_dir_all(s.folder.path.join("empty-dir/nested-empty")).unwrap();
        std::fs::set_permissions(
            s.folder.path.join("keep.txt"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        std::fs::set_permissions(
            s.folder.path.join("sub/deep"),
            std::fs::Permissions::from_mode(0o750),
        )
        .unwrap();
        symlink("keep.txt", s.folder.path.join("link")).unwrap();
        symlink("../keep.txt", s.folder.path.join("sub/up-link")).unwrap();
        symlink("nowhere", s.folder.path.join("dangling")).unwrap();
        set_mtime(&s.folder.path.join("empty-dir"), 2_000);
    }

    #[test]
    fn level_0_then_differentials_round_trip() {
        let s = setup();
        populate(&s);
        let day1 = tree(&s.folder.path);
        s.backup(DAY1);
        assert!(s.archive("2026-11", "L0").exists());
        assert!(s.paths.local_state.join("docs/2026-11.L0.idx").exists());
        assert_eq!(tree(&s.restore("2026-11", "L0")), day1);

        s.write("change.txt", "after, and longer", 5_000);
        s.write("same-size.txt", "bbbb", 5_000);
        s.write("added.txt", "new", 5_000);
        s.write("sub/new-dir/added", "new in a new dir", 5_000);
        std::fs::remove_file(s.folder.path.join("delete.txt")).unwrap();
        std::fs::remove_dir_all(s.folder.path.join("sub/removed-dir")).unwrap();
        std::fs::remove_dir(s.folder.path.join("empty-dir/nested-empty")).unwrap();
        std::fs::remove_file(s.folder.path.join("to-dir")).unwrap();
        s.write("to-dir/child", "now a directory", 5_000);
        std::fs::remove_dir_all(s.folder.path.join("to-file")).unwrap();
        s.write("to-file", "now a file", 5_000);
        std::fs::remove_file(s.folder.path.join("link")).unwrap();
        symlink("change.txt", s.folder.path.join("link")).unwrap();
        std::fs::remove_file(s.folder.path.join("dangling")).unwrap();
        std::fs::create_dir(s.folder.path.join("new-empty-dir")).unwrap();
        let day2 = tree(&s.folder.path);
        s.backup(DAY2);
        assert_eq!(tree(&s.restore("2026-11", "D01")), day2);

        // A differential is against the level 0, not the day before: D02 alone carries day 2's changes too.
        s.write("change.txt", "third", 9_000);
        std::fs::remove_file(s.folder.path.join("added.txt")).unwrap();
        let day3 = tree(&s.folder.path);
        s.backup(DAY3);
        std::fs::remove_file(s.archive("2026-11", "D01")).unwrap();
        assert_eq!(tree(&s.restore("2026-11", "D02")), day3);
        assert_ne!(day1, day2);
        assert_ne!(day2, day3);
    }

    #[test]
    fn differential_holds_only_what_changed() {
        let s = setup();
        populate(&s);
        s.backup(DAY1);
        s.write("added.txt", "new", 5_000);
        s.backup(DAY2);

        let mut archive = open(&s.identities, &s.archive("2026-11", "D01")).unwrap();
        let mut entries = archive.entries().unwrap();
        let manifest = read_manifest(&mut entries).unwrap();
        assert!(manifest.base.is_some());
        assert!(manifest.entries.contains_key(&b"keep.txt"[..]));
        assert!(
            manifest
                .entries
                .contains_key("tab\tnew\nline\\back".as_bytes())
        );
        let names: Vec<_> = entries
            .map(|e| e.unwrap().path().unwrap().display().to_string())
            .collect();
        assert_eq!(names, ["added.txt"]);
    }

    #[test]
    fn archives_are_gnu_tar_inside_zstd_inside_age() {
        let s = setup();
        s.write("a.txt", "hello", 1_000);
        s.backup(DAY1);
        let sealed = std::fs::read(s.archive("2026-11", "L0")).unwrap();
        assert!(sealed.starts_with(b"age-encryption.org/v1\n"));
        let mut zst = Vec::new();
        crypt::decrypt(&s.identities, &sealed[..])
            .unwrap()
            .read_to_end(&mut zst)
            .unwrap();
        assert_eq!(zst[..4], [0x28, 0xb5, 0x2f, 0xfd], "zstd magic");

        // The recovery path without preserver: the stock tools read what ruzstd and tar wrote.
        let plain = s.tmp.path().join("plain.tar.zst");
        std::fs::write(&plain, &zst).unwrap();
        let out = s.tmp.path().join("gnu");
        std::fs::create_dir(&out).unwrap();
        match std::process::Command::new("tar")
            .arg("--zstd")
            .arg("-xf")
            .arg(&plain)
            .arg("-C")
            .arg(&out)
            .output()
        {
            Ok(tar) => {
                assert!(
                    tar.status.success(),
                    "{}",
                    String::from_utf8_lossy(&tar.stderr)
                );
                assert_eq!(std::fs::read_to_string(out.join("a.txt")).unwrap(), "hello");
                assert!(out.join(MANIFEST).exists());
            }
            Err(e) => eprintln!("skipped the GNU tar check: {e}"),
        }
        let mode = |p: PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(s.archive("2026-11", "L0")), 0o600);
        assert_eq!(mode(s.paths.local_dest().join("docs/2026-11")), 0o700);
        let left: Vec<_> = std::fs::read_dir(s.paths.local_dest().join("docs/2026-11"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, ["L0.tar.zst.age"], "no .tmp is left");
    }

    #[test]
    fn a_new_month_starts_a_new_level_0() {
        let s = setup();
        s.write("a.txt", "one", 1_000);
        s.backup("2026-11-30T02:00:00+00:00[UTC]");
        s.write("a.txt", "two", 2_000);
        s.backup("2026-12-01T02:00:00+00:00[UTC]");
        assert!(s.archive("2026-12", "L0").exists());
        assert!(!s.archive("2026-11", "D01").exists());
        let state: Vec<_> = std::fs::read_dir(s.paths.local_state.join("docs"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(state, ["2026-12.L0.idx"], "the old index is removed");
        let out = s.restore("2026-12", "L0");
        assert_eq!(std::fs::read_to_string(out.join("a.txt")).unwrap(), "two");
    }

    #[test]
    fn differentials_are_numbered_after_the_highest() {
        let s = setup();
        s.backup(DAY1);
        let dir = s.paths.local_dest().join("docs/2026-11");
        for (existing, next) in [
            (vec![], 1),
            (vec!["D01.tar.zst.age"], 2),
            (
                vec![
                    "D07.tar.zst.age",
                    "D1.tar.zst.age",
                    "Dxx.tar.zst.age",
                    "D123.tar.zst.age",
                    "D09.tar.zst.age.tmp",
                ],
                8,
            ),
            (vec!["D98.tar.zst.age"], 99),
        ] {
            for name in &existing {
                std::fs::write(dir.join(name), "").unwrap();
            }
            assert_eq!(next_differential(&dir).unwrap(), next, "{existing:?}");
        }
        std::fs::write(dir.join("D99.tar.zst.age"), "").unwrap();
        assert!(next_differential(&dir).is_err());
        assert!(backup_folder(&s.paths, &s.recipients, &s.folder, &DAY2.parse().unwrap()).is_err());
    }

    #[test]
    fn a_level_0_without_its_index_is_not_guessed_at() {
        let s = setup();
        s.write("a.txt", "one", 1_000);
        s.backup(DAY1);
        std::fs::remove_file(s.paths.local_state.join("docs/2026-11.L0.idx")).unwrap();
        let err =
            backup_folder(&s.paths, &s.recipients, &s.folder, &DAY2.parse().unwrap()).unwrap_err();
        assert!(format!("{err:#}").contains("move"), "{err:#}");
        assert!(!s.archive("2026-11", "D01").exists());
    }

    #[test]
    fn one_failing_folder_does_not_stop_the_rest() {
        let s = setup();
        s.write("a.txt", "one", 1_000);
        let folders = [
            LocalFolder {
                name: "missing".to_string(),
                path: s.tmp.path().join("absent"),
                origin: None,
            },
            LocalFolder {
                name: "docs".to_string(),
                path: s.folder.path.clone(),
                origin: None,
            },
        ];
        let err = backup_all(
            &s.paths,
            &s.recipients,
            &folders,
            &DAY1.parse().unwrap(),
            &Hooks::NONE,
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "1 of 2 folders failed: missing");
        assert!(s.archive("2026-11", "L0").exists());
        assert!(
            !s.paths
                .local_dest()
                .join("missing/2026-11/L0.tar.zst.age")
                .exists()
        );
        assert!(
            !s.paths
                .local_dest()
                .join("missing/2026-11/L0.tar.zst.age.tmp")
                .exists()
        );
    }

    #[test]
    fn an_unreadable_file_fails_the_folder_and_leaves_no_archive() {
        let s = setup();
        s.write("secret", "x", 1_000);
        std::fs::set_permissions(
            s.folder.path.join("secret"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        if File::open(s.folder.path.join("secret")).is_ok() {
            return; // root reads anything
        }
        let err =
            backup_folder(&s.paths, &s.recipients, &s.folder, &DAY1.parse().unwrap()).unwrap_err();
        assert!(format!("{err:#}").contains("secret"), "{err:#}");
        assert_eq!(
            std::fs::read_dir(s.paths.local_dest().join("docs/2026-11"))
                .unwrap()
                .count(),
            0
        );
        assert!(!s.paths.local_state.join("docs/2026-11.L0.idx").exists());
    }

    #[test]
    fn restore_needs_the_matching_level_0() {
        let s = setup();
        s.write("a.txt", "one", 1_000);
        s.backup(DAY1);
        s.backup(DAY2);
        let d01 = s.archive("2026-11", "D01");

        let elsewhere = s.tmp.path().join("copy/D01.tar.zst.age");
        std::fs::create_dir_all(elsewhere.parent().unwrap()).unwrap();
        std::fs::copy(&d01, &elsewhere).unwrap();
        let out = s.tmp.path().join("out");
        let err = restore(&s.identities, &elsewhere, &out).unwrap_err();
        assert!(format!("{err:#}").contains("level 0"), "{err:#}");

        // Another month's level 0 put in its place is refused by its id.
        s.backup("2026-12-01T02:00:00+00:00[UTC]");
        std::fs::copy(
            s.archive("2026-12", "L0"),
            elsewhere.with_file_name("L0.tar.zst.age"),
        )
        .unwrap();
        let err = restore(&s.identities, &elsewhere, &out).unwrap_err();
        assert!(format!("{err:#}").contains("not the level 0"), "{err:#}");
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
    }

    #[test]
    fn restore_refuses_a_wrong_key_and_a_used_directory() {
        let s = setup();
        s.write("a.txt", "one", 1_000);
        s.backup(DAY1);
        let l0 = s.archive("2026-11", "L0");
        let out = s.tmp.path().join("out");
        let other: Identities = vec![Box::new(x25519::Identity::generate())];
        assert!(restore(&other, &l0, &out).is_err());
        assert!(!out.exists());

        std::fs::create_dir(&out).unwrap();
        std::fs::write(out.join("mine"), "keep").unwrap();
        let err = restore(&s.identities, &l0, &out).unwrap_err();
        assert!(err.to_string().contains("not empty"), "{err}");
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 1);
    }

    /// An archive as someone with the drive and the public recipient could craft it.
    fn crafted(s: &Setup, build: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> PathBuf {
        let mut tar = tar::Builder::new(Vec::new());
        let manifest = manifest_bytes("x", None, std::iter::empty());
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest.len() as u64);
        header.set_mode(0o600);
        tar.append_data(&mut header, MANIFEST, &manifest[..])
            .unwrap();
        build(&mut tar);
        let plain = tar.into_inner().unwrap();
        let file = s.tmp.path().join("crafted.tar.zst.age");
        let mut sealed = crypt::encrypt(&s.recipients, File::create(&file).unwrap()).unwrap();
        sealed
            .write_all(&ruzstd::encoding::compress_to_vec(
                &plain[..],
                CompressionLevel::Fastest,
            ))
            .unwrap();
        sealed.finish().unwrap();
        file
    }

    /// A header with a path the tar crate's own builder would refuse to write.
    fn raw_entry(
        tar: &mut tar::Builder<Vec<u8>>,
        path: &str,
        kind: tar::EntryType,
        link: &str,
        data: &[u8],
    ) {
        let mut header = tar::Header::new_gnu();
        header.as_old_mut().name[..path.len()].copy_from_slice(path.as_bytes());
        header.as_old_mut().linkname[..link.len()].copy_from_slice(link.as_bytes());
        header.set_entry_type(kind);
        header.set_mode(0o644);
        header.set_size(data.len() as u64);
        header.set_cksum();
        tar.append(&header, data).unwrap();
    }

    #[test]
    fn extraction_refuses_traversal() {
        use tar::EntryType::{Directory, Regular, Symlink};
        type Build = fn(&mut tar::Builder<Vec<u8>>);
        let cases: [(&str, Build); 5] = [
            ("dot-dot", |t| raw_entry(t, "../escaped", Regular, "", b"x")),
            ("dot-dot inside", |t| {
                raw_entry(t, "a/../../escaped", Regular, "", b"x");
            }),
            ("absolute", |t| {
                raw_entry(t, "/tmp/preserver-test-escaped", Regular, "", b"x");
            }),
            ("through a symlink to outside", |t| {
                raw_entry(t, "a", Symlink, "inside", b"");
                raw_entry(t, "inside", Symlink, "..", b"");
                raw_entry(t, "a/escaped", Regular, "", b"x");
            }),
            ("directory through a symlink", |t| {
                raw_entry(t, "real", Directory, "", b"");
                raw_entry(t, "alias", Symlink, "real", b"");
                raw_entry(t, "alias/sub/escaped", Regular, "", b"x");
            }),
        ];
        for (name, build) in cases {
            let s = setup();
            let file = crafted(&s, build);
            let out = s.tmp.path().join("jail/out");
            let result = restore(&s.identities, &file, &out);
            assert!(result.is_err(), "{name}");
            let escaped: Vec<_> = walk(s.tmp.path())
                .unwrap()
                .into_iter()
                .filter(|f| f.rel.ends_with("escaped"))
                .collect();
            assert!(escaped.is_empty(), "{name}: {escaped:?}");
            assert!(!Path::new("/tmp/preserver-test-escaped").exists(), "{name}");
        }
    }

    #[test]
    fn symlinks_that_leave_the_directory_are_skipped_and_reported() {
        use tar::EntryType::{Link, Regular, Symlink};
        let s = setup();
        let file = crafted(&s, |t| {
            raw_entry(t, "abs", Symlink, "/etc/passwd", b"");
            raw_entry(t, "sub/up2", Symlink, "../../x", b"");
            raw_entry(t, "sub/up1", Symlink, "../ok.txt", b"");
            raw_entry(t, "hard", Link, "ok.txt", b"");
            raw_entry(t, "ok.txt", Regular, "", b"fine");
            raw_entry(t, "./dot/./ok", Regular, "", b"fine");
            raw_entry(t, "a/b/s", Symlink, "../..", b"");
            raw_entry(t, "notes.md", Symlink, "a/b/s/../../.bashrc", b"");
        });
        let out = s.tmp.path().join("out");
        let skipped = restore(&s.identities, &file, &out).unwrap();
        assert_eq!(skipped.len(), 4, "{skipped:?}");
        assert!(skipped[0].starts_with("abs -> /etc/passwd"), "{skipped:?}");
        assert!(skipped[1].starts_with("sub/up2 -> ../../x"), "{skipped:?}");
        assert!(skipped[2].starts_with("hard "), "{skipped:?}");
        assert!(skipped[3].starts_with("notes.md -> "), "{skipped:?}");
        let names: Vec<_> = tree(&out).into_keys().collect();
        assert_eq!(
            names,
            [
                "a", "a/b", "a/b/s", "dot", "dot/ok", "ok.txt", "sub", "sub/up1"
            ]
        );
        assert_eq!(
            std::fs::read_to_string(out.join("sub/up1")).unwrap(),
            "fine"
        );
    }

    #[test]
    fn restore_names_what_is_not_ours() {
        let s = setup();
        let plain = {
            let mut tar = tar::Builder::new(Vec::new());
            raw_entry(&mut tar, "./", tar::EntryType::Directory, "", b"");
            tar.into_inner().unwrap()
        };
        let file = s.tmp.path().join("foreign.tar.zst.age");
        let mut sealed = crypt::encrypt(&s.recipients, File::create(&file).unwrap()).unwrap();
        sealed
            .write_all(&ruzstd::encoding::compress_to_vec(
                &plain[..],
                CompressionLevel::Fastest,
            ))
            .unwrap();
        sealed.finish().unwrap();
        let err = restore(&s.identities, &file, &s.tmp.path().join("out")).unwrap_err();
        assert!(err.to_string().contains("listed-incremental"), "{err}");

        let mut sealed = crypt::encrypt(&s.recipients, File::create(&file).unwrap()).unwrap();
        sealed.write_all(b"not zstd at all").unwrap();
        sealed.finish().unwrap();
        assert!(restore(&s.identities, &file, &s.tmp.path().join("out")).is_err());
        assert!(!s.tmp.path().join("out").exists());
    }

    #[test]
    fn manifest_round_trips_and_rejects_garbage() {
        let meta = |kind, mode, size, mtime, ctime| Meta {
            kind,
            mode,
            size,
            mtime,
            ctime,
        };
        let found = [
            (
                &b"plain"[..],
                meta(Kind::File, 0o644, 5, 1_700_000_000_123_456_789, 7),
            ),
            (b"dir/sub", meta(Kind::Dir, 0o2755, 0, -5, 0)),
            (
                b"tab\there\nnl\rcr\\bs",
                meta(Kind::Link, 0o777, 3, 0, i128::MAX),
            ),
            (
                b"not utf8 \xff\xfe",
                meta(Kind::File, 0, u64::MAX, i128::MIN, -1),
            ),
        ]
        .map(|(key, meta)| Found {
            rel: PathBuf::new(),
            key: key.to_vec(),
            meta,
        });
        for base in [None, Some("2026-11-01T02:00:00Z")] {
            let bytes = manifest_bytes("2026-11-02T02:00:00Z", base, found.iter());
            assert_eq!(bytes.split(|b| *b == b'\n').count(), 6, "one line per path");
            let m = parse_manifest(&bytes).unwrap();
            assert_eq!(m.id, "2026-11-02T02:00:00Z");
            assert_eq!(m.base.as_deref(), base);
            assert_eq!(m.entries.len(), found.len());
            for f in &found {
                assert_eq!(m.entries.get(&f.key), Some(&f.meta), "{:?}", f.key);
            }
        }

        let ok = "preserver-manifest\t1\tid\t-\n";
        assert!(parse_manifest(ok.as_bytes()).unwrap().entries.is_empty());
        let cases = [
            ("empty", String::new()),
            ("other magic", "something else\n".to_string()),
            (
                "newer version",
                "preserver-manifest\t2\tid\t-\n".to_string(),
            ),
            ("no base field", "preserver-manifest\t1\tid\n".to_string()),
            ("empty id", "preserver-manifest\t1\t\t-\n".to_string()),
            ("unknown kind", format!("{ok}x\t644\t1\t1\t1\tp\n")),
            ("mode not octal", format!("{ok}f\t9\t1\t1\t1\tp\n")),
            ("negative size", format!("{ok}f\t644\t-1\t1\t1\tp\n")),
            ("missing path", format!("{ok}f\t644\t1\t1\t1\n")),
            ("bad escape", format!("{ok}f\t644\t1\t1\t1\ta\\qb\n")),
            ("trailing backslash", format!("{ok}f\t644\t1\t1\t1\ta\\\n")),
        ];
        for (name, text) in cases {
            assert!(parse_manifest(text.as_bytes()).is_err(), "{name}");
        }
    }

    #[test]
    fn a_differential_reports_what_its_level_0_skipped() {
        let s = setup();
        symlink("/etc/hostname", s.folder.path.join("abs")).unwrap();
        symlink("/etc/hostname", s.folder.path.join("gone")).unwrap();
        s.write("f.txt", "one", 1_000);
        s.backup(DAY1);
        std::fs::remove_file(s.folder.path.join("gone")).unwrap();
        s.write("f.txt", "two", 2_000);
        s.backup(DAY2);
        let out = s.tmp.path().join("out");
        let skipped = restore(&s.identities, &s.archive("2026-11", "D01"), &out).unwrap();
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert!(
            skipped[0].starts_with("abs -> /etc/hostname"),
            "{skipped:?}"
        );
    }

    #[test]
    fn control_characters_in_archive_names_are_escaped() {
        use tar::EntryType::Symlink;
        let s = setup();
        let file = crafted(&s, |t| {
            raw_entry(t, "x\u{1b}[2K", Symlink, "/a\u{1b}]0;t", b"");
        });
        let skipped = restore(&s.identities, &file, &s.tmp.path().join("out")).unwrap();
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert!(!skipped[0].contains('\u{1b}'), "{skipped:?}");
    }

    #[test]
    fn symlink_escape_rule() {
        let cases = [
            ("a", "b", false),
            ("a", "./b/../c", true),
            ("d/a", "b/../c", true),
            ("d/e/a", "../../x", false),
            ("a", "..", true),
            ("a", "../x", true),
            ("d/a", "..", false),
            ("d/a", "../x", false),
            ("d/a", "../../x", true),
            ("d/a", "x/../../../y", true),
            ("d/e/a", "../../x", false),
            ("a", "/abs", true),
            ("a", "", false),
        ];
        for (rel, target, want) in cases {
            assert_eq!(
                escapes(Path::new(rel), Path::new(target)),
                want,
                "{rel} -> {target}"
            );
        }
    }

    #[test]
    fn what_vanishes_after_the_walk_is_left_out_of_the_index() {
        let s = setup();
        s.write("stays.txt", "x", 1_000);
        s.write("vanishes.txt", "x", 1_000);
        s.write("becomes-dir", "x", 1_000);
        let found = walk(&s.folder.path).unwrap();
        std::fs::remove_file(s.folder.path.join("vanishes.txt")).unwrap();
        std::fs::remove_file(s.folder.path.join("becomes-dir")).unwrap();
        std::fs::create_dir(s.folder.path.join("becomes-dir")).unwrap();
        let all: Vec<&Found> = found.iter().collect();
        let mut out = Vec::new();
        let left_out = write_tar(&mut out, &s.folder.path, b"m", &all).unwrap();
        let names: Vec<_> = left_out
            .iter()
            .map(|i| found[*i].rel.display().to_string())
            .collect();
        assert_eq!(names, ["becomes-dir", "vanishes.txt"]);
        let mut archive = tar::Archive::new(&out[..]);
        let stored: Vec<_> = archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().display().to_string())
            .collect();
        assert_eq!(stored, [MANIFEST, "stays.txt"]);
    }

    #[test]
    fn a_failing_destination_is_an_error_not_a_panic() {
        struct Full;
        impl Write for Full {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::from(ErrorKind::StorageFull))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let s = setup();
        s.write("big", &"x".repeat(4 << 20), 1_000);
        let found = walk(&s.folder.path).unwrap();
        let all: Vec<&Found> = found.iter().collect();
        let error = RefCell::new(None);
        let (reader, writer) = io::pipe().unwrap();
        let tarred = std::thread::scope(|scope| {
            let tar = scope.spawn(|| write_tar(BufWriter::new(writer), &s.folder.path, b"m", &all));
            let mut zstd = FrameCompressor::new(CompressionLevel::Fastest);
            zstd.set_source(Held {
                inner: reader,
                error: &error,
            });
            zstd.set_drain(Held {
                inner: Full,
                error: &error,
            });
            zstd.compress();
            drop(zstd);
            tar.join().unwrap()
        });
        assert_eq!(error.into_inner().unwrap().kind(), ErrorKind::StorageFull);
        assert!(tarred.is_err(), "the tar thread ends on the closed pipe");
    }

    #[test]
    fn modes_are_restored_without_special_bits() {
        let s = setup();
        s.write("tool", "#!/bin/sh\n", 1_000);
        std::fs::set_permissions(
            s.folder.path.join("tool"),
            std::fs::Permissions::from_mode(0o4755),
        )
        .unwrap();
        s.backup(DAY1);
        let out = s.tmp.path().join("out");
        restore(&s.identities, &s.archive("2026-11", "L0"), &out).unwrap();
        let mode = std::fs::metadata(out.join("tool"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o755);
    }
}
