//! The filesystem layer of a generation: the tree's bookkeeping files, the swap journal and its
//! roll-forward, and prune. Everything under `<tree>/.preserver/`:
//!
//! - `live.tsv`: the payload of the generation that is visible, sorted by `path_cmp`;
//! - `swap.json`: the journal of a swap in progress, removed last;
//! - `staging/<gen16>/{meta,old,live.tsv}`: the new swap paths, what they replace, and the
//!   `live.tsv` that goes with them.

use super::{Anchor, Check, Entry, alpine, rel_path};
use crate::copy::exec::{ensure_dir, safe_rel};
use crate::copy::plan::{Limits, bad_windows_name};
use crate::net::download::{Expect, Fetch};
use crate::platform;
use crate::public::versioned::{link_or_copy, plain_dirs, read_meta};
use crate::queue::{Planned, Whole};
use crate::resolve::hex;
use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fmt::{self, Write as _};
use std::fs;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

const BOOK: &str = ".preserver";
const MAGIC: &str = "#preserver-mirror";
/// Longest tsv line without its newline.
const LINE_CAP: usize = 4096;
const LINES_CAP: usize = 10_000_000;

/// The order of a depth-first walk that visits each directory's names in byte order: component
/// by component, so `a/b` sorts before `a.b` although `/` is above `.` in ASCII.
pub(crate) fn path_cmp(a: &str, b: &str) -> Ordering {
    a.split('/').cmp(b.split('/'))
}

/// `base` and `rel`, with every byte outside RFC 3986's unreserved set percent-encoded.
pub(crate) fn url_of(base: &str, rel: &str) -> String {
    let mut u = base.trim_end_matches('/').to_string();
    for c in rel.split('/') {
        u.push('/');
        for b in c.bytes() {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                u.push(char::from(b));
            } else {
                let _ = write!(u, "%{b:02X}");
            }
        }
    }
    u
}

/// The one check for every path a walk, a tsv line, the journal or an anchor names: plain
/// relative components, no control characters, nothing hidden (that keeps `.preserver` and
/// the `.part` sidecars out of reach). On Windows a `:` would make a component a drive prefix
/// (`C:x`), which `PathBuf::push` takes as a new root, or an NTFS stream name.
pub(crate) fn valid_path(rel: &str) -> bool {
    safe_rel(rel)
        && !rel.chars().any(char::is_control)
        && !rel
            .split('/')
            .any(|c| c.starts_with('.') || (cfg!(windows) && c.contains(':')))
}

fn under(p: &str, root: &str) -> bool {
    p.strip_prefix(root)
        .is_some_and(|t| t.is_empty() || t.starts_with('/'))
}

fn is_gen(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn book(tree: &Path) -> PathBuf {
    tree.join(BOOK)
}

fn journal_path(tree: &Path) -> PathBuf {
    book(tree).join("swap.json")
}

pub(crate) fn live_path(tree: &Path) -> PathBuf {
    book(tree).join("live.tsv")
}

pub(crate) fn staging_root(tree: &Path) -> PathBuf {
    book(tree).join("staging")
}

pub(crate) fn stage_dir(tree: &Path, generation: &str) -> PathBuf {
    staging_root(tree).join(&generation[..16])
}

/// The first line of `live.tsv` and of a staged one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Header {
    pub generation: String,
    pub files: u64,
    pub bytes: u64,
    pub at: jiff::Timestamp,
    /// Each anchor document's path with its metalink's `mm0:timestamp` at the commit (Fedora
    /// rollback rule), in the order `gen_of` hashed them.
    pub anchor_ts: Vec<(String, u64)>,
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{MAGIC}\t1\t{}\t{}\t{}\t{}",
            self.generation, self.files, self.bytes, self.at
        )?;
        for (p, t) in &self.anchor_ts {
            write!(f, "\t{t}:{p}")?;
        }
        Ok(())
    }
}

fn parse_header(line: &str) -> Result<Header> {
    let f: Vec<&str> = line.split('\t').collect();
    let [MAGIC, "1", generation, files, bytes, at, ts @ ..] = &f[..] else {
        bail!("not a preserver-mirror version 1 header");
    };
    if !is_gen(generation) {
        bail!("bad generation {generation:?}");
    }
    Ok(Header {
        generation: generation.to_string(),
        files: files.parse().context("file count")?,
        bytes: bytes.parse().context("byte count")?,
        at: at.parse().context("time")?,
        anchor_ts: ts
            .iter()
            .map(|f| {
                let (t, p) = f.split_once(':').context("anchor timestamp")?;
                if !valid_path(p) {
                    bail!("invalid anchor path {p:?}");
                }
                Ok((p.to_string(), t.parse().context("anchor timestamp")?))
            })
            .collect::<Result<_>>()?,
    })
}

fn parse_line(line: &str) -> Result<Entry> {
    let mut f = line.splitn(3, '\t');
    let (Some(check), Some(size), Some(path)) = (f.next(), f.next(), f.next()) else {
        bail!("not <check> <size> <path>");
    };
    if !valid_path(path) {
        bail!("invalid path {path:?}");
    }
    Ok(Entry {
        path: path.to_string(),
        size: size.parse().context("size")?,
        check: check.parse().map_err(|e: String| anyhow!(e))?,
    })
}

#[derive(Debug, Default)]
pub(crate) struct Tsv {
    pub header: Option<Header>,
    pub entries: Vec<Entry>,
    /// The last line had no newline (an append cut short) and was left out.
    pub torn: bool,
}

/// Reads a tsv a line at a time, each capped, so a planted file cannot make it allocate more
/// than the line and count caps allow.
pub(crate) fn parse_tsv(mut r: impl BufRead) -> Result<Tsv> {
    let mut out = Tsv::default();
    let mut line = Vec::new();
    for n in 1.. {
        line.clear();
        (&mut r)
            .take(LINE_CAP as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if line.is_empty() {
            break;
        }
        if line.last() != Some(&b'\n') {
            if line.len() > LINE_CAP {
                bail!("line {n}: longer than {LINE_CAP} bytes");
            }
            out.torn = true;
            break;
        }
        if n > LINES_CAP {
            bail!("more than {LINES_CAP} lines");
        }
        let text =
            std::str::from_utf8(&line[..line.len() - 1]).with_context(|| format!("line {n}"))?;
        if n == 1 && text.starts_with('#') {
            out.header = Some(parse_header(text).context("line 1")?);
            continue;
        }
        out.entries
            .push(parse_line(text).with_context(|| format!("line {n}"))?);
    }
    Ok(out)
}

pub(crate) fn read_tsv(path: &Path) -> Result<Tsv> {
    let f = platform::open_regular(path).with_context(|| path.display().to_string())?;
    parse_tsv(BufReader::new(f)).with_context(|| path.display().to_string())
}

/// The header of a tsv, `None` when the file does not exist.
pub(crate) fn read_header(path: &Path) -> Result<Option<Header>> {
    let f = match platform::open_regular(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        r => r.with_context(|| path.display().to_string())?,
    };
    let mut line = Vec::new();
    BufReader::new(f)
        .take(LINE_CAP as u64 + 1)
        .read_until(b'\n', &mut line)?;
    let text = std::str::from_utf8(line.strip_suffix(b"\n").unwrap_or(&line))
        .ok()
        .filter(|_| line.ends_with(b"\n"));
    text.map(parse_header)
        .transpose()
        .and_then(|h| h.ok_or_else(|| anyhow!("no header line")))
        .map(Some)
        .with_context(|| path.display().to_string())
}

/// The generation that is visible, from the `live.tsv` header.
pub(crate) fn live_gen(tree: &Path) -> Result<Option<String>> {
    Ok(read_header(&live_path(tree))?.map(|h| h.generation))
}

/// A new file at `path`; whatever was there, a planted link included, is removed, not followed.
fn create_fresh(path: &Path) -> io::Result<fs::File> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    fs::File::create_new(path)
}

fn tmp_of(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

/// Replaces `path` atomically and durably.
fn put(path: &Path, write: impl FnOnce(&mut BufWriter<fs::File>) -> io::Result<()>) -> Result<()> {
    let tmp = tmp_of(path);
    let ctx = || path.display().to_string();
    let mut w = BufWriter::new(create_fresh(&tmp).with_context(ctx)?);
    write(&mut w).with_context(ctx)?;
    w.into_inner()
        .map_err(io::IntoInnerError::into_error)
        .and_then(|f| f.sync_all())
        .with_context(ctx)?;
    fs::rename(&tmp, path).with_context(ctx)?;
    if let Some(dir) = path.parent() {
        platform::sync_dir(dir).with_context(ctx)?;
    }
    Ok(())
}

pub(crate) fn write_tsv(path: &Path, header: Option<&Header>, entries: &[Entry]) -> Result<()> {
    put(path, |w| {
        if let Some(h) = header {
            writeln!(w, "{h}")?;
        }
        for e in entries {
            writeln!(w, "{}\t{}\t{}", e.check, e.size, e.path)?;
        }
        Ok(())
    })
}

/// The journal of a swap. Written once every staged file is in place; from then on the swap
/// only rolls forward.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Journal {
    #[serde(rename = "gen")]
    pub generation: String,
    pub steps: Vec<Step>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Step {
    /// Swapped in as a whole: a directory or one file.
    pub path: String,
    /// The anchor document under `path`.
    pub key: String,
    /// Every file under `path` in the new generation.
    pub files: Vec<(String, Check)>,
    /// Ancestors of `path` in the live tree that are not plain directories; moved aside at
    /// the swap so nothing is written through them. `commit_swap` fills it in.
    pub replace: Vec<String>,
}

impl Journal {
    pub(crate) fn check(&self) -> Result<()> {
        if !is_gen(&self.generation) {
            bail!("swap journal: bad generation {:?}", self.generation);
        }
        if self.steps.is_empty() {
            bail!("swap journal: no steps");
        }
        for (i, s) in self.steps.iter().enumerate() {
            let bad = |what: String| anyhow!("swap journal: step {:?}: {what}", s.path);
            if !valid_path(&s.path) {
                return Err(bad("invalid path".into()));
            }
            if !valid_path(&s.key) || !under(&s.key, &s.path) {
                return Err(bad(format!("key {:?} is not under the path", s.key)));
            }
            let mut seen = HashSet::new();
            for (f, _) in &s.files {
                if !valid_path(f) || !under(f, &s.path) {
                    return Err(bad(format!("file {f:?} is not under the path")));
                }
                if !seen.insert(f.as_str()) {
                    return Err(bad(format!("file {f:?} listed twice")));
                }
            }
            if !seen.contains(s.key.as_str()) {
                return Err(bad("the key is not one of the files".into()));
            }
            for r in &s.replace {
                if !valid_path(r)
                    || !s
                        .path
                        .strip_prefix(r.as_str())
                        .is_some_and(|t| t.starts_with('/'))
                {
                    return Err(bad(format!("{r:?} is not an ancestor of the path")));
                }
            }
            if let Some(t) = self.steps[..i]
                .iter()
                .find(|t| under(&s.path, &t.path) || under(&t.path, &s.path))
            {
                return Err(bad(format!("overlaps {:?}", t.path)));
            }
        }
        Ok(())
    }
}

/// Lets a test make the next `commit_swap` of a tree fail after `n` steps, as a crash would.
#[cfg(test)]
pub(crate) mod crash {
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, PoisonError};

    static ARMED: Mutex<Vec<(PathBuf, usize)>> = Mutex::new(Vec::new());

    pub(crate) fn arm(tree: &Path, n: usize) {
        let mut a = ARMED.lock().unwrap_or_else(PoisonError::into_inner);
        a.push((tree.to_path_buf(), n));
    }

    pub(super) fn take(tree: &Path) -> Option<usize> {
        let mut a = ARMED.lock().unwrap_or_else(PoisonError::into_inner);
        let i = a.iter().position(|(t, _)| t == tree)?;
        Some(a.remove(i).1)
    }
}

type Tick<'a> = &'a mut dyn FnMut() -> io::Result<()>;

/// Swaps the staged generation in: `<stage>/meta/<path>` for every step and the staged
/// `live.tsv`, then prunes what the new generation does not name. The journal is written
/// first, so a crash at any point is finished by `recover`.
pub(crate) fn commit_swap(tree: &Path, j: Journal) -> Result<()> {
    #[cfg(test)]
    if let Some(n) = crash::take(tree) {
        let mut calls = 0;
        return commit_with(tree, j, true, &mut || {
            calls += 1;
            if calls > n {
                Err(io::Error::other("crash"))
            } else {
                Ok(())
            }
        });
    }
    commit_with(tree, j, true, &mut || Ok(()))
}

fn commit_with(tree: &Path, mut j: Journal, exch: bool, tick: Tick) -> Result<()> {
    let jp = journal_path(tree);
    plain_dirs(&[&book(tree)])?;
    if fs::symlink_metadata(&jp).is_ok() {
        bail!("an unfinished swap is pending in {}", jp.display());
    }
    for s in &mut j.steps {
        s.replace = blocked_ancestor(tree, &s.path)?.into_iter().collect();
    }
    j.check()?;
    // The same precondition `roll` checks, but before the journal exists: a journal whose steps
    // cannot roll forward would block every later commit and recover.
    let meta = stage_dir(tree, &j.generation).join("meta");
    for s in &j.steps {
        if !exact(&meta, s)? && !exact(tree, s)? {
            bail!(
                "{:?}: neither the staged nor the live copy matches the swap, so it was not started",
                s.path
            );
        }
    }
    let staged = stage_dir(tree, &j.generation).join("live.tsv");
    if read_header(&staged)?.map(|h| h.generation).as_ref() != Some(&j.generation) {
        bail!("{} is not for this generation", staged.display());
    }
    tick()?;
    let text = serde_json::to_vec_pretty(&j)?;
    put(&jp, |w| w.write_all(&text))?;
    roll(tree, &j, exch, tick)
}

/// The shallowest ancestor of `path` in the tree that is not a plain directory. Deeper ones
/// are not looked at: their lookup would go through it.
fn blocked_ancestor(tree: &Path, path: &str) -> Result<Option<String>> {
    for (i, _) in path.match_indices('/') {
        let a = &path[..i];
        let p = rel_path(tree, a);
        match fs::symlink_metadata(&p) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Ok(Some(a.to_string())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| p.display().to_string()),
        }
    }
    Ok(None)
}

/// Finishes a swap a crash interrupted. `false` when there was none.
pub(crate) fn recover(tree: &Path) -> Result<bool> {
    recover_with(tree, true, &mut || Ok(()))
}

fn recover_with(tree: &Path, exch: bool, tick: Tick) -> Result<bool> {
    let jp = journal_path(tree);
    match fs::symlink_metadata(&jp) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| jp.display().to_string()),
        Ok(_) => {}
    }
    plain_dirs(&[&book(tree)])?;
    let j: Journal =
        serde_json::from_slice(&read_meta(&jp).with_context(|| jp.display().to_string())?)
            .with_context(|| jp.display().to_string())?;
    j.check()?;
    roll(tree, &j, exch, tick)?;
    Ok(true)
}

/// Every step is checked against the journal before anything is renamed: a step whose staged
/// copy matches is swapped, one whose live copy matches is done, anything else stops here.
fn roll(tree: &Path, j: &Journal, exch: bool, tick: Tick) -> Result<()> {
    let stage = stage_dir(tree, &j.generation);
    let meta = stage.join("meta");
    let mut todo = Vec::new();
    for (i, s) in j.steps.iter().enumerate() {
        if exact(&meta, s)? {
            todo.push(i);
        } else if !exact(tree, s)? {
            bail!(
                "{:?}: neither the staged nor the live copy matches the swap journal, so nothing \
                 was renamed; remove {} and {} to start this generation over",
                s.path,
                stage.display(),
                journal_path(tree).display()
            );
        }
    }
    let live = live_path(tree);
    let staged_live = stage.join("live.tsv");
    let install = read_header(&live)?.map(|h| h.generation).as_ref() != Some(&j.generation);
    if install && read_header(&staged_live)?.map(|h| h.generation).as_ref() != Some(&j.generation) {
        bail!("{} is not for this generation", staged_live.display());
    }
    for i in todo {
        swap_step(tree, &stage, i, &j.steps[i], exch, tick)?;
    }
    if install {
        tick()?;
        fs::rename(&staged_live, &live).with_context(|| live.display().to_string())?;
        platform::sync_dir(&book(tree))?;
    }
    platform::sync_fs(tree).with_context(|| tree.display().to_string())?;
    let tsv = read_tsv(&live)?;
    if tsv.torn
        || tsv.header.map(|h| h.generation).as_ref() != Some(&j.generation)
        || !tsv
            .entries
            .is_sorted_by(|a, b| path_cmp(&a.path, &b.path).is_lt())
    {
        bail!("{} is damaged", live.display());
    }
    let skip: Vec<String> = j.steps.iter().map(|s| s.path.clone()).collect();
    tick()?;
    prune(tree, &tsv.entries, &skip)?;
    tick()?;
    match fs::remove_dir_all(&stage) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => {
            return Err(e).with_context(|| stage.display().to_string());
        }
        _ => {}
    }
    tick()?;
    fs::remove_file(journal_path(tree))?;
    platform::sync_dir(&book(tree))?;
    Ok(())
}

fn swap_step(tree: &Path, stage: &Path, i: usize, s: &Step, exch: bool, tick: Tick) -> Result<()> {
    let old = stage.join("old").join(i.to_string());
    let parent_of = |p: &Path| -> Result<()> {
        let dir = p.parent().context("no parent")?;
        fs::create_dir_all(dir).with_context(|| dir.display().to_string())
    };
    for a in &s.replace {
        let p = rel_path(tree, a);
        match fs::symlink_metadata(&p) {
            Ok(m) if !m.is_dir() => {
                let to = rel_path(&old, a);
                parent_of(&to)?;
                tick()?;
                fs::rename(&p, &to).with_context(|| p.display().to_string())?;
            }
            Err(e) if e.kind() != io::ErrorKind::NotFound => {
                return Err(e).with_context(|| p.display().to_string());
            }
            _ => {}
        }
    }
    ensure_dir(tree, s.path.rsplit_once('/').map_or("", |(p, _)| p))?;
    let live = rel_path(tree, &s.path);
    let new = rel_path(&stage.join("meta"), &s.path);
    let ctx = || live.display().to_string();
    match fs::symlink_metadata(&live) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            tick()?;
            fs::rename(&new, &live).with_context(ctx)?;
        }
        Err(e) => return Err(e).with_context(ctx),
        Ok(_) => {
            let aside = rel_path(&old, &s.path);
            parent_of(&aside)?;
            tick()?;
            if exch && platform::exchange(&new, &live).with_context(ctx)? {
                tick()?;
                fs::rename(&new, &aside).with_context(ctx)?;
            } else {
                fs::rename(&live, &aside).with_context(ctx)?;
                tick()?;
                fs::rename(&new, &live).with_context(ctx)?;
            }
        }
    }
    Ok(())
}

fn sha256_of(path: &Path) -> Result<[u8; 32]> {
    let mut f = platform::open_regular(path).with_context(|| path.display().to_string())?;
    let mut h = Sha256::new();
    io::copy(&mut f, &mut h).with_context(|| path.display().to_string())?;
    Ok(h.finalize().into())
}

/// `root/<step path>` holds exactly the step's files, with their hashes, and nothing else.
fn exact(root: &Path, s: &Step) -> Result<bool> {
    let top = rel_path(root, &s.path);
    let mut found = Vec::new();
    match fs::symlink_metadata(&top) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| top.display().to_string()),
        Ok(m) if m.is_file() => found.push(s.path.clone()),
        Ok(m) if m.is_dir() => {
            if !files_under(&top, &s.path, &mut found)? {
                return Ok(false);
            }
        }
        Ok(_) => return Ok(false),
    }
    found.sort();
    let mut want: Vec<&str> = s.files.iter().map(|(p, _)| p.as_str()).collect();
    want.sort_unstable();
    if found != want {
        return Ok(false);
    }
    for (p, c) in &s.files {
        if !holds(&rel_path(root, p), *c)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The regular files under `dir`; `false` on a link, a special file or a name no tsv could hold.
fn files_under(dir: &Path, rel: &str, out: &mut Vec<String>) -> Result<bool> {
    for e in fs::read_dir(dir).with_context(|| dir.display().to_string())? {
        let e = e?;
        let Some(r) = e.file_name().to_str().map(|n| format!("{rel}/{n}")) else {
            return Ok(false);
        };
        if !valid_path(&r) {
            return Ok(false);
        }
        let t = e.file_type()?;
        if t.is_dir() {
            if !files_under(&e.path(), &r, out)? {
                return Ok(false);
            }
        } else if t.is_file() {
            out.push(r);
        } else {
            return Ok(false);
        }
    }
    Ok(true)
}

enum Kind {
    Dir,
    File,
    Other,
}

/// A directory opened without following links, so a directory swapped for a link while prune
/// walks is refused rather than walked into.
#[cfg(unix)]
struct Dir(std::os::fd::OwnedFd);

#[cfg(unix)]
impl Dir {
    const FLAGS: rustix::fs::OFlags = rustix::fs::OFlags::RDONLY
        .union(rustix::fs::OFlags::DIRECTORY)
        .union(rustix::fs::OFlags::NOFOLLOW)
        .union(rustix::fs::OFlags::CLOEXEC);

    fn root(p: &Path) -> io::Result<Self> {
        Ok(Self(rustix::fs::open(
            p,
            Self::FLAGS,
            rustix::fs::Mode::empty(),
        )?))
    }

    fn names(&self) -> io::Result<Vec<OsString>> {
        use std::os::unix::ffi::OsStrExt;
        let mut out = Vec::new();
        for e in rustix::fs::Dir::read_from(&self.0)? {
            let e = e?;
            let n = e.file_name().to_bytes();
            if n != b"." && n != b".." {
                out.push(OsStr::from_bytes(n).to_owned());
            }
        }
        Ok(out)
    }

    fn kind(&self, n: &OsStr) -> io::Result<Kind> {
        use rustix::fs::FileType;
        let st = rustix::fs::statat(&self.0, n, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
        Ok(match FileType::from_raw_mode(st.st_mode) {
            FileType::Directory => Kind::Dir,
            FileType::RegularFile => Kind::File,
            _ => Kind::Other,
        })
    }

    fn sub(&self, n: &OsStr) -> io::Result<Self> {
        Ok(Self(rustix::fs::openat(
            &self.0,
            n,
            Self::FLAGS,
            rustix::fs::Mode::empty(),
        )?))
    }

    fn unlink(&self, n: &OsStr) -> io::Result<()> {
        Ok(rustix::fs::unlinkat(
            &self.0,
            n,
            rustix::fs::AtFlags::empty(),
        )?)
    }

    fn rmdir(&self, n: &OsStr) -> io::Result<()> {
        Ok(rustix::fs::unlinkat(
            &self.0,
            n,
            rustix::fs::AtFlags::REMOVEDIR,
        )?)
    }
}

/// Path based: Windows has no `openat`, so the link race is narrowed by checks, not closed.
#[cfg(windows)]
struct Dir(PathBuf);

#[cfg(windows)]
impl Dir {
    fn root(p: &Path) -> io::Result<Self> {
        if !fs::symlink_metadata(p)?.is_dir() {
            return Err(io::Error::other("not a plain directory"));
        }
        Ok(Self(p.to_path_buf()))
    }

    fn names(&self) -> io::Result<Vec<OsString>> {
        fs::read_dir(&self.0)?
            .map(|e| e.map(|e| e.file_name()))
            .collect()
    }

    fn kind(&self, n: &OsStr) -> io::Result<Kind> {
        let t = fs::symlink_metadata(self.0.join(n))?.file_type();
        Ok(if t.is_symlink() {
            Kind::Other
        } else if t.is_dir() {
            Kind::Dir
        } else if t.is_file() {
            Kind::File
        } else {
            Kind::Other
        })
    }

    fn sub(&self, n: &OsStr) -> io::Result<Self> {
        let p = self.0.join(n);
        if !matches!(self.kind(n)?, Kind::Dir) {
            return Err(io::Error::other("no longer a plain directory"));
        }
        Ok(Self(p))
    }

    fn unlink(&self, n: &OsStr) -> io::Result<()> {
        let p = self.0.join(n);
        fs::remove_file(&p).or_else(|_| fs::remove_dir(&p))
    }

    fn rmdir(&self, n: &OsStr) -> io::Result<()> {
        fs::remove_dir(self.0.join(n))
    }
}

/// Deletes everything in the tree except the regular files in `keep` (sorted by `path_cmp`),
/// the `skip` paths and `.preserver`. Links are removed, never followed. Returns the count.
pub(crate) fn prune(tree: &Path, keep: &[Entry], skip: &[String]) -> Result<u64> {
    let mut removed = 0;
    let root = Dir::root(tree).with_context(|| tree.display().to_string())?;
    prune_dir(&root, Some(""), keep, skip, &mut removed)
        .with_context(|| format!("pruning {}", tree.display()))?;
    Ok(removed)
}

/// `rel` is `None` inside a directory whose name no kept path can have. Returns whether
/// anything in `d` stays.
fn prune_dir(
    d: &Dir,
    rel: Option<&str>,
    keep: &[Entry],
    skip: &[String],
    removed: &mut u64,
) -> io::Result<bool> {
    let mut kept = false;
    for name in d.names()? {
        let r = rel.zip(name.to_str()).map(|(rel, n)| {
            if rel.is_empty() {
                n.to_string()
            } else {
                format!("{rel}/{n}")
            }
        });
        if r.as_deref()
            .is_some_and(|r| r == BOOK || skip.iter().any(|s| s == r))
        {
            kept = true;
            continue;
        }
        match d.kind(&name)? {
            Kind::Dir => {
                if prune_dir(&d.sub(&name)?, r.as_deref(), keep, skip, removed)? {
                    kept = true;
                } else {
                    d.rmdir(&name)?;
                }
            }
            Kind::File
                if r.as_deref()
                    .is_some_and(|r| keep.binary_search_by(|e| path_cmp(&e.path, r)).is_ok()) =>
            {
                kept = true;
            }
            Kind::File | Kind::Other => {
                d.unlink(&name)?;
                *removed += 1;
            }
        }
    }
    Ok(kept)
}

/// Refuses a generation the target filesystem cannot hold: files of 4 GiB or more on FAT,
/// and on FAT, exFAT, NTFS and Windows, names Windows refuses or that collide once case is
/// folded.
pub(crate) fn fs_limits<'e>(
    fstype: &str,
    entries: impl IntoIterator<Item = &'e Entry>,
) -> Result<()> {
    let lim = Limits::of(fstype, 1);
    let windows = lim.windows || cfg!(windows);
    let (mut big, mut names, mut case) = (0u64, 0u64, 0u64);
    let mut files = HashSet::new();
    let mut dirs: HashMap<String, &str> = HashMap::new();
    for e in entries {
        if lim.max_file.is_some_and(|m| e.size > m) {
            big += 1;
        }
        if !windows {
            continue;
        }
        if e.path.split('/').any(bad_windows_name) {
            names += 1;
        }
        if !files.insert(e.path.to_lowercase()) {
            case += 1;
        }
        for (i, _) in e.path.match_indices('/') {
            let d = &e.path[..i];
            let o = dirs.entry(d.to_lowercase()).or_insert(d);
            if *o != d {
                case += 1;
            }
        }
    }
    case += files.iter().filter(|f| dirs.contains_key(*f)).count() as u64;
    let mut why = Vec::new();
    for (n, what) in [
        (big, "of 4 GiB or more"),
        (names, "with a name Windows refuses"),
        (case, "whose name differs from another only in case"),
    ] {
        if n > 0 {
            why.push(format!("{n} file(s) {what}"));
        }
    }
    if why.is_empty() {
        return Ok(());
    }
    bail!(
        "a {fstype} filesystem cannot hold this mirror: {}",
        why.join(", ")
    )
}

/// Files and bytes handed out per batch; a larger file still goes, alone. Tests use two so a
/// handful of files spans several batches.
const BATCH_FILES: usize = if cfg!(test) { 2 } else { 2048 };
const BATCH_BYTES: u64 = 4 << 30;

pub(crate) fn done_path(tree: &Path) -> PathBuf {
    book(tree).join("done.tsv")
}

fn want_path(tree: &Path) -> PathBuf {
    book(tree).join("want.tsv")
}

fn parent(rel: &str) -> &str {
    rel.rsplit_once('/').map_or("", |(d, _)| d)
}

/// What a walk reports: a payload file, or a file it made under a swap path from verified
/// metadata (a by-hash link), which the commit accepts only with the contents of one of them.
#[derive(Debug)]
pub(crate) enum Walked {
    File(Entry),
    Link(String),
}

/// A walker: the anchor, the staged metadata directory and where to report what it finds.
pub(crate) type Walk<'a> = dyn FnMut(&Anchor, &Path, &mut dyn FnMut(Walked)) -> Result<()> + 'a;

pub(crate) enum Next {
    /// Downloads to run; plan again with the positions that verified.
    Batch(Planned),
    /// Everything the generation names is in place: `commit` swaps it in.
    Ready,
    OverBudget {
        need: u64,
        room: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Stage,
    Meta,
    Payload,
    Ready,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Have {
    Yes,
    /// Present with the right size but no done line: hashed before it is trusted.
    Suspect,
    No,
}

#[derive(Debug)]
struct Want {
    entry: Entry,
    /// The live tree holds something else at this path (another version of the file, a
    /// directory, a file where a directory goes): the file lands in the stage's `incoming/`
    /// and is swapped in with the metadata.
    incoming: bool,
    have: Have,
}

/// One run of a generation: stage and verify the metadata, walk it, land the payload it names,
/// then swap the metadata in. Nothing the live tree's metadata names is touched before the swap.
pub(crate) struct Gen {
    tree: PathBuf,
    base: String,
    anchor: Anchor,
    generation: String,
    /// This generation is the live one already: the run still checks the live metadata and
    /// payload, and swaps in only what it had to repair.
    current: bool,
    phase: Phase,
    /// Positions in `anchor.meta` of the metadata batch handed out.
    meta_out: Vec<usize>,
    want: Vec<Want>,
    links: Vec<String>,
    /// Positions in `want` still to hand out, from `cursor` on.
    todo: Vec<usize>,
    cursor: usize,
    /// Positions in `want` of the payload batch handed out, in batch order.
    out: Vec<usize>,
    done: Option<fs::File>,
    totals: (u64, u64, u64, u64),
}

/// The anchor is consistent before anything is written: swap paths valid and disjoint, every
/// document and metadata file under one of them, each swap path keyed by a document.
pub(crate) fn check_anchor(a: &Anchor) -> Result<()> {
    if a.swaps.is_empty() {
        bail!("anchor: no swap paths");
    }
    for (i, s) in a.swaps.iter().enumerate() {
        if !valid_path(s) {
            bail!("anchor: invalid swap path {s:?}");
        }
        if let Some(t) = a.swaps[..i].iter().find(|t| under(s, t) || under(t, s)) {
            bail!("anchor: swap paths {t:?} and {s:?} overlap");
        }
    }
    let mut paths: Vec<&str> = a
        .docs
        .iter()
        .map(|(p, _)| p.as_str())
        .chain(a.meta.iter().map(|m| m.entry.path.as_str()))
        .collect();
    for p in &paths {
        if !valid_path(p) {
            bail!("anchor: invalid path {p:?}");
        }
        if !a.swaps.iter().any(|s| under(p, s)) {
            bail!("anchor: {p:?} is under no swap path");
        }
    }
    if let Some(f) = a
        .meta
        .iter()
        .filter_map(|m| m.from.as_deref())
        .find(|f| !valid_path(f))
    {
        bail!("anchor: invalid fetch path {f:?}");
    }
    paths.sort_by(|x, y| path_cmp(x, y));
    if let Some([a, b]) = paths.windows(2).find(|w| under(w[1], w[0])) {
        bail!("anchor: {b:?} is listed twice or inside {a:?}");
    }
    if let Some(s) = a
        .swaps
        .iter()
        .find(|s| !a.docs.iter().any(|(p, _)| under(p, s)))
    {
        bail!("anchor: swap path {s:?} has no anchor document");
    }
    Ok(())
}

/// The generation is named by its anchor documents, path and bytes.
pub(crate) fn gen_of(a: &Anchor) -> String {
    let mut h = Sha256::new();
    for (p, b) in &a.docs {
        h.update((p.len() as u64).to_le_bytes());
        h.update(p);
        h.update((b.len() as u64).to_le_bytes());
        h.update(b);
    }
    hex(&h.finalize())
}

fn expect_of(c: Check) -> Expect {
    match c {
        Check::Sha256(h) => Expect::Sha256(h),
        Check::ApkQ1(q) => Expect::Apk(q),
    }
}

/// `path` is a regular file of the entry's size and check.
fn matches(path: &Path, e: &Entry) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.is_file() && m.len() == e.size => {}
        Ok(_) => return Ok(false),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err).with_context(|| path.display().to_string()),
    }
    holds(path, e.check)
}

/// The regular file at `path` is what `c` says; an apk that fails its check is not an I/O error.
fn holds(path: &Path, c: Check) -> Result<bool> {
    match c {
        Check::Sha256(h) => Ok(sha256_of(path)? == h),
        Check::ApkQ1(q) => {
            let f = platform::open_regular(path).with_context(|| path.display().to_string())?;
            Ok(alpine::apk_holds(f, &q).with_context(|| path.display().to_string())?)
        }
    }
}

/// `path` is a regular file of `size` bytes.
fn present(path: &Path, size: u64) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(m) => Ok(m.is_file() && m.len() == size),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| path.display().to_string()),
    }
}

/// Removes whatever is at `path`; a link is removed, not followed.
pub(crate) fn remove_any(path: &Path) -> Result<()> {
    let r = match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => Err(e),
        Ok(m) if m.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
    };
    r.with_context(|| path.display().to_string())
}

/// `ensure_dir` inside the stage, which is ours: anything in the way is removed.
pub(crate) fn clear_way(root: &Path, rel: &str) -> Result<()> {
    let mut p = root.to_path_buf();
    for c in rel.split('/').filter(|c| !c.is_empty()) {
        p.push(c);
        match fs::symlink_metadata(&p) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => remove_any(&p)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| p.display().to_string()),
        }
    }
    ensure_dir(root, rel).map(drop)
}

/// Whether `dir` (relative to the tree) or one of its ancestors exists and is not a plain
/// directory, so a file under it cannot land before the swap moves it aside.
fn blocked(tree: &Path, dir: &str, memo: &mut HashMap<String, bool>) -> Result<bool> {
    if dir.is_empty() {
        return Ok(false);
    }
    if let Some(&b) = memo.get(dir) {
        return Ok(b);
    }
    let b = blocked(tree, parent(dir), memo)?
        || match fs::symlink_metadata(rel_path(tree, dir)) {
            Ok(m) => !m.is_dir(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => return Err(e).with_context(|| dir.to_string()),
        };
    memo.insert(dir.to_string(), b);
    Ok(b)
}

fn line_of(out: &mut String, e: &Entry) {
    let _ = writeln!(out, "{}\t{}\t{}", e.check, e.size, e.path);
}

/// Starts a run of the generation `anchor` pins. Validates the anchor before writing anything,
/// then stages its documents. A pending swap must have been recovered first.
pub(crate) fn begin(tree: &Path, base: &str, anchor: Anchor) -> Result<Gen> {
    check_anchor(&anchor)?;
    let generation = gen_of(&anchor);
    match fs::create_dir(tree) {
        Err(e) if e.kind() != io::ErrorKind::AlreadyExists => {
            return Err(e).with_context(|| tree.display().to_string());
        }
        _ => {}
    }
    plain_dirs(&[tree, &book(tree)])?;
    if fs::symlink_metadata(journal_path(tree)).is_ok() {
        bail!(
            "an unfinished swap is pending in {}",
            journal_path(tree).display()
        );
    }
    let current = live_gen(tree)?.as_ref() == Some(&generation);
    let g = Gen {
        tree: tree.to_path_buf(),
        base: base.to_string(),
        anchor,
        generation,
        current,
        phase: Phase::Stage,
        meta_out: Vec::new(),
        want: Vec::new(),
        links: Vec::new(),
        todo: Vec::new(),
        cursor: 0,
        out: Vec::new(),
        done: None,
        totals: (0, 0, 0, 0),
    };
    let stage = format!("{BOOK}/staging/{}", &g.generation[..16]);
    ensure_dir(tree, &format!("{stage}/incoming"))?;
    let meta = ensure_dir(tree, &format!("{stage}/meta"))?;
    for (p, bytes) in &g.anchor.docs {
        clear_way(&meta, parent(p))?;
        let dst = rel_path(&meta, p);
        if read_meta(&dst).ok().as_ref() != Some(bytes) {
            remove_any(&dst)?;
            put(&dst, |w| w.write_all(bytes))?;
        }
    }
    Ok(g)
}

impl Gen {
    pub(crate) fn generation(&self) -> &str {
        &self.generation
    }

    /// Every file is in place; `commit` may run.
    pub(crate) fn ready(&self) -> bool {
        self.phase == Phase::Ready
    }

    fn stage(&self) -> PathBuf {
        stage_dir(&self.tree, &self.generation)
    }

    fn dest(&self, w: &Want) -> PathBuf {
        if w.incoming {
            rel_path(&self.stage().join("incoming"), &w.entry.path)
        } else {
            rel_path(&self.tree, &w.entry.path)
        }
    }

    fn whole(&self) -> Whole {
        let (files, bytes, files_done, bytes_done) = self.totals;
        Whole {
            files,
            bytes,
            files_done,
            bytes_done,
        }
    }

    /// Records the verified positions `ok` of the last batch, then plans the next step.
    /// `room` is the free space the mirror may still use, `fstype` the drive's filesystem.
    pub(crate) fn next(
        &mut self,
        ok: &[usize],
        walk: &mut Walk<'_>,
        room: u64,
        fstype: &str,
    ) -> Result<Next> {
        self.land(ok)?;
        match self.phase {
            Phase::Ready => return Ok(Next::Ready),
            Phase::Payload => return self.hand_out(),
            Phase::Stage => {
                let fetches = self.stage_meta()?;
                if !fetches.is_empty() {
                    self.phase = Phase::Meta;
                    return Ok(Next::Batch(Planned {
                        fetches,
                        more: true,
                        whole: None,
                    }));
                }
            }
            Phase::Meta => {
                let meta = self.stage().join("meta");
                for &i in &self.meta_out {
                    let e = &self.anchor.meta[i].entry;
                    if !matches(&rel_path(&meta, &e.path), e)? {
                        bail!("{}: the fetched metadata does not match the anchor", e.path);
                    }
                }
            }
        }
        self.walk(walk, fstype)?;
        let need = self
            .want
            .iter()
            .filter(|w| w.have == Have::No)
            .map(|w| w.entry.size)
            .sum::<u64>();
        if need > room {
            return Ok(Next::OverBudget { need, room });
        }
        self.phase = Phase::Payload;
        self.hand_out()
    }

    /// Records the verified positions `ok` of the last payload batch in the done ledger.
    pub(crate) fn land(&mut self, ok: &[usize]) -> Result<()> {
        let out = std::mem::take(&mut self.out);
        let mut lines = String::new();
        for &w in ok.iter().filter_map(|i| out.get(*i)) {
            let w = &mut self.want[w];
            w.have = Have::Yes;
            line_of(&mut lines, &w.entry);
            self.totals.2 += 1;
            self.totals.3 += w.entry.size;
        }
        self.append(&lines)
    }

    fn append(&mut self, lines: &str) -> Result<()> {
        if lines.is_empty() {
            return Ok(());
        }
        let f = self.done.as_mut().context("the done ledger is not open")?;
        f.write_all(lines.as_bytes())
            .and_then(|()| f.sync_data())
            .with_context(|| done_path(&self.tree).display().to_string())
    }

    /// Stages every metadata file: kept when the staged copy matches, linked from the live
    /// tree when that matches, fetched otherwise.
    fn stage_meta(&mut self) -> Result<Vec<Fetch>> {
        let meta = self.stage().join("meta");
        let mut fetches = Vec::new();
        self.meta_out.clear();
        for (i, m) in self.anchor.meta.iter().enumerate() {
            let e = &m.entry;
            let dst = rel_path(&meta, &e.path);
            clear_way(&meta, parent(&e.path))?;
            if matches(&dst, e)? {
                continue;
            }
            remove_any(&dst)?;
            let live = rel_path(&self.tree, &e.path);
            if blocked_ancestor(&self.tree, &e.path)?.is_none()
                && matches(&live, e)?
                && link_or_copy(&live, &dst)
                && matches(&dst, e)?
            {
                continue;
            }
            remove_any(&dst)?;
            fetches.push(Fetch {
                url: url_of(&self.base, m.from.as_deref().unwrap_or(&e.path)),
                dest: dst,
                size: Some(e.size),
                limit: e.size,
                expect: expect_of(e.check),
            });
            self.meta_out.push(i);
        }
        Ok(fetches)
    }

    /// Walks the verified metadata, checks what it names and writes `want.tsv`.
    fn walk(&mut self, walk: &mut Walk<'_>, fstype: &str) -> Result<()> {
        let meta = self.stage().join("meta");
        let (mut files, mut links) = (Vec::new(), Vec::new());
        walk(&self.anchor, &meta, &mut |w| match w {
            Walked::File(e) => files.push(e),
            Walked::Link(p) => links.push(p),
        })?;
        let swaps = &self.anchor.swaps;
        for e in &files {
            if !valid_path(&e.path) {
                bail!("the walk named an invalid path {:?}", e.path);
            }
            if let Some(s) = swaps
                .iter()
                .find(|s| under(&e.path, s) || under(s, &e.path))
            {
                bail!("the walk named {:?}, which collides with {s:?}", e.path);
            }
        }
        for l in &links {
            if !valid_path(l) || !swaps.iter().any(|s| under(l, s)) {
                bail!("the walk declared {l:?}, which is under no swap path");
            }
        }
        links.sort();
        links.dedup();
        files.sort_by(|a, b| path_cmp(&a.path, &b.path));
        files.dedup();
        for w in files.windows(2) {
            if w[0].path == w[1].path {
                bail!(
                    "the walk named {:?} twice with different contents",
                    w[0].path
                );
            }
            if under(&w[1].path, &w[0].path) {
                bail!("the walk named {:?} as a file and a directory", w[0].path);
            }
        }
        fs_limits(
            fstype,
            files
                .iter()
                .chain(self.anchor.meta.iter().map(|m| &m.entry)),
        )?;
        let header = Header {
            generation: self.generation.clone(),
            files: files.len() as u64,
            bytes: files.iter().map(|e| e.size).sum(),
            at: jiff::Timestamp::now(),
            anchor_ts: self.anchor.ts.clone(),
        };
        write_tsv(&want_path(&self.tree), Some(&header), &files)?;
        self.classify(files)?;
        self.links = links;
        Ok(())
    }

    /// Where each file lands and whether it is there already, by the live tree and the done
    /// ledger. Files in the way that are not trusted are deleted here, so a fetch that fails
    /// leaves nothing that could be taken for it.
    fn classify(&mut self, files: Vec<Entry>) -> Result<()> {
        let lp = live_path(&self.tree);
        let live = if fs::symlink_metadata(&lp).is_ok() {
            read_tsv(&lp)?
        } else {
            Tsv::default()
        };
        if live.torn {
            bail!("{} is damaged", lp.display());
        }
        let live: HashMap<&str, &Entry> =
            live.entries.iter().map(|e| (e.path.as_str(), e)).collect();
        let dp = done_path(&self.tree);
        let done: HashSet<Entry> = if fs::symlink_metadata(&dp).is_ok() {
            match read_tsv(&dp) {
                Ok(t) => t.entries.into_iter().collect(),
                Err(e) => {
                    tracing::warn!("{e:#}: ignored, landed files are hashed again");
                    HashSet::new()
                }
            }
        } else {
            HashSet::new()
        };

        let mut memo = HashMap::new();
        let mut want = Vec::with_capacity(files.len());
        let mut kept = Vec::new();
        for entry in files {
            let old = live.get(entry.path.as_str());
            let mut incoming = old.is_some_and(|l| **l != entry)
                || blocked(&self.tree, parent(&entry.path), &mut memo)?;
            let in_tree = rel_path(&self.tree, &entry.path);
            if !incoming {
                match fs::symlink_metadata(&in_tree) {
                    Ok(m) if m.is_dir() => incoming = true,
                    Ok(m) if !m.is_file() => remove_any(&in_tree)?,
                    _ => {}
                }
            }
            let mut w = Want {
                entry,
                incoming,
                have: Have::No,
            };
            let dest = self.dest(&w);
            let known = done.contains(&w.entry);
            w.have = match fs::symlink_metadata(&dest) {
                Ok(m) if m.is_file() && m.len() == w.entry.size => {
                    if (old.is_some() && !incoming) || known {
                        Have::Yes
                    } else {
                        Have::Suspect
                    }
                }
                Ok(_) => {
                    remove_any(&dest)?;
                    Have::No
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => Have::No,
                Err(e) => return Err(e).with_context(|| dest.display().to_string()),
            };
            if known && w.have == Have::Yes {
                kept.push(w.entry.clone());
            }
            want.push(w);
        }
        // Rewritten, not appended to: that drops a torn last line and the lines of files no
        // generation wants any more.
        self.done = None;
        write_tsv(&dp, None, &kept)?;
        self.done = Some(
            fs::OpenOptions::new()
                .append(true)
                .open(&dp)
                .with_context(|| dp.display().to_string())?,
        );
        self.totals = want
            .iter()
            .filter(|w| w.have != Have::Yes)
            .fold((0, 0, 0, 0), |t, w| (t.0 + 1, t.1 + w.entry.size, 0, 0));
        self.todo = (0..want.len())
            .filter(|&i| want[i].have != Have::Yes)
            .collect();
        self.cursor = 0;
        self.want = want;
        Ok(())
    }

    /// The next batch of payload, suspects hashed on the way. Once all is handed out and
    /// landed, every file is checked to be there; whatever is not is handed out again.
    fn hand_out(&mut self) -> Result<Next> {
        loop {
            // Positions go to `self.out` only with the batch they describe: a plan that fails
            // half way must leave nothing `land` could take for a fetch that never ran.
            let (mut fetches, mut out, mut bytes, mut lines) =
                (Vec::new(), Vec::new(), 0, String::new());
            let incoming = self.stage().join("incoming");
            while let Some(&w) = self.todo.get(self.cursor) {
                let size = self.want[w].entry.size;
                if !fetches.is_empty()
                    && (fetches.len() == BATCH_FILES || bytes + size > BATCH_BYTES)
                {
                    break;
                }
                self.cursor += 1;
                let dest = self.dest(&self.want[w]);
                let want = &mut self.want[w];
                if want.have == Have::Suspect {
                    if matches(&dest, &want.entry)? {
                        want.have = Have::Yes;
                        line_of(&mut lines, &want.entry);
                        self.totals.2 += 1;
                        self.totals.3 += size;
                        continue;
                    }
                    remove_any(&dest)?;
                    want.have = Have::No;
                }
                if want.incoming {
                    clear_way(&incoming, parent(&want.entry.path))?;
                } else {
                    ensure_dir(&self.tree, parent(&want.entry.path))?;
                }
                fetches.push(Fetch {
                    url: url_of(&self.base, &want.entry.path),
                    dest,
                    size: Some(size),
                    limit: size,
                    expect: expect_of(want.entry.check),
                });
                out.push(w);
                bytes += size;
            }
            self.append(&lines)?;
            if !fetches.is_empty() {
                self.out = out;
                return Ok(Next::Batch(Planned {
                    fetches,
                    more: true,
                    whole: Some(self.whole()),
                }));
            }
            let mut missing = Vec::new();
            for (i, w) in self.want.iter().enumerate() {
                if !present(&self.dest(w), w.entry.size)? {
                    missing.push(i);
                }
            }
            if missing.is_empty() {
                self.phase = Phase::Ready;
                return Ok(Next::Ready);
            }
            for &i in &missing {
                self.want[i].have = Have::No;
                self.totals.0 += 1;
                self.totals.1 += self.want[i].entry.size;
            }
            self.todo = missing;
            self.cursor = 0;
        }
    }

    /// One journal step per swap path. The staged documents and metadata are checked against
    /// the anchor once more, and nothing else may sit under a swap path but the walk's derived
    /// copies of them.
    fn swap_steps(&self, meta: &Path) -> Result<Vec<Step>> {
        let mut known: HashMap<&str, [u8; 32]> = HashMap::new();
        for (p, bytes) in &self.anchor.docs {
            let path = rel_path(meta, p);
            if read_meta(&path).with_context(|| path.display().to_string())? != *bytes {
                bail!("{p}: the staged document differs from the one verified");
            }
            known.insert(p, Sha256::digest(bytes).into());
        }
        for m in &self.anchor.meta {
            let e = &m.entry;
            if !matches(&rel_path(meta, &e.path), e)? {
                bail!(
                    "{}: the staged metadata no longer matches the anchor",
                    e.path
                );
            }
            let Check::Sha256(h) = e.check else {
                bail!("{}: metadata is checked by SHA-256", e.path);
            };
            known.insert(&e.path, h);
        }
        let sums: HashSet<[u8; 32]> = known.values().copied().collect();
        let mut steps = Vec::new();
        for s in &self.anchor.swaps {
            let top = rel_path(meta, s);
            let mut found = Vec::new();
            let is_dir = fs::symlink_metadata(&top)
                .with_context(|| top.display().to_string())?
                .is_dir();
            if !is_dir {
                found.push(s.clone());
            } else if !files_under(&top, s, &mut found)? {
                bail!("{s}: the staged metadata holds a link, a special file or a hidden name");
            }
            let mut files = Vec::new();
            for f in found {
                let h = match known.get(f.as_str()) {
                    Some(h) => *h,
                    None if self.links.binary_search(&f).is_ok() => {
                        let h = sha256_of(&rel_path(meta, &f))?;
                        if !sums.contains(&h) {
                            bail!("{f}: a derived file that is not a copy of verified metadata");
                        }
                        h
                    }
                    None => {
                        bail!("{f}: staged under {s:?} but not named by the anchor or the walk")
                    }
                };
                files.push((f, Check::Sha256(h)));
            }
            let key = self
                .anchor
                .docs
                .iter()
                .find(|(p, _)| under(p, s))
                .map(|(p, _)| p.clone())
                .context("a swap path without a document")?;
            steps.push(Step {
                path: s.clone(),
                key,
                files,
                replace: Vec::new(),
            });
        }
        Ok(steps)
    }

    /// Swaps the generation in: the anchor files are checked once more (`swap_steps`), every
    /// payload file must be there and the changed ones move from `incoming/` to the stage;
    /// then the journal, the swap, the new `live.tsv` and prune. When the generation is live
    /// already, only the swap paths the live tree no longer holds exactly are swapped, and with
    /// none the stage is dropped.
    pub(crate) fn commit(&mut self) -> Result<()> {
        if self.phase != Phase::Ready {
            bail!("the generation is not complete");
        }
        let stage = self.stage();
        let meta = stage.join("meta");
        let mut steps = self.swap_steps(&meta)?;
        if self.current {
            let mut damaged = Vec::new();
            for s in steps {
                if !exact(&self.tree, &s)? {
                    damaged.push(s);
                }
            }
            steps = damaged;
        }
        for w in &self.want {
            if !present(&self.dest(w), w.entry.size)? {
                bail!("{}: a landed file is gone or changed size", w.entry.path);
            }
        }
        for w in self.want.iter().filter(|w| w.incoming) {
            let (p, from) = (&w.entry.path, self.dest(w));
            if !holds(&from, w.entry.check)? {
                bail!("{p}: the staged file no longer matches");
            }
            clear_way(&meta, parent(p))?;
            let to = rel_path(&meta, p);
            remove_any(&to)?;
            fs::rename(&from, &to).with_context(|| to.display().to_string())?;
            steps.push(Step {
                path: p.clone(),
                key: p.clone(),
                files: vec![(p.clone(), w.entry.check)],
                replace: Vec::new(),
            });
        }
        let entries: Vec<Entry> = self.want.iter().map(|w| w.entry.clone()).collect();
        let header = Header {
            generation: self.generation.clone(),
            files: entries.len() as u64,
            bytes: entries.iter().map(|e| e.size).sum(),
            at: jiff::Timestamp::now(),
            anchor_ts: self.anchor.ts.clone(),
        };
        write_tsv(&stage.join("live.tsv"), Some(&header), &entries)?;
        platform::sync_fs(&self.tree).with_context(|| self.tree.display().to_string())?;
        if steps.is_empty() {
            remove_any(&stage)?;
        } else {
            commit_swap(
                &self.tree,
                Journal {
                    generation: self.generation.clone(),
                    steps,
                },
            )?;
        }
        self.done = None;
        for p in [done_path(&self.tree), want_path(&self.tree)] {
            remove_any(&p)?;
        }
        platform::sync_dir(&book(&self.tree))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::collections::BTreeMap;

    const NEW: &str = "abababababababababababababababababababababababababababababababab";
    type Edit = fn(&mut Journal);
    const OLD: &str = "0101010101010101010101010101010101010101010101010101010101010101";

    fn sha(b: &[u8]) -> Check {
        Check::Sha256(Sha256::digest(b).into())
    }

    fn put_file(root: &Path, rel: &str, data: &[u8]) {
        let p = rel_path(root, rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, data).unwrap();
    }

    fn entry(path: &str, data: &[u8]) -> Entry {
        Entry {
            path: path.to_string(),
            size: data.len() as u64,
            check: sha(data),
        }
    }

    fn header(generation: &str, n: u64) -> Header {
        Header {
            generation: generation.to_string(),
            files: n,
            bytes: 0,
            at: jiff::Timestamp::UNIX_EPOCH,
            anchor_ts: Vec::new(),
        }
    }

    fn step(path: &str, key: &str, files: &[(&str, &[u8])]) -> Step {
        Step {
            path: path.to_string(),
            key: key.to_string(),
            files: files.iter().map(|(p, d)| (p.to_string(), sha(d))).collect(),
            replace: Vec::new(),
        }
    }

    /// Every file and link under `root`, links as `link:<target>`.
    fn snapshot(root: &Path) -> BTreeMap<String, Vec<u8>> {
        fn walk(dir: &Path, rel: &str, out: &mut BTreeMap<String, Vec<u8>>) {
            for e in fs::read_dir(dir).unwrap() {
                let e = e.unwrap();
                let r = format!("{rel}{}", e.file_name().to_string_lossy());
                let t = e.file_type().unwrap();
                if t.is_symlink() {
                    let to = fs::read_link(e.path()).unwrap();
                    out.insert(r, format!("link:{}", to.display()).into_bytes());
                } else if t.is_dir() {
                    walk(&e.path(), &format!("{r}/"), out);
                } else {
                    out.insert(r, fs::read(e.path()).unwrap());
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(root, "", &mut out);
        out
    }

    /// An old generation live in `tree` and a new one staged, with three kinds of step: a
    /// directory, a file that exists, a file that does not.
    fn setup(tree: &Path) -> (Journal, BTreeMap<String, Vec<u8>>) {
        for (p, d) in [
            ("pool/a.deb", &b"A"[..]),
            ("pool/old.deb", b"OLD"),
            ("pool/new.deb", b"NEW"),
            ("dists/trixie/InRelease", b"old-rel"),
            ("dists/trixie/main/Packages", b"old-pk"),
            ("dists/trixie/main/stale", b"old"),
            ("top.idx", b"old-idx"),
        ] {
            put_file(tree, p, d);
        }
        fs::create_dir_all(book(tree)).unwrap();
        write_tsv(
            &live_path(tree),
            Some(&header(OLD, 2)),
            &[entry("pool/a.deb", b"A"), entry("pool/old.deb", b"OLD")],
        )
        .unwrap();
        let stage = stage_dir(tree, NEW);
        let meta = stage.join("meta");
        for (p, d) in [
            ("dists/trixie/InRelease", &b"new-rel"[..]),
            ("dists/trixie/main/Packages", b"new-pk"),
            ("top.idx", b"new-idx"),
            ("fresh/idx", b"fresh"),
        ] {
            put_file(&meta, p, d);
        }
        fs::create_dir_all(meta.join("dists/trixie/by-hash")).unwrap();
        fs::hard_link(
            meta.join("dists/trixie/main/Packages"),
            meta.join("dists/trixie/by-hash/x"),
        )
        .unwrap();
        let live = [entry("pool/a.deb", b"A"), entry("pool/new.deb", b"NEW")];
        write_tsv(&stage.join("live.tsv"), Some(&header(NEW, 2)), &live).unwrap();
        let staged_live = fs::read(stage.join("live.tsv")).unwrap();
        let j = Journal {
            generation: NEW.to_string(),
            steps: vec![
                step(
                    "dists/trixie",
                    "dists/trixie/InRelease",
                    &[
                        ("dists/trixie/InRelease", b"new-rel"),
                        ("dists/trixie/main/Packages", b"new-pk"),
                        ("dists/trixie/by-hash/x", b"new-pk"),
                    ],
                ),
                step("top.idx", "top.idx", &[("top.idx", b"new-idx")]),
                step("fresh/idx", "fresh/idx", &[("fresh/idx", b"fresh")]),
            ],
        };
        let want: BTreeMap<String, Vec<u8>> = [
            (".preserver/live.tsv", staged_live),
            ("pool/a.deb", b"A".to_vec()),
            ("pool/new.deb", b"NEW".to_vec()),
            ("dists/trixie/InRelease", b"new-rel".to_vec()),
            ("dists/trixie/main/Packages", b"new-pk".to_vec()),
            ("dists/trixie/by-hash/x", b"new-pk".to_vec()),
            ("top.idx", b"new-idx".to_vec()),
            ("fresh/idx", b"fresh".to_vec()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        (j, want)
    }

    /// A tick that fails from call `n + 1` on: a crash before that operation.
    fn crash_after(n: usize) -> impl FnMut() -> io::Result<()> {
        let mut c = 0;
        move || {
            c += 1;
            if c > n {
                Err(io::Error::other("crash"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn swap_recovers_from_every_crash_point() {
        for exch in [true, false] {
            let mut n = 0;
            loop {
                let mut m = 0;
                let finished = loop {
                    let tmp = TempDir::new();
                    let tree = tmp.path();
                    let (j, want) = setup(tree);
                    if commit_with(tree, j.clone(), exch, &mut crash_after(n)).is_ok() {
                        assert_eq!(snapshot(tree), want, "exch {exch}, no crash");
                        break true;
                    }
                    let again = recover_with(tree, exch, &mut crash_after(m));
                    match again {
                        Ok(false) => commit_swap(tree, j).unwrap(),
                        Ok(true) => {}
                        Err(_) => assert!(recover(tree).unwrap()),
                    }
                    assert_eq!(snapshot(tree), want, "exch {exch}, crash {n} then {m}");
                    assert!(!recover(tree).unwrap());
                    if again.is_ok() {
                        break false;
                    }
                    m += 1;
                };
                if finished {
                    assert!(n > 8, "only {n} crash points");
                    break;
                }
                n += 1;
            }
        }
    }

    #[test]
    fn recover_refuses_tampered_staged_file() {
        for tamper in ["dists/trixie/main/Packages", "dists/trixie/extra"] {
            let tmp = TempDir::new();
            let tree = tmp.path();
            let (j, _) = setup(tree);
            assert!(commit_with(tree, j, true, &mut crash_after(1)).is_err());
            put_file(&stage_dir(tree, NEW).join("meta"), tamper, b"evil");
            let before = snapshot(tree);
            let err = recover(tree).unwrap_err().to_string();
            assert!(
                err.contains("neither the staged nor the live"),
                "{tamper}: {err}"
            );
            assert_eq!(snapshot(tree), before, "{tamper}");
            assert!(journal_path(tree).exists());
        }
    }

    #[test]
    fn commit_refuses_inexact_stage_without_journal() {
        for stray in ["dists/trixie/main/Packages.part", "fresh/idx"] {
            let tmp = TempDir::new();
            let tree = tmp.path();
            let (j, _) = setup(tree);
            put_file(&stage_dir(tree, NEW).join("meta"), stray, b"junk");
            let before = snapshot(tree);
            let err = commit_swap(tree, j.clone()).unwrap_err().to_string();
            assert!(
                err.contains("neither the staged nor the live"),
                "{stray}: {err}"
            );
            assert!(!journal_path(tree).exists(), "{stray}");
            assert_eq!(snapshot(tree), before, "{stray}");
            assert!(!recover(tree).unwrap(), "{stray}");
        }
    }

    #[test]
    fn valid_path_table() {
        for (p, ok) in [
            ("pool/a.deb", true),
            ("pool/../x", false),
            ("pool/.part", false),
            ("pool/a\\b", false),
            ("pool/a\nb", false),
            ("pool/C:evil", !cfg!(windows)),
            ("pool/a:b", !cfg!(windows)),
        ] {
            assert_eq!(valid_path(p), ok, "{p:?}");
        }
    }

    #[test]
    fn journal_paths_validated() {
        let tmp = TempDir::new();
        let (good, _) = setup(tmp.path());
        good.check().unwrap();
        let cases: [(&str, Edit); 10] = [
            ("dotdot path", |j| {
                j.steps[1] = step("../x", "../x", &[("../x", b"")]);
            }),
            ("bookkeeping path", |j| {
                j.steps[1] = step(".preserver/x", ".preserver/x", &[(".preserver/x", b"")]);
            }),
            ("key outside path", |j| {
                j.steps[0].key = "dists/trixie-updates/InRelease".into();
            }),
            ("key not a file", |j| {
                j.steps[0].key = "dists/trixie/Release".into();
            }),
            ("file escapes", |j| {
                j.steps[0].files[1].0 = "dists/trixie/../../etc/passwd".into();
            }),
            ("short gen", |j| j.generation.truncate(62)),
            ("upper gen", |j| j.generation = j.generation.to_uppercase()),
            ("replace not ancestor", |j| {
                j.steps[0].replace = vec!["pool".into()];
            }),
            ("overlap", |j| {
                j.steps[2] = step("dists", "dists/x", &[("dists/x", b"")]);
            }),
            ("no steps", |j| j.steps.clear()),
        ];
        for (name, edit) in cases {
            let mut j = good.clone();
            edit(&mut j);
            assert!(j.check().is_err(), "{name}");
        }
        let mut bad = good.clone();
        bad.steps[1] = step("../x", "../x", &[("../x", b"")]);
        let tree = tmp.path();
        fs::write(journal_path(tree), serde_json::to_vec(&bad).unwrap()).unwrap();
        let before = snapshot(tree);
        assert!(recover(tree).is_err());
        assert_eq!(snapshot(tree), before);
    }

    #[test]
    fn collision_replaced_at_swap() {
        let tmp = TempDir::new();
        let tree = &tmp.path().join("tree");
        let outside = &tmp.path().join("outside");
        fs::create_dir_all(outside).unwrap();
        fs::create_dir_all(book(tree)).unwrap();
        put_file(tree, "dists", b"a stray file where a directory goes");
        platform::symlink(outside, &tree.join("links")).unwrap();
        let meta = stage_dir(tree, NEW).join("meta");
        put_file(&meta, "dists/trixie/InRelease", b"rel");
        put_file(&meta, "links/idx", b"idx");
        write_tsv(
            &stage_dir(tree, NEW).join("live.tsv"),
            Some(&header(NEW, 0)),
            &[],
        )
        .unwrap();
        let j = Journal {
            generation: NEW.to_string(),
            steps: vec![
                step(
                    "dists/trixie",
                    "dists/trixie/InRelease",
                    &[("dists/trixie/InRelease", b"rel")],
                ),
                step("links/idx", "links/idx", &[("links/idx", b"idx")]),
            ],
        };
        commit_swap(tree, j).unwrap();
        assert!(snapshot(outside).is_empty());
        let got = snapshot(tree);
        assert_eq!(got["dists/trixie/InRelease"], b"rel");
        assert_eq!(got["links/idx"], b"idx");
        assert!(fs::symlink_metadata(tree.join("links")).unwrap().is_dir());
        assert_eq!(live_gen(tree).unwrap().as_deref(), Some(NEW));
    }

    #[cfg(unix)]
    #[test]
    fn prune_removes_only_strays() {
        use std::os::unix::ffi::OsStrExt;
        let tmp = TempDir::new();
        let tree = &tmp.path().join("tree");
        let outside = &tmp.path().join("outside");
        put_file(outside, "f", b"keep me");
        put_file(outside, "d/g", b"keep me too");
        for p in [
            "pool/keep",
            "pool/stray",
            "pool/sub/deep",
            ".preserver/live.tsv",
            "dists/trixie/in-swap",
            "dists/old/x",
        ] {
            put_file(tree, p, b"x");
        }
        fs::create_dir_all(tree.join("empty/inner")).unwrap();
        fs::write(tree.join("pool").join(OsStr::from_bytes(b"\xff")), b"x").unwrap();
        std::os::unix::fs::symlink(outside.join("f"), tree.join("pool/link")).unwrap();
        std::os::unix::fs::symlink(outside.join("d"), tree.join("pool/dir")).unwrap();
        std::os::unix::fs::symlink(outside.join("f"), tree.join("pool/linked")).unwrap();
        let keep = [entry("pool/keep", b"x"), entry("pool/linked", b"x")];
        let n = prune(tree, &keep, &["dists/trixie".to_string()]).unwrap();
        assert_eq!(n, 7);
        assert_eq!(
            snapshot(tree).into_keys().collect::<Vec<_>>(),
            [".preserver/live.tsv", "dists/trixie/in-swap", "pool/keep"]
        );
        assert_eq!(snapshot(outside).len(), 2);
    }

    #[test]
    fn tsv_table() {
        let hd = header(NEW, 2).to_string();
        let la = format!("{}\t1\tpool/a", sha(b"a"));
        let lb = format!("{}\t22\tpool/b", sha(b"b"));
        let long = format!("{}\t1\t{}", sha(b"a"), "x".repeat(LINE_CAP));
        let ok: [(&str, String, bool, usize, bool); 5] = [
            ("full", format!("{hd}\n{la}\n{lb}\n"), true, 2, false),
            ("no header", format!("{la}\n"), false, 1, false),
            ("torn", format!("{hd}\n{la}\n{}", &lb[..70]), true, 1, true),
            ("empty", String::new(), false, 0, false),
            ("header only", format!("{hd}\n"), true, 0, false),
        ];
        for (name, text, has_header, n, torn) in ok {
            let t = parse_tsv(text.as_bytes()).unwrap();
            assert_eq!(t.header.is_some(), has_header, "{name}");
            assert_eq!(t.entries.len(), n, "{name}");
            assert_eq!(t.torn, torn, "{name}");
        }
        let bad = [
            ("over-long", format!("{long}\n")),
            ("over-long torn", long.clone()),
            ("dotdot", la.replace("pool/a", "../a") + "\n"),
            ("hidden", la.replace("pool/a", "pool/.a") + "\n"),
            ("control", la.replace("pool/a", "pool/a\tb") + "\n"),
            ("size", la.replace("\t1\t", "\t-1\t") + "\n"),
            ("check", la.replace("sha256:", "md5:") + "\n"),
            ("late header", format!("{la}\n{hd}\n")),
            ("version", hd.replace("\t1\t", "\t2\t") + "\n"),
            ("short", "x\n".to_string()),
        ];
        for (name, text) in bad {
            assert!(parse_tsv(text.as_bytes()).is_err(), "{name}");
        }
        let tmp = TempDir::new();
        let p = tmp.path().join("live.tsv");
        let es = [entry("a/b", b"1"), entry("a.b", b"22")];
        let mut h = header(NEW, 2);
        h.anchor_ts = vec![("a/b".into(), 1_700_000_000)];
        write_tsv(&p, Some(&h), &es).unwrap();
        let t = read_tsv(&p).unwrap();
        assert_eq!((t.header.as_ref(), &t.entries[..]), (Some(&h), &es[..]));
        assert_eq!(read_header(&p).unwrap(), Some(h));
        assert_eq!(read_header(&tmp.path().join("absent")).unwrap(), None);
    }

    #[test]
    fn url_of_encodes() {
        for (base, rel, want) in [
            (
                "https://deb.example/debian/",
                "pool/main/g/gcc/gcc_1.0+b1~rc1_amd64.deb",
                "https://deb.example/debian/pool/main/g/gcc/gcc_1.0%2Bb1~rc1_amd64.deb",
            ),
            (
                "https://h/r",
                "a b/c%d#e?f",
                "https://h/r/a%20b/c%25d%23e%3Ff",
            ),
            ("https://h/r//", "é", "https://h/r/%C3%A9"),
        ] {
            assert_eq!(url_of(base, rel), want, "{rel}");
        }
    }

    #[test]
    fn fs_limits_table() {
        let e = |p: &str, size: u64| Entry {
            path: p.to_string(),
            size,
            check: Check::Sha256([0; 32]),
        };
        let cases: Vec<(&str, Vec<Entry>, Option<&str>)> = vec![
            ("vfat", vec![e("a", 4 << 30)], Some("1 file(s) of 4 GiB")),
            ("vfat", vec![e("a", (4 << 30) - 1)], None),
            ("exfat", vec![e("a", 4 << 30)], None),
            ("exfat", vec![e("Pool/a", 1), e("pool/b", 1)], Some("case")),
            ("ntfs3", vec![e("A", 1), e("a", 1)], Some("case")),
            ("exfat", vec![e("a", 1), e("A/b", 1)], Some("case")),
            ("ntfs3", vec![e("x/aux", 1)], Some("Windows refuses")),
            ("vfat", vec![e("nul.txt", 1)], Some("Windows refuses")),
            ("exfat", vec![e("dir/x.", 1)], Some("Windows refuses")),
            (
                "exfat",
                vec![e("aux", 1), e("nul.txt", 1), e("A", 1), e("a", 1)],
                Some("2 file(s) with a name Windows refuses, 1 file(s)"),
            ),
            (
                "other",
                vec![e("aux", 4 << 30), e("A", 1), e("a", 1), e("x.", 1)],
                None,
            ),
        ];
        for (fs, entries, want) in cases {
            let got = fs_limits(fs, entries.iter());
            match want {
                None => assert!(got.is_ok(), "{fs} {entries:?}: {got:?}"),
                Some(w) => {
                    let msg = got.unwrap_err().to_string();
                    assert!(msg.contains(w), "{fs} {entries:?}: {msg}");
                }
            }
        }
    }

    const BASE: &str = "https://up.test/r";
    const LIST: &str = "dists/s/main/list";

    /// The upstream: files by path, and every path asked for.
    #[derive(Default)]
    struct Up {
        files: HashMap<String, Vec<u8>>,
        hits: Vec<String>,
    }

    impl Up {
        /// What the download pool does: a file lands at its dest only when it verifies.
        fn serve(&mut self, p: &Planned) -> Vec<usize> {
            let mut ok = Vec::new();
            for (i, f) in p.fetches.iter().enumerate() {
                let rel = f.url.strip_prefix(&format!("{BASE}/")).unwrap().to_string();
                assert!(f.dest.parent().unwrap().is_dir(), "{rel}: no directory");
                self.hits.push(rel.clone());
                let Some(b) = self.files.get(&rel) else {
                    continue;
                };
                let Expect::Sha256(h) = f.expect else {
                    panic!("{rel}: no sha256");
                };
                if <[u8; 32]>::from(Sha256::digest(b)) == h && f.size == Some(b.len() as u64) {
                    fs::write(&f.dest, b).unwrap();
                    ok.push(i);
                }
            }
            ok
        }

        /// Publishes `payload` with a list and a Release that names the list's hash.
        fn publish(&mut self, payload: &[(&str, &[u8])], tag: &str) -> Anchor {
            let mut list = String::new();
            for (p, b) in payload {
                let Check::Sha256(h) = sha(b) else {
                    unreachable!()
                };
                let _ = writeln!(list, "{} {} {p}", hex(&h), b.len());
                self.files.insert(p.to_string(), b.to_vec());
            }
            self.files.insert(LIST.into(), list.clone().into_bytes());
            let doc = format!("Release {tag} {}\n", sha(list.as_bytes()));
            Anchor {
                docs: vec![("dists/s/Release".into(), doc.into_bytes())],
                meta: vec![super::super::Meta {
                    entry: entry(LIST, list.as_bytes()),
                    from: None,
                }],
                swaps: vec!["dists/s".into()],
                ts: vec![("dists/s/Release".into(), 7)],
            }
        }

        fn take_hits(&mut self) -> Vec<String> {
            std::mem::take(&mut self.hits)
        }
    }

    /// Reads the list and makes a by-hash copy of it, as a Debian walk does.
    fn test_walk(_: &Anchor, meta: &Path, emit: &mut dyn FnMut(Walked)) -> Result<()> {
        let text = fs::read_to_string(rel_path(meta, LIST))?;
        for l in text.lines() {
            let mut f = l.splitn(3, ' ');
            let (Some(h), Some(size), Some(path)) = (f.next(), f.next(), f.next()) else {
                bail!("bad line");
            };
            emit(Walked::File(Entry {
                path: path.to_string(),
                size: size.parse()?,
                check: format!("sha256:{h}")
                    .parse()
                    .map_err(|e: String| anyhow!(e))?,
            }));
        }
        let Check::Sha256(h) = sha(text.as_bytes()) else {
            unreachable!()
        };
        let rel = format!("dists/s/by-hash/{}", hex(&h));
        let link = rel_path(meta, &rel);
        fs::create_dir_all(link.parent().unwrap())?;
        if !link.exists() {
            fs::hard_link(rel_path(meta, LIST), &link)?;
        }
        emit(Walked::Link(rel));
        Ok(())
    }

    #[derive(Debug, PartialEq)]
    enum End {
        Committed,
        Stopped,
        Over(u64, u64),
    }

    fn drive_with(
        tree: &Path,
        anchor: Anchor,
        up: &mut Up,
        walk: &mut Walk<'_>,
        room: u64,
    ) -> Result<End> {
        let mut g = begin(tree, BASE, anchor)?;
        let mut ok = Vec::new();
        loop {
            match g.next(&ok, walk, room, "ext4")? {
                Next::Batch(p) => {
                    ok = up.serve(&p);
                    if ok.len() < p.fetches.len() {
                        g.land(&ok)?;
                        return Ok(End::Stopped);
                    }
                }
                Next::Ready => {
                    g.commit()?;
                    return Ok(End::Committed);
                }
                Next::OverBudget { need, room } => return Ok(End::Over(need, room)),
            }
        }
    }

    fn drive(tree: &Path, anchor: Anchor, up: &mut Up) -> End {
        drive_with(tree, anchor, up, &mut test_walk, u64::MAX).unwrap()
    }

    /// The tree without its bookkeeping: what a package manager sees.
    fn visible(tree: &Path) -> BTreeMap<String, Vec<u8>> {
        let mut s = snapshot(tree);
        s.retain(|k, _| !k.starts_with(".preserver/"));
        s
    }

    fn done_paths(tree: &Path) -> Vec<String> {
        read_tsv(&done_path(tree))
            .unwrap()
            .entries
            .into_iter()
            .map(|e| e.path)
            .collect()
    }

    const AB: [(&str, &[u8]); 2] = [("pool/a", b"aaa"), ("pool/b/c", b"bc")];

    #[test]
    fn fresh_generation_end_to_end() {
        let tmp = TempDir::new();
        let tree = &tmp.path().join("tree");
        let mut up = Up::default();
        let a = up.publish(&AB, "1");
        let generation = gen_of(&a);
        let doc = a.docs[0].1.clone();
        assert_eq!(drive(tree, a, &mut up), End::Committed);
        assert_eq!(up.take_hits(), [LIST, "pool/a", "pool/b/c"]);
        let list = up.files[LIST].clone();
        let Check::Sha256(h) = sha(&list) else {
            unreachable!()
        };
        let want: BTreeMap<String, Vec<u8>> = [
            ("dists/s/Release".to_string(), doc),
            (LIST.to_string(), list.clone()),
            (format!("dists/s/by-hash/{}", hex(&h)), list),
            ("pool/a".to_string(), b"aaa".to_vec()),
            ("pool/b/c".to_string(), b"bc".to_vec()),
        ]
        .into_iter()
        .collect();
        assert_eq!(visible(tree), want);
        let live = read_tsv(&live_path(tree)).unwrap();
        let h = live.header.unwrap();
        assert_eq!(
            (h.generation, h.files, h.bytes, h.anchor_ts),
            (generation, 2, 5, vec![("dists/s/Release".to_string(), 7)])
        );
        assert_eq!(
            live.entries,
            [entry("pool/a", b"aaa"), entry("pool/b/c", b"bc")]
        );
        assert_eq!(
            snapshot(&book(tree)).into_keys().collect::<Vec<_>>(),
            ["live.tsv"]
        );
    }

    #[test]
    fn tampered_payload_never_visible() {
        let tmp = TempDir::new();
        let tree = &tmp.path().join("tree");
        let mut up = Up::default();
        let a = up.publish(&AB, "1");
        assert_eq!(drive(tree, a, &mut up), End::Committed);
        let before = visible(tree);
        let b = up.publish(&[AB[0], AB[1], ("pool/new", b"new")], "2");
        up.files.insert("pool/new".into(), b"evil".to_vec());
        assert_eq!(drive(tree, b, &mut up), End::Stopped);
        assert_eq!(visible(tree), before);
        assert_eq!(done_paths(tree), Vec::<String>::new());
    }

    #[test]
    fn tampered_metadata_rejected() {
        let tmp = TempDir::new();
        let tree = &tmp.path().join("tree");
        let mut up = Up::default();
        let a = up.publish(&AB, "1");
        up.files.insert(LIST.into(), b"pool/x".to_vec());
        let mut calls = 0;
        let mut walk = |a: &Anchor, m: &Path, e: &mut dyn FnMut(Walked)| {
            calls += 1;
            test_walk(a, m, e)
        };
        let end = drive_with(tree, a, &mut up, &mut walk, u64::MAX).unwrap();
        assert_eq!(
            (end, up.take_hits()),
            (End::Stopped, vec![LIST.to_string()])
        );

        // A file that changes after it verified is refused before the walk reads it.
        let a = up.publish(&AB, "1");
        let mut g = begin(tree, BASE, a).unwrap();
        let Next::Batch(p) = g.next(&[], &mut walk, u64::MAX, "ext4").unwrap() else {
            panic!("no metadata batch");
        };
        assert_eq!(up.serve(&p), [0]);
        fs::write(&p.fetches[0].dest, b"pool/x pool/y").unwrap();
        let err = g.next(&[0], &mut walk, u64::MAX, "ext4").err().unwrap();
        assert!(
            err.to_string().contains("does not match the anchor"),
            "{err}"
        );
        drop(g);
        assert_eq!(calls, 0);
        assert!(visible(tree).is_empty());
    }

    #[test]
    fn planted_meta_and_want_rejected() {
        let tmp = TempDir::new();
        let tree = &tmp.path().join("tree");
        let mut up = Up::default();
        let a = up.publish(&AB, "1");
        let stage = stage_dir(tree, &gen_of(&a));
        put_file(&stage.join("meta"), LIST, b"0000 1 pool/evil\n");
        put_file(
            tree,
            ".preserver/want.tsv",
            format!("{}\t4\tpool/evil\n", sha(b"evil")).as_bytes(),
        );
        assert_eq!(drive(tree, a, &mut up), End::Committed);
        assert_eq!(up.take_hits(), [LIST, "pool/a", "pool/b/c"]);
        assert!(!tree.join("pool/evil").exists());
        assert!(!want_path(tree).exists());
    }

    #[test]
    fn stale_wrong_size_plus_404_leaves_no_done_line() {
        let tmp = TempDir::new();
        let tree = &tmp.path().join("tree");
        let mut up = Up::default();
        let a = up.publish(&AB, "1");
        up.files.remove("pool/b/c");
        put_file(tree, "pool/b/c", b"stale and longer");
        assert_eq!(drive(tree, a, &mut up), End::Stopped);
        assert!(!tree.join("pool/b/c").exists());
        assert_eq!(done_paths(tree), ["pool/a"]);
    }

    #[test]
    fn interrupted_generation_resumes() {
        let tmp = TempDir::new();
        let tree = &tmp.path().join("tree");
        let mut up = Up::default();
        let files: [(&str, &[u8]); 4] = [
            ("pool/a", b"aa"),
            ("pool/b", b"bb"),
            ("pool/c", b"cc"),
            ("pool/d", b"dd"),
        ];
        let a = up.publish(&files, "1");
        up.files.remove("pool/d");
        assert_eq!(drive(tree, a, &mut up), End::Stopped);
        assert_eq!(done_paths(tree), ["pool/a", "pool/b", "pool/c"]);
        up.take_hits();
        // A crash in the middle of the last append, and a file that is not what landed.
        let dp = done_path(tree);
        let text = fs::read(&dp).unwrap();
        fs::write(&dp, &text[..text.len() - 4]).unwrap();
        fs::write(tree.join("pool/c"), b"xx").unwrap();
        let a = up.publish(&files, "1");
        assert_eq!(drive(tree, a, &mut up), End::Committed);
        assert_eq!(up.take_hits(), ["pool/c", "pool/d"]);
        assert_eq!(fs::read(tree.join("pool/c")).unwrap(), b"cc");
        assert_eq!(read_tsv(&live_path(tree)).unwrap().entries.len(), 4);
    }

    #[test]
    fn carries_landed_files() {
        let tmp = TempDir::new();
        let tree = &tmp.path().join("tree");
        let mut up = Up::default();
        let a = up.publish(&AB, "1");
        up.files.remove("pool/b/c");
        assert_eq!(drive(tree, a, &mut up), End::Stopped);
        up.take_hits();
        let b = up.publish(&[AB[0], AB[1], ("pool/e", b"e")], "2");
        assert_eq!(drive(tree, b, &mut up), End::Committed);
        assert_eq!(up.take_hits(), [LIST, "pool/b/c", "pool/e"]);
        assert_eq!(read_tsv(&live_path(tree)).unwrap().entries.len(), 3);
    }

    #[test]
    fn unchanged_fetches_nothing() {
        let tmp = TempDir::new();
        let tree = &tmp.path().join("tree");
        let mut up = Up::default();
        let a = up.publish(&AB, "1");
        assert_eq!(drive(tree, a, &mut up), End::Committed);
        up.take_hits();
        let before = snapshot(tree);
        let a = up.publish(&AB, "1");
        assert_eq!(drive(tree, a, &mut up), End::Committed);
        assert_eq!(up.take_hits(), Vec::<String>::new());
        assert_eq!(snapshot(tree), before);
        // Re-signed: a new document over the same list reuses the live list.
        let b = up.publish(&AB, "2");
        let doc = b.docs[0].1.clone();
        assert_eq!(drive(tree, b, &mut up), End::Committed);
        assert_eq!(up.take_hits(), Vec::<String>::new());
        assert_eq!(fs::read(tree.join("dists/s/Release")).unwrap(), doc);
    }

    #[test]
    fn unchanged_generation_repaired() {
        let tmp = TempDir::new();
        let tree = &tmp.path().join("tree");
        let mut up = Up::default();
        let a = up.publish(&AB, "1");
        let stage = stage_dir(tree, &gen_of(&a));
        assert_eq!(drive(tree, a, &mut up), End::Committed);
        up.take_hits();
        let before = visible(tree);
        fs::remove_file(tree.join("pool/a")).unwrap();
        fs::write(tree.join(LIST), b"damaged").unwrap();
        let a = up.publish(&AB, "1");
        assert_eq!(drive(tree, a, &mut up), End::Committed);
        assert_eq!(up.take_hits(), [LIST, "pool/a"]);
        assert_eq!(visible(tree), before);
        assert!(!stage.exists());
        assert!(!done_path(tree).exists());
    }

    /// A plan that fails half way through a batch leaves nothing for `land` to record.
    #[cfg(unix)]
    #[test]
    fn failed_plan_lands_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new();
        let tree = &tmp.path().join("tree");
        let mut up = Up::default();
        let a = up.publish(&[("pool/a", b"aa"), ("pool/b", b"bb")], "1");
        put_file(tree, "pool/b", b"xx");
        let b = tree.join("pool/b");
        fs::set_permissions(&b, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::File::open(&b).is_ok() {
            return; // root reads it anyway
        }
        let mut g = begin(tree, BASE, a).unwrap();
        let Next::Batch(p) = g.next(&[], &mut test_walk, u64::MAX, "ext4").unwrap() else {
            panic!("no metadata batch");
        };
        let ok = up.serve(&p);
        assert!(g.next(&ok, &mut test_walk, u64::MAX, "ext4").is_err());
        g.land(&ok).unwrap();
        assert!(!tree.join("pool/a").exists());
        assert_eq!(done_paths(tree), Vec::<String>::new());
        fs::set_permissions(&b, fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[test]
    fn budget_refuses_before_payload() {
        let tmp = TempDir::new();
        let tree = &tmp.path().join("tree");
        let mut up = Up::default();
        let a = up.publish(&AB, "1");
        let end = drive_with(tree, a, &mut up, &mut test_walk, 4).unwrap();
        assert_eq!(end, End::Over(5, 4));
        assert_eq!(up.take_hits(), [LIST]);
        assert!(visible(tree).is_empty());
    }

    #[test]
    fn changed_payload_staged_until_swap() {
        let tmp = TempDir::new();
        let tree = &tmp.path().join("tree");
        let mut up = Up::default();
        let a = up.publish(&[("pool/a", b"v1"), ("pool/d", b"file")], "1");
        assert_eq!(drive(tree, a, &mut up), End::Committed);
        // pool/a changes, and pool/d becomes a directory.
        let b = up.publish(
            &[("pool/a", b"v2!"), ("pool/d/x", b"x"), ("pool/z", b"z")],
            "2",
        );
        up.files.remove("pool/z");
        assert_eq!(drive(tree, b, &mut up), End::Stopped);
        assert_eq!(fs::read(tree.join("pool/a")).unwrap(), b"v1");
        assert_eq!(fs::read(tree.join("pool/d")).unwrap(), b"file");
        up.take_hits();
        let b = up.publish(
            &[("pool/a", b"v2!"), ("pool/d/x", b"x"), ("pool/z", b"z")],
            "2",
        );
        assert_eq!(drive(tree, b, &mut up), End::Committed);
        assert_eq!(up.take_hits(), ["pool/z"]);
        let got = visible(tree);
        assert_eq!(got["pool/a"], b"v2!");
        assert_eq!(got["pool/d/x"], b"x");
        assert_eq!(got.len(), 6);
    }

    #[test]
    fn anchor_validation_table() {
        type AEdit = fn(&mut Anchor);
        let mut up = Up::default();
        let good = up.publish(&AB, "1");
        check_anchor(&good).unwrap();
        let doc = |p: &str| (p.to_string(), b"d".to_vec());
        let cases: [(&str, AEdit); 11] = [
            ("no swaps", |a| a.swaps.clear()),
            ("dotdot swap", |a| a.swaps.push("../x".into())),
            ("bookkeeping swap", |a| a.swaps.push(".preserver".into())),
            ("overlap", |a| a.swaps.push("dists".into())),
            ("doc under no swap", |a| {
                a.docs.push(("other/Release".into(), Vec::new()));
            }),
            ("meta under no swap", |a| {
                a.meta[0].entry.path = "pool/list".into();
            }),
            ("swap without doc", |a| a.swaps.push("dists/t".into())),
            ("duplicate", |a| {
                let d = a.docs[0].clone();
                a.docs.push(d);
            }),
            ("doc inside meta", |a| {
                a.docs.push((format!("{LIST}/x"), Vec::new()));
            }),
            ("bad from", |a| a.meta[0].from = Some("../by-hash/x".into())),
            ("hidden doc", |a| {
                a.docs.push(("dists/s/.x".into(), Vec::new()));
            }),
        ];
        let _ = doc;
        for (name, edit) in cases {
            let mut a = up.publish(&AB, "1");
            edit(&mut a);
            let tmp = TempDir::new();
            let tree = tmp.path().join("tree");
            assert!(begin(&tree, BASE, a).is_err(), "{name}");
            assert!(!tree.exists(), "{name}");
        }
    }

    #[test]
    fn extra_file_in_swap_dir_refused() {
        for planted in ["evil", "by-hash"] {
            let tmp = TempDir::new();
            let tree = &tmp.path().join("tree");
            let mut up = Up::default();
            let a = up.publish(&AB, "1");
            let meta = stage_dir(tree, &gen_of(&a)).join("meta");
            let mut g = begin(tree, BASE, a).unwrap();
            let mut ok = Vec::new();
            loop {
                match g.next(&ok, &mut test_walk, u64::MAX, "ext4").unwrap() {
                    Next::Batch(p) => ok = up.serve(&p),
                    Next::Ready => break,
                    Next::OverBudget { .. } => panic!("over budget"),
                }
            }
            if planted == "evil" {
                put_file(&meta, "dists/s/evil", b"x");
            } else {
                let link = fs::read_dir(meta.join("dists/s/by-hash"))
                    .unwrap()
                    .next()
                    .unwrap()
                    .unwrap()
                    .path();
                fs::remove_file(&link).unwrap();
                fs::write(&link, b"not the list").unwrap();
            }
            let err = g.commit().unwrap_err().to_string();
            assert!(
                err.contains("not named") || err.contains("not a copy"),
                "{planted}: {err}"
            );
            assert_eq!(
                visible(tree).into_keys().collect::<Vec<_>>(),
                ["pool/a", "pool/b/c"],
                "{planted}"
            );
            assert!(!live_path(tree).exists(), "{planted}");
            assert!(!journal_path(tree).exists(), "{planted}");
        }
    }

    fn walk_order(dir: &Path, rel: &str, out: &mut Vec<String>) {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        for n in names {
            let r = if rel.is_empty() {
                n.clone()
            } else {
                format!("{rel}/{n}")
            };
            if dir.join(&n).is_dir() {
                walk_order(&dir.join(&n), &r, out);
            } else {
                out.push(r);
            }
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

        #[test]
        fn path_order_matches_tree_walk(
            raw in proptest::collection::btree_set("[a-c][-.a-c~]{0,2}(/[a-c-][-.a-c~]{0,2}){0,3}", 1..24)
        ) {
            let paths: Vec<&String> = raw
                .iter()
                .filter(|p| valid_path(p))
                .filter(|p| !raw.iter().any(|q| q.starts_with(&format!("{p}/"))))
                .collect();
            let tmp = TempDir::new();
            for p in &paths {
                put_file(tmp.path(), p, b"");
            }
            let mut walked = Vec::new();
            walk_order(tmp.path(), "", &mut walked);
            let mut sorted: Vec<String> = paths.into_iter().cloned().collect();
            sorted.sort_by(|a, b| path_cmp(a, b));
            proptest::prop_assert_eq!(walked, sorted);
        }
    }
}
