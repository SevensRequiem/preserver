//! In-place repository mirrors: a tree on the drive that a package manager reads, kept whole
//! by swapping its metadata in only after every file it names has landed and verified.

pub(crate) mod alpine;
pub(crate) mod deb822;
pub(crate) mod debian;
pub(crate) mod fedora;
pub(crate) mod generation;

use crate::catalog::{RepoFormat, Source};
use crate::keys::Keyring;
use crate::net::download::Downloader;
use crate::resolve::hex;
use anyhow::{Context, Result, bail};
use generation::{Walked, live_path, read_tsv, url_of};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// How a file is known to be the right one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(crate) enum Check {
    Sha256([u8; 32]),
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Check::Sha256(h) => write!(f, "sha256:{}", hex(h)),
        }
    }
}

impl FromStr for Check {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let h = s
            .strip_prefix("sha256:")
            .ok_or_else(|| format!("unknown check {s:?}"))?;
        let b = h.as_bytes();
        if b.len() != 64 {
            return Err(format!("sha256 of {} characters", b.len()));
        }
        let nib = |c: u8| match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            _ => Err(format!("not lowercase hex: {h:?}")),
        };
        let mut out = [0u8; 32];
        for (o, pair) in out.iter_mut().zip(b.as_chunks::<2>().0) {
            *o = (nib(pair[0])? << 4) | nib(pair[1])?;
        }
        Ok(Check::Sha256(out))
    }
}

impl TryFrom<String> for Check {
    type Error = String;

    fn try_from(s: String) -> Result<Self, String> {
        s.parse()
    }
}

impl From<Check> for String {
    fn from(c: Check) -> Self {
        c.to_string()
    }
}

/// A file of the tree, by its path relative to the tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Entry {
    pub path: String,
    pub size: u64,
    pub check: Check,
}

/// A metadata file the walk reads. `from` is where to fetch it, relative to the base URL, when
/// that is not `entry.path` (a by-hash path).
#[derive(Debug, Clone)]
pub(crate) struct Meta {
    pub entry: Entry,
    pub from: Option<String>,
}

/// What a generation is pinned by: the signed or TLS-anchored documents with their exact
/// bytes, the metadata they vouch for, and the paths swapped in as a whole at commit.
#[derive(Debug, Default)]
pub(crate) struct Anchor {
    pub docs: Vec<(String, Vec<u8>)>,
    pub meta: Vec<Meta>,
    pub swaps: Vec<String>,
    /// Per document path, its metalink's `mm0:timestamp` (Fedora), kept in the `live.tsv`
    /// header at the commit.
    pub ts: Vec<(String, u64)>,
}

/// What a walker may use to fetch and verify its anchor.
pub(crate) struct Ctx<'a> {
    pub dl: &'a Downloader,
    pub keys: &'a [Keyring<'a>],
    /// The metalink service; production passes the Fedora constant, tests a loopback server.
    pub metalink: &'a str,
    pub plain_http: bool,
    /// The live tree when the drive is mounted, for rollback checks against it.
    pub tree: Option<&'a Path>,
}

/// `base` joined with a `/`-separated path that `generation::valid_path` accepted.
pub(crate) fn rel_path(base: &Path, rel: &str) -> PathBuf {
    let mut p = base.to_path_buf();
    p.extend(rel.split('/'));
    p
}

/// The Fedora metalink service, which production passes in `Ctx`.
pub(crate) const FEDORA_METALINK: &str = "https://mirrors.fedoraproject.org/metalink";

type WalkFn = fn(&Source, &Anchor, &Path, &mut dyn FnMut(Walked)) -> Result<()>;

/// The three steps a format provides, so a test can stand in for a real upstream.
#[derive(Clone, Copy)]
pub(crate) struct Walkers {
    pub anchor: fn(&Ctx<'_>, &Source) -> Result<Anchor>,
    pub walk: WalkFn,
    /// The metadata files `walk` reads, which is all a dry run fetches.
    pub walk_meta: for<'a> fn(&Source, &'a Anchor) -> Vec<&'a Entry>,
}

pub(crate) const WALKERS: Walkers = Walkers {
    anchor,
    walk,
    walk_meta,
};

fn no_walker(src: &Source) -> anyhow::Error {
    match src.format {
        Some(f) => anyhow::anyhow!("{f:?} mirrors have no walker yet"),
        None => anyhow::anyhow!("a repo source needs a format"),
    }
}

fn anchor(ctx: &Ctx<'_>, src: &Source) -> Result<Anchor> {
    match src.format {
        Some(RepoFormat::Fedora) => fedora::anchor(ctx, src),
        _ => Err(no_walker(src)),
    }
}

fn walk(src: &Source, a: &Anchor, meta: &Path, emit: &mut dyn FnMut(Walked)) -> Result<()> {
    match src.format {
        Some(RepoFormat::Fedora) => fedora::walk(src, a, meta, emit),
        _ => Err(no_walker(src)),
    }
}

fn walk_meta<'a>(src: &Source, a: &'a Anchor) -> Vec<&'a Entry> {
    match src.format {
        Some(RepoFormat::Fedora) => fedora::walk_meta(src, a),
        _ => a.meta.iter().map(|m| &m.entry).collect(),
    }
}

/// Prints what a run of `src` would fetch. Only the metadata `walk_meta` names is downloaded,
/// into `cache`, and the cache is deleted afterwards. `tree` is the live tree when the drive
/// is mounted: what it already holds is left out of the payload to fetch.
pub(crate) fn dry_run(
    ctx: &Ctx<'_>,
    w: &Walkers,
    src: &Source,
    cache: &Path,
    out: &mut dyn Write,
) -> Result<()> {
    let anchor = (w.anchor)(ctx, src)?;
    generation::check_anchor(&anchor)?;
    let dir = cache.join(&generation::gen_of(&anchor)[..16]);
    let res = dry_walk(ctx, w, src, &anchor, &dir, out);
    let _ = std::fs::remove_dir_all(&dir);
    res
}

fn dry_walk(
    ctx: &Ctx<'_>,
    w: &Walkers,
    src: &Source,
    anchor: &Anchor,
    dir: &Path,
    out: &mut dyn Write,
) -> Result<()> {
    let put = |rel: &str, bytes: &[u8]| -> Result<()> {
        let dest = rel_path(dir, rel);
        std::fs::create_dir_all(dest.parent().context("a file at the root")?)?;
        std::fs::write(&dest, bytes).with_context(|| dest.display().to_string())
    };
    for (p, bytes) in &anchor.docs {
        put(p, bytes)?;
    }
    for e in (w.walk_meta)(src, anchor) {
        let from = anchor
            .meta
            .iter()
            .find(|m| m.entry == *e)
            .and_then(|m| m.from.as_deref())
            .unwrap_or(&e.path);
        let body = ctx.dl.get(&url_of(&src.url, from), e.size)?;
        let Check::Sha256(want) = e.check;
        if body.len() as u64 != e.size || <[u8; 32]>::from(Sha256::digest(&body)) != want {
            bail!("{}: does not match the anchor", e.path);
        }
        put(&e.path, &body)?;
    }
    let mut files = Vec::new();
    (w.walk)(src, anchor, dir, &mut |f| {
        if let Walked::File(e) = f {
            files.push(e);
        }
    })?;
    let total: u64 = files.iter().map(|e| e.size).sum();
    write!(
        out,
        "   {:<22} {} files, {} bytes",
        src.name,
        files.len(),
        total
    )?;
    if let Some(tree) = ctx.tree {
        let mut held = HashSet::new();
        for path in [live_path(tree), generation::done_path(tree)] {
            if let Ok(t) = read_tsv(&path) {
                held.extend(t.entries);
            }
        }
        let (n, bytes) = files
            .iter()
            .filter(|e| !held.contains(*e))
            .fold((0, 0), |(n, b), e| (n + 1, b + e.size));
        write!(out, "; {n} files, {bytes} bytes to fetch")?;
    }
    writeln!(out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_round_trips_and_refuses_junk() {
        let c = Check::Sha256([0xab; 32]);
        let s = c.to_string();
        assert_eq!(s, format!("sha256:{}", "ab".repeat(32)));
        assert_eq!(s.parse::<Check>().unwrap(), c);
        for bad in [
            "sha256:ab",
            &format!("sha256:{}", "AB".repeat(32)),
            &format!("sha512:{}", "ab".repeat(32)),
            &format!("sha256:{}g", "a".repeat(63)),
            "",
        ] {
            assert!(bad.parse::<Check>().is_err(), "{bad:?}");
        }
    }
}
