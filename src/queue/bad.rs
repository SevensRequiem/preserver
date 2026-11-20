//! Files that never verify: `public/<set>/.preserver/bad.json`. A file whose whole download did
//! not match its published hash, or that failed verification at publish, is not downloaded
//! again while a one-byte probe of each of its URLs sees what it saw then. Retry and
//! `public --recheck` bypass the ledger for one run.
//!
//! The ledger has the drive's trust and can only suppress a download: the job then ends Failed
//! with the reason, and nothing unverified becomes visible. Probes go only to URLs of the
//! current plan (`Bad::known`), so a forged entry cannot direct traffic. An unreadable ledger
//! counts as empty. One worker per lane runs one job at a time, so it is the only writer.

use crate::copy::exec::ensure_dir;
use crate::mirror::generation::put;
use crate::net::download::{Downloader, Fetch, Seen, host_of};
use crate::public::versioned::{plain_dirs, read_meta};
use anyhow::Result;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

const VERSION: u8 = 1;
const CAP: usize = 256;
/// Entries of another build never match: the rules that wrote them may have changed.
const BUILD: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Entry {
    /// The file first, then the side files that took part in a publish-time failure.
    pub urls: Vec<String>,
    /// `Expect::tag` of the fetch.
    pub expect: String,
    pub size: Option<u64>,
    /// `seen[i]` is what `urls[i]` answered.
    pub seen: Vec<Seen>,
    pub build: String,
    pub since: Timestamp,
    pub reason: String,
}

impl Entry {
    pub(crate) fn new(urls: Vec<String>, expect: String, size: Option<u64>, reason: &str) -> Self {
        Self {
            urls,
            expect,
            size,
            seen: Vec::new(),
            build: BUILD.into(),
            since: Timestamp::now(),
            reason: reason.chars().take(200).collect(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Ledger {
    v: u8,
    entries: Vec<Entry>,
}

/// A batch's ledger: the set directory it lives under and every URL the current plan lists.
#[derive(Debug)]
pub(crate) struct Bad {
    pub set_dir: PathBuf,
    pub known: HashSet<String>,
}

fn load(set_dir: &Path) -> Vec<Entry> {
    let dir = set_dir.join(".preserver");
    if let Err(e) = plain_dirs(&[set_dir, &dir]) {
        tracing::warn!("bad-file ledger: {e:#}");
        return Vec::new();
    }
    let file = dir.join("bad.json");
    match read_meta(&file).map(|b| serde_json::from_slice::<Ledger>(&b)) {
        Ok(Ok(l)) if l.v == VERSION => l.entries,
        Ok(Ok(_)) => Vec::new(),
        Ok(Err(e)) => {
            tracing::warn!("{}: {e}", file.display());
            Vec::new()
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            tracing::warn!("{}: {e}", file.display());
            Vec::new()
        }
    }
}

fn save(set_dir: &Path, mut entries: Vec<Entry>) -> Result<()> {
    entries.retain(|e| e.build == BUILD);
    entries.sort_by_key(|e| std::cmp::Reverse(e.since));
    entries.truncate(CAP);
    plain_dirs(&[set_dir])?;
    let dir = ensure_dir(set_dir, ".preserver")?;
    let json = serde_json::to_vec_pretty(&Ledger {
        v: VERSION,
        entries,
    })?;
    put(&dir.join("bad.json"), |w| w.write_all(&json))
}

/// Replaces the entry for the same file; a failure of the same expected bytes keeps its date.
fn record_into(entries: &mut Vec<Entry>, mut e: Entry) {
    let first = e.urls.first().cloned();
    if let Some(old) = entries
        .iter()
        .find(|o| o.urls.first() == first.as_ref() && o.expect == e.expect)
    {
        e.since = old.since;
    }
    entries.retain(|o| o.urls.first() != first.as_ref());
    entries.push(e);
}

/// Why each fetch is not downloaded, if it is not: its entry matches the fetch, it has no
/// candidate to reuse (that costs no network and is proved against the hash), and every URL
/// of the entry answers a probe exactly as recorded. A host whose probe fails is not asked
/// again in this call, so a dead host costs one timeout. Once `stop` is true nothing more is
/// probed or held, so a pause, cancel or yield does not wait behind the probes.
pub(crate) fn held(
    b: &Bad,
    fetches: &[Fetch],
    dl: &Downloader,
    stop: &dyn Fn() -> bool,
) -> Vec<Option<String>> {
    let entries = load(&b.set_dir);
    if entries.is_empty() {
        return Vec::new();
    }
    let mut dead = HashSet::new();
    fetches
        .iter()
        .map(|f| {
            if f.reuse.is_some() {
                return None;
            }
            let tag = f.expect.tag();
            let e = entries.iter().find(|e| {
                e.urls.first() == Some(&f.url)
                    && e.expect == tag
                    && e.size == f.size
                    && e.build == BUILD
                    && e.seen.len() == e.urls.len()
                    && e.urls.iter().skip(1).all(|u| b.known.contains(u))
            })?;
            if stop() {
                return None;
            }
            for (u, seen) in e.urls.iter().zip(&e.seen) {
                let host = host_of(u);
                if dead.contains(&host) {
                    return None;
                }
                match dl.probe(u) {
                    Some(s) if s == *seen => {}
                    Some(_) => return None,
                    None => {
                        dead.insert(host);
                        return None;
                    }
                }
            }
            let how = if e.seen.iter().any(Seen::has_validator) {
                "upstream unchanged"
            } else {
                "upstream sends no validator"
            };
            Some(format!(
                "skipped {}: {} since {}, {how}",
                f.url,
                e.reason,
                e.since.strftime("%Y-%m-%d")
            ))
        })
        .collect()
}

/// After a batch: a verified fetch drops its entry, a whole download that did not match adds
/// one. A failure to write is logged; it never fails the job.
pub(crate) fn update(b: &Bad, fetches: &[Fetch], ok: &[usize], mismatched: &[(usize, Seen)]) {
    if mismatched.is_empty() && ok.is_empty() {
        return;
    }
    let mut entries = load(&b.set_dir);
    let before = entries.clone();
    let verified: HashSet<&str> = ok.iter().map(|i| fetches[*i].url.as_str()).collect();
    entries.retain(|e| {
        e.urls
            .first()
            .is_none_or(|u| !verified.contains(u.as_str()))
    });
    for (i, seen) in mismatched {
        let f = &fetches[*i];
        let mut e = Entry::new(
            vec![f.url.clone()],
            f.expect.tag(),
            f.size,
            "checksum mismatch",
        );
        e.seen = vec![seen.clone()];
        record_into(&mut entries, e);
    }
    if entries != before
        && let Err(e) = save(&b.set_dir, entries)
    {
        tracing::warn!("bad-file ledger: {e:#}");
    }
}

/// Adds publish-time failures.
pub(crate) fn record(set_dir: &Path, new: Vec<Entry>) {
    if new.is_empty() {
        return;
    }
    let mut entries = load(set_dir);
    for e in new {
        record_into(&mut entries, e);
    }
    if let Err(e) = save(set_dir, entries) {
        tracing::warn!("bad-file ledger: {e:#}");
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod unix_tests;
