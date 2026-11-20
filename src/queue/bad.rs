//! Files that never verify: `public/<set>/.preserver/bad.json`. A file whose whole download did
//! not match its published hash, or that failed verification at publish, is not downloaded
//! again while a one-byte probe of each of its URLs sees what it saw then. Retry and
//! `public --recheck` bypass the ledger for one run.
//!
//! The ledger has the drive's trust and can only suppress a download: the job then ends Failed
//! with the reason, and nothing unverified becomes visible. Probes go only to URLs of the
//! current plan (`Bad::known`), so a forged entry cannot direct traffic. An unreadable ledger
//! counts as empty. One worker per lane runs one job at a time, so it is the only writer.
//! Entries are bounded on load (count, URLs per entry, reason length), and a URL is probed at
//! most once per batch, so a forged ledger costs at most one probe per URL of the plan.

use crate::copy::exec::ensure_dir;
use crate::mirror::generation::put;
use crate::net::download::{Downloader, Fetch, Seen, host_of};
use crate::public::versioned::{plain_dirs, read_meta};
use anyhow::Result;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};

const VERSION: u8 = 1;
const CAP: usize = 256;
/// The file and its signature, sums and sums signature.
const MAX_URLS: usize = 4;
const MISMATCH: &str = "checksum mismatch";
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
            reason: clean(reason),
        }
    }

    /// Well-formed: it names its file, no URL twice, and a probe result per URL once probed.
    fn sane(&self) -> bool {
        let distinct: HashSet<&String> = self.urls.iter().collect();
        (1..=MAX_URLS).contains(&self.urls.len())
            && distinct.len() == self.urls.len()
            && (self.seen.is_empty() || self.seen.len() == self.urls.len())
    }
}

/// The reason reaches job errors, the tray, the GUI and a terminal: no control characters
/// (escape sequences), and short.
fn clean(reason: &str) -> String {
    reason
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect()
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
        Ok(Ok(l)) if l.v == VERSION => l
            .entries
            .into_iter()
            .filter(Entry::sane)
            .take(CAP)
            .map(|mut e| {
                e.reason = clean(&e.reason);
                e
            })
            .collect(),
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

/// Why a fetch is not downloaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Held {
    pub why: String,
    /// Its reuse candidate is tried first: the entry is a download that did not match, and a
    /// local file proved against the hash costs no network. A file refused at publish is held
    /// outright, since the same bytes from anywhere get the same verdict.
    pub adopt: bool,
}

/// Which fetches are not downloaded: those whose entry matches the fetch and every URL of
/// which answers a probe exactly as recorded. Each URL is probed at most once per call, and a
/// host whose probe fails is not asked again, so a dead host costs one timeout. Once `stop` is
/// true nothing more is probed or held, so a pause, cancel or yield does not wait behind the
/// probes.
pub(crate) fn held(
    b: &Bad,
    fetches: &[Fetch],
    dl: &Downloader,
    stop: &dyn Fn() -> bool,
) -> Vec<Option<Held>> {
    let entries = load(&b.set_dir);
    if entries.is_empty() {
        return Vec::new();
    }
    let mut dead = HashSet::new();
    let mut probed: HashMap<String, Option<Seen>> = HashMap::new();
    let mut probe = |u: &str| -> Option<Seen> {
        if let Some(s) = probed.get(u) {
            return s.clone();
        }
        let host = host_of(u);
        if dead.contains(&host) || stop() {
            return None;
        }
        let s = dl.probe(u);
        if s.is_none() {
            dead.insert(host);
        }
        probed.insert(u.to_owned(), s.clone());
        s
    };
    fetches
        .iter()
        .map(|f| {
            let tag = f.expect.tag();
            let e = entries.iter().find(|e| {
                e.urls.first() == Some(&f.url)
                    && e.expect == tag
                    && e.size == f.size
                    && e.build == BUILD
                    && e.seen.len() == e.urls.len()
                    && e.urls.iter().skip(1).all(|u| b.known.contains(u))
            })?;
            for (u, seen) in e.urls.iter().zip(&e.seen) {
                if probe(u).as_ref() != Some(seen) {
                    return None;
                }
            }
            let how = if e.seen.iter().any(Seen::has_validator) {
                "upstream unchanged"
            } else {
                "upstream sends no validator"
            };
            Some(Held {
                why: format!(
                    "skipped {}: {} since {}, {how}",
                    f.url,
                    e.reason,
                    e.since.strftime("%Y-%m-%d")
                ),
                adopt: f.reuse.is_some() && e.reason == MISMATCH,
            })
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
        let mut e = Entry::new(vec![f.url.clone()], f.expect.tag(), f.size, MISMATCH);
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
