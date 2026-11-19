//! Verioned sets: `<set>/.staging/<plan16>/` fills up, and becomes `<set>/<date>/` in one
//! rename once every file in it has verified. Files a new version shares with the previous
//! one are hard links, so keeping several versions costs only what changed.

use crate::catalog::{Kind, Set, Source};
use crate::net::download::{Expect, Fetch};
use crate::platform;
use crate::resolve::{HF_BASE, Item, hex};
use crate::verify::{SIDE_LIMIT, Verifier, side};
use anyhow::{Context, Result, bail};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// One file of a set version. The layout of a version's `SET.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct PlanEntry {
    pub source: String,
    pub name: String,
    pub url: String,
    pub version: String,
    pub sha256: String,
    pub verify: String,
}

impl PlanEntry {
    fn new(source: &str, it: &Item) -> Self {
        Self {
            source: source.to_string(),
            name: it.name.clone(),
            url: it.url.clone(),
            version: it.version.clone(),
            sha256: it.sha256.clone(),
            verify: String::new(),
        }
    }

    fn same_file(&self, o: &Self) -> bool {
        (
            &self.source,
            &self.name,
            &self.url,
            &self.version,
            &self.sha256,
        ) == (&o.source, &o.name, &o.url, &o.version, &o.sha256)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct SetSource {
    pub name: String,
    pub kind: String,
    pub url: String,
    pub version: String,
    pub license: String,
    pub verify: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct SetFile {
    pub set: String,
    pub title: String,
    pub version: String,
    pub fetched: String,
    pub plan: String,
    /// Set on a copy that holds only some of the sources (`preserver copy`).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub variant: String,
    pub bytes: u64,
    #[serde(rename = "source")]
    pub sources: Vec<SetSource>,
    #[serde(rename = "entry")]
    pub entries: Vec<PlanEntry>,
}

/// The identity of a resolved set: what would be fetched, sorted by source and name. A set
/// whose newest version has this hash is unchanged.
pub(crate) fn plan_hash(by: &[(&Source, Vec<Item>)]) -> String {
    let mut plan: Vec<PlanEntry> = by
        .iter()
        .flat_map(|(s, items)| items.iter().map(|it| PlanEntry::new(&s.name, it)))
        .collect();
    plan.sort_by_cached_key(|e| format!("{}/{}", e.source, e.name));
    let mut h = Sha256::new();
    for e in &plan {
        h.update(format!(
            "{}\t{}\t{}\t{}\t{}\n",
            e.source, e.name, e.url, e.version, e.sha256
        ));
    }
    hex(&h.finalize())
}

/// Refuses a path that exists and is not a plain directory, a symlink most of all: the drive
/// is writable by anyone who holds it, and a link must never carry a read, a write or a
/// recursive delete out of the archive. A path that does not exist yet passes.
pub(crate) fn plain_dirs(paths: &[&Path]) -> Result<()> {
    for p in paths {
        match std::fs::symlink_metadata(p) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => bail!("{} is not a plain directory, refusing the set", p.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| p.display().to_string()),
        }
    }
    Ok(())
}

/// The visible versions of a set, newest first.
pub(crate) fn version_dirs(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter(|e| e.path().join("SET.toml").is_file())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !n.starts_with('.'))
        .collect();
    out.sort_by(|a, b| b.cmp(a));
    out
}

/// The most a metadata file read from a drive may hold; the drive is not trusted.
const META_CAP: u64 = 32 << 20;

/// Reads a metadata file from a drive anyone may have written to: never through a link, never
/// waiting on a FIFO, and never more than `META_CAP` bytes.
pub(crate) fn read_meta(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    platform::open_regular(path)?
        .take(META_CAP + 1)
        .read_to_end(&mut buf)?;
    if buf.len() as u64 > META_CAP {
        return Err(std::io::Error::other("file too large"));
    }
    Ok(buf)
}

pub(crate) fn read_set_file(path: &Path) -> SetFile {
    read_meta(path)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|t| toml::from_str(&t).ok())
        .unwrap_or_default()
}

/// `SHA256SUMS` as a map from relative path to hash.
pub(crate) fn read_sums(path: &Path) -> HashMap<String, String> {
    String::from_utf8(read_meta(path).unwrap_or_default())
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_once("  "))
        .map(|(h, name)| (name.to_string(), h.to_string()))
        .collect()
}

fn expect(it: &Item) -> Result<Expect> {
    fn bytes<const N: usize>(h: &str) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        if h.len() != 2 * N || !h.is_ascii() {
            bail!("published hash {h:?} is malformed");
        }
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&h[2 * i..2 * i + 2], 16)
                .with_context(|| format!("published hash {h:?} is malformed"))?;
        }
        Ok(out)
    }
    Ok(match (it.sha256.is_empty(), it.sha512.is_empty()) {
        (true, true) => Expect::None,
        (false, true) => Expect::Sha256(bytes(&it.sha256)?),
        (true, false) => Expect::Sha512(bytes(&it.sha512)?),
        (false, false) => Expect::Both(bytes(&it.sha256)?, bytes(&it.sha512)?),
    })
}

/// A hard link, or a copy where the filesystem has none (FAT, exFAT). The copy is renamed
/// into place, so a file under its final name is always whole.
pub(crate) fn link_or_copy(from: &Path, to: &Path) -> bool {
    if std::fs::hard_link(from, to).is_ok() {
        return true;
    }
    let mut tmp = to.as_os_str().to_owned();
    tmp.push(".copying");
    let tmp = PathBuf::from(tmp);
    let ok = std::fs::copy(from, &tmp).is_ok() && std::fs::rename(&tmp, to).is_ok();
    if !ok {
        let _ = std::fs::remove_file(&tmp);
    }
    ok
}

struct Slot {
    source: usize,
    item: Item,
    rel: String,
    /// The verdict and sha256 carried over with a file linked from the previous version.
    linked: Option<(String, String)>,
}

/// A set version being built.
pub(crate) struct Staged {
    set: Set,
    /// The sources that resolved, in catalog order; `Slot::source` indexes it.
    sources: Vec<Source>,
    dir: PathBuf,
    stage: PathBuf,
    plan: String,
    slots: Vec<Slot>,
}

pub(crate) enum Prepared {
    /// The newest version already is this plan.
    Unchanged(String),
    Staged(Box<Staged>, Vec<Fetch>),
}

/// Deletes the stages of older plans; `stage_root` has been checked to be a plain directory.
pub(crate) fn clear_other_stages(stage_root: &Path, keep: &str) {
    for e in std::fs::read_dir(stage_root)
        .into_iter()
        .flatten()
        .flatten()
    {
        if e.file_name().to_str() != Some(keep) {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

/// Sets up the staging directory for the resolved set: links what the previous version
/// already has and lists the downloads for the rest, signatures and sums files included.
/// `room` is what the set may still take: the size limit of a body nobody announced.
pub(crate) fn prepare(
    set: &Set,
    dir: &Path,
    by: &[(&Source, Vec<Item>)],
    room: u64,
) -> Result<Prepared> {
    let plan = plan_hash(by);
    let have = version_dirs(dir);
    let mut prior = SetFile::default();
    let mut prior_dir = PathBuf::new();
    let mut prior_sums = HashMap::new();
    if let Some(newest) = have.first() {
        prior_dir = dir.join(newest);
        prior = read_set_file(&prior_dir.join("SET.toml"));
        prior_sums = read_sums(&prior_dir.join("SHA256SUMS"));
        if prior.plan == plan {
            return Ok(Prepared::Unchanged(newest.clone()));
        }
    }
    let stage_root = dir.join(".staging");
    let stage = stage_root.join(&plan[..16]);
    plain_dirs(&[dir, &stage_root, &stage])?;
    clear_other_stages(&stage_root, &plan[..16]);
    std::fs::create_dir_all(&stage).with_context(|| stage.display().to_string())?;

    let mut slots = Vec::new();
    let mut fetches: Vec<Fetch> = Vec::new();
    let mut side_links = Vec::new();
    for (si, (src, items)) in by.iter().enumerate() {
        plain_dirs(&[&stage.join(&src.name)])?;
        if !have.is_empty() {
            plain_dirs(&[&prior_dir.join(&src.name)])?;
        }
        std::fs::create_dir_all(stage.join(&src.name))?;
        for it in items {
            let rel = format!("{}/{}", src.name, it.name);
            let dst = stage.join(&src.name).join(&it.name);
            let sides: Vec<&String> = [&it.sig_url, &it.sums_url, &it.sums_sig_url]
                .into_iter()
                .flatten()
                .collect();
            let entry = PlanEntry::new(&src.name, it);
            let carried = prior
                .entries
                .iter()
                .find(|p| p.same_file(&entry))
                .zip(prior_sums.get(&rel))
                .filter(|_| !dst.exists())
                .filter(|_| link_or_copy(&prior_dir.join(&src.name).join(&it.name), &dst))
                .map(|(p, sum)| (p.verify.clone(), sum.clone()));
            if carried.is_some() {
                for url in &sides {
                    let from = side(&prior_dir.join(&src.name).join(&it.name), url);
                    side_links.push((from, side(&dst, url)));
                }
            } else {
                if !dst.exists() {
                    fetches.push(Fetch {
                        url: it.url.clone(),
                        dest: dst.clone(),
                        size: it.size,
                        limit: room,
                        expect: expect(it).with_context(|| rel.clone())?,
                    });
                }
                for url in sides {
                    let beside = side(&dst, url);
                    if !beside.exists() && !fetches.iter().any(|f| f.dest == beside) {
                        fetches.push(Fetch {
                            url: url.clone(),
                            dest: beside,
                            size: None,
                            limit: SIDE_LIMIT,
                            expect: Expect::None,
                        });
                    }
                }
            }
            slots.push(Slot {
                source: si,
                item: it.clone(),
                rel,
                linked: carried,
            });
        }
    }
    // A carried file's signature and sums files come along, unless a changed file shares
    // the path: that one needs the current sums file, not the previous version's.
    for (from, to) in side_links {
        if !to.exists() && from.is_file() && !fetches.iter().any(|f| f.dest == to) {
            link_or_copy(&from, &to);
        }
    }
    let staged = Staged {
        set: set.clone(),
        sources: by.iter().map(|(s, _)| (*s).clone()).collect(),
        dir: dir.to_path_buf(),
        stage,
        plan,
        slots,
    };
    Ok(Prepared::Staged(Box::new(staged), fetches))
}

pub(crate) fn regular_files(dir: &Path, rel: &str, out: &mut Vec<(String, u64)>) -> Result<()> {
    for e in std::fs::read_dir(dir).with_context(|| dir.display().to_string())? {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        let rel = if rel.is_empty() {
            name
        } else {
            format!("{rel}/{name}")
        };
        let t = e.file_type()?;
        if t.is_dir() {
            regular_files(&e.path(), &rel, out)?;
        } else if t.is_file() {
            out.push((rel, e.metadata()?.len()));
        }
    }
    Ok(())
}

pub(crate) fn sha256_file(path: &Path) -> Result<String> {
    let mut f = File::open(path).with_context(|| path.display().to_string())?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok(hex(&h.finalize()));
        }
        h.update(&buf[..n]);
    }
}

pub(crate) fn write_synced(path: &Path, data: &[u8]) -> Result<()> {
    let mut f = File::create(path).with_context(|| path.display().to_string())?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

/// Writes SET.toml and SHA256SUMS over everything in the stage; `known` saves re-hashing.
fn fill_sums(stage: &Path, known: &HashMap<String, String>, sf: &mut SetFile) -> Result<()> {
    let mut files = Vec::new();
    regular_files(stage, "", &mut files)?;
    files.sort();
    let mut lines = String::new();
    for (rel, len) in &files {
        sf.bytes += len;
        let h = match known.get(rel) {
            Some(h) => h.clone(),
            None => sha256_file(&stage.join(rel))?,
        };
        let _ = writeln!(lines, "{h}  {rel}");
    }
    let toml = toml::to_string(sf)?;
    write_synced(&stage.join("SET.toml"), toml.as_bytes())?;
    let _ = writeln!(lines, "{}  SET.toml", hex(&Sha256::digest(toml.as_bytes())));
    write_synced(&stage.join("SHA256SUMS"), lines.as_bytes())
}

impl Staged {
    /// Only the plan's files and their side files go public: a crash can leave download
    /// bookkeeping, or an earlier attempt's SET.toml and SHA256SUMS, in the stage.
    fn drop_strays(&self) -> Result<()> {
        let mut wanted = HashSet::new();
        for slot in &self.slots {
            let dst = self.stage.join(&slot.rel);
            let it = &slot.item;
            for url in [&it.sig_url, &it.sums_url, &it.sums_sig_url]
                .into_iter()
                .flatten()
            {
                wanted.insert(side(&dst, url));
            }
            wanted.insert(dst);
        }
        let mut present = Vec::new();
        regular_files(&self.stage, "", &mut present)?;
        for (rel, _) in present {
            let path = self.stage.join(&rel);
            if !wanted.contains(&path) {
                std::fs::remove_file(&path).with_context(|| path.display().to_string())?;
            }
        }
        Ok(())
    }

    /// Verifies every downloaded file and, only if all pass, makes the stage the newest
    /// version and prunes to `keep`. A file that fails is deleted with its signature and sums
    /// files, so the next run fetches them again; the rest of the stage is kept.
    pub(crate) fn publish(self, verifier: &Verifier, now: Timestamp) -> Result<String> {
        let mut known = HashMap::new();
        let mut entries = Vec::new();
        let mut errs = Vec::new();
        for slot in &self.slots {
            let src = &self.sources[slot.source];
            let mut entry = PlanEntry::new(&src.name, &slot.item);
            let (how, sum) = if let Some(l) = &slot.linked {
                l.clone()
            } else {
                let dst = self.stage.join(&slot.rel);
                match verifier.item(src, &slot.item, &dst) {
                    Ok(v) => v,
                    Err(e) => {
                        let it = &slot.item;
                        let _ = std::fs::remove_file(&dst);
                        for url in [&it.sig_url, &it.sums_url, &it.sums_sig_url]
                            .into_iter()
                            .flatten()
                        {
                            let _ = std::fs::remove_file(side(&dst, url));
                        }
                        errs.push(format!("{}: {e:#}", slot.rel));
                        continue;
                    }
                }
            };
            entry.verify = how;
            known.insert(slot.rel.clone(), sum);
            entries.push(entry);
        }
        if !errs.is_empty() {
            bail!(errs.join("; "));
        }

        let day = now.strftime("%Y-%m-%d").to_string();
        let mut version = day.clone();
        let mut n = 2;
        while self.dir.join(&version).exists() {
            version = format!("{day}-{n}");
            n += 1;
        }
        let mut sf = SetFile {
            set: self.set.name.clone(),
            title: self.set.title.clone(),
            version: version.clone(),
            fetched: now.strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
            plan: self.plan.clone(),
            ..SetFile::default()
        };
        let mut seen = Vec::new();
        for slot in &self.slots {
            if seen.contains(&slot.source) {
                continue;
            }
            seen.push(slot.source);
            let src = &self.sources[slot.source];
            let url = match src.kind() {
                Kind::Hf => format!("{HF_BASE}{}", src.repo),
                _ if !src.repo.is_empty() => format!("https://github.com/{}", src.repo),
                _ => src.url.clone(),
            };
            sf.sources.push(SetSource {
                name: src.name.clone(),
                kind: src.kind().as_str().to_string(),
                url,
                version: slot.item.version.clone(),
                license: src.license.clone(),
                verify: entries
                    .iter()
                    .find(|e| e.source == src.name)
                    .map(|e| e.verify.clone())
                    .unwrap_or_default(),
            });
        }
        sf.entries = entries;
        self.drop_strays()?;
        fill_sums(&self.stage, &known, &mut sf)?;
        // Copies (FAT, exFAT) and directory entries must be on the disk before the previous
        // version, which may hold the only durable copy of a carried file, is pruned.
        platform::sync_fs(&self.stage).with_context(|| self.stage.display().to_string())?;
        let dest = self.dir.join(&version);
        std::fs::rename(&self.stage, &dest).with_context(|| dest.display().to_string())?;
        platform::sync_dir(&self.dir)?;
        for old in version_dirs(&self.dir).into_iter().skip(self.set.keep) {
            if let Err(e) = std::fs::remove_dir_all(self.dir.join(&old)) {
                tracing::warn!("prune {} {old}: {e}", self.set.name);
            }
        }
        Ok(version)
    }
}
