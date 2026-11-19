//! `preserver public`: each selected set becomes a queue job. The worker resolves it, stages
//! it under `public/<set>/.staging/`, downloads what is missing, and only after every file
//! has verified renames the stage into place as a new version.

pub(crate) mod index;
pub(crate) mod versioned;

use crate::catalog::{Catalog, Kind, Set, Source};
use crate::config::{Config, DriveId};
use crate::git::http::Remote;
use crate::git::mirror::{Trust, Via, refs_state, update};
use crate::keys;
use crate::mirror::generation::{Gen, Next, live_path, read_header};
use crate::mirror::{self, Ctx, WALKERS, Walkers};
use crate::net::client;
use crate::net::download::{CHECKPOINT, Downloader};
use crate::net::throttle::Throttle;
use crate::paths::Paths;
use crate::queue::{Job, JobKind, JobState, Lane, Pass, Store, Work, Worker, runnable};
use crate::resolve::{GH_API, HF_BASE, Item, Resolver};
use crate::verify::Verifier;
use crate::{actions, platform, status};
use anyhow::{Context, Result, bail};
use gix::protocol::transport::client::blocking_io::http::Http;
use jiff::Timestamp;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use versioned::{Prepared, Staged};

type Free<'a> = &'a (dyn Fn(&Path) -> std::io::Result<(u64, u64)> + Sync);

pub(crate) struct Public<'a> {
    cat: &'a Catalog,
    paths: &'a Paths,
    resolver: Resolver<'a>,
    verifier: Verifier<'a>,
    reserve_percent: u8,
    /// Free and total bytes of the filesystem holding a path.
    free: Free<'a>,
    /// The stage each planned job is filling, until the worker settles the job.
    staged: Mutex<HashMap<String, Staged>>,
    /// What each planned set job resolved, per source name, so a re-plan after a pause,
    /// yield or retry does not list the upstream again.
    resolved: Mutex<HashMap<String, HashMap<String, Vec<Item>>>>,
    /// The generation each planned repo mirror job is filling, until the worker settles it.
    gens: Mutex<HashMap<String, Gen>>,
    walkers: Walkers,
    /// The Fedora metalink service: the constant in production, a loopback server in tests.
    metalink: &'a str,
}

#[expect(clippy::cast_precision_loss, reason = "a size shown to two decimals")]
pub(crate) fn gb(n: u64) -> String {
    format!("{:.2} GB", n as f64 / 1e9)
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "a catalog estimate in GB, far below u64::MAX bytes"
)]
fn gb_bytes(gb: f64) -> u64 {
    (gb.max(0.0) * 1e9) as u64
}

/// FAT32 cannot hold a file of 4 GiB or more, and a big mirror's pack can be one.
fn fat_refuses(fstype: &str, est: u64) -> bool {
    matches!(fstype, "vfat" | "msdos") && est >= 4_000_000_000
}

/// The short id HEAD points at, or empty.
fn short_head(repo: &Path) -> String {
    let head = String::from_utf8(versioned::read_meta(&repo.join("HEAD")).unwrap_or_default())
        .unwrap_or_default();
    let head = head.trim();
    let id = match head.strip_prefix("ref: ") {
        None => head.to_string(),
        Some(name) => refs_state(repo)
            .ok()
            .and_then(|r| String::from_utf8(r).ok())
            .and_then(|r| {
                r.lines()
                    .find_map(|l| l.strip_suffix(name)?.strip_suffix(' ').map(str::to_string))
            })
            .unwrap_or_default(),
    };
    if id.bytes().all(|b| b.is_ascii_hexdigit()) {
        id.chars().take(7).collect()
    } else {
        String::new()
    }
}

/// What a dry run says about the headers of the `info/refs` answer, or the error instead.
fn probe_text(head: std::io::Result<String>) -> String {
    let head = match head {
        Ok(h) => h,
        Err(e) => {
            let e = e.to_string();
            let rest = e.split_once(": ").map_or(e.as_str(), |(_, r)| r);
            return match rest
                .strip_prefix("HTTP 3")
                .and_then(|r| r.split_once(" to "))
            {
                Some((_, to)) => {
                    let host = to.split_once("://").map_or(to, |(_, h)| h);
                    format!("redirect to {}", host.split('/').next().unwrap_or_default())
                }
                None => rest.to_string(),
            };
        }
    };
    if head
        .to_ascii_lowercase()
        .contains("content-type:application/x-git-upload-pack-advertisement")
    {
        "ok".into()
    } else {
        "not smart http".into()
    }
}

fn trunc(s: &str, n: usize) -> String {
    match s.char_indices().nth(n) {
        Some((i, _)) => format!("{}...", &s[..i]),
        None => s.to_string(),
    }
}

impl Public<'_> {
    fn public_dir(root: &Path) -> std::path::PathBuf {
        root.join("preserver").join("public")
    }

    /// Bytes the drive can still take with the reserve kept free.
    fn room(&self, root: &Path) -> Result<u64> {
        let (free, total) = (self.free)(root)?;
        Ok(free.saturating_sub(total / 100 * u64::from(self.reserve_percent)))
    }

    /// Refuses a set whose estimate would eat into the reserve. Otherwise returns how many
    /// bytes the set may still take, the reserve kept free. In-place sources are budgeted by
    /// their own jobs, so their estimates are left out here.
    fn budget(&self, set: &Set, root: &Path) -> Result<u64> {
        let left = self.room(root)?;
        let versioned: f64 = set
            .sources
            .iter()
            .filter(|s| s.on() && !s.kind().in_place())
            .map(|s| s.est)
            .sum();
        let estimate = gb_bytes(versioned);
        // A resumed job's stage holds part of the set already. A stage of an older plan is
        // deleted by prepare(), so its bytes come back as free space.
        let mut staged = Vec::new();
        let stage = Self::public_dir(root).join(&set.name).join(".staging");
        if stage.is_dir() {
            versioned::regular_files(&stage, "", &mut staged)?;
        }
        let held: u64 = staged.iter().map(|(_, len)| len).sum();
        let need = estimate.saturating_sub(held);
        if need > left {
            bail!(
                "budget: needs about {}, {} free above the {}% reserve",
                gb(need),
                gb(left),
                self.reserve_percent
            );
        }
        Ok(left + held)
    }

    /// The set's line in `status/public.json`.
    fn record(&self, set: &str, state: &str, version: &str, detail: &str) {
        tracing::info!("set {set}: {state} {version} {detail}");
        let mut res = serde_json::json!({
            "name": set,
            "state": state,
            "time": Timestamp::now().to_string(),
        });
        if !version.is_empty() {
            res["version"] = version.into();
        }
        if !detail.is_empty() {
            res["detail"] = trunc(detail, 600).into();
        }
        let file = self.paths.status_file("public");
        let mut st = status::Status::read(&file);
        match st.sets.iter_mut().find(|x| x["name"] == set) {
            Some(x) => *x = res,
            None => st.sets.push(res),
        }
        if let Err(e) = st.write(&file) {
            tracing::warn!("status write failed: {e:#}");
        }
    }

    fn resolve_set<'s>(&self, job: &str, set: &'s Set) -> Result<Vec<(&'s Source, Vec<Item>)>> {
        let mut by = Vec::new();
        let mut errs = Vec::new();
        for src in set
            .sources
            .iter()
            .filter(|s| s.on() && !s.kind().in_place())
        {
            let cached = self
                .resolved()
                .get(job)
                .and_then(|m| m.get(&src.name))
                .cloned();
            if let Some(items) = cached {
                by.push((src, items));
                continue;
            }
            match self.resolver.resolve(src) {
                Ok(items) => {
                    self.resolved()
                        .entry(job.to_string())
                        .or_default()
                        .insert(src.name.clone(), items.clone());
                    by.push((src, items));
                }
                Err(e) => errs.push(format!("{}: resolve: {e:#}", src.name)),
            }
        }
        if !errs.is_empty() {
            bail!(errs.join("; "));
        }
        Ok(by)
    }

    fn resolved(&self) -> std::sync::MutexGuard<'_, HashMap<String, HashMap<String, Vec<Item>>>> {
        self.resolved.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn gens(&self) -> std::sync::MutexGuard<'_, HashMap<String, Gen>> {
        self.gens.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn staged(&self) -> std::sync::MutexGuard<'_, HashMap<String, Staged>> {
        self.staged.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The worker's planner: what a set job has to download. A set that needs nothing (no
    /// usable source, over budget, unchanged) is recorded here and plans no files.
    pub(crate) fn plan(&self, job: &Job, root: &Path, ok: &[usize]) -> Result<Work<'_>> {
        let name = match &job.kind {
            JobKind::Set { set } => set,
            JobKind::Mirror { set, source } => {
                return self.plan_mirror(job, set, source, root, ok);
            }
            _ => bail!("not a public job"),
        };
        let set = self
            .cat
            .sets
            .iter()
            .find(|s| s.name == *name)
            .with_context(|| format!("no set {name:?} in the catalog"))?;
        if !set.sources.iter().any(Source::on) {
            self.record(name, "skipped", "", "no enabled sources");
            return Ok(Vec::new().into());
        }
        // The drive is writable by whoever holds it: a link in the way would send the
        // staging cleanup and the downloads out of the set.
        let dir = Self::public_dir(root).join(name);
        versioned::plain_dirs(&[
            &root.join("preserver"),
            &Self::public_dir(root),
            &dir,
            &dir.join(".staging"),
        ])?;
        let allowed = match self.budget(set, root) {
            Ok(n) => n,
            Err(e) => {
                self.record(name, "skipped", "", &format!("{e:#}"));
                return Ok(Vec::new().into());
            }
        };
        let by = self.resolve_set(&job.id, set)?;
        if by.is_empty() {
            self.record(
                name,
                "skipped",
                "",
                "git and repo mirrors arrive in phase 3",
            );
            return Ok(Vec::new().into());
        }
        std::fs::create_dir_all(&dir).with_context(|| dir.display().to_string())?;
        match versioned::prepare(set, &dir, &by, allowed)? {
            Prepared::Unchanged(version) => {
                self.record(name, "unchanged", &version, "");
                Ok(Vec::new().into())
            }
            Prepared::Staged(staged, fetches) => {
                self.staged().insert(job.id.clone(), *staged);
                Ok(fetches.into())
            }
        }
    }

    /// The enabled in-place source a Mirror job names, if the catalog still has it.
    fn mirror_source(&self, set: &str, source: &str) -> Option<&Source> {
        self.cat
            .sets
            .iter()
            .find(|s| s.name == set)?
            .sources
            .iter()
            .find(|s| s.name == source && s.on() && s.kind().in_place())
    }

    /// A git mirror is one closure job: gix fetches into the bare repo under
    /// `<set>/git/<source>.git`. A repo mirror is a generation of the tree
    /// `<set>/<source>`, planned batch by batch. A source gone from the catalog ends the job
    /// in `settle`.
    fn plan_mirror(
        &self,
        job: &Job,
        set: &str,
        source: &str,
        root: &Path,
        ok: &[usize],
    ) -> Result<Work<'_>> {
        let id = format!("{set}/{source}");
        let skip = |detail: &str| {
            self.record(&id, "skipped", "", detail);
            Ok(Vec::new().into())
        };
        let Some(src) = self.mirror_source(set, source) else {
            return skip("source no longer in the catalog");
        };
        if src.kind() != Kind::Git {
            return self.plan_repo(job, set, src, root, ok);
        }
        let set_dir = Self::public_dir(root).join(set);
        let repo = set_dir.join("git").join(format!("{source}.git"));
        versioned::plain_dirs(&[
            &root.join("preserver"),
            &Self::public_dir(root),
            &set_dir,
            &set_dir.join("git"),
            &repo,
            &repo.join("objects"),
            &repo.join("objects").join("pack"),
            &repo.join("refs"),
        ])?;
        let est = gb_bytes(src.est);
        if fat_refuses(&platform::fs_type(root).unwrap_or_default(), est) {
            bail!("needs a filesystem with files over 4 GiB");
        }
        // A mirror already on the drive holds part of the estimate.
        let mut have = Vec::new();
        if repo.is_dir() {
            versioned::regular_files(&repo, "", &mut have)?;
        }
        let held: u64 = have.iter().map(|(_, len)| len).sum();
        let left = self.room(root)?;
        let need = est.saturating_sub(held);
        if need > left {
            return skip(&format!(
                "budget: needs about {}, {} free above the {}% reserve",
                gb(need),
                gb(left),
                self.reserve_percent
            ));
        }
        let dl = self.resolver.dl;
        let (source, root) = (source.to_string(), root.to_path_buf());
        let names: Vec<&str> = self
            .cat
            .sets
            .iter()
            .filter(|s| s.name == set)
            .flat_map(|s| &s.sources)
            .map(|s| s.name.as_str())
            .collect();
        Ok(Work::Run(Box::new(move |stop, got| {
            // Remote's request threads outlive the call and need a shared flag, so the
            // job's flag is forwarded to it.
            let halt = Arc::new(AtomicBool::new(false));
            let done = AtomicBool::new(false);
            let ran = std::thread::scope(|s| {
                s.spawn(|| {
                    while !done.load(Ordering::Relaxed) {
                        if stop.load(Ordering::Relaxed) {
                            halt.store(true, Ordering::Relaxed);
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(50));
                    }
                });
                let http = Remote::new(dl.agent(), dl.throttle(), got.clone(), left, halt.clone());
                let ran = update(
                    &repo,
                    &src.url,
                    Via::Https { http, token: None },
                    Trust::Drive,
                    stop,
                    &|_| (),
                );
                done.store(true, Ordering::Relaxed);
                ran
            });
            ran?;
            let mut files = Vec::new();
            versioned::regular_files(&repo, "", &mut files)?;
            let version = short_head(&repo);
            index::record_mirror(
                &set_dir,
                &names,
                index::Mirror {
                    name: source,
                    kind: "git".into(),
                    url: src.url.clone(),
                    updated: Timestamp::now().to_string(),
                    bytes: files.iter().map(|(_, len)| len).sum(),
                    license: src.license.clone(),
                    ..index::Mirror::default()
                },
            )?;
            self.record(&id, "ok", &version, "");
            if let Err(e) = index::write(self.cat, &root.join("preserver")) {
                tracing::warn!("index: {e:#}");
            }
            Ok(())
        })))
    }

    /// The next batch of a repo mirror. The first call of a job starts its generation: a
    /// swap a crash left is finished, the anchor is fetched and the stages of other
    /// generations are dropped. Later calls hand `ok` to the generation.
    fn plan_repo(
        &self,
        jb: &Job,
        set: &str,
        src: &Source,
        root: &Path,
        ok: &[usize],
    ) -> Result<Work<'_>> {
        let set_dir = Self::public_dir(root).join(set);
        let tree = set_dir.join(&src.name);
        let id = format!("{set}/{}", src.name);
        let job = jb.id.as_str();
        // An unknown filesystem gets the Windows name rules, the strictest that still hold
        // files over 4 GiB.
        let fstype = platform::list_filesystems()
            .ok()
            .and_then(|fs| fs.into_iter().find(|f| jb.drive.matches(&f.id)))
            .map(|f| f.fstype)
            .filter(|t| !t.is_empty())
            .or_else(|| platform::fs_type(root).ok())
            .unwrap_or_else(|| "exfat".into());
        let mut gens = self.gens();
        if !gens.contains_key(job) {
            versioned::plain_dirs(&[
                &root.join("preserver"),
                &Self::public_dir(root),
                &set_dir,
                &tree,
            ])?;
            std::fs::create_dir_all(&tree).with_context(|| tree.display().to_string())?;
            mirror::generation::recover(&tree)?;
            let ctx = Ctx {
                dl: self.resolver.dl,
                keys: self.verifier.keys,
                metalink: self.metalink,
                plain_http: self.resolver.plain_http,
                tree: tree.is_dir().then_some(tree.as_path()),
            };
            let anchor = (self.walkers.anchor)(&ctx, src)?;
            let g = mirror::generation::begin(&tree, &src.url, anchor)?;
            let g16 = g.generation()[..16].to_string();
            versioned::clear_other_stages(&mirror::generation::staging_root(&tree), &g16);
            gens.insert(job.to_string(), g);
        }
        let g = gens.get_mut(job).context("the generation is gone")?;
        let walkers = self.walkers;
        let mut walk =
            |a: &mirror::Anchor, meta: &Path, emit: &mut dyn FnMut(mirror::generation::Walked)| {
                (walkers.walk)(src, a, meta, emit)
            };
        let next = self
            .room(root)
            .and_then(|room| g.next(ok, &mut walk, room, &fstype));
        let next = match next {
            Ok(n) => n,
            Err(e) => {
                gens.remove(job);
                return Err(e);
            }
        };
        match next {
            Next::Batch(p) => Ok(Work::Fetch(p)),
            Next::Ready => Ok(Vec::new().into()),
            Next::OverBudget { need, room } => {
                gens.remove(job);
                self.record(
                    &id,
                    "skipped",
                    "",
                    &format!(
                        "budget: needs about {}, {} free above the {}% reserve",
                        gb(need),
                        gb(room),
                        self.reserve_percent
                    ),
                );
                Ok(Vec::new().into())
            }
        }
    }

    /// Called by the worker when a job stops. A job whose downloads all arrived is verified
    /// and published here; a verification failure turns it into a failed job.
    pub(crate) fn settle(&self, job: &mut Job, root: &Path, ok: &[usize]) {
        if let JobKind::Mirror { set, source } = job.kind.clone() {
            let g = self.gens().remove(&job.id);
            self.settle_mirror(job, &set, &source, root, g, ok);
            return;
        }
        let JobKind::Set { set } = &job.kind else {
            return;
        };
        let staged = self.staged().remove(&job.id);
        if matches!(
            job.state,
            JobState::Done | JobState::Failed | JobState::Canceled
        ) {
            self.resolved().remove(&job.id);
        }
        match job.state {
            JobState::Done => {
                let Some(staged) = staged else { return };
                match staged.publish(&self.verifier, Timestamp::now()) {
                    Ok(version) => self.record(set, "ok", &version, ""),
                    Err(e) => {
                        let msg = format!("{e:#}");
                        self.record(set, "failed", "", &msg);
                        job.state = JobState::Failed;
                        job.error = Some(trunc(&msg, 600));
                    }
                }
                if let Err(e) = index::write(self.cat, &root.join("preserver")) {
                    tracing::warn!("index: {e:#}");
                }
            }
            JobState::Failed => {
                self.record(set, "failed", "", job.error.as_deref().unwrap_or_default());
            }
            _ => {}
        }
    }

    /// Settles a Mirror job. A repo mirror whose files all landed is committed; in every
    /// other state the generation only keeps what verified. The generation is dropped either way.
    fn settle_mirror(
        &self,
        job: &mut Job,
        set: &str,
        source: &str,
        root: &Path,
        g: Option<Gen>,
        ok: &[usize],
    ) {
        let id = format!("{set}/{source}");
        if job.state == JobState::Done && self.mirror_source(set, source).is_none() {
            job.state = JobState::Canceled;
            return;
        }
        if let Some(mut g) = g {
            if job.state == JobState::Done && g.ready() {
                if let Err(e) = self.commit_repo(set, source, root, &mut g) {
                    let msg = trunc(&format!("{e:#}"), 600);
                    job.state = JobState::Failed;
                    job.error = Some(msg);
                }
            } else if let Err(e) = g.land(ok) {
                tracing::warn!("{id}: done ledger: {e:#}");
            }
        }
        if job.state == JobState::Failed {
            self.record(&id, "failed", "", job.error.as_deref().unwrap_or_default());
        }
    }

    /// Swaps a finished generation in and records it: `MIRRORS.toml`, the status line and the
    /// archive index.
    fn commit_repo(&self, set: &str, source: &str, root: &Path, g: &mut Gen) -> Result<()> {
        let set_dir = Self::public_dir(root).join(set);
        let tree = set_dir.join(source);
        g.commit()?;
        // The swap has landed: a failure below must not turn the job into a failed one.
        if let Err(e) = self.record_repo(set, source, root, &set_dir, &tree) {
            tracing::warn!("{set}/{source}: committed, bookkeeping failed: {e:#}");
        }
        Ok(())
    }

    fn record_repo(
        &self,
        set: &str,
        source: &str,
        root: &Path,
        set_dir: &Path,
        tree: &Path,
    ) -> Result<()> {
        let head = read_header(&live_path(tree))?.context("no live.tsv after the commit")?;
        let src = self
            .mirror_source(set, source)
            .context("the source left the catalog")?;
        let names: Vec<&str> = self
            .cat
            .sets
            .iter()
            .filter(|s| s.name == set)
            .flat_map(|s| &s.sources)
            .map(|s| s.name.as_str())
            .collect();
        let g16 = head.generation[..16].to_string();
        index::record_mirror(
            set_dir,
            &names,
            index::Mirror {
                name: source.to_string(),
                kind: "repo".into(),
                url: src.url.clone(),
                updated: head.at.to_string(),
                bytes: head.bytes,
                files: Some(head.files),
                generation: Some(g16.clone()),
                license: src.license.clone(),
            },
        )?;
        self.record(&format!("{set}/{source}"), "ok", &g16, "");
        if let Err(e) = index::write(self.cat, &root.join("preserver")) {
            tracing::warn!("index: {e:#}");
        }
        Ok(())
    }

    /// One `info/refs` request: whether the URL speaks smart http, and where it says to go.
    fn probe(&self, url: &str) -> String {
        let dl = self.resolver.dl;
        let mut remote = Remote::new(
            dl.agent(),
            dl.throttle(),
            Arc::default(),
            1 << 20,
            Arc::default(),
        );
        let url = format!(
            "{}/info/refs?service=git-upload-pack",
            url.trim_end_matches('/')
        );
        let head = remote
            .get(&url, &url, std::iter::empty::<&str>())
            .map_err(std::io::Error::other)
            .and_then(|mut r| {
                let mut head = String::new();
                r.headers.read_to_string(&mut head)?;
                Ok(head)
            });
        probe_text(head)
    }

    /// Resolves a set and prints what a real run would fetch.
    fn dry_run(&self, set: &Set, root: Option<&Path>, w: &mut dyn Write) -> Result<()> {
        writeln!(w, "== {} (estimate {:.1} GB)", set.name, set.estimate)?;
        if let Some(Err(e)) = root.map(|r| self.budget(set, r)) {
            writeln!(w, "   would skip: {e:#}")?;
        }
        let mut total = 0;
        for src in &set.sources {
            if !src.on() {
                writeln!(w, "   {:<22} disabled: {}", src.name, src.todo)?;
                continue;
            }
            if src.kind() == Kind::Git {
                writeln!(
                    w,
                    "   {:<22} git mirror {} (estimate {:.2} GB): {}",
                    src.name,
                    src.url,
                    src.est,
                    self.probe(&src.url)
                )?;
                continue;
            }
            if src.kind().in_place() {
                writeln!(
                    w,
                    "   {:<22} repo mirror {} (estimate {:.2} GB)",
                    src.name, src.url, src.est
                )?;
                let tree = root.map(|r| Self::public_dir(r).join(&set.name).join(&src.name));
                let ctx = Ctx {
                    dl: self.resolver.dl,
                    keys: self.verifier.keys,
                    metalink: self.metalink,
                    plain_http: self.resolver.plain_http,
                    tree: tree.as_deref().filter(|t| t.is_dir()),
                };
                let cache = self.paths.mirrors.with_file_name("repo-meta");
                let cache = cache.join(&set.name).join(&src.name);
                if let Err(e) = mirror::dry_run(&ctx, &self.walkers, src, &cache, w) {
                    writeln!(w, "   {:<22} FAILED: {e:#}", src.name)?;
                }
                continue;
            }
            let items = match self.resolver.resolve(src) {
                Ok(i) => i,
                Err(e) => {
                    writeln!(w, "   {:<22} FAILED: {e:#}", src.name)?;
                    continue;
                }
            };
            for it in items {
                let size = it.size.or_else(|| self.resolver.head_size(&it.url));
                total += size.unwrap_or(0);
                writeln!(
                    w,
                    "   {:<22} {:<10} {:>10}  {}",
                    src.name,
                    it.version,
                    gb(size.unwrap_or(0)),
                    it.url
                )?;
            }
        }
        writeln!(w, "   measured total {}", gb(total))?;
        Ok(())
    }
}

/// Queues a Set job per set that has a versioned source (or no enabled in-place one) and a Mirror job per
/// enabled in-place source, earlier sets first, except the jobs `skip` names. Returns each
/// job's name (`set` or `set/source`) and id.
pub(crate) fn enqueue_all(
    store: &Store,
    sets: &[&Set],
    drive: &DriveId,
    tidy: bool,
    skip: &dyn Fn(&JobKind) -> bool,
) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for (i, set) in sets.iter().enumerate() {
        let prio = u32::try_from(i).unwrap_or(u32::MAX);
        let in_place = |s: &&Source| s.on() && s.kind().in_place();
        let set_job = (!set.sources.iter().any(|s| in_place(&s))
            || set.sources.iter().any(|s| s.on() && !s.kind().in_place()))
        .then(|| {
            (
                set.name.clone(),
                JobKind::Set {
                    set: set.name.clone(),
                },
            )
        });
        let mirrors = set.sources.iter().filter(in_place).map(|s| {
            (
                format!("{}/{}", set.name, s.name),
                JobKind::Mirror {
                    set: set.name.clone(),
                    source: s.name.clone(),
                },
            )
        });
        for (name, kind) in set_job.into_iter().chain(mirrors) {
            if !skip(&kind) {
                out.push((name, store.enqueue(&kind, drive, prio, tidy)?));
            }
        }
    }
    Ok(out)
}

fn downloader(cfg: &Config) -> Downloader {
    Downloader::new(
        client::agent(client::os_roots()),
        Arc::new(Throttle::from_mbit(cfg.bandwidth_mbit)),
        CHECKPOINT,
    )
}

fn notify(urgent: bool, title: &str, body: &str) {
    platform::notify(urgent, title, body);
}

fn public<'a>(cat: &'a Catalog, paths: &'a Paths, cfg: &Config, dl: &'a Downloader) -> Public<'a> {
    Public {
        cat,
        paths,
        resolver: Resolver {
            dl,
            gh_api: GH_API,
            hf_base: HF_BASE,
            plain_http: false,
        },
        verifier: Verifier {
            keys: keys::EMBEDDED,
            tofu: &paths.tofu,
            note: &notify,
        },
        reserve_percent: cfg.reserve_percent,
        free: &platform::disk_free,
        staged: Mutex::new(HashMap::new()),
        resolved: Mutex::new(HashMap::new()),
        gens: Mutex::new(HashMap::new()),
        walkers: WALKERS,
        metalink: mirror::FEDORA_METALINK,
    }
}

/// Runs the queue worker until nothing is runnable. The caller holds the queue lock.
fn work(p: &Public, store: &Store, dl: &Downloader, pass: Pass) -> Result<()> {
    Worker {
        store,
        dl,
        plan: &|job, root, ok| p.plan(job, root, ok),
        settle: &|job, root, ok| p.settle(job, root, ok),
        drive: &platform::locate,
    }
    .run(pass)
}

/// `preserver queue run`.
pub(crate) fn queue_run(paths: &Paths, cfg: &Config) -> Result<()> {
    let Some(_lock) = status::try_lock(&paths.lock_file("queue"))? else {
        println!("queued; worker running");
        return Ok(());
    };
    let cat = Catalog::embedded()?;
    let dl = downloader(cfg);
    work(
        &public(&cat, paths, cfg, &dl),
        &Store::new(paths.queue.clone()),
        &dl,
        Pass::FRESH,
    )
}

/// One pass of the daemon's download lane. It skips without a word when a CLI run holds the
/// queue or nothing is runnable, so an idle tick writes nothing. The config and the
/// downloader are rebuilt per pass, so an edited bandwidth applies without a restart.
pub(crate) fn daemon_pass(paths: &Paths, pass: Pass) -> Result<()> {
    let Some(_lock) = status::try_lock(&paths.lock_file("queue"))? else {
        return Ok(());
    };
    let store = Store::new(paths.queue.clone());
    if !runnable(&store, Lane::Download, pass)? {
        return Ok(());
    }
    let cfg = Config::load(&paths.cfg)?;
    let cat = Catalog::embedded()?;
    let dl = downloader(&cfg);
    let start = Timestamp::now();
    // Same lock order as run(): queue, then public.
    status::job(&mut paths.clone(), "public", |paths| {
        work(&public(&cat, paths, &cfg, &dl), &store, &dl, pass)?;
        let mut errs = Vec::new();
        for j in store.jobs()? {
            let name = match &j.kind {
                JobKind::Mirror { set, source } => format!("{set}/{source}"),
                JobKind::Set { set } => set.clone(),
                _ => continue,
            };
            match j.state {
                // Nobody waits on the result here, unlike run(): the worker tidies up.
                JobState::Done | JobState::Canceled => store.remove(&j.id)?,
                JobState::Failed if j.updated >= start => {
                    errs.push(format!(
                        "{name}: {}",
                        j.error.as_deref().unwrap_or_default()
                    ));
                }
                _ => {}
            }
        }
        if errs.is_empty() {
            return Ok(());
        }
        let msg = errs.join("; ");
        notify(true, "Public sync had failures", &trunc(&msg, 600));
        bail!(msg)
    })
}

/// `preserver public --list`: the sets in priority order with their variants, estimated and,
/// when the primary is connected, measured in its newest version.
pub(crate) fn list_report(paths: &mut Paths, cfg: &Config) -> Result<String> {
    let cat = Catalog::embedded()?;
    let (note, root) = match paths.mount(&cfg.primary_uuid) {
        Ok(()) => (String::new(), Some(paths.mnt.clone())),
        Err(e) => (format!("note: {e:#}, so sizes are estimates only\n"), None),
    };
    let st = status::Status::read(&paths.status_file("public"));
    Ok(note + &list_text(&cat, root.as_deref(), &st)?)
}

fn list_text(cat: &Catalog, root: Option<&Path>, st: &status::Status) -> Result<String> {
    use std::fmt::Write as _;
    let mut out = String::new();
    for set in cat.select(&[], false)? {
        let dir = root.map(|r| Public::public_dir(r).join(&set.name));
        let newest = dir
            .as_deref()
            .and_then(|d| versioned::version_dirs(d).into_iter().next());
        let _ = writeln!(
            out,
            "{:<16} priority {:>3}  keep {}  estimate {:>7.1} GB  newest {}",
            set.name,
            set.priority,
            set.keep,
            set.estimate,
            newest.as_deref().unwrap_or("-")
        );
        // Bytes per source in the newest version: its files sit under `<version>/<source>/`.
        let mut measured = HashMap::new();
        if let (Some(dir), Some(v)) = (&dir, &newest) {
            for src in &set.sources {
                let mut files = Vec::new();
                if versioned::regular_files(&dir.join(v).join(&src.name), "", &mut files).is_ok() {
                    measured.insert(src.name.as_str(), files.iter().map(|(_, n)| n).sum::<u64>());
                }
            }
        }
        for v in set.variants() {
            let bytes = newest.is_some().then(|| {
                v.sources
                    .iter()
                    .filter_map(|s| measured.get(s.as_str()))
                    .sum::<u64>()
            });
            let _ = writeln!(
                out,
                "    {:<14} estimate {:>7.1} GB  measured {}",
                v.name,
                set.estimate_of(&v),
                bytes.map_or_else(|| "-".to_string(), gb)
            );
        }
        let mirrors = dir.as_deref().map(index::read_mirrors);
        for src in set.sources.iter().filter(|s| s.on() && s.kind().in_place()) {
            let line = st
                .sets
                .iter()
                .find(|x| x["name"] == format!("{}/{}", set.name, src.name));
            let field = |k: &str| line.and_then(|x| x[k].as_str()).unwrap_or("-");
            let size = match (src.kind(), &dir) {
                (Kind::Git, _) => mirrors
                    .as_ref()
                    .and_then(|m| m.mirror.iter().find(|m| m.name == src.name))
                    .map(|m| m.bytes),
                (_, Some(d)) => read_header(&live_path(&d.join(&src.name)))
                    .ok()
                    .flatten()
                    .map(|h| h.bytes),
                _ => None,
            };
            let _ = writeln!(
                out,
                "    {:<14} mirror {}  gen {}  {}",
                src.name,
                field("state"),
                field("version"),
                size.map_or_else(|| "-".to_string(), gb)
            );
        }
    }
    Ok(out)
}

/// `preserver public [SET...] [--dry-run] [--first-pass] [--foreground]`.
pub(crate) fn run(
    paths: &mut Paths,
    cfg: &Config,
    names: &[String],
    dry: bool,
    first_pass: bool,
    foreground: bool,
) -> Result<()> {
    let cat = Catalog::embedded()?;
    let sets = cat.select(names, first_pass)?;
    if dry {
        let mounted = paths.mount(&cfg.primary_uuid);
        if let Err(e) = &mounted {
            println!("note: {e:#}, so budgets are unchecked");
        }
        let dl = downloader(cfg);
        let p = public(&cat, paths, cfg, &dl);
        let root = mounted.is_ok().then_some(paths.mnt.as_path());
        let mut out = std::io::stdout().lock();
        for set in sets {
            p.dry_run(set, root, &mut out)?;
        }
        return Ok(());
    }
    actions::mount(&cfg.primary_uuid);
    let store = Store::new(paths.queue.clone());
    let Some((_lock, ids)) = actions::handoff(paths, "queue", foreground, |tidy| {
        let jobs = enqueue_all(&store, &sets, &cfg.primary_uuid, tidy, &|_| false)?;
        Ok(jobs.into_iter().map(|(_, id)| id).collect())
    })?
    else {
        return Ok(());
    };
    let dl = downloader(cfg);
    status::job(paths, "public", |paths| {
        work(&public(&cat, paths, cfg, &dl), &store, &dl, Pass::FRESH)?;
        let mut errs = Vec::new();
        for id in &ids {
            let job = store.job(id)?;
            let name = match &job.kind {
                JobKind::Mirror { set, source } => format!("{set}/{source}"),
                JobKind::Set { set } => set.clone(),
                _ => continue,
            };
            match job.state {
                JobState::Done => {}
                JobState::Failed => {
                    errs.push(format!("{name}: {}", job.error.unwrap_or_default()));
                }
                s => println!("{name}: {s} (job {id})"),
            }
        }
        if errs.is_empty() {
            return Ok(());
        }
        let msg = errs.join("; ");
        notify(true, "Public sync had failures", &trunc(&msg, 600));
        bail!(msg)
    })
}

#[cfg(test)]
mod tests;
