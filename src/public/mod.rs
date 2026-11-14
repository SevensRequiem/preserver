//! `preserver public`: each selected set becomes a queue job. The worker resolves it, stages
//! it under `public/<set>/.staging/`, downloads what is missing, and only after every file
//! has verified renames the stage into place as a new version.

mod index;
mod versioned;

use crate::catalog::{Catalog, Set, Source};
use crate::config::{Config, DriveId};
use crate::keys;
use crate::net::client;
use crate::net::download::{CHECKPOINT, Downloader, Fetch};
use crate::net::throttle::Throttle;
use crate::paths::Paths;
use crate::queue::{Job, JobKind, JobState, Store, Worker};
use crate::resolve::{GH_API, HF_BASE, Item, Resolver};
use crate::verify::Verifier;
use crate::{platform, status};
use anyhow::{Context, Result, bail};
use jiff::Timestamp;
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
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
}

#[expect(clippy::cast_precision_loss, reason = "a size shown to two decimals")]
pub(crate) fn gb(n: u64) -> String {
    format!("{:.2} GB", n as f64 / 1e9)
}

fn trunc(s: &str, n: usize) -> String {
    match s.char_indices().nth(n) {
        Some((i, _)) => format!("{}...", &s[..i]),
        None => s.to_string(),
    }
}

impl Public<'_> {
    fn public_dir(root: &Path) -> std::path::PathBuf {
        root.join("code-archive").join("public")
    }

    /// Refuses a set whose estimate would eat into the reserve.
    fn budget(&self, set: &Set, root: &Path) -> Result<()> {
        let (free, total) = (self.free)(root)?;
        let reserve = total / 100 * u64::from(self.reserve_percent);
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "a catalog estimate in GB, far below u64::MAX bytes"
        )]
        let estimate = (set.estimate * 1e9) as u64;
        // A resumed job's stage holds part of the set already. A stage of an older plan is
        // deleted by prepare(), so its bytes come back as free space.
        let mut staged = Vec::new();
        let stage = Self::public_dir(root).join(&set.name).join(".staging");
        if stage.is_dir() {
            versioned::regular_files(&stage, "", &mut staged)?;
        }
        let need = estimate.saturating_sub(staged.iter().map(|(_, len)| len).sum());
        if free < reserve || need > free - reserve {
            bail!(
                "budget: needs about {}, {} free above the {}% reserve",
                gb(need),
                gb(free.saturating_sub(reserve)),
                self.reserve_percent
            );
        }
        Ok(())
    }

    /// The set's line in `status/public.json`, in the Go tool's format.
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

    fn resolve_set<'s>(&self, set: &'s Set) -> Result<Vec<(&'s Source, Vec<Item>)>> {
        let mut by = Vec::new();
        let mut errs = Vec::new();
        for src in set
            .sources
            .iter()
            .filter(|s| s.on() && !s.kind().in_place())
        {
            match self.resolver.resolve(src) {
                Ok(items) => by.push((src, items)),
                Err(e) => errs.push(format!("{}: resolve: {e:#}", src.name)),
            }
        }
        if !errs.is_empty() {
            bail!(errs.join("; "));
        }
        Ok(by)
    }

    fn staged(&self) -> std::sync::MutexGuard<'_, HashMap<String, Staged>> {
        self.staged.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The worker's planner: what a set job has to download. A set that needs nothing (no
    /// usable source, over budget, unchanged) is recorded here and plans no files.
    pub(crate) fn plan(&self, job: &Job, root: &Path) -> Result<Vec<Fetch>> {
        let JobKind::Set { set: name } = &job.kind;
        let set = self
            .cat
            .sets
            .iter()
            .find(|s| s.name == *name)
            .with_context(|| format!("no set {name:?} in the catalog"))?;
        if !set.sources.iter().any(Source::on) {
            self.record(name, "skipped", "", "no enabled sources");
            return Ok(Vec::new());
        }
        if let Err(e) = self.budget(set, root) {
            self.record(name, "skipped", "", &format!("{e:#}"));
            return Ok(Vec::new());
        }
        let by = self.resolve_set(set)?;
        if by.is_empty() {
            self.record(
                name,
                "skipped",
                "",
                "git and repo mirrors arrive in phase 3",
            );
            return Ok(Vec::new());
        }
        let dir = Self::public_dir(root).join(name);
        std::fs::create_dir_all(&dir).with_context(|| dir.display().to_string())?;
        match versioned::prepare(set, &dir, &by)? {
            Prepared::Unchanged(version) => {
                self.record(name, "unchanged", &version, "");
                Ok(Vec::new())
            }
            Prepared::Staged(staged, fetches) => {
                self.staged().insert(job.id.clone(), *staged);
                Ok(fetches)
            }
        }
    }

    /// Called by the worker when a job stops. A job whose downloads all arrived is verified
    /// and published here; a verification failure turns it into a failed job.
    pub(crate) fn settle(&self, job: &mut Job, root: &Path) {
        let JobKind::Set { set } = &job.kind;
        let staged = self.staged().remove(&job.id);
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
                if let Err(e) = index::write(self.cat, &root.join("code-archive")) {
                    tracing::warn!("index: {e:#}");
                }
            }
            JobState::Failed => {
                self.record(set, "failed", "", job.error.as_deref().unwrap_or_default());
            }
            _ => {}
        }
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
            if src.kind().in_place() {
                writeln!(
                    w,
                    "   {:<22} {} mirror {} (estimate {:.2} GB, phase 3)",
                    src.name,
                    src.kind().as_str(),
                    src.url,
                    src.est
                )?;
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

/// Queues a job per set, unless one is already waiting, and returns the job ids in set order.
/// `tidy` (the caller holds the worker lock) also drops the finished jobs of those sets.
fn enqueue(store: &Store, sets: &[&Set], drive: &DriveId, tidy: bool) -> Result<Vec<String>> {
    let jobs = store.jobs()?;
    let mut ids = Vec::new();
    for (i, set) in sets.iter().enumerate() {
        let mut waiting = None;
        for j in jobs.iter().filter(|j| {
            let JobKind::Set { set: s } = &j.kind;
            *s == set.name
        }) {
            if !matches!(j.state, JobState::Done | JobState::Canceled) {
                waiting.get_or_insert_with(|| j.id.clone());
            } else if tidy {
                store.remove(&j.id)?;
            }
        }
        let id = if let Some(id) = waiting {
            id
        } else {
            let kind = JobKind::Set {
                set: set.name.clone(),
            };
            store
                .create(&kind, drive, u32::try_from(i).unwrap_or(u32::MAX))?
                .id
        };
        ids.push(id);
    }
    Ok(ids)
}

fn downloader(cfg: &Config) -> Result<Downloader> {
    Ok(Downloader::new(
        client::agent(client::os_roots()?),
        Arc::new(Throttle::from_mbit(cfg.bandwidth_mbit)),
        CHECKPOINT,
    ))
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
    }
}

/// Runs the queue worker until nothing is runnable. The caller holds the queue lock.
fn work(p: &Public, store: &Store, dl: &Downloader) -> Result<()> {
    Worker {
        store,
        dl,
        plan: &|job, root| p.plan(job, root),
        settle: &|job, root| p.settle(job, root),
        drive: &|id| platform::mount(id).ok(),
    }
    .run()
}

/// `preserver queue run`.
pub(crate) fn queue_run(paths: &Paths, cfg: &Config) -> Result<()> {
    let Some(_lock) = status::try_lock(&paths.lock_file("queue"))? else {
        println!("queued; worker running");
        return Ok(());
    };
    let cat = Catalog::embedded()?;
    let dl = downloader(cfg)?;
    work(
        &public(&cat, paths, cfg, &dl),
        &Store::new(paths.queue.clone()),
        &dl,
    )
}

/// `preserver public [SET...] [--dry-run] [--first-pass]`.
pub(crate) fn run(
    paths: &mut Paths,
    cfg: &Config,
    names: &[String],
    dry: bool,
    first_pass: bool,
) -> Result<()> {
    let cat = Catalog::embedded()?;
    let sets = cat.select(names, first_pass)?;
    let mounted = paths.mount(&cfg.primary_uuid);
    let dl = downloader(cfg)?;
    if dry {
        if let Err(e) = &mounted {
            println!("note: {e:#}, so budgets are unchecked");
        }
        let p = public(&cat, paths, cfg, &dl);
        let root = mounted.is_ok().then_some(paths.mnt.as_path());
        let mut out = std::io::stdout().lock();
        for set in sets {
            p.dry_run(set, root, &mut out)?;
        }
        return Ok(());
    }
    mounted?;
    let store = Store::new(paths.queue.clone());
    let Some(_lock) = status::try_lock(&paths.lock_file("queue"))? else {
        enqueue(&store, &sets, &cfg.primary_uuid, false)?;
        println!("queued; worker running");
        return Ok(());
    };
    status::job(paths, "public", |paths| {
        let ids = enqueue(&store, &sets, &cfg.primary_uuid, true)?;
        work(&public(&cat, paths, cfg, &dl), &store, &dl)?;
        let mut errs = Vec::new();
        for (set, id) in sets.iter().zip(&ids) {
            let job = store.job(id)?;
            match job.state {
                JobState::Done => {}
                JobState::Failed => {
                    errs.push(format!("{}: {}", set.name, job.error.unwrap_or_default()));
                }
                s => errs.push(format!("{}: {s}", set.name)),
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
