//! `preserver public`: each selected set becomes a queue job. The worker resolves it, stages
//! it under `public/<set>/.staging/`, downloads what is missing, and only after every file
//! has verified renames the stage into place as a new version.

pub(crate) mod index;
pub(crate) mod versioned;

use crate::catalog::{Catalog, Set, Source};
use crate::config::{Config, DriveId};
use crate::keys;
use crate::net::client;
use crate::net::download::{CHECKPOINT, Downloader, Fetch};
use crate::net::throttle::Throttle;
use crate::paths::Paths;
use crate::queue::{Job, JobKind, JobState, Lane, Pass, Store, Work, Worker, runnable};
use crate::resolve::{GH_API, HF_BASE, Item, Resolver};
use crate::verify::Verifier;
use crate::{actions, platform, status};
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
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "a catalog estimate in GB, far below u64::MAX bytes"
        )]
        let estimate = (versioned.max(0.0) * 1e9) as u64;
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
        let name = match &job.kind {
            JobKind::Set { set } => set,
            JobKind::Mirror { set, source } => return Ok(self.plan_mirror(set, source)),
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
            return Ok(Vec::new());
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
                return Ok(Vec::new());
            }
        };
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
        std::fs::create_dir_all(&dir).with_context(|| dir.display().to_string())?;
        match versioned::prepare(set, &dir, &by, allowed)? {
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

    /// The mirror walkers arrive in later steps of phase 3; until then an enabled source only
    /// records that it was skipped. A source gone from the catalog ends the job in `settle`.
    fn plan_mirror(&self, set: &str, source: &str) -> Vec<Fetch> {
        let detail = if self.mirror_source(set, source).is_some() {
            "arrives later in phase 3"
        } else {
            "source no longer in the catalog"
        };
        self.record(&format!("{set}/{source}"), "skipped", "", detail);
        Vec::new()
    }

    /// Called by the worker when a job stops. A job whose downloads all arrived is verified
    /// and published here; a verification failure turns it into a failed job.
    pub(crate) fn settle(&self, job: &mut Job, root: &Path) {
        if let JobKind::Mirror { set, source } = &job.kind {
            if job.state == JobState::Done && self.mirror_source(set, source).is_none() {
                job.state = JobState::Canceled;
            }
            return;
        }
        let JobKind::Set { set } = &job.kind else {
            return;
        };
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
    }
}

/// Runs the queue worker until nothing is runnable. The caller holds the queue lock.
fn work(p: &Public, store: &Store, dl: &Downloader, pass: Pass) -> Result<()> {
    Worker {
        store,
        dl,
        plan: &|job, root, _| p.plan(job, root).map(Work::from),
        settle: &|job, root, _| p.settle(job, root),
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
    Ok(note + &list_text(&cat, root.as_deref())?)
}

fn list_text(cat: &Catalog, root: Option<&Path>) -> Result<String> {
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
