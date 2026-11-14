//! What a person asks for, from the CLI or the tray, on its way to the queue. People's actions
//! mount the drives a job needs (the daemon's lanes never do), then hand the job to the daemon
//! when it runs, or to this process.

use crate::catalog::Catalog;
use crate::config::{Config, DriveId, Transport};
use crate::copy::{self, rules};
use crate::paths::Paths;
use crate::queue::{JobKind, Store, Target};
use crate::status::{self, Status};
use crate::tray_model::{Command, Inputs, Job};
use crate::{platform, public};
use anyhow::{Context, Result, ensure};
use std::fs::File;
use std::process::{Child, Stdio};

/// The daemon holds its lock for life, so the lock, not `status/daemon.json`, says it runs.
pub(crate) fn daemon_live(paths: &Paths) -> bool {
    status::lock_held(&paths.lock_file("daemon"))
}

/// The daemon watches the queue directory for this file, so a new job runs at once.
pub(crate) fn wake(paths: &Paths) -> Result<()> {
    Ok(platform::write_private(&paths.queue.join("wake"), b"")?)
}

/// Best effort: a drive that will not mount leaves its job Blocked, where the queue shows it.
pub(crate) fn mount(id: &DriveId) {
    if let Err(e) = platform::mount(id) {
        tracing::info!("{id} is not mounted ({e:#}); its jobs wait for it");
    }
}

/// Queues the local-folder job (when config.toml lists any) and, unless `local_only`, the
/// GitHub one. A GitHub job already waiting keeps the transport it was queued with.
pub(crate) fn enqueue_personal(
    paths: &Paths,
    cfg: &Config,
    local_only: bool,
    transport: Option<Transport>,
    tidy: bool,
) -> Result<Vec<String>> {
    mount(&cfg.primary_uuid);
    let store = Store::new(paths.queue.clone());
    let mut ids = Vec::new();
    if !cfg.local.is_empty() {
        ids.push(store.enqueue(&JobKind::Local, &cfg.primary_uuid, 0, tidy)?);
    }
    if !local_only {
        ids.push(store.enqueue(&JobKind::Github { transport }, &cfg.primary_uuid, 1, tidy)?);
    }
    Ok(ids)
}

/// Queues a job per catalog set (or the named ones).
#[cfg_attr(
    windows,
    allow(dead_code, reason = "the Windows tray arrives in phase 5")
)]
pub(crate) fn enqueue_public(
    paths: &Paths,
    cfg: &Config,
    sets: &[String],
    tidy: bool,
) -> Result<Vec<String>> {
    mount(&cfg.primary_uuid);
    let cat = Catalog::embedded()?;
    let sets = cat.select(sets, false)?;
    public::enqueue_all(
        &Store::new(paths.queue.clone()),
        &sets,
        &cfg.primary_uuid,
        tidy,
    )
}

/// Queues one run of a saved copy rule, ahead of its schedule.
pub(crate) fn enqueue_copy_rule(
    paths: &Paths,
    cfg: &Config,
    rule_id: &str,
    tidy: bool,
) -> Result<String> {
    let kind = copy::rule_kind(paths, rule_id)?;
    mount(&cfg.primary_uuid);
    if let JobKind::Copy {
        target: Target::Drive { id, .. },
        ..
    } = &kind
    {
        mount(id);
    }
    Store::new(paths.queue.clone()).enqueue(&kind, &cfg.primary_uuid, copy::RULE_PRIORITY, tidy)
}

#[cfg_attr(
    windows,
    allow(dead_code, reason = "the Windows tray arrives in phase 5")
)]
pub(crate) fn cancel(paths: &Paths, id: &str) -> Result<()> {
    Store::new(paths.queue.clone()).edit_control(Some(id), |c| c.cancel = true)
}

/// Pauses or resumes the whole queue through `all.ctl`.
#[cfg_attr(
    windows,
    allow(dead_code, reason = "the Windows tray arrives in phase 5")
)]
pub(crate) fn pause_all(paths: &Paths, pause: bool) -> Result<()> {
    Store::new(paths.queue.clone()).edit_control(None, |c| c.pause = pause)
}

/// Runs `preserver <args>` as this binary, with no shell and no stdin.
#[cfg_attr(
    windows,
    allow(dead_code, reason = "the Windows tray arrives in phase 5")
)]
pub(crate) fn spawn_foreground(args: &[String]) -> std::io::Result<Child> {
    std::process::Command::new(std::env::current_exe()?)
        .args(args)
        .stdin(Stdio::null())
        .spawn()
}

/// What the tray and the GUI do for a command: queue it for the daemon when one runs, else run
/// it here as a `--foreground` child and wait for its exit status.
#[cfg_attr(
    windows,
    allow(dead_code, reason = "the Windows tray arrives in phase 5")
)]
pub(crate) fn run(paths: &Paths, cmd: &Command) -> Result<()> {
    if !daemon_live(paths) {
        let status = spawn_foreground(&cmd.args())
            .context("start preserver")?
            .wait()?;
        ensure!(status.success(), "preserver exited with {status}");
        return Ok(());
    }
    let cfg = Config::load(&paths.cfg)?;
    match cmd {
        Command::Personal => enqueue_personal(paths, &cfg, false, None, false).map(drop)?,
        Command::Local => enqueue_personal(paths, &cfg, true, None, false).map(drop)?,
        Command::Public => enqueue_public(paths, &cfg, &[], false).map(drop)?,
        Command::CopyRule(id) => enqueue_copy_rule(paths, &cfg, id, false).map(drop)?,
    }
    wake(paths)
}

/// Everything the tray model needs, read from the status files, locks and queue.
#[cfg_attr(
    windows,
    allow(dead_code, reason = "the Windows tray arrives in phase 5")
)]
pub(crate) fn snapshot(paths: &Paths, starting: bool, start_failure: Option<String>) -> Inputs {
    let job = |name| {
        let status = Status::read(&paths.status_file(name));
        // The lock is only probed for a job that claims to run: probing takes it for an instant.
        let locked = status.running && status::lock_held(&paths.lock_file(name));
        Job { status, locked }
    };
    let store = Store::new(paths.queue.clone());
    let cfg = Config::load(&paths.cfg).ok();
    let now = jiff::Zoned::now();
    Inputs {
        github: job("github"),
        local: job("local"),
        public: job("public"),
        daemon: job("daemon"),
        jobs: store.jobs().unwrap_or_default(),
        queue_paused: store.control(None).pause,
        starting,
        start_failure,
        today: now.date(),
        tz: now.time_zone().clone(),
        transport: cfg.as_ref().map(|c| c.transport),
        has_local: cfg.as_ref().is_some_and(|c| !c.local.is_empty()),
        rules: rules::load(&paths.copy_rules)
            .unwrap_or_default()
            .into_iter()
            .map(|r| (r.id, r.target.name()))
            .collect(),
    }
}

/// Mounts the job's drives, then asks its worker to run it again (a paused one too). The
/// control file wakes the daemon by itself.
pub(crate) fn retry(paths: &Paths, id: &str) -> Result<()> {
    let store = Store::new(paths.queue.clone());
    let job = store.job(id)?;
    mount(&job.drive);
    if let JobKind::Copy {
        target: Target::Drive { id, .. },
        ..
    } = &job.kind
    {
        mount(id);
    }
    store.edit_control(Some(id), |c| {
        c.retry += 1;
        c.pause = false;
    })
}

/// Steps the CLI's `personal`, `public` and `copy` share. With a daemon running (and no
/// `--foreground`) or another worker on the lane, the jobs are queued for it and `None` comes
/// back. Otherwise this process takes the lane's lock before it queues, so the daemon cannot
/// pick the jobs up, and gets the lock and the job ids to run them itself.
pub(crate) fn handoff(
    paths: &Paths,
    lane_lock: &str,
    foreground: bool,
    enqueue: impl Fn(bool) -> Result<Vec<String>>,
) -> Result<Option<(File, Vec<String>)>> {
    if !foreground && daemon_live(paths) {
        let ids = enqueue(false)?;
        wake(paths)?;
        println!(
            "queued as {}; the daemon runs it ('preserver queue list --watch')",
            ids.join(", ")
        );
        return Ok(None);
    }
    let Some(lock) = status::try_lock(&paths.lock_file(lane_lock))? else {
        enqueue(false)?;
        wake(paths)?;
        println!("queued; a worker is running");
        return Ok(None);
    };
    if !foreground {
        println!("no daemon running; running here");
    }
    Ok(Some((lock, enqueue(true)?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, paths};

    #[test]
    fn snapshot_of_an_empty_home() {
        let tmp = TempDir::new();
        let i = snapshot(&paths(tmp.path()), false, None);
        assert!(i.jobs.is_empty() && i.rules.is_empty() && !i.has_local);
    }

    #[test]
    fn the_daemon_lock_says_whether_it_runs() {
        let tmp = TempDir::new();
        let paths = paths(tmp.path());
        assert!(!daemon_live(&paths));
        let lock = status::try_lock(&paths.lock_file("daemon"))
            .unwrap()
            .unwrap();
        assert!(daemon_live(&paths));
        drop(lock);
    }
}
