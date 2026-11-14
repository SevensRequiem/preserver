//! What a person asks for, from the CLI or the tray, on its way to the queue. People's actions
//! mount the drives a job needs (the daemon's lanes never do), then hand the job to the daemon
//! when it runs, or to this process.

use crate::config::{Config, DriveId, Transport};
use crate::paths::Paths;
use crate::queue::{JobKind, Store, Target};
use crate::{platform, status};
use anyhow::Result;
use std::fs::File;

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
