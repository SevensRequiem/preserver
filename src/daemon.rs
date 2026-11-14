//! `preserver daemon`: the always-on user service. It owns no job state itself. Each lane
//! takes its lock for one pass only, so the CLI can still run a lane in the foreground and
//! otherwise just enqueues. Control stays file-based: `.ctl` files in, job JSON and
//! `status/*.json` out, no socket.
//!
//! Threads: main (event loop, holds `preserver-daemon.lock` for life, turns due schedules and
//! copy rules into jobs, mounts wanted drives as they are plugged in), the download, copy and
//! personal lanes, the udisks watcher and the queue watcher. Each lane owns its pass; main only
//! sends it `Pass` values. Main is the only daemon code that mounts anything.

use crate::config::{Config, DriveId};
use crate::paths::Paths;
use crate::platform::{self, DriveEvent};
use crate::queue::{JobKind, JobState, Pass, Store, Target};
use crate::status::Status;
use crate::{copy, personal, public, schedule};
use anyhow::{Context, Result, bail};
use jiff::{Timestamp, Zoned};
use std::fs::TryLockError;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

const TICK: Duration = Duration::from_secs(30);
/// A blocked job is retried at least this often, in case a drive event was missed.
const SWEEP: Duration = Duration::from_secs(3600);

const DRIVE_EVENT: Pass = Pass {
    retry_failed: false,
    retry_blocked: true,
};

enum Wake {
    /// A new job, a `.ctl` edit or a `wake` file in the queue directory.
    Queue,
    Drive(DriveEvent),
}

pub(crate) fn run(paths: &Paths) -> Result<()> {
    let file = paths.lock_file("daemon");
    let lock = platform::private_file(&file).with_context(|| file.display().to_string())?;
    match lock.try_lock() {
        Ok(()) => {}
        // Waiting instead of failing: a restart overlapping the old process is no crash loop.
        Err(TryLockError::WouldBlock) => {
            tracing::info!("waiting for the running daemon to exit");
            lock.lock().with_context(|| file.display().to_string())?;
        }
        Err(TryLockError::Error(e)) => return Err(e).with_context(|| file.display().to_string()),
    }
    // Never reset: the process ends by a signal, and the tray reads a running flag without
    // the lock as "not running".
    Status {
        running: true,
        last_run: Some(Timestamp::now()),
        ..Status::default()
    }
    .write(&paths.status_file("daemon"))?;
    tracing::info!("daemon started");
    match Config::load(&paths.cfg) {
        Ok(cfg) => {
            let s = &cfg.schedule;
            for (name, when) in [
                ("personal", &s.personal),
                ("local", &s.local),
                ("public", &s.public),
            ] {
                if let Some(when) = when {
                    tracing::info!("schedule: {name} {when}");
                }
            }
        }
        Err(e) => tracing::warn!("config: {e:#}"),
    }

    // `wake` lives as long as this loop, so `woken` never disconnects, even when the watchers
    // drop their senders (Windows has none yet).
    let (wake, woken) = mpsc::channel::<Wake>();
    let drive_wake = wake.clone();
    platform::watch_drives(move |event| {
        let _ = drive_wake.send(Wake::Drive(event));
    });
    let queue_wake = wake.clone();
    platform::watch_queue(&paths.queue, move || {
        let _ = queue_wake.send(Wake::Queue);
    });

    let lanes = [
        spawn_lane(paths, "download", public::daemon_pass)?,
        spawn_lane(paths, "copy", copy::daemon_pass)?,
        spawn_lane(paths, "personal", personal::lane::daemon_pass)?,
    ];

    let mut swept = Instant::now();
    let mut pass = DRIVE_EVENT;
    let mut public_queued = None;
    loop {
        schedule::tick(paths, &Zoned::now(), &mut public_queued);
        if let Err(e) = copy::schedule(paths, Timestamp::now()) {
            tracing::warn!("copy rules: {e:#}");
        }
        // A lane only ends by panicking; exit so systemd restarts the daemon.
        for (name, lane) in &lanes {
            if lane.send(pass).is_err() {
                bail!("the {name} lane stopped");
            }
        }
        pass = match woken.recv_timeout(TICK) {
            Ok(Wake::Drive(event)) => {
                if let DriveEvent::Added(object) = event {
                    mount_added(paths, &object);
                }
                DRIVE_EVENT
            }
            Err(RecvTimeoutError::Timeout) if swept.elapsed() >= SWEEP => {
                swept = Instant::now();
                DRIVE_EVENT
            }
            Ok(Wake::Queue) | Err(RecvTimeoutError::Timeout) => Pass::TICK,
            Err(RecvTimeoutError::Disconnected) => unreachable!("main holds a sender"),
        };
    }
}

/// Mounts a drive just plugged in when a job could want it: the primary, or the target of a
/// copy rule or of an unfinished copy job. Anything else is left to the desktop.
fn mount_added(paths: &Paths, object: &str) {
    let mut wanted: Vec<DriveId> = Vec::new();
    match Config::load(&paths.cfg) {
        Ok(cfg) => wanted.push(cfg.primary_uuid),
        Err(e) => tracing::warn!("config: {e:#}"),
    }
    let mut targets: Vec<Target> = copy::rules::load(&paths.copy_rules)
        .unwrap_or_default()
        .into_iter()
        .map(|r| r.target)
        .collect();
    let jobs = Store::new(paths.queue.clone()).jobs().unwrap_or_default();
    targets.extend(jobs.into_iter().filter_map(|j| match j.kind {
        JobKind::Copy { target, .. } if !matches!(j.state, JobState::Done | JobState::Canceled) => {
            Some(target)
        }
        _ => None,
    }));
    wanted.extend(targets.into_iter().filter_map(|t| match t {
        Target::Drive { id, .. } => Some(id),
        Target::Dir { .. } => None,
    }));
    match platform::mount_added(object, &wanted) {
        Ok(Some((id, at))) => tracing::info!("mounted {id} at {}", at.display()),
        Ok(None) => {}
        Err(e) => tracing::warn!("mount {object}: {e:#}"),
    }
}

fn spawn_lane(
    paths: &Paths,
    name: &'static str,
    pass_fn: fn(&Paths, Pass) -> Result<()>,
) -> Result<(&'static str, mpsc::Sender<Pass>)> {
    let (lane, passes) = mpsc::channel::<Pass>();
    let lane_paths = paths.clone();
    std::thread::Builder::new()
        .name(name.into())
        .spawn(move || {
            while let Ok(mut pass) = passes.recv() {
                // Wake-ups that piled up during the last pass need one pass, not one each.
                while let Ok(more) = passes.try_recv() {
                    pass.retry_failed |= more.retry_failed;
                    pass.retry_blocked |= more.retry_blocked;
                }
                if let Err(e) = pass_fn(&lane_paths, pass) {
                    tracing::warn!("{name} lane: {e:#}");
                }
            }
        })
        .with_context(|| format!("start the {name} lane"))?;
    Ok((name, lane))
}
