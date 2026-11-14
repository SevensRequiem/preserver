//! `preserver daemon`: the always-on user service. It owns no job state itself. Each lane
//! takes its lock for one pass only, so `preserver public` and `queue run` work as before and
//! just enqueue while a pass runs. Control stays file-based: `.ctl` files in, job JSON and
//! `status/*.json` out, no socket.
//!
//! Threads: main (event loop, holds `preserver-daemon.lock` for life), the download lane, and
//! the udisks watcher. The lane owns its pass; main only sends it `Pass` values.

use crate::paths::Paths;
use crate::queue::Pass;
use crate::status::Status;
use crate::{platform, public};
use anyhow::{Context, Result, bail};
use jiff::Timestamp;
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

    // `wake` lives as long as this loop, so `woken` never disconnects, even when the watcher
    // drops its sender (Windows has none yet).
    let (wake, woken) = mpsc::channel::<()>();
    let watcher_wake = wake.clone();
    platform::watch_drives(move || {
        let _ = watcher_wake.send(());
    });

    let (lane, passes) = mpsc::channel::<Pass>();
    let lane_paths = paths.clone();
    std::thread::Builder::new()
        .name("download".into())
        .spawn(move || {
            while let Ok(mut pass) = passes.recv() {
                // Wake-ups that piled up during the last pass need one pass, not one each.
                while let Ok(more) = passes.try_recv() {
                    pass.retry_failed |= more.retry_failed;
                    pass.retry_blocked |= more.retry_blocked;
                }
                if let Err(e) = public::daemon_pass(&lane_paths, pass) {
                    tracing::warn!("download lane: {e:#}");
                }
            }
        })
        .context("start the download lane")?;

    let mut swept = Instant::now();
    let mut pass = DRIVE_EVENT;
    loop {
        // The lane only ends by panicking; exit so systemd restarts the daemon.
        if lane.send(pass).is_err() {
            bail!("the download lane stopped");
        }
        pass = match woken.recv_timeout(TICK) {
            Ok(()) => DRIVE_EVENT,
            Err(RecvTimeoutError::Timeout) if swept.elapsed() >= SWEEP => {
                swept = Instant::now();
                DRIVE_EVENT
            }
            Err(RecvTimeoutError::Timeout) => Pass::TICK,
            Err(RecvTimeoutError::Disconnected) => unreachable!("main holds a sender"),
        };
    }
}
