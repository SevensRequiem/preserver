//! The worker: one job at a time, its files over `STREAMS` threads with at most `PER_HOST` per
//! host, per-file retries with backoff, and the controls applied while it runs.

use super::job::{BlockReason, Job, JobState, Lane, Progress};
use super::store::Store;
use crate::config::DriveId;
use crate::net::download::{Downloader, Fail, Fetch, STREAMS};
use crate::platform::DriveAt;
use anyhow::{Result, anyhow};
use std::collections::{BTreeSet, HashMap};
use std::hash::BuildHasher;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

pub(crate) const PER_HOST: usize = 2;
/// Tries in a row without progress per file per run; after that the job is Failed and the
/// next run retries it.
pub(crate) const TRIES: u32 = 6;

/// The wait after the `n`th failure (from 0): 5 s·2ⁿ capped at 10 min, less up to a quarter
/// for `jitter` in [0, 1], so retries from many files don't land together.
pub(crate) fn backoff(n: u32, jitter: f64) -> Duration {
    let base = 5u64.saturating_mul(1 << n.min(20)).min(600);
    Duration::from_secs(base).mul_f64(1.0 - jitter.clamp(0.0, 1.0) / 4.0)
}

fn jitter() -> f64 {
    // Not security relevant: std's per-process random hash keys are plenty.
    let h = std::hash::RandomState::new().hash_one(Instant::now());
    #[expect(clippy::cast_precision_loss, reason = "a fraction")]
    let j = h as f64 / u64::MAX as f64;
    j
}

#[derive(Default)]
struct State {
    /// Waiting files per host, by plan position.
    queues: HashMap<String, BTreeSet<usize>>,
    delayed: Vec<(Instant, usize)>,
    active: HashMap<String, usize>,
    host_until: HashMap<String, Instant>,
    tries: Vec<u32>,
    running: usize,
    current: BTreeSet<usize>,
    files_done: u64,
    /// Plan positions that finished verified.
    ok: Vec<usize>,
    failed: Vec<String>,
    drive_gone: bool,
}

impl State {
    fn idle(&self) -> bool {
        self.queues.values().all(BTreeSet::is_empty) && self.delayed.is_empty()
    }
}

struct Pool<'a> {
    fetches: &'a [Fetch],
    hosts: Vec<String>,
    st: Mutex<State>,
    cv: Condvar,
    stop: AtomicBool,
}

impl<'a> Pool<'a> {
    fn new(fetches: &'a [Fetch]) -> Self {
        let hosts: Vec<String> = fetches.iter().map(Fetch::host).collect();
        let mut st = State {
            tries: vec![0; fetches.len()],
            ..State::default()
        };
        for (i, h) in hosts.iter().enumerate() {
            st.queues.entry(h.clone()).or_default().insert(i);
        }
        Self {
            fetches,
            hosts,
            st: Mutex::new(st),
            cv: Condvar::new(),
            stop: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn halt(&self) {
        // Relaxed: the downloads only need to see it soon; the state is under the mutex.
        self.stop.store(true, Ordering::Relaxed);
        self.cv.notify_all();
    }

    /// The earliest waiting file whose host has a free slot, blocking until one is ready.
    /// `None` once stopped, or when nothing waits and nothing runs that could come back.
    fn next(&self) -> Option<usize> {
        let mut st = self.lock();
        loop {
            if self.stop.load(Ordering::Relaxed) {
                return None;
            }
            let now = Instant::now();
            let (ready, later): (Vec<_>, Vec<_>) =
                st.delayed.drain(..).partition(|(t, _)| *t <= now);
            st.delayed = later;
            for (_, i) in ready {
                st.queues
                    .entry(self.hosts[i].clone())
                    .or_default()
                    .insert(i);
            }
            let pick = st
                .queues
                .iter()
                .filter(|(h, _)| {
                    st.active.get(*h).copied().unwrap_or(0) < PER_HOST
                        && st.host_until.get(*h).is_none_or(|t| *t <= now)
                })
                .filter_map(|(_, q)| q.first().copied())
                .min();
            if let Some(i) = pick {
                let h = &self.hosts[i];
                st.queues.entry(h.clone()).or_default().remove(&i);
                *st.active.entry(h.clone()).or_default() += 1;
                st.running += 1;
                st.current.insert(i);
                return Some(i);
            }
            if st.idle() && st.running == 0 {
                self.cv.notify_all();
                return None;
            }
            let wake = st
                .delayed
                .iter()
                .map(|(t, _)| *t)
                .chain(st.host_until.values().copied().filter(|t| *t > now))
                .min()
                .map_or(Duration::from_secs(1), |t| t - now);
            st = self
                .cv
                .wait_timeout(st, wake.min(Duration::from_secs(1)))
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    fn finish(&self, i: usize, r: Result<(), Fail>, drive_ok: &dyn Fn() -> bool) {
        let gone = matches!(r, Err(Fail::Disk(_))) && !drive_ok();
        let mut st = self.lock();
        let h = &self.hosts[i];
        *st.active.entry(h.clone()).or_default() -= 1;
        st.running -= 1;
        st.current.remove(&i);
        match r {
            Ok(()) => {
                st.files_done += 1;
                st.ok.push(i);
            }
            Err(Fail::Stopped) => {}
            Err(_) if gone => {
                st.drive_gone = true;
                self.halt();
            }
            Err(Fail::Permanent(msg)) => st.failed.push(msg),
            Err(e @ (Fail::Retry { .. } | Fail::Disk(_))) => {
                // Only tries that got nowhere count: a large file over a flaky route may need
                // many attempts, and each one that saved a checkpoint brought it closer.
                st.tries[i] = match e {
                    Fail::Retry {
                        progressed: true, ..
                    } => 0,
                    _ => st.tries[i] + 1,
                };
                if st.tries[i] >= TRIES {
                    st.failed.push(format!("{e} ({TRIES} tries)"));
                } else {
                    let now = Instant::now();
                    if let Fail::Retry { after: Some(a), .. } = &e {
                        st.host_until.insert(h.clone(), now + *a);
                    }
                    tracing::info!("{e}; retrying");
                    let at = now + backoff(st.tries[i].saturating_sub(1), jitter());
                    st.delayed.push((at, i));
                }
            }
        }
        drop(st);
        self.cv.notify_all();
    }

    fn work(&self, dl: &Downloader, done: &AtomicU64, drive_ok: &dyn Fn() -> bool) {
        while let Some(i) = self.next() {
            let r = dl.fetch(&self.fetches[i], &self.stop, done);
            self.finish(i, r, drive_ok);
        }
    }

    /// Waits up to `d`; true once every download thread is about to exit.
    fn wait(&self, d: Duration) -> bool {
        let finished =
            |st: &State| st.running == 0 && (st.idle() || self.stop.load(Ordering::Relaxed));
        let st = self.lock();
        if finished(&st) {
            return true;
        }
        let st = self
            .cv
            .wait_timeout(st, d)
            .unwrap_or_else(PoisonError::into_inner)
            .0;
        finished(&st)
    }
}

/// Which stopped jobs a worker pass puts back in the queue. A CLI run is `FRESH`: a person
/// asked, so Failed and Blocked jobs get another try. The daemon passes every 30 s with `TICK`,
/// or else a failed set would be retried every 30 s; it sets `retry_blocked` on a drive event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Pass {
    pub retry_failed: bool,
    pub retry_blocked: bool,
}

impl Pass {
    pub(crate) const FRESH: Self = Self {
        retry_failed: true,
        retry_blocked: true,
    };
    pub(crate) const TICK: Self = Self {
        retry_failed: false,
        retry_blocked: false,
    };
}

/// Whether a pass of `lane` under `pass` would do anything, so an idle daemon tick touches
/// no status file. Mirrors the reset in `Worker::run` and the rules of `apply`.
pub(crate) fn runnable(store: &Store, lane: Lane, pass: Pass) -> Result<bool> {
    let paused = store.control(None).pause;
    Ok(store
        .jobs()?
        .iter()
        .filter(|j| j.kind.lane() == lane)
        .any(|j| {
            let c = store.control(Some(&j.id));
            let retry = c.retry > j.retry_seen;
            match j.state {
                JobState::Done | JobState::Canceled => false,
                _ if c.cancel => true,
                _ if paused => false,
                JobState::Running { .. } | JobState::Queued => true,
                JobState::Blocked(r) => {
                    (pass.retry_blocked && r != BlockReason::NeedsTouch) || retry
                }
                JobState::Failed => pass.retry_failed || retry,
                JobState::Paused => !c.pause || retry,
            }
        }))
}

/// Applies the job's control to an idle job; true when something changed. Shared by both lanes.
pub(crate) fn apply_control(store: &Store, job: &mut Job) -> bool {
    if matches!(job.state, JobState::Done | JobState::Canceled) {
        return false;
    }
    let c = store.control(Some(&job.id));
    let before = (job.state, job.priority, job.retry_seen);
    if let Some(p) = c.priority {
        job.priority = p;
    }
    if c.retry > job.retry_seen {
        job.retry_seen = c.retry;
        job.attempts = 0;
        if matches!(job.state, JobState::Failed | JobState::Blocked(_)) {
            job.state = JobState::Queued;
        }
    }
    job.state = match job.state {
        _ if c.cancel => JobState::Canceled,
        JobState::Queued | JobState::Blocked(_) if c.pause => JobState::Paused,
        JobState::Paused if !c.pause => JobState::Queued,
        s => s,
    };
    before != (job.state, job.priority, job.retry_seen)
}

/// Puts a lane's stopped jobs back in the queue as `pass` says. The caller holds the lane lock,
/// so a job left Running is a crashed worker's.
pub(crate) fn reset(store: &Store, lane: Lane, pass: Pass) -> Result<()> {
    for mut job in store.jobs()?.into_iter().filter(|j| j.kind.lane() == lane) {
        let requeue = match job.state {
            JobState::Running { .. } => true,
            // An unanswered touch prompt is asked again only on a retry or the next scheduled
            // occurrence, never on a drive event.
            JobState::Blocked(r) => pass.retry_blocked && r != BlockReason::NeedsTouch,
            JobState::Failed => pass.retry_failed,
            _ => false,
        };
        if requeue {
            job.state = JobState::Queued;
            store.save(&mut job)?;
        }
    }
    Ok(())
}

/// What the controls ask of a running job.
pub(crate) fn halt_requested(store: &Store, id: &str) -> Option<Halt> {
    let c = store.control(Some(id));
    if c.cancel {
        Some(Halt::Cancel)
    } else if c.pause || store.control(None).pause {
        Some(Halt::Pause)
    } else {
        None
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Halt {
    Pause,
    Cancel,
    /// A job that sorts first was queued: this one goes back in the queue, partials kept.
    Yield,
}

/// Whether a queued download job sorts before `job`. Without this a long set (a 100 GB zim)
/// holds the lane for days and every set queued after it waits, whatever its priority.
fn outranked(store: &Store, job: &Job) -> bool {
    let key = (job.priority, job.created, &job.id);
    store.jobs().is_ok_and(|jobs| {
        jobs.iter().any(|j| {
            let c = store.control(Some(&j.id));
            j.kind.lane() == Lane::Download
                && j.state == JobState::Queued
                && !c.pause
                && !c.cancel
                && (c.priority.unwrap_or(j.priority), j.created, &j.id) < key
        })
    })
}

/// A job's size as the planner knows it, when it is more than the current batch.
pub(crate) struct Whole {
    pub files: u64,
    pub bytes: u64,
    pub files_done: u64,
    pub bytes_done: u64,
}

/// One batch of downloads; `more` asks the worker to plan again once they all verified.
#[derive(Default)]
pub(crate) struct Planned {
    pub fetches: Vec<Fetch>,
    pub more: bool,
    pub whole: Option<Whole>,
}

pub(crate) enum Work<'a> {
    Fetch(Planned),
    /// Work that is not a download (a git transfer): it gets the stop flag and a byte counter.
    /// It is never yielded, since it cannot resume; pause and cancel still stop it.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the git mirror job builds it in a later step")
    )]
    Run(Run<'a>),
}

pub(crate) type Run<'a> = Box<dyn FnOnce(&AtomicBool, &Arc<AtomicU64>) -> Result<()> + Send + 'a>;
pub(crate) type Planner<'a> = dyn Fn(&Job, &Path, &[usize]) -> Result<Work<'a>> + Sync + 'a;

impl From<Vec<Fetch>> for Work<'_> {
    fn from(fetches: Vec<Fetch>) -> Self {
        Self::Fetch(Planned {
            fetches,
            ..Planned::default()
        })
    }
}

pub(crate) struct Worker<'a> {
    pub store: &'a Store,
    pub dl: &'a Downloader,
    /// The job's next work, given the root of its mounted drive and the positions in the
    /// previous batch that finished verified (empty for the first call).
    pub plan: &'a Planner<'a>,
    /// Called with the job's outcome before it is saved, whenever a job stops, and with the
    /// last batch's verified positions. It finishes what the downloads were for, and may turn
    /// a Done job into a Failed one.
    pub settle: &'a (dyn Fn(&mut Job, &Path, &[usize]) + Sync),
    /// Where the drive is; the worker never mounts it.
    pub drive: &'a (dyn Fn(&DriveId) -> DriveAt + Sync),
}

impl<'a> Worker<'a> {
    /// The download lane's jobs: the worker never resets or saves another lane's.
    fn jobs(&self) -> Result<Vec<Job>> {
        let mut jobs = self.store.jobs()?;
        jobs.retain(|j| j.kind.lane() == Lane::Download);
        Ok(jobs)
    }

    /// Runs queued jobs until none is runnable. The caller holds the queue lock, so a job left
    /// Running is a crashed worker's; `pass` says whether Blocked and Failed get another try.
    pub(crate) fn run(&self, pass: Pass) -> Result<()> {
        reset(self.store, Lane::Download, pass)?;
        loop {
            let paused = self.store.control(None).pause;
            let mut jobs = self.jobs()?;
            for job in &mut jobs {
                if apply_control(self.store, job) {
                    self.store.save(job)?;
                }
            }
            jobs.sort_by(|a, b| {
                (a.priority, a.created, &a.id).cmp(&(b.priority, b.created, &b.id))
            });
            let next = jobs.into_iter().find(|j| j.state == JobState::Queued);
            match next {
                Some(job) if !paused => self.run_job(job)?,
                _ => return Ok(()),
            }
        }
    }

    fn drive_ok(&self, job: &Job) -> bool {
        matches!((self.drive)(&job.drive), DriveAt::Mounted(r) if r.exists())
    }

    fn run_job(&self, mut job: Job) -> Result<()> {
        let root = match (self.drive)(&job.drive) {
            DriveAt::Mounted(root) => root,
            DriveAt::Unmounted => {
                job.state = JobState::Blocked(BlockReason::Unmounted);
                return self.store.save(&mut job);
            }
            DriveAt::Absent => {
                job.state = JobState::Blocked(BlockReason::DriveAbsent);
                return self.store.save(&mut job);
            }
        };
        let mut work = match (self.plan)(&job, &root, &[]) {
            Ok(w) => w,
            Err(_) if !self.drive_ok(&job) => {
                job.state = JobState::Blocked(BlockReason::DriveAbsent);
                return self.store.save(&mut job);
            }
            Err(e) => {
                job.state = JobState::Failed;
                job.error = Some(format!("{e:#}"));
                (self.settle)(&mut job, &root, &[]);
                return self.store.save(&mut job);
            }
        };
        job.state = JobState::Running {
            pid: std::process::id(),
        };
        job.attempts += 1;
        job.error = None;
        // Files and bytes finished in earlier batches, when the planner gives no total.
        let mut seen = (0, 0);
        let mut ok = Vec::new();
        let state = loop {
            let planned = match work {
                Work::Run(f) => {
                    job.progress = Progress::default();
                    self.store.save(&mut job)?;
                    break self.run_closure(&mut job, f);
                }
                Work::Fetch(p) => p,
            };
            let Planned {
                fetches,
                more,
                whole,
            } = planned;
            if more && fetches.is_empty() {
                job.error = Some("planner returned an empty batch".into());
                break JobState::Failed;
            }
            let base = whole
                .as_ref()
                .map_or(seen, |w| (w.files_done, w.bytes_done));
            job.progress = Progress {
                files_total: whole
                    .as_ref()
                    .map_or(seen.0 + fetches.len() as u64, |w| w.files),
                bytes_total: whole.as_ref().map_or_else(
                    || seen.1 + fetches.iter().filter_map(|f| f.size).sum::<u64>(),
                    |w| w.bytes,
                ),
                files_done: base.0,
                bytes_done: base.1,
                ..Progress::default()
            };
            self.store.save(&mut job)?;

            let (st, halt, bytes) = self.batch(&job, &fetches, base);
            job.progress.bytes_done = base.1 + bytes;
            job.progress.files_done = base.0 + st.files_done;
            job.progress.rate_bps = 0;
            job.progress.current.clear();
            seen = (seen.0 + st.files_done, seen.1 + bytes);
            ok.clone_from(&st.ok);
            ok.sort_unstable();
            let state = stopped(&mut job, st, halt, &fetches);
            if state != JobState::Done || !more {
                break state;
            }
            match halt_requested(self.store, &job.id) {
                Some(Halt::Cancel) => break JobState::Canceled,
                Some(_) => break JobState::Paused,
                None => {}
            }
            match (self.plan)(&job, &root, &ok) {
                Ok(w) => work = w,
                Err(_) if !self.drive_ok(&job) => {
                    job.attempts -= 1;
                    break JobState::Blocked(BlockReason::DriveAbsent);
                }
                Err(e) => {
                    job.error = Some(format!("{e:#}"));
                    break JobState::Failed;
                }
            }
        };
        job.state = state;
        (self.settle)(&mut job, &root, &ok);
        self.store.save(&mut job)
    }

    /// Downloads one batch over the pool, saving progress every second until it ends. Returns
    /// the pool's state, what halted it and the bytes fetched.
    fn batch(&self, job: &Job, fetches: &[Fetch], base: (u64, u64)) -> (State, Option<Halt>, u64) {
        let pool = Pool::new(fetches);
        let done = AtomicU64::new(0);
        let drive_ok = || self.drive_ok(job);
        let mut halt = None;
        std::thread::scope(|s| {
            for _ in 0..STREAMS {
                s.spawn(|| pool.work(self.dl, &done, &drive_ok));
            }
            let mut last = (Instant::now(), base.1);
            while !pool.wait(Duration::from_secs(1)) {
                if let Some(h) = halt_requested(self.store, &job.id)
                    .or_else(|| outranked(self.store, job).then_some(Halt::Yield))
                {
                    halt = Some(h);
                    pool.halt();
                }
                let st = pool.lock();
                let files = base.0 + st.files_done;
                let current = st.current.iter().map(|i| fetches[*i].url.clone()).collect();
                drop(st);
                self.progress(
                    job,
                    &mut last,
                    base.1 + done.load(Ordering::Relaxed),
                    files,
                    current,
                );
            }
        });
        let st = pool.st.into_inner().unwrap_or_else(PoisonError::into_inner);
        (st, halt, done.load(Ordering::Relaxed))
    }

    /// Runs a `Work::Run` job on a scoped thread, saving progress and applying the controls
    /// every second.
    fn run_closure(&self, job: &mut Job, f: Run<'a>) -> JobState {
        let stop = AtomicBool::new(false);
        let done = Arc::new(AtomicU64::new(0));
        let (tx, rx) = channel();
        let mut halt = None;
        let mut last = (Instant::now(), 0);
        let r = std::thread::scope(|s| {
            s.spawn(|| {
                let _ = tx.send(f(&stop, &done));
            });
            loop {
                match rx.recv_timeout(Duration::from_secs(1)) {
                    Ok(r) => return r,
                    Err(RecvTimeoutError::Disconnected) => return Err(anyhow!("job thread died")),
                    Err(RecvTimeoutError::Timeout) => {}
                }
                if halt.is_none()
                    && let Some(h) = halt_requested(self.store, &job.id)
                {
                    halt = Some(h);
                    // Relaxed: the job only needs to see it soon.
                    stop.store(true, Ordering::Relaxed);
                }
                self.progress(job, &mut last, done.load(Ordering::Relaxed), 0, Vec::new());
            }
        });
        job.progress.bytes_done = done.load(Ordering::Relaxed);
        job.progress.rate_bps = 0;
        job.progress.current.clear();
        match r {
            Ok(()) => JobState::Done,
            Err(_) if !self.drive_ok(job) => {
                job.attempts -= 1;
                JobState::Blocked(BlockReason::DriveAbsent)
            }
            Err(_) if halt == Some(Halt::Cancel) => JobState::Canceled,
            Err(_) if halt == Some(Halt::Pause) => JobState::Paused,
            Err(e) => {
                job.error = Some(format!("{e:#}"));
                JobState::Failed
            }
        }
    }

    fn progress(
        &self,
        job: &Job,
        last: &mut (Instant, u64),
        bytes: u64,
        files: u64,
        current: Vec<String>,
    ) {
        let secs = last.0.elapsed().as_secs_f64();
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss,
            reason = "a displayed rate"
        )]
        let rate = (bytes.saturating_sub(last.1) as f64 / secs) as u64;
        *last = (Instant::now(), bytes);
        let mut j = job.clone();
        j.progress.bytes_done = bytes;
        j.progress.rate_bps = rate;
        j.progress.files_done = files;
        j.progress.current = current;
        if let Err(e) = self.store.save(&mut j) {
            tracing::warn!("progress: {e:#}");
        }
    }
}

/// The state a job's run ends in, from what its downloads did and what stopped them.
fn stopped(job: &mut Job, st: State, halt: Option<Halt>, fetches: &[Fetch]) -> JobState {
    if st.drive_gone {
        // Unplugging is not the job's fault.
        job.attempts -= 1;
        JobState::Blocked(BlockReason::DriveAbsent)
    } else if st.files_done == fetches.len() as u64 {
        JobState::Done
    } else if halt == Some(Halt::Cancel) {
        for f in fetches {
            for p in [f.part(), f.sidecar()] {
                let _ = std::fs::remove_file(p);
            }
        }
        JobState::Canceled
    } else if halt == Some(Halt::Pause) {
        JobState::Paused
    } else if halt == Some(Halt::Yield) {
        job.attempts -= 1;
        JobState::Queued
    } else {
        let n = st.failed.len();
        let mut msg = st.failed.into_iter().take(3).collect::<Vec<_>>().join("; ");
        if n > 3 {
            msg = format!("{msg} (and {} more)", n - 3);
        }
        job.error = Some(msg);
        JobState::Failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::client::loopback_agent;
    use crate::net::download::Expect;
    use crate::net::testserver::{Behaviour, Server, body};
    use crate::net::throttle::Throttle;
    use crate::queue::job::JobKind;
    use crate::testutil::TempDir;
    use sha2::Digest;
    use std::path::PathBuf;
    use std::sync::Arc;
    use ureq::tls::RootCerts;

    const CP: u64 = 1 << 20;

    fn dl(rate: u64) -> Downloader {
        Downloader::new(
            loopback_agent(RootCerts::new_with_certs(&[])),
            Arc::new(Throttle::new(rate)),
            CP,
        )
    }

    #[test]
    fn only_tries_without_progress_count() {
        let fetches = [Fetch {
            url: "https://example.org/big.zim".into(),
            dest: PathBuf::new(),
            size: None,
            limit: u64::MAX,
            expect: Expect::None,
        }];
        let p = Pool::new(&fetches);
        let fail = |progressed| {
            {
                let mut st = p.lock();
                st.running += 1;
                *st.active.entry(p.hosts[0].clone()).or_default() += 1;
            }
            let e = Fail::Retry {
                msg: "timeout: connect".into(),
                after: None,
                progressed,
            };
            p.finish(0, Err(e), &|| true);
        };
        for _ in 0..2 * TRIES {
            fail(true);
        }
        for _ in 1..TRIES {
            fail(false);
        }
        assert_eq!(p.lock().failed, Vec::<String>::new());
        fail(false);
        assert_eq!(p.lock().failed.len(), 1);
    }

    #[test]
    fn backoff_schedule() {
        let secs: Vec<u64> = (0..9).map(|n| backoff(n, 0.0).as_secs()).collect();
        assert_eq!(secs, [5, 10, 20, 40, 80, 160, 320, 600, 600]);
        assert_eq!(backoff(u32::MAX, 0.0), Duration::from_secs(600));
        assert_eq!(backoff(0, 1.0), Duration::from_millis(3750));
        for _ in 0..100 {
            let d = backoff(3, jitter());
            assert!(
                d <= Duration::from_secs(40) && d >= Duration::from_secs(30),
                "{d:?}"
            );
        }
    }

    #[test]
    fn per_host_limit_holds_with_four_streams() {
        let tmp = TempDir::new();
        let data = body(256 << 10, 1);
        let pace = Duration::from_millis(5);
        let a = Server::start(
            "127.0.0.1",
            Behaviour {
                pace,
                ..Behaviour::new(data.clone())
            },
        );
        let b = Server::start(
            "127.0.0.2",
            Behaviour {
                pace,
                ..Behaviour::new(data.clone())
            },
        );
        let fetches: Vec<Fetch> = (0..12)
            .map(|i| Fetch {
                url: if i % 2 == 0 {
                    a.url(&format!("f{i}"))
                } else {
                    b.url(&format!("f{i}"))
                },
                dest: tmp.path().join(format!("f{i}")),
                size: Some(data.len() as u64),
                limit: u64::MAX,
                expect: Expect::None,
            })
            .collect();
        let pool = Pool::new(&fetches);
        let d = dl(0);
        let done = AtomicU64::new(0);
        std::thread::scope(|s| {
            for _ in 0..STREAMS {
                s.spawn(|| pool.work(&d, &done, &|| true));
            }
        });
        assert_eq!(pool.lock().files_done, 12);
        assert_eq!((a.max_active(), b.max_active()), (PER_HOST, PER_HOST));
    }

    struct Rig {
        tmp: TempDir,
        srv: Server,
        data: Vec<u8>,
        store: Store,
        dl: Downloader,
        drive: Box<dyn Fn(&DriveId) -> DriveAt + Sync>,
    }

    impl Rig {
        fn new(len: u64, rate: u64) -> Self {
            let tmp = TempDir::new();
            std::fs::create_dir_all(tmp.path().join("mnt/staging")).unwrap();
            let data = body(len, 42);
            let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
            let store = Store::new(tmp.path().join("queue"));
            let mnt = tmp.path().join("mnt");
            Self {
                tmp,
                srv,
                data,
                store,
                dl: dl(rate),
                drive: Box::new(move |_| {
                    if mnt.exists() {
                        DriveAt::Mounted(mnt.clone())
                    } else {
                        DriveAt::Absent
                    }
                }),
            }
        }

        fn mnt(&self) -> PathBuf {
            self.tmp.path().join("mnt")
        }

        fn job(&self) -> Job {
            self.store
                .create(
                    &JobKind::Set { set: "s".into() },
                    &"ABCD-0123".parse().unwrap(),
                    1,
                )
                .unwrap()
        }

        fn fetch(&self, root: &Path) -> Fetch {
            Fetch {
                url: self.srv.url("big.iso"),
                dest: root.join("staging/big.iso"),
                size: Some(self.data.len() as u64),
                limit: u64::MAX,
                expect: Expect::Sha256(sha2::Sha256::digest(&self.data).into()),
            }
        }

        fn run(&self) {
            self.run_with(Pass::FRESH);
        }

        fn run_with(&self, pass: Pass) {
            let mnt = self.mnt();
            let drive = |_: &DriveId| {
                if mnt.exists() {
                    DriveAt::Mounted(mnt.clone())
                } else {
                    DriveAt::Absent
                }
            };
            self.run_on(pass, &drive);
        }

        fn run_on(&self, pass: Pass, drive: &(dyn Fn(&DriveId) -> DriveAt + Sync)) {
            let plan = |_: &Job, root: &Path, _: &[usize]| Ok(vec![self.fetch(root)].into());
            Worker {
                store: &self.store,
                dl: &self.dl,
                plan: &plan,
                settle: &|_, _, _| {},
                drive,
            }
            .run(pass)
            .unwrap();
        }

        /// Runs the worker on a thread and calls `during` once `at` bytes were served.
        fn run_until(&self, at: u64, during: impl FnOnce()) {
            std::thread::scope(|s| {
                let w = s.spawn(|| self.run());
                while self.srv.served() < at {
                    assert!(!w.is_finished(), "worker ended before {at} bytes");
                    std::thread::sleep(Duration::from_millis(20));
                }
                during();
                w.join().unwrap();
            });
        }

        fn dest(&self) -> PathBuf {
            self.mnt().join("staging/big.iso")
        }
    }

    #[test]
    fn crashed_worker_job_resumes_from_its_checkpoint() {
        let r = Rig::new(4 * CP, 0);
        let mut job = r.job();
        // A worker died mid-transfer: Running in the file, a checkpointed part on the drive.
        r.srv.set(|b| b.die_at = Some(5 * CP / 2));
        let f = r.fetch(&r.mnt());
        assert!(
            r.dl.fetch(&f, &AtomicBool::new(false), &AtomicU64::new(0))
                .is_err()
        );
        job.state = JobState::Running { pid: u32::MAX };
        r.store.save(&mut job).unwrap();
        r.srv.clear_log();

        r.run();
        let job = r.store.job(&job.id).unwrap();
        assert_eq!(job.state, JobState::Done, "{:?}", job.error);
        assert_eq!(job.attempts, 1);
        assert_eq!(std::fs::read(r.dest()).unwrap(), r.data);
        assert_eq!(r.srv.served(), 2 * CP);
    }

    #[test]
    fn pause_then_resume_across_worker_runs() {
        let r = Rig::new(6 * CP, 2 << 20);
        let job = r.job();
        r.run_until(3 * CP / 2, || {
            r.store
                .edit_control(Some(&job.id), |c| c.pause = true)
                .unwrap();
        });
        let j = r.store.job(&job.id).unwrap();
        assert_eq!(j.state, JobState::Paused);
        let side = std::fs::read(r.dest().with_extension("iso.part.json")).unwrap();
        let saved = serde_json::from_slice::<serde_json::Value>(&side).unwrap()["offset"]
            .as_u64()
            .unwrap();
        assert!(saved >= CP && saved < r.data.len() as u64, "{saved}");

        // Paused jobs don't run until resumed.
        r.run();
        assert_eq!(r.store.job(&job.id).unwrap().state, JobState::Paused);

        r.store
            .edit_control(Some(&job.id), |c| c.pause = false)
            .unwrap();
        r.run();
        let j = r.store.job(&job.id).unwrap();
        assert_eq!(j.state, JobState::Done, "{:?}", j.error);
        assert_eq!(j.progress.files_done, 1);
        assert_eq!(std::fs::read(r.dest()).unwrap(), r.data);
        // The resume asked only for what the last checkpoint did not hold.
        let hits = r.srv.hits();
        let want = format!("bytes={saved}-");
        assert_eq!(hits.last().unwrap().range.as_deref(), Some(want.as_str()));
    }

    #[test]
    fn a_job_queued_with_higher_priority_runs_first() {
        let r = Rig::new(6 * CP, 2 << 20);
        let drive: DriveId = "ABCD-0123".parse().unwrap();
        let big = r
            .store
            .create(&JobKind::Set { set: "big".into() }, &drive, 20)
            .unwrap();
        let order = Mutex::new(Vec::new());
        let mnt = r.mnt();
        let plan = |j: &Job, root: &Path, _: &[usize]| {
            let JobKind::Set { set } = &j.kind else {
                unreachable!()
            };
            order.lock().unwrap().push(set.clone());
            Ok(vec![Fetch {
                dest: root.join(format!("staging/{set}.iso")),
                ..r.fetch(root)
            }]
            .into())
        };
        let worker = Worker {
            store: &r.store,
            dl: &r.dl,
            plan: &plan,
            settle: &|_, _, _| {},
            drive: &|_| DriveAt::Mounted(mnt.clone()),
        };
        let mut small = None;
        std::thread::scope(|s| {
            let w = s.spawn(|| worker.run(Pass::TICK).unwrap());
            while r.srv.served() < 3 * CP / 2 {
                assert!(!w.is_finished());
                std::thread::sleep(Duration::from_millis(20));
            }
            small = Some(
                r.store
                    .create(
                        &JobKind::Set {
                            set: "small".into(),
                        },
                        &drive,
                        3,
                    )
                    .unwrap(),
            );
            w.join().unwrap();
        });
        assert_eq!(*order.lock().unwrap(), ["big", "small", "big"]);
        for id in [&big.id, &small.unwrap().id] {
            let j = r.store.job(id).unwrap();
            assert_eq!(j.state, JobState::Done, "{:?}", j.error);
            assert_eq!(j.attempts, 1, "a yield is not an attempt");
        }
        // The yielded job resumed from its checkpoint instead of starting over.
        let resumed = r.srv.hits().iter().filter(|h| h.range.is_some()).count();
        assert!(resumed >= 1, "{:?}", r.srv.hits());
    }

    #[test]
    fn unplugged_drive_blocks_without_counting_an_attempt() {
        let r = Rig::new(6 * CP, 2 << 20);
        let job = r.job();
        let gone = r.tmp.path().join("gone");
        r.run_until(3 * CP / 2, || std::fs::rename(r.mnt(), &gone).unwrap());
        let j = r.store.job(&job.id).unwrap();
        assert_eq!(j.state, JobState::Blocked(BlockReason::DriveAbsent));
        assert_eq!(j.attempts, 0);

        // Replugged: the next run picks the job up and resumes from the drive's sidecar.
        std::fs::rename(&gone, r.mnt()).unwrap();
        r.run();
        let j = r.store.job(&job.id).unwrap();
        assert_eq!(j.state, JobState::Done, "{:?}", j.error);
        assert_eq!(std::fs::read(r.dest()).unwrap(), r.data);
    }

    #[test]
    fn an_unmounted_drive_blocks_without_an_attempt() {
        let r = Rig::new(1000, 0);
        let job = r.job();
        r.run_on(Pass::FRESH, &|_| DriveAt::Unmounted);
        let j = r.store.job(&job.id).unwrap();
        assert_eq!(
            (j.state, j.attempts),
            (JobState::Blocked(BlockReason::Unmounted), 0)
        );
        r.run();
        assert_eq!(r.store.job(&job.id).unwrap().state, JobState::Done);
    }

    #[test]
    fn drive_events_skip_a_job_waiting_for_a_touch() {
        let r = Rig::new(1000, 0);
        let set = |state| {
            let mut j = r.job();
            j.state = state;
            r.store.save(&mut j).unwrap();
            j.id
        };
        let touch = set(JobState::Blocked(BlockReason::NeedsTouch));
        let state = |id: &str| r.store.job(id).unwrap().state;
        let can = |pass| runnable(&r.store, Lane::Download, pass).unwrap();
        let drive_event = Pass {
            retry_blocked: true,
            ..Pass::TICK
        };
        assert!(!can(drive_event) && !can(Pass::FRESH));
        reset(&r.store, Lane::Download, Pass::FRESH).unwrap();
        assert_eq!(state(&touch), JobState::Blocked(BlockReason::NeedsTouch));

        let unmounted = set(JobState::Blocked(BlockReason::Unmounted));
        assert!(can(drive_event));
        r.run_with(drive_event);
        assert_eq!(state(&unmounted), JobState::Done);
        assert_eq!(state(&touch), JobState::Blocked(BlockReason::NeedsTouch));

        r.store
            .edit_control(Some(&touch), |c| c.retry += 1)
            .unwrap();
        assert!(can(Pass::TICK));
        r.run_with(Pass::TICK);
        assert_eq!(state(&touch), JobState::Done);
    }

    #[test]
    fn cancel_removes_the_partials() {
        let r = Rig::new(6 * CP, 2 << 20);
        let job = r.job();
        r.run_until(3 * CP / 2, || {
            r.store
                .edit_control(Some(&job.id), |c| c.cancel = true)
                .unwrap();
        });
        assert_eq!(r.store.job(&job.id).unwrap().state, JobState::Canceled);
        let f = r.fetch(&r.mnt());
        assert!(!f.part().exists() && !f.sidecar().exists() && !f.dest.exists());
    }

    #[test]
    fn a_tick_retries_only_crashed_jobs_and_a_drive_event_only_blocked_ones() {
        let r = Rig::new(1000, 0);
        let set = |state| {
            let mut j = r.job();
            j.state = state;
            r.store.save(&mut j).unwrap();
            j.id
        };
        let failed = set(JobState::Failed);
        let blocked = set(JobState::Blocked(BlockReason::DriveAbsent));
        let crashed = set(JobState::Running { pid: u32::MAX });
        let state = |id: &str| r.store.job(id).unwrap().state;
        let drive_event = Pass {
            retry_blocked: true,
            ..Pass::TICK
        };
        let can = |pass| runnable(&r.store, Lane::Download, pass).unwrap();

        assert!(can(Pass::TICK), "a crashed job wants a pass");
        r.run_with(Pass::TICK);
        assert_eq!(state(&crashed), JobState::Done);
        assert_eq!(state(&failed), JobState::Failed);
        assert_eq!(state(&blocked), JobState::Blocked(BlockReason::DriveAbsent));
        assert!(!can(Pass::TICK), "an idle tick does nothing");

        assert!(can(drive_event));
        r.run_with(drive_event);
        assert_eq!(state(&blocked), JobState::Done);
        assert_eq!(state(&failed), JobState::Failed);
        assert!(!can(drive_event));

        // An explicit retry needs no special pass.
        r.store
            .edit_control(Some(&failed), |c| c.retry += 1)
            .unwrap();
        assert!(can(Pass::TICK));
        r.run_with(Pass::TICK);
        assert_eq!(state(&failed), JobState::Done);
        assert!(!can(Pass::FRESH), "only finished jobs are left");
    }

    #[test]
    fn controls_decide_whether_a_pass_is_needed() {
        let r = Rig::new(1000, 0);
        let can = || runnable(&r.store, Lane::Download, Pass::TICK).unwrap();
        assert!(!can(), "empty queue");
        let job = r.job();
        assert!(can(), "queued");
        r.store.edit_control(None, |c| c.pause = true).unwrap();
        assert!(!can(), "queue paused");
        r.store
            .edit_control(Some(&job.id), |c| c.cancel = true)
            .unwrap();
        assert!(can(), "a cancel is applied even while paused");
        r.run();
        assert_eq!(r.store.job(&job.id).unwrap().state, JobState::Canceled);
        assert!(!can(), "canceled");

        r.store.edit_control(None, |c| c.pause = false).unwrap();
        let mut job = r.job();
        job.state = JobState::Paused;
        r.store.save(&mut job).unwrap();
        r.store
            .edit_control(Some(&job.id), |c| c.pause = true)
            .unwrap();
        assert!(!can(), "paused job");
        r.store
            .edit_control(Some(&job.id), |c| c.pause = false)
            .unwrap();
        assert!(can(), "resumed job");
    }

    #[test]
    fn permanent_error_fails_the_job_and_retry_requeues_it() {
        let r = Rig::new(1000, 0);
        let job = r.job();
        r.srv.set(|b| b.status = Some(404));
        r.run();
        let j = r.store.job(&job.id).unwrap();
        assert_eq!(j.state, JobState::Failed);
        assert!(
            j.error.as_deref().unwrap_or_default().contains("HTTP 404"),
            "{:?}",
            j.error
        );

        r.srv.set(|b| b.status = None);
        r.store
            .edit_control(Some(&job.id), |c| c.retry += 1)
            .unwrap();
        r.run();
        let j = r.store.job(&job.id).unwrap();
        assert_eq!((j.state, j.attempts), (JobState::Done, 1));
    }
    fn run_plan<'a>(r: &'a Rig, plan: &'a Planner<'a>) {
        run_settle(r, plan, &|_, _, _| {});
    }

    fn run_settle<'a>(
        r: &'a Rig,
        plan: &'a Planner<'a>,
        settle: &'a (dyn Fn(&mut Job, &Path, &[usize]) + Sync),
    ) {
        Worker {
            store: &r.store,
            dl: &r.dl,
            plan,
            settle,
            drive: &*r.drive,
        }
        .run(Pass::FRESH)
        .unwrap();
    }

    #[test]
    fn batches_run_until_the_planner_stops_asking() {
        let r = Rig::new(1000, 0);
        let job = r.job();
        let calls = Mutex::new(Vec::new());
        let plan = |_: &Job, root: &Path, ok: &[usize]| {
            let mut c = calls.lock().unwrap();
            c.push(ok.to_vec());
            let n = c.len();
            let fetches = (0..n)
                .map(|i| Fetch {
                    dest: root.join(format!("staging/f{n}-{i}")),
                    ..r.fetch(root)
                })
                .collect();
            Ok(Work::Fetch(Planned {
                fetches,
                more: n < 3,
                whole: Some(Whole {
                    files: 6,
                    bytes: 6000,
                    files_done: (n * (n - 1) / 2) as u64,
                    bytes_done: 1000 * (n * (n - 1) / 2) as u64,
                }),
            }))
        };
        let settled = Mutex::new(Vec::new());
        run_settle(&r, &plan, &|_, _, ok| {
            settled.lock().unwrap().push(ok.to_vec());
        });
        let j = r.store.job(&job.id).unwrap();
        assert_eq!(j.state, JobState::Done, "{:?}", j.error);
        assert_eq!(*calls.lock().unwrap(), [vec![], vec![0], vec![0, 1]]);
        assert_eq!(*settled.lock().unwrap(), [vec![0, 1, 2]]);
        assert_eq!((j.progress.files_done, j.progress.files_total), (6, 6));
        assert_eq!(j.attempts, 1);
    }

    #[test]
    fn an_empty_batch_that_wants_more_fails_the_job() {
        let r = Rig::new(1000, 0);
        let job = r.job();
        run_plan(&r, &|_, _, _| {
            Ok(Work::Fetch(Planned {
                more: true,
                ..Planned::default()
            }))
        });
        let j = r.store.job(&job.id).unwrap();
        assert_eq!(j.state, JobState::Failed);
        assert_eq!(j.error.as_deref(), Some("planner returned an empty batch"));
    }

    #[test]
    fn a_failed_batch_stops_the_job_before_the_next_plan() {
        let r = Rig::new(1000, 0);
        let job = r.job();
        r.srv.set(|b| b.status = Some(404));
        let calls = Mutex::new(0);
        run_plan(&r, &|_, root, _| {
            *calls.lock().unwrap() += 1;
            Ok(Work::Fetch(Planned {
                fetches: vec![r.fetch(root)],
                more: true,
                whole: None,
            }))
        });
        assert_eq!(r.store.job(&job.id).unwrap().state, JobState::Failed);
        assert_eq!(*calls.lock().unwrap(), 1);
    }

    #[test]
    fn a_closure_job_ends_done_or_failed() {
        let r = Rig::new(1000, 0);
        let job = r.job();
        run_plan(&r, &|_, _, _| {
            Ok(Work::Run(Box::new(|_, done| {
                done.store(77, Ordering::Relaxed);
                Ok(())
            })))
        });
        let j = r.store.job(&job.id).unwrap();
        assert_eq!((j.state, j.progress.bytes_done), (JobState::Done, 77));

        let job = r.job();
        run_plan(&r, &|_, _, _| {
            Ok(Work::Run(Box::new(|_, _| Err(anyhow!("git said no")))))
        });
        let j = r.store.job(&job.id).unwrap();
        assert_eq!(j.state, JobState::Failed);
        assert_eq!(j.error.as_deref(), Some("git said no"));
    }

    #[test]
    fn a_closure_job_stops_on_cancel_and_pause() {
        for cancel in [true, false] {
            let r = Rig::new(1000, 0);
            let job = r.job();
            let plan = |_: &Job, _: &Path, _: &[usize]| {
                Ok(Work::Run(Box::new(
                    |stop: &AtomicBool, _: &Arc<AtomicU64>| {
                        while !stop.load(Ordering::Relaxed) {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        Err(anyhow!("stopped"))
                    },
                )))
            };
            std::thread::scope(|s| {
                s.spawn(|| {
                    std::thread::sleep(Duration::from_millis(300));
                    r.store
                        .edit_control(Some(&job.id), |c| {
                            c.cancel = cancel;
                            c.pause = !cancel;
                        })
                        .unwrap();
                });
                run_plan(&r, &plan);
            });
            let want = if cancel {
                JobState::Canceled
            } else {
                JobState::Paused
            };
            assert_eq!(r.store.job(&job.id).unwrap().state, want, "cancel={cancel}");
        }
    }

    #[test]
    fn a_closure_job_with_the_drive_gone_blocks_without_an_attempt() {
        let r = Rig::new(1000, 0);
        let job = r.job();
        let gone = r.tmp.path().join("gone");
        run_plan(&r, &|_, _, _| {
            Ok(Work::Run(Box::new(|_, _| {
                std::fs::rename(r.mnt(), &gone).unwrap();
                Err(anyhow!("write failed"))
            })))
        });
        let j = r.store.job(&job.id).unwrap();
        assert_eq!(
            (j.state, j.attempts),
            (JobState::Blocked(BlockReason::DriveAbsent), 0)
        );
    }

    #[test]
    fn a_halt_between_batches_stops_without_planning_again() {
        for cancel in [true, false] {
            let r = Rig::new(1000, 0);
            let job = r.job();
            let calls = Mutex::new(0);
            let plan = |_: &Job, root: &Path, _: &[usize]| {
                *calls.lock().unwrap() += 1;
                r.store
                    .edit_control(Some(&job.id), |c| {
                        c.cancel = cancel;
                        c.pause = !cancel;
                    })
                    .unwrap();
                Ok(Work::Fetch(Planned {
                    fetches: vec![r.fetch(root)],
                    more: true,
                    whole: None,
                }))
            };
            run_plan(&r, &plan);
            let want = if cancel {
                JobState::Canceled
            } else {
                JobState::Paused
            };
            assert_eq!(r.store.job(&job.id).unwrap().state, want, "cancel={cancel}");
            assert_eq!(*calls.lock().unwrap(), 1, "cancel={cancel}");
        }
    }

    #[test]
    fn a_drive_gone_between_batches_blocks_without_an_attempt() {
        let r = Rig::new(1000, 0);
        let job = r.job();
        let gone = r.tmp.path().join("gone");
        let calls = Mutex::new(0);
        run_plan(&r, &|_, root, _| {
            let mut n = calls.lock().unwrap();
            *n += 1;
            if *n == 2 {
                std::fs::rename(r.mnt(), &gone).unwrap();
                return Err(anyhow!("read failed"));
            }
            Ok(Work::Fetch(Planned {
                fetches: vec![r.fetch(root)],
                more: true,
                whole: None,
            }))
        });
        let j = r.store.job(&job.id).unwrap();
        assert_eq!(
            (j.state, j.attempts),
            (JobState::Blocked(BlockReason::DriveAbsent), 0)
        );
    }

    #[test]
    fn a_running_closure_job_is_not_outranked() {
        let r = Rig::new(1000, 0);
        let job = r.job();
        let mut urgent = r.job();
        urgent.priority = 0;
        urgent.state = JobState::Paused;
        r.store.save(&mut urgent).unwrap();
        let plan = |j: &Job, _: &Path, _: &[usize]| {
            let first = j.id == job.id;
            let (store, urgent_id) = (&r.store, urgent.id.clone());
            Ok(Work::Run(Box::new(
                move |_: &AtomicBool, _: &Arc<AtomicU64>| {
                    if first {
                        store
                            .edit_control(Some(&urgent_id), |c| c.pause = false)
                            .unwrap();
                        std::thread::sleep(Duration::from_millis(2500));
                    }
                    Ok(())
                },
            )))
        };
        run_plan(&r, &plan);
        let j = r.store.job(&job.id).unwrap();
        assert_eq!((j.state, j.attempts), (JobState::Done, 1));
        assert_eq!(r.store.job(&urgent.id).unwrap().state, JobState::Done);
    }

    #[test]
    fn a_paused_closure_job_runs_to_done_once_resumed() {
        let r = Rig::new(1000, 0);
        let job = r.job();
        let runs = Mutex::new(0);
        let plan = |_: &Job, _: &Path, _: &[usize]| {
            let first = {
                let mut n = runs.lock().unwrap();
                *n += 1;
                *n == 1
            };
            Ok(Work::Run(Box::new(
                move |stop: &AtomicBool, _: &Arc<AtomicU64>| {
                    if !first {
                        return Ok(());
                    }
                    while !stop.load(Ordering::Relaxed) {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(anyhow!("stopped"))
                },
            )))
        };
        std::thread::scope(|s| {
            s.spawn(|| {
                std::thread::sleep(Duration::from_millis(300));
                r.store
                    .edit_control(Some(&job.id), |c| c.pause = true)
                    .unwrap();
            });
            run_plan(&r, &plan);
        });
        assert_eq!(r.store.job(&job.id).unwrap().state, JobState::Paused);
        r.store
            .edit_control(Some(&job.id), |c| c.pause = false)
            .unwrap();
        run_plan(&r, &plan);
        let j = r.store.job(&job.id).unwrap();
        assert_eq!(j.state, JobState::Done, "{:?}", j.error);
        assert_eq!(*runs.lock().unwrap(), 2);
    }
}
