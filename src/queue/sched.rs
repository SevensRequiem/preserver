//! The worker: one job at a time, its files over `STREAMS` threads with at most `PER_HOST` per
//! host, per-file retries with backoff, and the controls applied while it runs.

use super::job::{BlockReason, Job, JobState, Progress};
use super::store::Store;
use crate::config::DriveId;
use crate::net::download::{Downloader, Fail, Fetch, STREAMS};
use anyhow::Result;
use std::collections::{BTreeSet, HashMap};
use std::hash::BuildHasher;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

pub(crate) const PER_HOST: usize = 2;
/// Tries per file per run; after that the job is Failed and the next run retries it.
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
            Ok(()) => st.files_done += 1,
            Err(Fail::Stopped) => {}
            Err(_) if gone => {
                st.drive_gone = true;
                self.halt();
            }
            Err(Fail::Permanent(msg)) => st.failed.push(msg),
            Err(e @ (Fail::Retry { .. } | Fail::Disk(_))) => {
                st.tries[i] += 1;
                if st.tries[i] >= TRIES {
                    st.failed.push(format!("{e} ({TRIES} tries)"));
                } else {
                    let now = Instant::now();
                    if let Fail::Retry { after: Some(a), .. } = &e {
                        st.host_until.insert(h.clone(), now + *a);
                    }
                    tracing::info!("{e}; retrying");
                    let at = now + backoff(st.tries[i] - 1, jitter());
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Halt {
    Pause,
    Cancel,
}

pub(crate) struct Worker<'a> {
    pub store: &'a Store,
    pub dl: &'a Downloader,
    /// The job's files, given the root of its mounted drive.
    pub plan: &'a (dyn Fn(&Job, &Path) -> Result<Vec<Fetch>> + Sync),
    /// Called with the job's outcome before it is saved, whenever a job stops. It finishes
    /// what the downloads were for, and may turn a Done job into a Failed one.
    pub settle: &'a (dyn Fn(&mut Job, &Path) + Sync),
    /// The drive's mount point, or `None` when it is not connected.
    pub drive: &'a (dyn Fn(&DriveId) -> Option<PathBuf> + Sync),
}

impl Worker<'_> {
    /// Runs queued jobs until none is runnable. The caller holds the queue lock, so a job left
    /// Running is a crashed worker's; Blocked and Failed jobs get one more try per run.
    pub(crate) fn run(&self) -> Result<()> {
        for mut job in self.store.jobs()? {
            if matches!(
                job.state,
                JobState::Running { .. } | JobState::Blocked(_) | JobState::Failed
            ) {
                job.state = JobState::Queued;
                self.store.save(&mut job)?;
            }
        }
        loop {
            let paused = self.store.control(None).pause;
            let mut jobs = self.store.jobs()?;
            for job in &mut jobs {
                if self.apply(job) {
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

    /// Applies the job's control to an idle job; true when something changed.
    fn apply(&self, job: &mut Job) -> bool {
        if matches!(job.state, JobState::Done | JobState::Canceled) {
            return false;
        }
        let c = self.store.control(Some(&job.id));
        let before = (job.state, job.priority, job.retry_seen);
        if let Some(p) = c.priority {
            job.priority = p;
        }
        if c.retry > job.retry_seen {
            job.retry_seen = c.retry;
            job.attempts = 0;
            if job.state == JobState::Failed {
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

    fn run_job(&self, mut job: Job) -> Result<()> {
        let Some(root) = (self.drive)(&job.drive) else {
            job.state = JobState::Blocked(BlockReason::DriveAbsent);
            return self.store.save(&mut job);
        };
        let fetches = match (self.plan)(&job, &root) {
            Ok(f) => f,
            Err(e) => {
                job.state = JobState::Failed;
                job.error = Some(format!("{e:#}"));
                (self.settle)(&mut job, &root);
                return self.store.save(&mut job);
            }
        };
        job.state = JobState::Running {
            pid: std::process::id(),
        };
        job.attempts += 1;
        job.error = None;
        job.progress = Progress {
            files_total: fetches.len() as u64,
            bytes_total: fetches.iter().filter_map(|f| f.size).sum(),
            ..Progress::default()
        };
        self.store.save(&mut job)?;

        let pool = Pool::new(&fetches);
        let done = AtomicU64::new(0);
        let drive_ok = || (self.drive)(&job.drive).is_some_and(|r| r.exists());
        let mut halt = None;
        std::thread::scope(|s| {
            for _ in 0..STREAMS {
                s.spawn(|| pool.work(self.dl, &done, &drive_ok));
            }
            let mut last = (Instant::now(), 0);
            while !pool.wait(Duration::from_secs(1)) {
                let c = self.store.control(Some(&job.id));
                if c.cancel {
                    halt = Some(Halt::Cancel);
                } else if c.pause || self.store.control(None).pause {
                    halt = Some(Halt::Pause);
                }
                if halt.is_some() {
                    pool.halt();
                }
                let bytes = done.load(Ordering::Relaxed);
                let secs = last.0.elapsed().as_secs_f64();
                #[expect(
                    clippy::cast_possible_truncation,
                    clippy::cast_sign_loss,
                    clippy::cast_precision_loss,
                    reason = "a displayed rate"
                )]
                let rate = (bytes.saturating_sub(last.1) as f64 / secs) as u64;
                last = (Instant::now(), bytes);
                let st = pool.lock();
                let mut j = job.clone();
                j.progress.bytes_done = bytes;
                j.progress.rate_bps = rate;
                j.progress.files_done = st.files_done;
                j.progress.current = st.current.iter().map(|i| fetches[*i].url.clone()).collect();
                drop(st);
                if let Err(e) = self.store.save(&mut j) {
                    tracing::warn!("progress: {e:#}");
                }
            }
        });

        let st = pool.st.into_inner().unwrap_or_else(PoisonError::into_inner);
        job.progress.bytes_done = done.load(Ordering::Relaxed);
        job.progress.files_done = st.files_done;
        job.progress.rate_bps = 0;
        job.progress.current.clear();
        job.state = if st.drive_gone {
            // Unplugging is not the job's fault.
            job.attempts -= 1;
            JobState::Blocked(BlockReason::DriveAbsent)
        } else if st.files_done == fetches.len() as u64 {
            JobState::Done
        } else if halt == Some(Halt::Cancel) {
            for f in &fetches {
                for p in [f.part(), f.sidecar()] {
                    let _ = std::fs::remove_file(p);
                }
            }
            JobState::Canceled
        } else if halt == Some(Halt::Pause) {
            JobState::Paused
        } else {
            let n = st.failed.len();
            let mut msg = st.failed.into_iter().take(3).collect::<Vec<_>>().join("; ");
            if n > 3 {
                msg = format!("{msg} (and {} more)", n - 3);
            }
            job.error = Some(msg);
            JobState::Failed
        };
        (self.settle)(&mut job, &root);
        self.store.save(&mut job)
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
    }

    impl Rig {
        fn new(len: u64, rate: u64) -> Self {
            let tmp = TempDir::new();
            std::fs::create_dir_all(tmp.path().join("mnt/staging")).unwrap();
            let data = body(len, 42);
            let srv = Server::start("127.0.0.1", Behaviour::new(data.clone()));
            let store = Store::new(tmp.path().join("queue"));
            Self {
                tmp,
                srv,
                data,
                store,
                dl: dl(rate),
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
                expect: Expect::Sha256(sha2::Sha256::digest(&self.data).into()),
            }
        }

        fn run(&self) {
            let mnt = self.mnt();
            let plan = |_: &Job, root: &Path| Ok(vec![self.fetch(root)]);
            let drive = |_: &DriveId| Some(mnt.clone()).filter(|m| m.exists());
            Worker {
                store: &self.store,
                dl: &self.dl,
                plan: &plan,
                settle: &|_, _| {},
                drive: &drive,
            }
            .run()
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
        assert!(r.dest().with_extension("iso.part.json").exists());
        let served = r.srv.served();
        assert!(served < r.data.len() as u64);

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
        // At most the unfinished segment was fetched twice.
        assert!(
            r.srv.served() <= r.data.len() as u64 + CP,
            "{}",
            r.srv.served()
        );
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
}
