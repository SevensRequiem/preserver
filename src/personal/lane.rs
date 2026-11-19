//! The personal lane: GitHub and local-folder jobs, one at a time, under
//! `preserver-personal-queue.lock`, then `github`/`local` (`status::job`), so the status files
//! keep their meaning.

use super::{Hooks, Stopped, github, local};
use crate::config::{Config, DriveId, Transport};
use crate::paths::Paths;
use crate::platform::{self, DriveAt, TouchMissing};
use crate::queue::{
    BlockReason, Halt, Job, JobKind, JobState, Lane, Pass, Progress, Store, apply_control,
    halt_requested, reset, runnable,
};
use crate::status;
use anyhow::{Result, anyhow};
use jiff::Timestamp;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

/// Everything the lane needs from the OS, so tests can stand in for the drive and session.
pub(crate) struct Env<'a> {
    pub drive: &'a (dyn Fn(&DriveId) -> DriveAt + Sync),
    /// The graphical session's display and agent, for ssh and its askpass.
    pub session: &'a (dyn Fn() -> Vec<(String, String)> + Sync),
    /// A foreground CLI run: a person is at the terminal, so no session is needed to prompt.
    pub interactive: bool,
    pub say: &'a (dyn Fn(&str) + Sync),
}

pub(crate) fn real_env<T>(
    interactive: bool,
    say: &(dyn Fn(&str) + Sync),
    f: impl FnOnce(&Env) -> T,
) -> T {
    // A foreground run inherits the terminal's session as it is.
    let session = || {
        if interactive {
            Vec::new()
        } else {
            platform::session_env()
        }
    };
    f(&Env {
        drive: &platform::locate,
        session: &session,
        interactive,
        say,
    })
}

pub(crate) fn label(kind: &JobKind) -> &'static str {
    match kind {
        JobKind::Local => "local folders",
        JobKind::Github { .. } => "GitHub",
        JobKind::Set { .. } | JobKind::Mirror { .. } | JobKind::Copy { .. } => "job",
    }
}

/// One pass of the daemon's personal lane; quiet when a CLI run holds the lane or nothing is
/// runnable.
pub(crate) fn daemon_pass(paths: &Paths, pass: Pass) -> Result<()> {
    let Some(_lock) = status::try_lock(&paths.lock_file("personal-queue"))? else {
        return Ok(());
    };
    let store = Store::new(paths.queue.clone());
    if !runnable(&store, Lane::Personal, pass)? {
        return Ok(());
    }
    let start = Timestamp::now();
    real_env(false, &|s| tracing::info!("{}", s.trim_end()), |e| {
        work(paths, &store, e, pass)
    })?;
    record(paths, &store, start)
}

/// `preserver personal` in this process, under the lane lock the caller holds: runs the lane
/// and reports what became of the jobs in `ids`. Failing and a key nobody touched are errors.
pub(crate) fn foreground(paths: &Paths, ids: &[String]) -> Result<()> {
    let store = Store::new(paths.queue.clone());
    let start = Timestamp::now();
    real_env(true, &|s| print!("{s}"), |e| {
        work(paths, &store, e, Pass::FRESH)
    })?;
    let mut errs = Vec::new();
    for id in ids {
        let job = store.job(id)?;
        let what = label(&job.kind);
        match job.state {
            JobState::Done => println!("{what}: done"),
            JobState::Failed | JobState::Blocked(BlockReason::NeedsTouch) => errs.push(format!(
                "{what}: {}",
                job.error.unwrap_or_else(|| job.state.to_string())
            )),
            s => println!("{what}: {s} (job {id})"),
        }
    }
    record(paths, &store, start)?;
    if errs.is_empty() {
        return Ok(());
    }
    anyhow::bail!(errs.join("; "))
}

/// Runs queued personal jobs until none is runnable. The caller holds the `personal-queue`
/// lock, so a job left Running is a crashed worker's.
pub(crate) fn work(paths: &Paths, store: &Store, env: &Env, pass: Pass) -> Result<()> {
    reset(store, Lane::Personal, pass)?;
    loop {
        let paused = store.control(None).pause;
        let mut jobs: Vec<Job> = store
            .jobs()?
            .into_iter()
            .filter(|j| j.kind.lane() == Lane::Personal)
            .collect();
        for job in &mut jobs {
            if apply_control(store, job) {
                store.save(job)?;
            }
        }
        jobs.sort_by(|a, b| (a.priority, a.created, &a.id).cmp(&(b.priority, b.created, &b.id)));
        match jobs.into_iter().find(|j| j.state == JobState::Queued) {
            Some(job) if !paused => run_job(paths, store, env, job)?,
            _ => return Ok(()),
        }
    }
}

fn blocked(at: &DriveAt) -> Option<BlockReason> {
    match at {
        DriveAt::Mounted(r) if r.exists() => None,
        DriveAt::Unmounted => Some(BlockReason::Unmounted),
        _ => Some(BlockReason::DriveAbsent),
    }
}

/// Runs one job on a thread while this one applies pause and cancel and saves progress. A
/// missing drive or an unanswered key prompt blocks the job without counting an attempt.
fn run_job(paths: &Paths, store: &Store, env: &Env, mut job: Job) -> Result<()> {
    let cfg = match Config::load(&paths.cfg) {
        Ok(c) => c,
        Err(e) => {
            job.state = JobState::Failed;
            job.error = Some(format!("{e:#}"));
            return store.save(&mut job);
        }
    };
    let at = (env.drive)(&job.drive);
    if let Some(r) = blocked(&at) {
        job.state = JobState::Blocked(r);
        return store.save(&mut job);
    }
    let mut paths = paths.clone();
    if let DriveAt::Mounted(root) = at {
        paths.mnt = root;
    }
    let transport = match job.kind {
        JobKind::Github { transport } => Some(transport.unwrap_or(cfg.transport)),
        _ => None,
    };
    let session = if transport.is_some() {
        (env.session)()
    } else {
        Vec::new()
    };
    let can_prompt = env.interactive
        || session
            .iter()
            .any(|(k, _)| k == "DISPLAY" || k == "WAYLAND_DISPLAY");
    if transport == Some(Transport::Ssh) && !can_prompt {
        job.state = JobState::Blocked(BlockReason::NeedsTouch);
        job.error = Some("no graphical session to ask for the security key".into());
        return store.save(&mut job);
    }

    job.state = JobState::Running {
        pid: std::process::id(),
    };
    job.attempts += 1;
    job.error = None;
    job.progress = Progress::default();
    store.save(&mut job)?;

    let progress = Mutex::new(Progress::default());
    let stop = AtomicBool::new(false);
    let mut halt = None;
    let on_item = |n: usize, m: usize, what: &str| {
        if env.interactive {
            (env.say)(&format!("[{}/{m}] {what}\n", n + 1));
        }
        let mut p = progress.lock().unwrap_or_else(PoisonError::into_inner);
        p.files_done = n as u64;
        p.files_total = m as u64;
        p.current = vec![what.to_string()];
    };
    // Relaxed: the run only has to see it soon; nothing else rides on the flag.
    let stopped = || stop.load(Ordering::Relaxed);
    let hooks = Hooks {
        on_item: &on_item,
        stop: &stopped,
    };
    let name = if transport.is_some() {
        "github"
    } else {
        "local"
    };
    let result = std::thread::scope(|s| {
        let (tx, rx) = mpsc::channel::<()>();
        let worker = s.spawn(|| {
            let r = status::job(&mut paths, name, |p| match transport {
                Some(t) => github::run(p, &cfg, t, &session, &hooks),
                None => local::run(p, &cfg, &hooks),
            });
            drop(tx);
            r
        });
        while let Err(RecvTimeoutError::Timeout) = rx.recv_timeout(Duration::from_secs(1)) {
            if let Some(h) = halt_requested(store, &job.id) {
                halt = Some(h);
                stop.store(true, Ordering::Relaxed);
            }
            let mut j = job.clone();
            j.progress = progress
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            if let Err(e) = store.save(&mut j) {
                tracing::warn!("progress: {e:#}");
            }
        }
        worker.join()
    });
    let result = result.unwrap_or_else(|_| Err(anyhow!("the backup thread panicked")));
    job.progress = progress
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner);
    job.progress.current.clear();
    job.state = outcome(&mut job, result, halt, env);
    store.save(&mut job)
}

/// What a finished run makes of its job. Neither an unanswered key prompt nor an unplugged
/// drive counts as an attempt.
fn outcome(job: &mut Job, result: Result<()>, halt: Option<Halt>, env: &Env) -> JobState {
    match result {
        Ok(()) => {
            job.progress.files_done = job.progress.files_total;
            JobState::Done
        }
        // A stop while the key prompt was open ends ssh too.
        Err(e) if e.is::<Stopped>() || (halt.is_some() && e.is::<TouchMissing>()) => {
            if halt == Some(Halt::Cancel) {
                JobState::Canceled
            } else {
                JobState::Paused
            }
        }
        Err(e) => {
            job.error = Some(format!("{e:#}"));
            let gone = blocked(&(env.drive)(&job.drive));
            if e.is::<TouchMissing>() {
                job.attempts -= 1;
                JobState::Blocked(BlockReason::NeedsTouch)
            } else if let Some(r) = gone {
                // Unplugging is not the job's fault.
                job.attempts -= 1;
                JobState::Blocked(r)
            } else {
                JobState::Failed
            }
        }
    }
}

/// After a pass: notifies about the jobs that failed since `start` and forgets finished ones.
/// The outcome stays in `status/github.json` and `status/local.json`. A canceled job counts
/// as a run there, so the schedule does not queue again the occurrence a person dismissed.
pub(crate) fn record(paths: &Paths, store: &Store, start: Timestamp) -> Result<()> {
    let mut errs = Vec::new();
    for j in store.jobs()? {
        if j.kind.lane() != Lane::Personal {
            continue;
        }
        match j.state {
            JobState::Done => store.remove(&j.id)?,
            JobState::Canceled => {
                let name = if j.kind == JobKind::Local {
                    "local"
                } else {
                    "github"
                };
                let file = paths.status_file(name);
                let mut st = status::Status::read(&file);
                st.last_run = Some(Timestamp::now());
                st.write(&file)?;
                store.remove(&j.id)?;
            }
            JobState::Failed if j.updated >= start => errs.push(format!(
                "{}: {}",
                label(&j.kind),
                j.error.as_deref().unwrap_or_default()
            )),
            _ => {}
        }
    }
    if !errs.is_empty() {
        platform::notify(true, "Personal backup failed", &errs.join("; "));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, paths};

    const DRIVE: &str = "0123-ABCD";

    struct Rig {
        _tmp: TempDir,
        paths: Paths,
        store: Store,
    }

    impl Rig {
        fn new() -> Self {
            let tmp = TempDir::new();
            let paths = paths(tmp.path());
            for name in ["a", "b"] {
                let dir = tmp.path().join("data").join(name);
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::write(dir.join("f.txt"), name).unwrap();
            }
            let cfg = format!(
                "owners = [\"o\"]\nprimary_uuid = \"{DRIVE}\"\n\
                 [[local]]\nname = \"a\"\npath = \"{0}/data/a\"\n\
                 [[local]]\nname = \"b\"\npath = \"{0}/data/b\"\n",
                tmp.path().display()
            );
            platform::write_private(&paths.cfg.join("config.toml"), cfg.as_bytes()).unwrap();
            let recipient = age::x25519::Identity::generate().to_public().to_string();
            platform::write_private(
                &paths.personal.join("recipient.txt"),
                format!("{recipient}\n").as_bytes(),
            )
            .unwrap();
            Self {
                store: Store::new(paths.queue.clone()),
                _tmp: tmp,
                paths,
            }
        }

        fn job(&self, kind: &JobKind) -> String {
            self.store
                .enqueue(kind, &DRIVE.parse().unwrap(), 0, true)
                .unwrap()
        }

        fn run(&self, at: DriveAt, session: &[(&str, &str)], interactive: bool) {
            let session = || {
                session
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect()
            };
            let env = Env {
                drive: &move |_| at.clone(),
                session: &session,
                interactive,
                say: &|_| {},
            };
            work(&self.paths, &self.store, &env, Pass::FRESH).unwrap();
        }

        fn mounted(&self) -> DriveAt {
            DriveAt::Mounted(self.paths.mnt.clone())
        }
    }

    #[test]
    fn a_local_job_backs_up_every_folder_and_is_forgotten() {
        let r = Rig::new();
        let id = r.job(&JobKind::Local);
        let start = Timestamp::now();
        r.run(r.mounted(), &[], false);
        let j = r.store.job(&id).unwrap();
        assert_eq!(j.state, JobState::Done, "{:?}", j.error);
        assert_eq!((j.progress.files_done, j.progress.files_total), (2, 2));
        assert_eq!(j.attempts, 1);
        let st = status::Status::read(&r.paths.status_file("local"));
        assert!(st.last_ok.is_some() && !st.running, "{st:?}");
        for name in ["a", "b"] {
            assert!(
                r.paths
                    .mnt
                    .join("preserver/local-personal")
                    .join(name)
                    .is_dir()
            );
        }
        record(&r.paths, &r.store, start).unwrap();
        assert!(r.store.job(&id).is_err(), "done jobs are removed");
    }

    #[test]
    fn a_missing_drive_blocks_without_an_attempt() {
        let r = Rig::new();
        let id = r.job(&JobKind::Local);
        for (at, why) in [
            (DriveAt::Absent, BlockReason::DriveAbsent),
            (DriveAt::Unmounted, BlockReason::Unmounted),
        ] {
            r.run(at, &[], false);
            let j = r.store.job(&id).unwrap();
            assert_eq!((j.state, j.attempts), (JobState::Blocked(why), 0));
        }
        assert!(!r.paths.status_file("local").exists(), "nothing ran");
    }

    #[test]
    fn ssh_without_a_session_waits_for_a_touch_and_runs_nothing() {
        let r = Rig::new();
        let id = r.job(&JobKind::Github {
            transport: Some(Transport::Ssh),
        });
        r.run(r.mounted(), &[("SSH_AUTH_SOCK", "/x")], false);
        let j = r.store.job(&id).unwrap();
        assert_eq!(
            (j.state, j.attempts),
            (JobState::Blocked(BlockReason::NeedsTouch), 0)
        );
        assert!(j.error.unwrap().contains("graphical session"));
        assert!(!r.paths.status_file("github").exists(), "nothing ran");
        r.run(r.mounted(), &[], false);
        assert_eq!(
            r.store.job(&id).unwrap().state,
            JobState::Blocked(BlockReason::NeedsTouch),
            "a fresh pass does not ask again by itself"
        );
    }

    #[test]
    fn cancel_while_queued() {
        let r = Rig::new();
        let id = r.job(&JobKind::Local);
        r.store
            .edit_control(Some(&id), |c| c.cancel = true)
            .unwrap();
        r.run(r.mounted(), &[], false);
        assert_eq!(r.store.job(&id).unwrap().state, JobState::Canceled);
        assert!(!r.paths.status_file("local").exists());
        let before = Timestamp::now();
        record(&r.paths, &r.store, before).unwrap();
        assert!(r.store.job(&id).is_err(), "canceled jobs are removed");
        let st = status::Status::read(&r.paths.status_file("local"));
        assert!(
            st.last_run.is_some_and(|t| t >= before) && st.last_ok.is_none(),
            "the dismissed run counts for the schedule: {st:?}"
        );
    }
}
