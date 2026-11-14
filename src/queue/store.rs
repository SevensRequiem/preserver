use super::job::{Control, Job, JobKind, JobState, Progress, valid_id};
use crate::config::DriveId;
use crate::platform;
use anyhow::{Context, Result, bail};
use jiff::Timestamp;
use std::io::{self, Write};
use std::path::PathBuf;

/// The queue directory: `<id>.json` per job, `<id>.ctl` per control, `all.ctl` for all jobs.
pub(crate) struct Store {
    dir: PathBuf,
}

impl Store {
    pub(crate) fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn file(&self, id: &str, ext: &str) -> Result<PathBuf> {
        if !valid_id(id) {
            bail!("bad job id {id:?}");
        }
        Ok(self.dir.join(format!("{id}.{ext}")))
    }

    /// Every readable job, in run order: priority, then age. A file another process is still
    /// creating (empty or partial) is skipped until the next scan.
    pub(crate) fn jobs(&self) -> Result<Vec<Job>> {
        let entries = match std::fs::read_dir(&self.dir) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            r => r.with_context(|| self.dir.display().to_string())?,
        };
        let mut jobs = Vec::new();
        for e in entries {
            let path = e?.path();
            let id_ok = path
                .file_stem()
                .and_then(|s| s.to_str())
                .is_some_and(valid_id);
            if !id_ok || path.extension().is_none_or(|x| x != "json") {
                continue;
            }
            match std::fs::read(&path).map(|b| serde_json::from_slice::<Job>(&b)) {
                Ok(Ok(j)) => jobs.push(j),
                Ok(Err(e)) => tracing::debug!("{}: {e}", path.display()),
                Err(e) => tracing::debug!("{}: {e}", path.display()),
            }
        }
        jobs.sort_by(|a, b| (a.priority, a.created, &a.id).cmp(&(b.priority, b.created, &b.id)));
        Ok(jobs)
    }

    pub(crate) fn job(&self, id: &str) -> Result<Job> {
        let file = self.file(id, "json")?;
        let b = std::fs::read(&file).with_context(|| format!("no job {id}"))?;
        serde_json::from_slice(&b).with_context(|| file.display().to_string())
    }

    /// Worker only.
    pub(crate) fn save(&self, job: &mut Job) -> Result<()> {
        job.updated = Timestamp::now();
        let file = self.file(&job.id, "json")?;
        platform::write_private(&file, &serde_json::to_vec_pretty(job)?)
            .with_context(|| file.display().to_string())
    }

    /// Adds a queued job. Anyone may: the file is created exclusively, under a fresh id.
    pub(crate) fn create(&self, kind: &JobKind, drive: &DriveId, priority: u32) -> Result<Job> {
        platform::private_dir_all(&self.dir)?;
        let now = Timestamp::now();
        let nanos = u128::try_from(now.as_nanosecond()).unwrap_or_default();
        for n in 0u32.. {
            let mut job = Job {
                id: format!("{nanos:x}-{:x}-{n:x}", std::process::id()),
                kind: kind.clone(),
                priority,
                state: JobState::Queued,
                attempts: 0,
                drive: drive.clone(),
                created: now,
                updated: now,
                progress: Progress::default(),
                error: None,
                retry_seen: 0,
            };
            let file = self.file(&job.id, "json")?;
            match platform::private_file_new(&file) {
                Ok(mut f) => {
                    job.updated = Timestamp::now();
                    f.write_all(&serde_json::to_vec_pretty(&job)?)?;
                    return Ok(job);
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e).with_context(|| file.display().to_string()),
            }
        }
        unreachable!("ids are unbounded")
    }

    /// Forgets a finished job. Worker only, like `save`.
    pub(crate) fn remove(&self, id: &str) -> Result<()> {
        for ext in ["json", "ctl"] {
            match std::fs::remove_file(self.file(id, ext)?) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => {
                    return Err(e).with_context(|| format!("remove job {id}"));
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn control_file(&self, id: Option<&str>) -> Result<PathBuf> {
        match id {
            Some(id) => self.file(id, "ctl"),
            None => Ok(self.dir.join("all.ctl")),
        }
    }

    /// The job's control, or the global one for `None`; absent or unreadable means defaults.
    pub(crate) fn control(&self, id: Option<&str>) -> Control {
        self.control_file(id)
            .ok()
            .and_then(|f| std::fs::read(f).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// CLI and tray only.
    pub(crate) fn edit_control(
        &self,
        id: Option<&str>,
        f: impl FnOnce(&mut Control),
    ) -> Result<()> {
        let file = self.control_file(id)?;
        let mut c = self.control(id);
        f(&mut c);
        platform::write_private(&file, &serde_json::to_vec(&c)?)
            .with_context(|| file.display().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    #[test]
    fn create_list_save_and_controls() {
        let tmp = TempDir::new();
        let s = Store::new(tmp.path().join("queue"));
        assert!(s.jobs().unwrap().is_empty());
        let drive: DriveId = "0123-ABCD".parse().unwrap();
        let a = s
            .create(&JobKind::Set { set: "a".into() }, &drive, 5)
            .unwrap();
        let b = s
            .create(&JobKind::Set { set: "b".into() }, &drive, 1)
            .unwrap();
        assert_ne!(a.id, b.id);
        let ids: Vec<_> = s.jobs().unwrap().into_iter().map(|j| j.id).collect();
        assert_eq!(ids, [b.id.clone(), a.id.clone()], "priority order");

        let mut j = s.job(&a.id).unwrap();
        j.state = JobState::Paused;
        s.save(&mut j).unwrap();
        assert_eq!(s.job(&a.id).unwrap().state, JobState::Paused);

        s.edit_control(Some(&a.id), |c| c.pause = true).unwrap();
        s.edit_control(Some(&a.id), |c| c.retry += 1).unwrap();
        assert_eq!(
            s.control(Some(&a.id)),
            Control {
                pause: true,
                retry: 1,
                ..Control::default()
            }
        );
        s.edit_control(None, |c| c.pause = true).unwrap();
        assert!(s.control(None).pause);
        assert!(!s.control(Some(&b.id)).pause);

        // A half-written job file and stray names are skipped, bad ids refused.
        std::fs::write(tmp.path().join("queue/abc.json"), b"{").unwrap();
        std::fs::write(tmp.path().join("queue/notes.txt"), b"x").unwrap();
        assert_eq!(s.jobs().unwrap().len(), 2);
        assert!(s.job("../x").is_err());
        assert!(s.edit_control(Some("all"), |c| c.cancel = true).is_err());
    }
}
