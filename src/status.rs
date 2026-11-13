use crate::paths::Paths;
use crate::platform;
use anyhow::{Context, Result, bail};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use std::fs::{File, TryLockError};
use std::path::Path;

/// The Go tool's status file: same names, and Go's zero time stands for "never".
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Status {
    #[serde(with = "go_time")]
    pub last_ok: Option<Timestamp>,
    #[serde(with = "go_time")]
    pub last_run: Option<Timestamp>,
    pub error: String,
    pub running: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sets: Vec<serde_json::Value>,
}

mod go_time {
    use jiff::Timestamp;
    use serde::{Deserialize, Deserializer, Serializer};

    const ZERO: &str = "0001-01-01T00:00:00Z";

    #[expect(
        clippy::ref_option,
        reason = "serde's with-module passes the field by reference"
    )]
    pub(super) fn serialize<S: Serializer>(t: &Option<Timestamp>, s: S) -> Result<S::Ok, S::Error> {
        match t {
            Some(t) => s.collect_str(t),
            None => s.serialize_str(ZERO),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<Timestamp>, D::Error> {
        let t: Timestamp = String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)?;
        let zero: Timestamp = ZERO.parse().map_err(serde::de::Error::custom)?;
        Ok((t > zero).then_some(t))
    }
}

impl Status {
    /// An absent or unreadable file reads as "never ran", as in Go.
    pub(crate) fn read(file: &Path) -> Self {
        std::fs::read(file)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub(crate) fn write(&self, file: &Path) -> Result<()> {
        platform::write_private(file, &serde_json::to_vec(self)?)
            .with_context(|| file.display().to_string())
    }
}

/// Takes the job lock, or returns `None` when another process holds it.
/// It is a flock, so it interlocks with the Go tool and is released when the file closes.
pub(crate) fn try_lock(file: &Path) -> Result<Option<File>> {
    let f = platform::private_file(file).with_context(|| file.display().to_string())?;
    match f.try_lock() {
        Ok(()) => Ok(Some(f)),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(e)) => Err(e).with_context(|| file.display().to_string()),
    }
}

/// Runs `f` under the job's lock and records the outcome in its status file.
pub(crate) fn job(
    paths: &mut Paths,
    name: &str,
    f: impl FnOnce(&mut Paths) -> Result<()>,
) -> Result<()> {
    let Some(_lock) = try_lock(&paths.lock_file(name))? else {
        bail!("another {name} backup is already running");
    };
    let file = paths.status_file(name);
    let mut st = Status::read(&file);
    st.running = true;
    st.last_run = Some(Timestamp::now());
    st.error.clear();
    st.write(&file)?;

    let result = f(paths);
    st.sets = Status::read(&file).sets;
    st.running = false;
    match &result {
        Ok(()) => st.last_ok = Some(Timestamp::now()),
        Err(e) => st.error = format!("{e:#}"),
    }
    let written = st.write(&file);
    result.and(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, paths};

    #[test]
    fn reads_go_status() {
        let cases = [
            (
                "never ran",
                r#"{"last_ok":"0001-01-01T00:00:00Z","last_run":"0001-01-01T00:00:00Z","error":"","running":false}"#,
                None,
                None,
            ),
            (
                "local offset and nanoseconds",
                r#"{"last_ok":"2026-11-13T12:00:00.123456789-05:00","last_run":"2026-11-13T18:00:01+01:00","error":"x","running":true}"#,
                Some("2026-11-13T17:00:00.123456789Z"),
                Some("2026-11-13T17:00:01Z"),
            ),
        ];
        let tmp = TempDir::new();
        let file = tmp.path().join("s.json");
        for (name, json, ok, run) in cases {
            std::fs::write(&file, json).unwrap();
            let st = Status::read(&file);
            assert_eq!(st.last_ok, ok.map(|t| t.parse().unwrap()), "{name}");
            assert_eq!(st.last_run, run.map(|t| t.parse().unwrap()), "{name}");
        }
    }

    #[test]
    fn unreadable_status_is_empty() {
        let tmp = TempDir::new();
        let file = tmp.path().join("s.json");
        assert!(Status::read(&file).last_run.is_none());
        std::fs::write(&file, "{not json").unwrap();
        assert!(Status::read(&file).last_run.is_none());
    }

    #[test]
    fn writes_go_field_names_and_keeps_sets() {
        let tmp = TempDir::new();
        let file = tmp.path().join("status/public.json");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(
            &file,
            r#"{"last_ok":"2026-11-13T12:00:00Z","last_run":"0001-01-01T00:00:00Z","error":"","running":false,"sets":[{"name":"kernel","state":"ok","time":"2026-11-13T12:00:00Z"}]}"#,
        )
        .unwrap();
        Status::read(&file).write(&file).unwrap();
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            r#"{"last_ok":"2026-11-13T12:00:00Z","last_run":"0001-01-01T00:00:00Z","error":"","running":false,"sets":[{"name":"kernel","state":"ok","time":"2026-11-13T12:00:00Z"}]}"#
        );

        Status::default().write(&file).unwrap();
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            r#"{"last_ok":"0001-01-01T00:00:00Z","last_run":"0001-01-01T00:00:00Z","error":"","running":false}"#
        );
    }

    #[test]
    fn lock_excludes_a_second_holder() {
        let tmp = TempDir::new();
        let file = tmp.path().join("code-archive-github.lock");
        let held = try_lock(&file).unwrap();
        assert!(held.is_some());
        assert!(try_lock(&file).unwrap().is_none());
    }

    // Each test takes a lock once and never checks that it is free again: a process another
    // test thread is spawning shares the lock until it execs, so that check would race.
    #[test]
    fn job_records_success() {
        let tmp = TempDir::new();
        let mut p = paths(tmp.path());
        let file = p.status_file("github");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(
            &file,
            r#"{"last_ok":"2026-11-01T00:00:00Z","last_run":"2026-11-02T00:00:00Z","error":"old","running":false}"#,
        )
        .unwrap();
        let before = Status::read(&file);

        job(&mut p, "github", |p| {
            let st = Status::read(&p.status_file("github"));
            assert!(st.running && st.error.is_empty());
            assert!(st.last_run > before.last_run);
            assert_eq!(st.last_ok, before.last_ok);
            Ok(())
        })
        .unwrap();
        let after = Status::read(&file);
        assert!(!after.running && after.error.is_empty());
        assert!(after.last_ok > before.last_ok);
    }

    #[test]
    fn job_records_failure_and_keeps_last_ok() {
        let tmp = TempDir::new();
        let mut p = paths(tmp.path());
        let file = p.status_file("github");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(
            &file,
            r#"{"last_ok":"2026-11-01T00:00:00Z","last_run":"2026-11-01T00:00:00Z","error":"","running":false}"#,
        )
        .unwrap();

        let err = job(&mut p, "github", |_| bail!("boom")).unwrap_err();
        assert_eq!(err.to_string(), "boom");
        let failed = Status::read(&file);
        assert!(!failed.running);
        assert_eq!(failed.error, "boom");
        assert_eq!(
            failed.last_ok,
            Some("2026-11-01T00:00:00Z".parse().unwrap())
        );
        assert!(failed.last_run > failed.last_ok);
    }

    #[test]
    fn job_refuses_while_locked() {
        let tmp = TempDir::new();
        let mut p = paths(tmp.path());
        let _held = try_lock(&p.lock_file("github")).unwrap().unwrap();
        let err = job(&mut p, "github", |_| Ok(())).unwrap_err();
        assert!(err.to_string().contains("already running"), "{err}");
        assert!(!p.status_file("github").exists());
    }
}
