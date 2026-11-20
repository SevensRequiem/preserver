use crate::config::{DriveId, Transport};
use anyhow::{Result, bail};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum JobKind {
    Set {
        set: String,
    },
    /// One in-place (`git` or `repo`) source of a set.
    Mirror {
        set: String,
        source: String,
    },
    /// `preserver copy`: the archive from the primary (`Job::drive`) to `target`.
    Copy {
        target: Target,
        /// Resolved: catalog sets, `personal`, `kit`.
        sets: Vec<String>,
        /// The most the copy may take on the target, in bytes.
        #[serde(default)]
        size: Option<u64>,
        /// The `copy.toml` rule that made the job.
        #[serde(default)]
        rule: Option<String>,
    },
    /// `preserver personal`: the GitHub bundles.
    Github {
        /// `None` takes `config.toml`'s at run time.
        #[serde(default)]
        transport: Option<Transport>,
    },
    /// `preserver personal --local-only`: the `[[local]]` folders.
    Local,
}

/// Where a copy goes: a drive (by filesystem id, wherever it is mounted) or a plain directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Target {
    Drive {
        id: DriveId,
        /// Relative to the drive's mount point; empty for its root.
        #[serde(default)]
        subdir: String,
        /// Shown to people only; the id decides.
        #[serde(default)]
        label: String,
    },
    Dir {
        path: PathBuf,
    },
}

impl Target {
    /// One key per place, so a second `copy` to it reuses its rule and job.
    pub(crate) fn key(&self) -> String {
        match self {
            Self::Drive { id, subdir, .. } => format!("drive:{}/{subdir}", id.key()),
            Self::Dir { path } => format!("dir:{}", path.display()),
        }
    }

    pub(crate) fn name(&self) -> String {
        match self {
            Self::Drive { id, subdir, label } => {
                let base = if label.is_empty() {
                    id.to_string()
                } else {
                    label.clone()
                };
                if subdir.is_empty() {
                    base
                } else {
                    format!("{base}/{subdir}")
                }
            }
            Self::Dir { path } => path.display().to_string(),
        }
    }

    /// Job files and `copy.toml` can be edited by hand: a subdir must stay on its drive.
    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::Drive { subdir, label, .. } => {
                let ok = subdir.is_empty()
                    || (!subdir.contains('\\')
                        && !subdir.chars().any(char::is_control)
                        && Path::new(subdir)
                            .components()
                            .all(|c| matches!(c, Component::Normal(_))));
                if !ok {
                    bail!(
                        "bad subdirectory {subdir:?}: relative names only, no '..', backslash or control characters"
                    );
                }
                if label.chars().any(char::is_control) {
                    bail!("bad label {label:?}");
                }
            }
            Self::Dir { path } if !path.is_absolute() => {
                bail!("{} is not an absolute path", path.display());
            }
            Self::Dir { .. } => {}
        }
        Ok(())
    }
}

/// Which daemon lane runs a job. A lane resets, applies and saves only its own jobs, so two
/// lanes can share the queue directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lane {
    Download,
    Copy,
    Personal,
}

impl JobKind {
    pub(crate) fn lane(&self) -> Lane {
        match self {
            Self::Set { .. } | Self::Mirror { .. } => Lane::Download,
            Self::Copy { .. } => Lane::Copy,
            Self::Github { .. } | Self::Local => Lane::Personal,
        }
    }

    /// One unfinished job per kind: a GitHub job is the same whatever its transport.
    pub(crate) fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Github { .. }, Self::Github { .. }) => true,
            _ => self == other,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BlockReason {
    DriveAbsent,
    /// Plugged in but not mounted: the daemon never mounts a drive that was already there.
    Unmounted,
    /// The security key prompt went unanswered. Only a retry or the next scheduled occurrence
    /// asks again, so the daemon never prompts in a loop.
    NeedsTouch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum JobState {
    Queued,
    Blocked(BlockReason),
    Running { pid: u32 },
    Paused,
    Done,
    Failed,
    Canceled,
}

impl std::fmt::Display for JobState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Queued => f.write_str("queued"),
            Self::Blocked(BlockReason::DriveAbsent) => f.write_str("blocked (drive absent)"),
            Self::Blocked(BlockReason::Unmounted) => f.write_str("blocked (drive not mounted)"),
            Self::Blocked(BlockReason::NeedsTouch) => f.write_str("blocked (needs security key)"),
            Self::Running { pid } => write!(f, "running (pid {pid})"),
            Self::Paused => f.write_str("paused"),
            Self::Done => f.write_str("done"),
            Self::Failed => f.write_str("failed"),
            Self::Canceled => f.write_str("canceled"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Progress {
    pub files_done: u64,
    pub files_total: u64,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub rate_bps: u64,
    pub current: Vec<String>,
}

/// `<id>.json`: written by the worker only (tmp + rename), after creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Job {
    pub id: String,
    pub kind: JobKind,
    pub priority: u32,
    pub state: JobState,
    pub attempts: u32,
    pub drive: DriveId,
    pub created: Timestamp,
    pub updated: Timestamp,
    #[serde(default)]
    pub progress: Progress,
    #[serde(default)]
    pub error: Option<String>,
    /// The last `Control::retry` the worker acted on.
    #[serde(default)]
    pub retry_seen: u32,
    /// The last `Control::recheck` a finished run honoured.
    #[serde(default)]
    pub recheck_seen: u32,
    /// Failed only because files that failed verification before were skipped, upstream
    /// unchanged: no new notification.
    #[serde(default)]
    pub known_bad: bool,
}

/// `<id>.ctl` (or `all.ctl` for every job): written by the CLI and tray only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Control {
    pub pause: bool,
    pub cancel: bool,
    pub priority: Option<u32>,
    /// Bumped by `queue retry`; a level would re-fire on every scan, a counter fires once.
    pub retry: u32,
    /// Bumped only by a person (Retry, `public --recheck`), never by the scheduler: the next
    /// run downloads files that `queue/bad.rs` would skip.
    pub recheck: u32,
}

/// Ids are lower-case hex and dashes: safe as file names, and never `all`.
pub(crate) fn valid_id(s: &str) -> bool {
    (1..=40).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_kinds_and_reasons_round_trip_and_old_files_parse() {
        for (kind, state) in [
            (
                JobKind::Github {
                    transport: Some(Transport::Https),
                },
                JobState::Blocked(BlockReason::NeedsTouch),
            ),
            (
                JobKind::Github { transport: None },
                JobState::Blocked(BlockReason::Unmounted),
            ),
            (JobKind::Local, JobState::Queued),
        ] {
            let k: JobKind = serde_json::from_str(&serde_json::to_string(&kind).unwrap()).unwrap();
            let s: JobState =
                serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
            assert_eq!((k, s), (kind, state));
        }
        let gh: JobKind = serde_json::from_str(r#"{"github":{}}"#).unwrap();
        assert_eq!(gh, JobKind::Github { transport: None });
        let mirror = JobKind::Mirror {
            set: "s".into(),
            source: "x".into(),
        };
        let k: JobKind = serde_json::from_str(&serde_json::to_string(&mirror).unwrap()).unwrap();
        assert_eq!(k, mirror);
        assert_eq!(k.lane(), Lane::Download);
        assert!(!k.same(&JobKind::Set { set: "s".into() }));
        let old: JobKind = serde_json::from_str(r#"{"set":{"set":"a"}}"#).unwrap();
        assert_eq!(old.lane(), Lane::Download);
        let old: JobState = serde_json::from_str(r#"{"blocked":"drive_absent"}"#).unwrap();
        assert_eq!(old.to_string(), "blocked (drive absent)");
        assert!(JobKind::Github { transport: None }.same(&JobKind::Github {
            transport: Some(Transport::Ssh)
        }));
        assert!(!JobKind::Local.same(&JobKind::Github { transport: None }));
        let old: Job = serde_json::from_str(
            r#"{"id":"a","kind":"local","priority":1,"state":"queued","attempts":0,
            "drive":"0123-ABCD","created":"2026-01-01T00:00:00Z","updated":"2026-01-01T00:00:00Z"}"#,
        )
        .unwrap();
        assert_eq!((old.recheck_seen, old.known_bad), (0, false));
        let ctl: Control = serde_json::from_str(r#"{"retry":3}"#).unwrap();
        assert_eq!((ctl.retry, ctl.recheck), (3, 0));
    }
}
