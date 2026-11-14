use crate::catalog::valid_name;
use crate::config::DriveId;
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
                    || Path::new(subdir).components().all(
                        |c| matches!(c, Component::Normal(n) if n.to_str().is_some_and(valid_name)),
                    );
                if !ok {
                    bail!("bad subdirectory {subdir:?}: relative names only, no '..'");
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
}

impl JobKind {
    pub(crate) fn lane(&self) -> Lane {
        match self {
            Self::Set { .. } => Lane::Download,
            Self::Copy { .. } => Lane::Copy,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BlockReason {
    DriveAbsent,
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
}

/// Ids are lower-case hex and dashes: safe as file names, and never `all`.
pub(crate) fn valid_id(s: &str) -> bool {
    (1..=40).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b'-')
}
