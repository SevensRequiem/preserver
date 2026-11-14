use crate::config::DriveId;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum JobKind {
    Set { set: String },
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
