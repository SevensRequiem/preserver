//! What the tray shows, as a pure function of the status files and job locks.

use crate::config::Transport;
use crate::queue::{self, BlockReason, JobKind, JobState, Lane};
use crate::status::Status;
use jiff::civil::Date;
use jiff::tz::TimeZone;
use std::time::Duration;

const REMIND_DAYS: i32 = 4;

/// One job's status file, and whether its lock is held right now.
#[derive(Debug, Default)]
pub(crate) struct Job {
    pub status: Status,
    pub locked: bool,
}

impl Job {
    /// A `running` flag without the lock is left over from a run that was killed.
    fn running(&self) -> bool {
        self.status.running && self.locked
    }
}

#[derive(Debug)]
pub(crate) struct Inputs {
    pub github: Job,
    pub local: Job,
    pub public: Job,
    pub daemon: Job,
    /// Every job in the queue, read-only.
    pub jobs: Vec<queue::Job>,
    /// `all.ctl` pauses the whole queue.
    pub queue_paused: bool,
    /// Runs the tray (or the GUI) started as children that have not exited, one entry each.
    pub starting: Vec<Command>,
    /// Why the run the tray asked for did not start or exited non-zero.
    pub start_failure: Option<String>,
    pub today: Date,
    pub tz: TimeZone,
    /// `None` when config.toml does not load: the tray still shows the status.
    pub transport: Option<Transport>,
    /// Saved copy rules as (id, target name).
    pub rules: Vec<(String, String)>,
    /// config.toml lists `[[local]]` folders.
    pub has_local: bool,
}

/// Everything the tray, the GUI and the CLI can start. `args` is the foreground command line
/// for when no daemon runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Command {
    Personal,
    Local,
    Public,
    CopyRule(String),
}

impl Command {
    pub(crate) fn args(&self) -> Vec<String> {
        let args: &[&str] = match self {
            Self::Personal => &["personal", "--foreground"],
            Self::Local => &["personal", "--local-only", "--foreground"],
            Self::Public => &["public", "--foreground"],
            Self::CopyRule(id) => &["copy", "--rule", id, "--foreground"],
        };
        args.iter().map(|a| (*a).to_string()).collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommandItem {
    pub cmd: Command,
    pub label: String,
    pub enabled: bool,
}

/// The preserver-gui next to the running binary.
pub(crate) fn gui_path(exe: &std::path::Path) -> std::path::PathBuf {
    exe.with_file_name(format!("preserver-gui{}", std::env::consts::EXE_SUFFIX))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    Running,
    Failed,
    Stale,
    Ok,
}

impl State {
    pub(crate) fn icon(self) -> &'static str {
        match self {
            Self::Running => "view-refresh",
            Self::Failed | Self::Stale => "dialog-warning",
            Self::Ok => "folder-git",
        }
    }

    pub(crate) fn needs_attention(self) -> bool {
        matches!(self, Self::Failed | Self::Stale)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Model {
    pub state: State,
    pub tooltip: String,
    pub last_label: String,
    /// Absent until the public sync has run once.
    pub public_label: Option<String>,
    /// The last good GitHub backup is 4 or more days old, or there is none.
    pub overdue: bool,
    pub transport: Option<Transport>,
    pub daemon_label: String,
    /// Absent while no job waits, runs or failed.
    pub queue_label: Option<String>,
    pub queue_paused: bool,
    /// The pause or resume item, shown while there is something to pause or resume.
    pub pause_label: Option<&'static str>,
    /// Every job that has not finished, each with what can be done to it.
    pub jobs: Vec<JobItem>,
    pub commands: Vec<CommandItem>,
    /// A GitHub job is waiting for the security key.
    pub touch_needed: Option<String>,
    /// How soon to read the files again: often while a job moves, hourly when idle.
    pub poll: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JobItem {
    pub id: String,
    pub label: String,
    pub retry: bool,
}

impl Model {
    /// The daily reminder is for a backup nobody is running, even when the last try failed.
    pub(crate) fn reminder_due(&self) -> bool {
        self.overdue && self.state != State::Running
    }
}

fn public_label(job: &Job, tz: &TimeZone) -> Option<String> {
    if job.running() {
        return Some("Public: syncing…".to_string());
    }
    let s = &job.status;
    let last_run = s.last_run?;
    let failed = s.sets.iter().filter(|set| set["state"] == "failed").count();
    if !s.error.is_empty() || failed > 0 {
        return Some(format!(
            "Public: {} set(s) failed ({})",
            failed.max(1),
            stamp(last_run, tz)
        ));
    }
    Some(format!(
        "Public: ok {}",
        stamp(s.last_ok.unwrap_or(last_run), tz)
    ))
}

fn stamp(t: jiff::Timestamp, tz: &TimeZone) -> String {
    t.to_zoned(tz.clone()).strftime("%b %-d %H:%M").to_string()
}

fn daemon_label(job: &Job, tz: &TimeZone) -> String {
    match job.status.last_run {
        Some(t) if job.running() => format!("Daemon: running since {}", stamp(t, tz)),
        Some(_) => "Daemon: not running".to_string(),
        None => "Daemon: never started".to_string(),
    }
}

#[expect(clippy::cast_precision_loss, reason = "a size shown to a few decimals")]
fn gb(n: u64, decimals: usize) -> String {
    format!("{:.decimals$}", n as f64 / 1e9)
}

fn percent(p: &queue::Progress) -> Option<u64> {
    (p.bytes_total > 0).then(|| p.bytes_done.min(p.bytes_total) * 100 / p.bytes_total)
}

/// One line per job: what it is and where it stands.
fn job_label(j: &queue::Job) -> String {
    let p = &j.progress;
    let cur = p.current.first().map_or("", String::as_str);
    let item = || {
        format!(
            "{}/{}",
            (p.files_done + 1).min(p.files_total),
            p.files_total
        )
    };
    let public = || match percent(p) {
        Some(pc) => format!(
            "{pc}% ({}/{} GB)",
            gb(p.bytes_done, 2),
            gb(p.bytes_total, 2)
        ),
        None if p.files_total > 0 => format!("files {}/{}", p.files_done, p.files_total),
        None => "running".to_string(),
    };
    let (name, running) = match &j.kind {
        JobKind::Github { .. } => (
            "GitHub".to_string(),
            if p.files_total > 0 {
                format!("repo {} ({cur})", item())
            } else {
                "starting".to_string()
            },
        ),
        JobKind::Local => (
            "Local folders".to_string(),
            if p.files_total > 0 {
                format!("{} ({cur})", item())
            } else {
                "starting".to_string()
            },
        ),
        JobKind::Set { set } => (format!("Public {set}"), public()),
        JobKind::Mirror { set, source } => (format!("Public {set}/{source}"), public()),
        JobKind::Copy { target, .. } => (
            format!("Copy to {}", target.name()),
            percent(p).map_or_else(|| "copying".to_string(), |pc| format!("{pc}%")),
        ),
    };
    let what = match j.state {
        JobState::Running { .. } => running,
        JobState::Blocked(BlockReason::DriveAbsent) => "waiting for the drive".to_string(),
        JobState::Blocked(BlockReason::Unmounted) => "drive not mounted".to_string(),
        JobState::Blocked(BlockReason::NeedsTouch) => "waiting for your security key".to_string(),
        s => s.to_string(),
    };
    format!("{name}: {what}")
}

/// Unfinished jobs, personal lane first, then downloads, then copies, each by priority. Every
/// one can be canceled; a stopped one can be retried.
fn job_items(jobs: &[queue::Job]) -> Vec<JobItem> {
    let lane = |j: &queue::Job| match j.kind.lane() {
        Lane::Personal => 0,
        Lane::Download => 1,
        Lane::Copy => 2,
    };
    let mut open: Vec<_> = jobs
        .iter()
        .filter(|j| !matches!(j.state, JobState::Done | JobState::Canceled))
        .collect();
    open.sort_by_key(|j| (lane(j), j.priority));
    open.into_iter()
        .map(|j| JobItem {
            id: j.id.clone(),
            label: job_label(j),
            retry: matches!(
                j.state,
                JobState::Failed | JobState::Blocked(_) | JobState::Paused
            ),
        })
        .collect()
}

fn commands(i: &Inputs) -> Vec<CommandItem> {
    let running = |f: fn(&queue::Job) -> bool| {
        i.jobs
            .iter()
            .any(|j| matches!(j.state, JobState::Running { .. }) && f(j))
    };
    let starts = |c: &Command| i.starting.contains(c);
    let personal = starts(&Command::Personal)
        || i.github.running()
        || running(|j| matches!(j.kind, JobKind::Github { .. }));
    let local = starts(&Command::Personal)
        || starts(&Command::Local)
        || i.local.running()
        || running(|j| j.kind == JobKind::Local);
    let public = starts(&Command::Public)
        || i.public.running()
        || running(|j| matches!(j.kind, JobKind::Set { .. } | JobKind::Mirror { .. }));
    let mut out = vec![
        CommandItem {
            cmd: Command::Personal,
            label: "Back up personal now".into(),
            enabled: !personal,
        },
        CommandItem {
            cmd: Command::Local,
            label: "Back up local folders now".into(),
            enabled: i.has_local && !local,
        },
        CommandItem {
            cmd: Command::Public,
            label: "Mirror public sets now".into(),
            enabled: !public,
        },
    ];
    out.extend(i.rules.iter().map(|(id, target)| CommandItem {
        cmd: Command::CopyRule(id.clone()),
        label: format!("Copy now: {target}"),
        enabled: !starts(&Command::CopyRule(id.clone()))
            && !i.jobs.iter().any(|j| {
                matches!(j.state, JobState::Running { .. })
                    && matches!(&j.kind, JobKind::Copy { rule: Some(r), .. } if r == id)
            }),
    }));
    out
}

/// The queue line and the poll interval, both from the job states.
fn queue(jobs: &[queue::Job]) -> (Option<String>, Duration) {
    let count = |f: fn(&JobState) -> bool| jobs.iter().filter(|j| f(&j.state)).count();
    let parts = [
        (count(|s| matches!(s, JobState::Running { .. })), "running"),
        (count(|s| *s == JobState::Queued), "waiting"),
        (
            count(|s| matches!(s, JobState::Blocked(r) if *r != BlockReason::NeedsTouch)),
            "waiting for drive",
        ),
        (
            count(|s| *s == JobState::Blocked(BlockReason::NeedsTouch)),
            "waiting for your key",
        ),
        (count(|s| *s == JobState::Paused), "paused"),
        (count(|s| *s == JobState::Failed), "failed"),
    ];
    let label = parts
        .iter()
        .filter(|(n, _)| *n > 0)
        .map(|(n, what)| format!("{n} {what}"))
        .collect::<Vec<_>>();
    let poll = if parts[0].0 > 0 {
        Duration::from_secs(5)
    } else if parts[1..5].iter().any(|(n, _)| *n > 0) {
        Duration::from_secs(60)
    } else {
        Duration::from_secs(3600)
    };
    let mut label = label;
    let (done, total) = jobs
        .iter()
        .filter(|j| matches!(j.state, JobState::Running { .. } | JobState::Queued))
        .fold((0, 0), |(d, t), j| {
            (d + j.progress.bytes_done, t + j.progress.bytes_total)
        });
    if total > 0 {
        label.push(format!("{}/{} GB", gb(done.min(total), 1), gb(total, 1)));
    }
    let label = (!label.is_empty()).then(|| format!("Queue: {}", label.join(", ")));
    (label, poll)
}

/// How soon the GUI's status page reads the queue again: every second while a job moves, every
/// 5 s while one waits, a minute otherwise.
#[cfg(any(test, feature = "gui"))]
pub(crate) fn refresh_interval(jobs: &[queue::Job]) -> Duration {
    let any = |f: fn(&JobState) -> bool| jobs.iter().any(|j| f(&j.state));
    Duration::from_secs(if any(|s| matches!(s, JobState::Running { .. })) {
        1
    } else if any(|s| {
        matches!(
            s,
            JobState::Queued | JobState::Blocked(_) | JobState::Paused
        )
    }) {
        5
    } else {
        60
    })
}

pub(crate) fn model(i: &Inputs) -> Model {
    let last = i
        .github
        .status
        .last_ok
        .map(|t| t.to_zoned(i.tz.clone()).date());
    // A clock that went backwards reads as "today", not as a negative age.
    let days = last.map(|d| (i.today - d).get_days().max(0));
    let last_label = match (days, last) {
        (Some(0), _) => "Last backup: today".to_string(),
        (Some(1), _) => "Last backup: yesterday".to_string(),
        (Some(n), Some(date)) => {
            format!("Last backup: {n} days ago ({})", date.strftime("%b %-d"))
        }
        _ => "Last backup: never".to_string(),
    };
    let overdue = days.is_none_or(|d| d >= REMIND_DAYS);

    let (github, local) = (&i.github.status.error, &i.local.status.error);
    let failure = if !github.is_empty() {
        Some(github.clone())
    } else if !local.is_empty() {
        Some(format!("local folders: {local}"))
    } else if let Some((j, target)) = i.jobs.iter().find_map(|j| match &j.kind {
        JobKind::Copy { target, .. } if j.state == JobState::Failed => Some((j, target)),
        _ => None,
    }) {
        Some(format!(
            "copy to {}: {}",
            target.name(),
            j.error.as_deref().unwrap_or("failed")
        ))
    } else {
        i.start_failure.clone()
    };
    let personal_start = [Command::Personal, Command::Local]
        .iter()
        .any(|c| i.starting.contains(c));
    let (state, tooltip) = if personal_start || i.github.running() || i.local.running() {
        (State::Running, "Backing up…".to_string())
    } else if let Some(failure) = failure {
        (State::Failed, format!("Last run failed: {failure}"))
    } else if overdue {
        (State::Stale, last_label.clone())
    } else {
        (State::Ok, last_label.clone())
    };
    let (queue_label, poll) = queue(&i.jobs);
    Model {
        state,
        tooltip,
        last_label,
        public_label: public_label(&i.public, &i.tz),
        overdue,
        transport: i.transport,
        daemon_label: daemon_label(&i.daemon, &i.tz),
        pause_label: if i.queue_paused {
            Some("Resume queue")
        } else {
            queue_label.is_some().then_some("Pause queue")
        },
        queue_label,
        queue_paused: i.queue_paused,
        jobs: job_items(&i.jobs),
        commands: commands(i),
        touch_needed: i.jobs.iter().find_map(|j| {
            (matches!(j.kind, JobKind::Github { .. })
                && j.state == JobState::Blocked(BlockReason::NeedsTouch))
            .then(|| j.id.clone())
        }),
        poll,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::civil::date;

    fn job(json: &str, locked: bool) -> Job {
        Job {
            status: serde_json::from_str(json).unwrap(),
            locked,
        }
    }

    fn ok_at(time: &str) -> Job {
        job(
            &format!(r#"{{"last_ok":"{time}","last_run":"{time}"}}"#),
            false,
        )
    }

    fn inputs(github: Job) -> Inputs {
        Inputs {
            github,
            local: Job::default(),
            public: Job::default(),
            daemon: Job::default(),
            jobs: Vec::new(),
            queue_paused: false,
            starting: Vec::new(),
            start_failure: None,
            today: date(2026, 11, 13),
            tz: TimeZone::UTC,
            transport: Some(Transport::Ssh),
            rules: Vec::new(),
            has_local: false,
        }
    }

    #[test]
    fn age_of_the_last_good_backup() {
        let cases = [
            (
                "today",
                "2026-11-13T00:00:00Z",
                "Last backup: today",
                State::Ok,
                false,
            ),
            (
                "late yesterday",
                "2026-11-12T23:59:59Z",
                "Last backup: yesterday",
                State::Ok,
                false,
            ),
            (
                "three days",
                "2026-11-10T12:00:00Z",
                "Last backup: 3 days ago (Nov 10)",
                State::Ok,
                false,
            ),
            (
                "four days is stale",
                "2026-11-09T23:00:00Z",
                "Last backup: 4 days ago (Nov 9)",
                State::Stale,
                true,
            ),
            (
                "across a year",
                "2025-12-31T08:00:00Z",
                "Last backup: 317 days ago (Dec 31)",
                State::Stale,
                true,
            ),
            (
                "clock went backwards",
                "2026-11-20T00:00:00Z",
                "Last backup: today",
                State::Ok,
                false,
            ),
        ];
        for (name, time, label, state, overdue) in cases {
            let m = model(&inputs(ok_at(time)));
            assert_eq!(m.last_label, label, "{name}");
            assert_eq!(m.tooltip, label, "{name}");
            assert_eq!(m.state, state, "{name}");
            assert_eq!(m.overdue, overdue, "{name}");
            assert_eq!(m.reminder_due(), overdue, "{name}");
            assert!(m.commands[0].enabled, "{name}");
            assert_eq!(m.commands[0].label, "Back up personal now", "{name}");
        }
    }

    #[test]
    fn never_backed_up_is_stale() {
        for (name, github) in [
            ("no status file", Job::default()),
            (
                "null times",
                job(r#"{"last_ok":null,"last_run":null}"#, false),
            ),
        ] {
            let m = model(&inputs(github));
            assert_eq!(m.state, State::Stale, "{name}");
            assert_eq!(m.last_label, "Last backup: never", "{name}");
            assert!(m.reminder_due(), "{name}");
        }
    }

    #[test]
    fn the_day_is_counted_in_the_local_zone() {
        let mut i = inputs(ok_at("2026-11-12T23:30:00Z"));
        assert_eq!(model(&i).last_label, "Last backup: yesterday");
        i.tz = TimeZone::fixed(jiff::tz::offset(1));
        assert_eq!(model(&i).last_label, "Last backup: today");
    }

    #[test]
    fn running_needs_the_flag_and_the_lock() {
        type Set = fn(&mut Inputs, Job, Job);
        let fresh = "2026-11-13T00:00:00Z";
        let running = |locked| {
            job(
                &format!(r#"{{"last_ok":"{fresh}","running":true}}"#),
                locked,
            )
        };
        let cases: [(&str, Set, State); 5] = [
            (
                "github flag and lock",
                |i, on, _| i.github = on,
                State::Running,
            ),
            (
                "github flag without lock",
                |i, _, stale| i.github = stale,
                State::Ok,
            ),
            (
                "local flag and lock",
                |i, on, _| i.local = on,
                State::Running,
            ),
            (
                "local flag without lock",
                |i, _, stale| i.local = stale,
                State::Ok,
            ),
            (
                "started by the tray",
                |i, _, _| i.starting = vec![Command::Personal],
                State::Running,
            ),
        ];
        for (name, set, state) in cases {
            let mut i = inputs(ok_at(fresh));
            set(&mut i, running(true), running(false));
            let m = model(&i);
            assert_eq!(m.state, state, "{name}");
            let busy = state == State::Running && !name.starts_with("local");
            assert_eq!(m.commands[0].enabled, !busy, "{name}");
            if state == State::Running {
                assert_eq!(m.tooltip, "Backing up…", "{name}");
            }
        }
    }

    #[test]
    fn a_started_run_greys_out_only_its_own_commands() {
        let rule = Command::CopyRule("abc123abc123".into());
        let enabled = |starting: Vec<Command>| {
            let mut i = inputs(job(r#"{"last_ok":"2026-11-13T08:00:00Z"}"#, false));
            i.has_local = true;
            i.rules = vec![("abc123abc123".into(), "stick".into())];
            i.starting = starting;
            let m = model(&i);
            let on: Vec<bool> = m.commands.iter().map(|c| c.enabled).collect();
            (on, m.state == State::Running)
        };
        assert_eq!(enabled(vec![]), (vec![true; 4], false));
        assert_eq!(
            enabled(vec![Command::Public]),
            (vec![true, true, false, true], false)
        );
        assert_eq!(
            enabled(vec![rule.clone()]),
            (vec![true, true, true, false], false)
        );
        assert_eq!(
            enabled(vec![Command::Local]),
            (vec![true, false, true, true], true)
        );
        assert_eq!(
            enabled(vec![Command::Personal, rule]),
            (vec![false, false, true, false], true)
        );
    }

    #[test]
    fn running_wins_over_failure_and_silences_the_reminder() {
        let mut i = inputs(job(r#"{"error":"boom","running":true}"#, true));
        i.start_failure = Some("x".to_string());
        let m = model(&i);
        assert_eq!(m.state, State::Running);
        assert!(m.overdue);
        assert!(!m.reminder_due());
    }

    #[test]
    fn failure_text_by_precedence() {
        let fresh = "2026-11-13T00:00:00Z";
        let failed = |err: &str| {
            job(
                &format!(r#"{{"last_ok":"{fresh}","error":"{err}"}}"#),
                false,
            )
        };
        let cases = [
            ("github", "gh down", "", None, "Last run failed: gh down"),
            (
                "github over local",
                "gh down",
                "disk",
                Some("unit"),
                "Last run failed: gh down",
            ),
            (
                "local",
                "",
                "disk full",
                Some("unit"),
                "Last run failed: local folders: disk full",
            ),
            (
                "start failure last",
                "",
                "",
                Some("see journalctl"),
                "Last run failed: see journalctl",
            ),
        ];
        for (name, github, local, start, tooltip) in cases {
            let mut i = inputs(failed(github));
            i.local = failed(local);
            i.start_failure = start.map(str::to_string);
            let m = model(&i);
            assert_eq!(m.state, State::Failed, "{name}");
            assert_eq!(m.tooltip, tooltip, "{name}");
            assert_eq!(m.last_label, "Last backup: today", "{name}");
            assert!(!m.reminder_due(), "{name}");
        }
    }

    #[test]
    fn failed_and_overdue_still_reminds() {
        let m = model(&inputs(job(
            r#"{"last_ok":"2026-11-01T00:00:00Z","error":"boom"}"#,
            false,
        )));
        assert_eq!(m.state, State::Failed);
        assert!(m.reminder_due());
    }

    #[test]
    fn public_line() {
        let cases = [
            ("never ran", "{}", false, None),
            (
                "syncing",
                r#"{"running":true}"#,
                true,
                Some("Public: syncing…"),
            ),
            (
                "stale running flag",
                r#"{"running":true,"last_ok":"2026-11-02T15:04:00Z","last_run":"2026-11-02T15:04:00Z"}"#,
                false,
                Some("Public: ok Nov 2 15:04"),
            ),
            (
                "ok",
                r#"{"last_ok":"2026-11-12T03:10:00Z","last_run":"2026-11-12T03:00:00Z","sets":[{"name":"kernel","state":"ok"}]}"#,
                false,
                Some("Public: ok Nov 12 03:10"),
            ),
            (
                "two sets failed",
                r#"{"last_run":"2026-11-12T03:00:00Z","sets":[{"state":"failed"},{"state":"ok"},{"state":"failed"}]}"#,
                false,
                Some("Public: 2 set(s) failed (Nov 12 03:00)"),
            ),
            (
                "error without a failed set",
                r#"{"last_run":"2026-11-12T03:00:00Z","error":"no drive"}"#,
                false,
                Some("Public: 1 set(s) failed (Nov 12 03:00)"),
            ),
        ];
        for (name, json, locked, want) in cases {
            let mut i = inputs(ok_at("2026-11-13T00:00:00Z"));
            i.public = job(json, locked);
            let m = model(&i);
            assert_eq!(m.public_label.as_deref(), want, "{name}");
            assert_eq!(m.state, State::Ok, "{name}: public never changes the icon");
        }
    }

    #[test]
    fn looks() {
        let cases = [
            (State::Running, "view-refresh", false),
            (State::Failed, "dialog-warning", true),
            (State::Stale, "dialog-warning", true),
            (State::Ok, "folder-git", false),
        ];
        for (state, icon, attention) in cases {
            assert_eq!(state.icon(), icon, "{state:?}");
            assert_eq!(state.needs_attention(), attention, "{state:?}");
        }
    }

    #[test]
    fn daemon_line() {
        let cases = [
            ("never started", Job::default(), "Daemon: never started"),
            (
                "running",
                job(
                    r#"{"running":true,"last_run":"2026-11-13T08:05:00Z"}"#,
                    true,
                ),
                "Daemon: running since Nov 13 08:05",
            ),
            (
                "killed: flag without the lock",
                job(
                    r#"{"running":true,"last_run":"2026-11-13T08:05:00Z"}"#,
                    false,
                ),
                "Daemon: not running",
            ),
        ];
        for (name, daemon, want) in cases {
            let mut i = inputs(ok_at("2026-11-13T00:00:00Z"));
            i.daemon = daemon;
            let m = model(&i);
            assert_eq!(m.daemon_label, want, "{name}");
            assert_eq!(
                m.state,
                State::Ok,
                "{name}: the daemon never changes the icon"
            );
        }
    }

    fn queued(state: &str) -> queue::Job {
        serde_json::from_str(&format!(
            r#"{{"id":"1-2-3","kind":{{"set":{{"set":"s"}}}},"priority":0,"state":{state},"attempts":0,"drive":"0123-ABCD","created":"2026-11-13T00:00:00Z","updated":"2026-11-13T00:00:00Z"}}"#
        ))
        .unwrap()
    }

    #[test]
    fn queue_line_pause_item_and_poll() {
        // name, job states, all.ctl paused, queue line, pause item, poll seconds
        type Case<'a> = (
            &'a str,
            &'a [&'a str],
            bool,
            Option<&'a str>,
            Option<&'a str>,
            u64,
        );
        let cases: [Case; 8] = [
            ("empty", &[], false, None, None, 3600),
            (
                "only finished",
                &[r#""done""#, r#""canceled""#],
                false,
                None,
                None,
                3600,
            ),
            (
                "failed only",
                &[r#""failed""#],
                false,
                Some("Queue: 1 failed"),
                Some("Pause queue"),
                3600,
            ),
            (
                "waiting",
                &[
                    r#""queued""#,
                    r#""queued""#,
                    r#"{"blocked":"drive_absent"}"#,
                    r#""paused""#,
                ],
                false,
                Some("Queue: 2 waiting, 1 waiting for drive, 1 paused"),
                Some("Pause queue"),
                60,
            ),
            (
                "the key is not the drive",
                &[r#"{"blocked":"needs_touch"}"#, r#"{"blocked":"unmounted"}"#],
                false,
                Some("Queue: 1 waiting for drive, 1 waiting for your key"),
                Some("Pause queue"),
                60,
            ),
            (
                "paused only",
                &[r#""paused""#],
                false,
                Some("Queue: 1 paused"),
                Some("Pause queue"),
                60,
            ),
            (
                "running",
                &[r#"{"running":{"pid":7}}"#, r#""queued""#, r#""done""#],
                false,
                Some("Queue: 1 running, 1 waiting"),
                Some("Pause queue"),
                5,
            ),
            (
                "paused and empty",
                &[],
                true,
                None,
                Some("Resume queue"),
                3600,
            ),
        ];
        for (name, states, paused, label, pause, poll) in cases {
            let mut i = inputs(ok_at("2026-11-13T00:00:00Z"));
            i.jobs = states.iter().map(|s| queued(s)).collect();
            i.queue_paused = paused;
            let m = model(&i);
            assert_eq!(m.queue_label.as_deref(), label, "{name}");
            assert_eq!(m.pause_label, pause, "{name}");
            assert_eq!(m.queue_paused, paused, "{name}");
            assert_eq!(m.poll, Duration::from_secs(poll), "{name}");
        }
    }

    fn copy_job(state: &str, progress: &str, error: &str) -> queue::Job {
        serde_json::from_str(&format!(
            r#"{{"id":"4-5-6","kind":{{"copy":{{"target":{{"dir":{{"path":"/media/stick"}}}},"sets":["personal"]}}}},"priority":10,"state":{state},"attempts":1,"drive":"0123-ABCD","created":"2026-11-13T00:00:00Z","updated":"2026-11-13T00:00:00Z","progress":{progress},"error":{error}}}"#
        ))
        .unwrap()
    }

    #[test]
    fn copy_jobs_get_items_and_a_failure_shows() {
        let mut i = inputs(ok_at("2026-11-13T00:00:00Z"));
        i.jobs = vec![
            copy_job(
                r#"{"running":{"pid":7}}"#,
                r#"{"bytes_done":25,"bytes_total":100}"#,
                "null",
            ),
            copy_job(r#"{"blocked":"drive_absent"}"#, "{}", "null"),
            copy_job(r#""done""#, "{}", "null"),
            queued(r#""failed""#),
        ];
        let m = model(&i);
        let labels: Vec<_> = m.jobs.iter().map(|c| (c.label.as_str(), c.retry)).collect();
        assert_eq!(
            labels,
            [
                ("Public s: failed", true),
                ("Copy to /media/stick: 25%", false),
                ("Copy to /media/stick: waiting for the drive", true)
            ]
        );
        assert_eq!(
            m.state,
            State::Ok,
            "a failed download is the queue line's business"
        );

        i.jobs.push(copy_job(r#""failed""#, "{}", r#""disk full""#));
        let m = model(&i);
        assert_eq!(m.state, State::Failed);
        assert_eq!(
            m.tooltip,
            "Last run failed: copy to /media/stick: disk full"
        );
        assert!(m.jobs.last().unwrap().retry);
    }

    fn kind_job(kind: &str, state: &str, progress: &str) -> queue::Job {
        serde_json::from_str(&format!(
            r#"{{"id":"7-8-9","kind":{kind},"priority":1,"state":{state},"attempts":1,"drive":"0123-ABCD","created":"2026-11-13T00:00:00Z","updated":"2026-11-13T00:00:00Z","progress":{progress}}}"#
        ))
        .unwrap()
    }

    #[test]
    fn job_lines_by_kind_and_state() {
        let running = r#"{"running":{"pid":7}}"#;
        let gh = r#"{"github":{}}"#;
        let set = r#"{"set":{"set":"kernel"}}"#;
        let cases = [
            (
                gh,
                running,
                r#"{"files_done":11,"files_total":40,"current":["owner/name"]}"#,
                "GitHub: repo 12/40 (owner/name)",
            ),
            (gh, running, "{}", "GitHub: starting"),
            (
                gh,
                r#"{"blocked":"needs_touch"}"#,
                "{}",
                "GitHub: waiting for your security key",
            ),
            (
                gh,
                r#"{"blocked":"unmounted"}"#,
                "{}",
                "GitHub: drive not mounted",
            ),
            (
                gh,
                r#"{"blocked":"drive_absent"}"#,
                "{}",
                "GitHub: waiting for the drive",
            ),
            (
                r#""local""#,
                running,
                r#"{"files_done":0,"files_total":3,"current":["documents"]}"#,
                "Local folders: 1/3 (documents)",
            ),
            (
                set,
                running,
                r#"{"bytes_done":1200000000,"bytes_total":2600000000}"#,
                "Public kernel: 46% (1.20/2.60 GB)",
            ),
            (
                set,
                running,
                r#"{"files_done":3,"files_total":9}"#,
                "Public kernel: files 3/9",
            ),
            (set, r#""queued""#, "{}", "Public kernel: queued"),
        ];
        for (kind, state, progress, want) in cases {
            assert_eq!(job_label(&kind_job(kind, state, progress)), want);
        }
        let mut i = inputs(Job::default());
        i.jobs = vec![
            queued(r#""queued""#),
            copy_job(r#""queued""#, "{}", "null"),
            kind_job(gh, r#""queued""#, "{}"),
        ];
        let order: Vec<_> = model(&i).jobs.iter().map(|j| j.label.clone()).collect();
        assert_eq!(
            order,
            [
                "GitHub: queued",
                "Public s: queued",
                "Copy to /media/stick: queued"
            ]
        );
    }

    #[test]
    fn commands_and_their_enablement() {
        let running = r#"{"running":{"pid":7}}"#;
        let mut i = inputs(Job::default());
        i.rules = vec![("abc123abc123".into(), "stick".into())];
        let m = model(&i);
        let got: Vec<_> = m
            .commands
            .iter()
            .map(|c| (c.label.as_str(), c.enabled))
            .collect();
        assert_eq!(
            got,
            [
                ("Back up personal now", true),
                ("Back up local folders now", false),
                ("Mirror public sets now", true),
                ("Copy now: stick", true)
            ]
        );
        assert_eq!(m.commands[3].cmd, Command::CopyRule("abc123abc123".into()));

        i.has_local = true;
        i.jobs = vec![
            kind_job(r#"{"github":{}}"#, running, "{}"),
            kind_job(r#"{"set":{"set":"s"}}"#, running, "{}"),
            kind_job(
                r#"{"copy":{"target":{"dir":{"path":"/m"}},"sets":[],"rule":"abc123abc123"}}"#,
                running,
                "{}",
            ),
        ];
        let en: Vec<_> = model(&i).commands.iter().map(|c| c.enabled).collect();
        assert_eq!(en, [false, true, false, false]);
        i.jobs = vec![kind_job(r#""local""#, running, "{}")];
        let en: Vec<_> = model(&i).commands.iter().map(|c| c.enabled).collect();
        assert_eq!(en, [true, false, true, true]);
    }

    #[test]
    fn foreground_arguments_and_the_gui_path() {
        assert_eq!(
            Command::Local.args(),
            ["personal", "--local-only", "--foreground"]
        );
        assert_eq!(
            Command::CopyRule("abc".into()).args(),
            ["copy", "--rule", "abc", "--foreground"]
        );
        assert_eq!(
            gui_path(std::path::Path::new("/home/u/.local/bin/preserver")),
            std::path::Path::new("/home/u/.local/bin/preserver-gui")
        );
    }

    #[test]
    fn touch_needed_and_queue_totals() {
        let mut i = inputs(Job::default());
        i.jobs = vec![kind_job(
            r#"{"github":{}}"#,
            r#"{"blocked":"needs_touch"}"#,
            "{}",
        )];
        assert_eq!(model(&i).touch_needed.as_deref(), Some("7-8-9"));
        i.jobs = vec![
            kind_job(
                r#"{"set":{"set":"a"}}"#,
                r#"{"running":{"pid":7}}"#,
                r#"{"bytes_done":4100000000,"bytes_total":10000000000}"#,
            ),
            kind_job(
                r#"{"set":{"set":"b"}}"#,
                r#""queued""#,
                r#"{"bytes_total":8000000000}"#,
            ),
        ];
        let m = model(&i);
        assert_eq!(m.touch_needed, None);
        assert_eq!(
            m.queue_label.as_deref(),
            Some("Queue: 1 running, 1 waiting, 4.1/18.0 GB")
        );
    }

    #[test]
    fn transport_passes_through() {
        for t in [None, Some(Transport::Ssh), Some(Transport::Https)] {
            let mut i = inputs(Job::default());
            i.transport = t;
            assert_eq!(model(&i).transport, t);
        }
    }

    #[test]
    fn gui_refresh_interval() {
        let cases: [(&[&str], u64); 6] = [
            (&[], 60),
            (&[r#""done""#, r#""failed""#], 60),
            (&[r#""queued""#], 5),
            (&[r#"{"blocked":"needs_touch"}"#], 5),
            (&[r#""paused""#, r#""failed""#], 5),
            (&[r#""queued""#, r#"{"running":{"pid":7}}"#], 1),
        ];
        for (states, secs) in cases {
            let jobs: Vec<_> = states.iter().map(|s| queued(s)).collect();
            assert_eq!(
                refresh_interval(&jobs),
                Duration::from_secs(secs),
                "{states:?}"
            );
        }
    }
}
