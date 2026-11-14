//! `[schedule]` in config.toml: when the daemon queues the GitHub, local-folder and public jobs.
//! A missed occurrence (machine off) fires once when the daemon next looks, like systemd's
//! `Persistent=true`, from the `last_run` the status files already keep.

use crate::catalog::Catalog;
use crate::config::Config;
use crate::paths::Paths;
use crate::public;
use crate::queue::{BlockReason, Job, JobKind, JobState, Store};
use crate::status::Status;
use anyhow::{Context, Result, bail};
use jiff::civil::Time;
use jiff::{Timestamp, Zoned};
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub(crate) enum Schedule {
    /// Seconds since the last run.
    Every(u64),
    /// Daily at this local time.
    Daily(Time),
}

/// `H:MM:SS`, at least one second; hours are unbounded.
pub(crate) fn parse_interval(s: &str) -> Result<u64> {
    let parts: Vec<&str> = s.split(':').collect();
    let parsed = match parts.as_slice() {
        [h, m, sec] if m.len() == 2 && sec.len() == 2 => num(h).zip(num(m)).zip(num(sec)),
        _ => None,
    };
    let Some(((h, m), sec)) = parsed.filter(|((_, m), sec)| *m < 60 && *sec < 60) else {
        bail!("bad interval {s:?}: give hh:mm:ss, like 24:00:00");
    };
    let total = h
        .checked_mul(3600)
        .and_then(|t| t.checked_add(m * 60 + sec))
        .filter(|t| *t > 0);
    total.with_context(|| format!("bad interval {s:?}: give hh:mm:ss, like 24:00:00"))
}

fn num(p: &str) -> Option<u64> {
    (!p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        .then(|| p.parse().ok())
        .flatten()
}

pub(crate) fn show_interval(secs: u64) -> String {
    format!("{}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
}

impl std::str::FromStr for Schedule {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.matches(':').count() == 2 {
            return parse_interval(s).map(Self::Every);
        }
        let daily = s
            .split_once(':')
            .filter(|(h, m)| (1..=2).contains(&h.len()) && m.len() == 2)
            .and_then(|(h, m)| num(h).zip(num(m)))
            .filter(|(h, m)| *h < 24 && *m < 60)
            .and_then(|(h, m)| Time::new(i8::try_from(h).ok()?, i8::try_from(m).ok()?, 0, 0).ok());
        daily.map(Self::Daily).with_context(|| {
            format!(
                "bad schedule {s:?}: give H:MM:SS for an interval since the last run (24:00:00) \
                 or HH:MM for a time of day (01:30)"
            )
        })
    }
}

impl TryFrom<String> for Schedule {
    type Error = anyhow::Error;

    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl std::fmt::Display for Schedule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Every(secs) => write!(f, "every {}", show_interval(*secs)),
            Self::Daily(t) => write!(f, "daily at {}", t.strftime("%H:%M")),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Act {
    Create,
    Retry(String),
}

/// What a schedule owes at `now`. `pending` is the kind's unfinished job, `last_run` when a
/// run of it last started (manual runs included, so a run after 01:30 covers the 01:30
/// occurrence). A waiting job gets nothing: drive events or the person handle those. A failed
/// or untouched one gets one retry per occurrence, so a key prompt is never repeated in a loop.
pub(crate) fn due(
    s: &Schedule,
    pending: Option<&Job>,
    last_run: Option<Timestamp>,
    now: &Zoned,
) -> Option<Act> {
    // True when `t` is before the latest occurrence.
    let before: Box<dyn Fn(Timestamp) -> bool> = match *s {
        Schedule::Every(interval) => Box::new(move |t: Timestamp| {
            // A `t` in the future (the clock went back) has not elapsed.
            u64::try_from(now.timestamp().as_second() - t.as_second()).is_ok_and(|d| d >= interval)
        }),
        Schedule::Daily(at) => {
            let today = now.date().to_datetime(at).to_zoned(now.time_zone().clone());
            let occ = match today {
                Ok(z) if z.timestamp() <= now.timestamp() => Some(z),
                _ => now
                    .date()
                    .yesterday()
                    .ok()
                    .and_then(|d| d.to_datetime(at).to_zoned(now.time_zone().clone()).ok()),
            }
            .map_or(Timestamp::MIN, |z| z.timestamp());
            Box::new(move |t: Timestamp| t < occ)
        }
    };
    match pending {
        None => last_run.is_none_or(&before).then_some(Act::Create),
        Some(j)
            if matches!(
                j.state,
                JobState::Failed | JobState::Blocked(BlockReason::NeedsTouch)
            ) && before(j.updated) =>
        {
            Some(Act::Retry(j.id.clone()))
        }
        Some(_) => None,
    }
}

/// The daemon's scheduler, run before every pass next to the copy rules'.
pub(crate) fn tick(paths: &Paths, now: &Zoned) {
    if let Err(e) = try_tick(paths, now) {
        tracing::warn!("schedule: {e:#}");
    }
}

fn try_tick(paths: &Paths, now: &Zoned) -> Result<()> {
    let cfg = Config::load(&paths.cfg)?;
    let store = Store::new(paths.queue.clone());
    let jobs = store.jobs()?;
    let unfinished = |j: &&Job| !matches!(j.state, JobState::Done | JobState::Canceled);
    let last = |name: &str| Status::read(&paths.status_file(name)).last_run;
    let retry = |id: &str| store.edit_control(Some(id), |c| c.retry += 1);

    let personal = [
        (
            cfg.schedule.personal,
            JobKind::Github { transport: None },
            1,
            "github",
        ),
        (
            cfg.schedule.local.filter(|_| !cfg.local.is_empty()),
            JobKind::Local,
            0,
            "local",
        ),
    ];
    for (s, kind, priority, name) in personal {
        let Some(s) = s else { continue };
        let pending = jobs.iter().filter(unfinished).find(|j| j.kind.same(&kind));
        match due(&s, pending, last(name), now) {
            Some(Act::Create) => {
                let id = store.create(&kind, &cfg.primary_uuid, priority)?.id;
                tracing::info!("schedule: queued {name} as {id}");
            }
            Some(Act::Retry(id)) => {
                retry(&id)?;
                tracing::info!("schedule: retrying {name} job {id}");
            }
            None => {}
        }
    }

    let Some(s) = cfg.schedule.public else {
        return Ok(());
    };
    let sets: Vec<&Job> = jobs
        .iter()
        .filter(unfinished)
        .filter(|j| matches!(j.kind, JobKind::Set { .. }))
        .collect();
    if sets.is_empty() {
        if due(&s, None, last("public"), now) == Some(Act::Create) {
            let cat = Catalog::embedded()?;
            let ids =
                public::enqueue_all(&store, &cat.select(&[], false)?, &cfg.primary_uuid, false)?;
            tracing::info!("schedule: queued {} public sets", ids.len());
        }
        return Ok(());
    }
    for j in sets {
        if let Some(Act::Retry(id)) = due(&s, Some(j), last("public"), now) {
            retry(&id)?;
            tracing::info!("schedule: retrying public job {id}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::tz::TimeZone;

    #[test]
    fn parse_both_forms() {
        let t = |h, m| Some(Schedule::Daily(Time::new(h, m, 0, 0).unwrap()));
        for (s, want) in [
            ("24:00:00", Some(Schedule::Every(86_400))),
            ("0:00:01", Some(Schedule::Every(1))),
            ("01:30", t(1, 30)),
            ("1:30", t(1, 30)),
            ("23:59", t(23, 59)),
            ("24:00", None),
            ("01:60", None),
            ("0:00:00", None),
            ("1:3", None),
            ("001:30", None),
            ("abc", None),
            ("", None),
        ] {
            assert_eq!(s.parse::<Schedule>().ok(), want, "{s:?}");
        }
        let e = "abc".parse::<Schedule>().unwrap_err().to_string();
        assert!(e.contains("H:MM:SS") && e.contains("HH:MM"), "{e}");
        assert_eq!(Schedule::Every(90).to_string(), "every 0:01:30");
        assert_eq!(t(1, 30).unwrap().to_string(), "daily at 01:30");
    }

    fn at(s: &str) -> Zoned {
        format!("{s}[UTC]").parse().unwrap()
    }

    fn job(state: JobState, updated: &str) -> Job {
        let mut j: Job = serde_json::from_str(
            r#"{"id":"1-2-3","kind":"local","priority":0,"state":"queued","attempts":0,"drive":"0123-ABCD","created":"2026-11-01T00:00:00Z","updated":"2026-11-01T00:00:00Z"}"#,
        )
        .unwrap();
        j.state = state;
        j.updated = updated.parse().unwrap();
        j
    }

    #[test]
    fn when_schedules_come_due() {
        let daily: Schedule = "01:30".parse().unwrap();
        let day: Schedule = "24:00:00".parse().unwrap();
        let ts = |s: &str| Some(s.parse::<Timestamp>().unwrap());
        let now = at("2026-11-14T12:00:00");

        assert_eq!(
            due(&daily, None, None, &now),
            Some(Act::Create),
            "never ran"
        );
        assert_eq!(due(&day, None, None, &now), Some(Act::Create));
        assert_eq!(
            due(&day, None, ts("2026-11-13T12:00:00Z"), &now),
            Some(Act::Create)
        );
        assert_eq!(due(&day, None, ts("2026-11-13T12:00:01Z"), &now), None);
        assert_eq!(
            due(&day, None, ts("2026-11-15T00:00:00Z"), &now),
            None,
            "clock went back"
        );

        let before = at("2026-11-14T01:00:00");
        assert_eq!(
            due(&daily, None, ts("2026-11-13T01:30:00Z"), &before),
            None,
            "yesterday's occurrence ran"
        );
        assert_eq!(
            due(&daily, None, ts("2026-11-13T01:30:00Z"), &now),
            Some(Act::Create),
            "today's is past"
        );
        assert_eq!(
            due(&daily, None, ts("2026-11-10T01:30:00Z"), &now),
            Some(Act::Create),
            "machine was off for days: once"
        );
        assert_eq!(
            due(&daily, None, ts("2026-11-14T09:00:00Z"), &now),
            None,
            "a manual run after 01:30 covers it"
        );

        for (state, why) in [
            (JobState::Queued, "queued"),
            (JobState::Blocked(BlockReason::Unmounted), "unmounted"),
            (JobState::Blocked(BlockReason::DriveAbsent), "absent"),
            (JobState::Paused, "paused"),
        ] {
            let j = job(state, "2026-11-01T00:00:00Z");
            assert_eq!(due(&daily, Some(&j), None, &now), None, "{why}");
        }
        for state in [JobState::Failed, JobState::Blocked(BlockReason::NeedsTouch)] {
            let old = job(state, "2026-11-13T23:00:00Z");
            assert_eq!(
                due(&daily, Some(&old), None, &now),
                Some(Act::Retry("1-2-3".into()))
            );
            let new = job(state, "2026-11-14T02:00:00Z");
            assert_eq!(due(&daily, Some(&new), None, &now), None, "{state}");
            assert_eq!(due(&day, Some(&new), None, &now), None);
        }
    }

    #[test]
    fn a_spring_forward_day_fires_once() {
        let tz = TimeZone::posix("EST5EDT,M3.2.0,M11.1.0").unwrap();
        // 02:30 does not exist on 2026-03-08: it runs at 03:30 EDT.
        let s: Schedule = "02:30".parse().unwrap();
        let mut last = Some(
            "2026-03-07T02:30"
                .parse::<jiff::civil::DateTime>()
                .unwrap()
                .to_zoned(tz.clone())
                .unwrap()
                .timestamp(),
        );
        let mut now = "2026-03-07T12:00"
            .parse::<jiff::civil::DateTime>()
            .unwrap()
            .to_zoned(tz)
            .unwrap();
        let mut fired = Vec::new();
        for _ in 0..(36 * 6) {
            if due(&s, None, last, &now) == Some(Act::Create) {
                fired.push(now.clone());
                last = Some(now.timestamp());
            }
            now = now
                .checked_add(jiff::SignedDuration::from_mins(10))
                .unwrap();
        }
        assert_eq!(fired.len(), 1, "{fired:?}");
        assert_eq!(
            fired[0].strftime("%F %H:%M").to_string(),
            "2026-03-08 03:30"
        );
    }
}
