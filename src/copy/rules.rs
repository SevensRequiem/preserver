//! `copy.toml`: the copies that repeat. One rule per target, keyed by its place, so running
//! `preserver copy -t` again for the same target replaces the rule instead of adding one.

use crate::catalog::{Catalog, RESERVED};
use crate::platform;
use crate::queue::{Job, JobKind, JobState, Target};
use crate::resolve::hex;
use anyhow::{Context, Result, bail};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

const HEADER: &str =
    "# Managed by 'preserver copy'. Change rules with 'preserver copy -t' and 'copy --remove'.\n";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rule {
    pub id: String,
    /// Seconds between runs.
    pub interval: u64,
    /// The `--sets` tokens as given, resolved per job, so a set added to the catalog later
    /// comes along.
    #[serde(default)]
    pub sets: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    pub target: Target,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    rule: Vec<Rule>,
}

/// The rule id of a target: stable, short, and never a job id (those have dashes).
pub(crate) fn rule_id(target: &Target) -> String {
    hex(&Sha256::digest(target.key().as_bytes()))[..12].to_string()
}

pub(crate) fn is_rule_id(s: &str) -> bool {
    s.len() == 12
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The file is hand-editable, so every rule is checked as it would be on the command line.
pub(crate) fn load(file: &Path) -> Result<Vec<Rule>> {
    let text = match std::fs::read_to_string(file) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        r => r.with_context(|| file.display().to_string())?,
    };
    let f: File = toml::from_str(&text).with_context(|| file.display().to_string())?;
    let cat = Catalog::embedded()?;
    for r in &f.rule {
        let ok = is_rule_id(&r.id) && r.id == rule_id(&r.target) && r.interval > 0;
        if !ok {
            bail!("{}: bad rule {:?}", file.display(), r.id);
        }
        r.target
            .validate()
            .and_then(|()| resolve_sets(&cat, &r.sets).map(drop))
            .with_context(|| format!("{}: rule {}", file.display(), r.id))?;
    }
    Ok(f.rule)
}

fn save(file: &Path, rules: Vec<Rule>) -> Result<()> {
    let body = toml::to_string(&File { rule: rules })?;
    platform::write_private(file, format!("{HEADER}{body}").as_bytes())
        .with_context(|| file.display().to_string())
}

/// Adds the rule, replacing the one for the same target. Returns whether one was replaced.
pub(crate) fn upsert(file: &Path, rule: Rule) -> Result<bool> {
    let mut rules = load(file)?;
    let before = rules.len();
    rules.retain(|r| r.id != rule.id);
    let replaced = rules.len() != before;
    rules.push(rule);
    save(file, rules)?;
    Ok(replaced)
}

/// Removes a rule; false when there is none with this id.
pub(crate) fn remove(file: &Path, id: &str) -> Result<bool> {
    let mut rules = load(file)?;
    let before = rules.len();
    rules.retain(|r| r.id != id);
    if rules.len() == before {
        return Ok(false);
    }
    save(file, rules)?;
    Ok(true)
}

/// `H:MM:SS`, at least one second; hours are unbounded.
pub(crate) fn parse_interval(s: &str) -> Result<u64> {
    let parts: Vec<&str> = s.split(':').collect();
    let num = |p: &str| {
        (!p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
            .then(|| p.parse::<u64>().ok())
            .flatten()
    };
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

pub(crate) fn show_interval(secs: u64) -> String {
    format!("{}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
}

/// `32G` is decimal (SD cards and sticks are sold that way), `32Gi` binary; a plain number is
/// bytes. A trailing `B` is allowed.
pub(crate) fn parse_size(s: &str) -> Result<u64> {
    let t = s.strip_suffix(['B', 'b']).unwrap_or(s);
    let split = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    let (digits, unit) = t.split_at(split);
    let mul: Option<u64> = match unit.to_ascii_lowercase().as_str() {
        "" => Some(1),
        "k" => Some(1_000),
        "m" => Some(1_000_000),
        "g" => Some(1_000_000_000),
        "t" => Some(1_000_000_000_000),
        "ki" => Some(1 << 10),
        "mi" => Some(1 << 20),
        "gi" => Some(1 << 30),
        "ti" => Some(1 << 40),
        _ => None,
    };
    digits
        .parse::<u64>()
        .ok()
        .zip(mul)
        .and_then(|(n, m)| n.checked_mul(m))
        .filter(|n| *n > 0)
        .with_context(|| {
            format!("bad size {s:?}: give a number with K, M, G or T (Ki, Gi... for binary)")
        })
}

fn check_sets(cat: &Catalog, sets: &[String]) -> Result<()> {
    if let Some(s) = sets
        .iter()
        .find(|s| !RESERVED.contains(&s.as_str()) && !cat.sets.iter().any(|c| c.name == **s))
    {
        bail!("no set {s:?}; 'preserver public --list' shows them, besides personal and kit");
    }
    Ok(())
}

/// `--sets`: catalog sets, `personal` and `kit`; `-name` leaves one out. Without a positive
/// name every set is wanted; `personal` comes along unless `-personal` says otherwise.
pub(crate) fn resolve_sets(cat: &Catalog, tokens: &[String]) -> Result<Vec<String>> {
    let (minus, plus): (Vec<&String>, Vec<&String>) = tokens
        .iter()
        .filter(|t| !t.is_empty())
        .partition(|t| t.starts_with('-'));
    let minus: Vec<String> = minus.iter().map(|t| t[1..].to_string()).collect();
    let mut out: Vec<String> = if plus.is_empty() {
        RESERVED
            .iter()
            .map(ToString::to_string)
            .chain(cat.sets.iter().map(|s| s.name.clone()))
            .collect()
    } else {
        let mut v = vec!["personal".to_string()];
        v.extend(plus.into_iter().cloned());
        v
    };
    check_sets(cat, &out)?;
    check_sets(cat, &minus)?;
    out.retain(|s| !minus.contains(s));
    let mut seen = std::collections::HashSet::new();
    out.retain(|s| seen.insert(s.clone()));
    if out.is_empty() {
        bail!("--sets leaves nothing to copy");
    }
    Ok(out)
}

pub(crate) enum Act {
    Create(Rule),
    Retry(String),
}

/// What the daemon owes the rules at `now`: a job for a rule whose last run is an interval
/// old (or that never ran), a retry for a rule's failed job once an interval has passed since.
/// A rule with a waiting or blocked job gets nothing: drive events retry blocked jobs.
pub(crate) fn due(
    rules: &[Rule],
    jobs: &[Job],
    last: &HashMap<String, Timestamp>,
    now: Timestamp,
) -> Vec<Act> {
    let elapsed = |t: Timestamp, interval: u64| {
        u64::try_from(now.as_second() - t.as_second()).is_ok_and(|d| d >= interval)
    };
    let mut acts = Vec::new();
    for r in rules {
        let pending = jobs.iter().find(|j| {
            matches!(&j.kind, JobKind::Copy { rule: Some(id), .. } if *id == r.id)
                && !matches!(j.state, JobState::Done | JobState::Canceled)
        });
        match pending {
            Some(j) if j.state == JobState::Failed && elapsed(j.updated, r.interval) => {
                acts.push(Act::Retry(j.id.clone()));
            }
            None if last.get(&r.id).is_none_or(|t| elapsed(*t, r.interval)) => {
                acts.push(Act::Create(r.clone()));
            }
            _ => {}
        }
    }
    acts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    fn drive_rule(id: &str, subdir: &str) -> Rule {
        let target = Target::Drive {
            id: id.parse().unwrap(),
            subdir: subdir.into(),
            label: "STICK".into(),
        };
        Rule {
            id: rule_id(&target),
            interval: 86_400,
            sets: vec!["personal".into(), "keys".into()],
            size: Some(32_000_000_000),
            target,
        }
    }

    #[test]
    fn rule_add_list_replace_and_remove() {
        let tmp = TempDir::new();
        let file = tmp.path().join("cfg/copy.toml");
        assert_eq!(load(&file).unwrap(), Vec::<Rule>::new());

        let a = drive_rule("0123-ABCD", "");
        let b = drive_rule("0123-ABCD", "backup/one");
        let dir_target = Target::Dir {
            path: "/srv/copy".into(),
        };
        let c = Rule {
            id: rule_id(&dir_target),
            interval: 3600,
            sets: Vec::new(),
            size: None,
            target: dir_target,
        };
        assert_ne!(a.id, b.id, "the subdir is part of the place");
        assert!(!upsert(&file, a.clone()).unwrap());
        assert!(!upsert(&file, b.clone()).unwrap());
        assert!(!upsert(&file, c.clone()).unwrap());
        assert_eq!(load(&file).unwrap(), [a.clone(), b.clone(), c.clone()]);
        assert!(
            std::fs::read_to_string(&file)
                .unwrap()
                .starts_with("# Managed by")
        );

        // The same place again, spelled another way, replaces its rule.
        let mut a2 = drive_rule("0123abcd", "");
        a2.interval = 60;
        assert_eq!(a2.id, a.id);
        assert!(upsert(&file, a2.clone()).unwrap());
        assert_eq!(load(&file).unwrap(), [b.clone(), c.clone(), a2]);

        assert!(remove(&file, &b.id).unwrap());
        assert!(!remove(&file, &b.id).unwrap());
        assert_eq!(load(&file).unwrap().len(), 2);
    }

    #[test]
    fn hand_edits_are_checked() {
        let tmp = TempDir::new();
        let file = tmp.path().join("copy.toml");
        let good = drive_rule("0123-ABCD", "");
        upsert(&file, good.clone()).unwrap();
        let text = std::fs::read_to_string(&file).unwrap();
        for (name, bad) in [
            (
                "id not of the target",
                text.replace(&good.id, "000000000000"),
            ),
            (
                "escaping subdir",
                text.replace("subdir = \"\"", "subdir = \"../x\""),
            ),
            ("unknown set", text.replace("\"keys\"", "\"nope\"")),
            ("zero interval", text.replace("86400", "0")),
            ("unknown field", format!("{text}\nextra = 1\n")),
        ] {
            assert_ne!(bad, text, "{name}");
            std::fs::write(&file, bad).unwrap();
            assert!(load(&file).is_err(), "{name}");
        }
    }

    #[test]
    fn intervals_and_sizes() {
        for (s, want) in [
            ("24:00:00", Some(86_400)),
            ("0:00:01", Some(1)),
            ("168:30:05", Some(168 * 3600 + 30 * 60 + 5)),
            ("0:00:00", None),
            ("1:60:00", None),
            ("1:00:60", None),
            ("1:0:00", None),
            ("24h", None),
            ("-1:00:00", None),
            ("", None),
        ] {
            assert_eq!(parse_interval(s).ok(), want, "{s}");
        }
        assert_eq!(show_interval(86_400 + 61), "24:01:01");
        for (s, want) in [
            ("32G", Some(32_000_000_000)),
            ("32GB", Some(32_000_000_000)),
            ("16Gi", Some(16 << 30)),
            ("2T", Some(2_000_000_000_000)),
            ("512", Some(512)),
            ("0G", None),
            ("G", None),
            ("1.5G", None),
            ("3X", None),
            ("99999999999T", None),
        ] {
            assert_eq!(parse_size(s).ok(), want, "{s}");
        }
    }

    #[test]
    fn sets_tokens() {
        let cat = Catalog::embedded().unwrap();
        let t =
            |v: &[&str]| resolve_sets(&cat, &v.iter().map(ToString::to_string).collect::<Vec<_>>());
        let all = t(&[]).unwrap();
        assert_eq!(all.len(), cat.sets.len() + 2);
        assert_eq!(all[..2], ["personal", "kit"]);
        assert_eq!(
            t(&["keys", "specs"]).unwrap(),
            ["personal", "keys", "specs"]
        );
        assert_eq!(t(&["keys", "-personal"]).unwrap(), ["keys"]);
        assert_eq!(t(&["keys", "keys"]).unwrap(), ["personal", "keys"]);
        let no_personal = t(&["-personal"]).unwrap();
        assert!(!no_personal.contains(&"personal".to_string()));
        assert!(no_personal.contains(&"kit".to_string()));
        assert!(t(&["nope"]).is_err());
        assert!(t(&["-nope"]).is_err());
        assert!(t(&["personal", "-personal"]).is_err());
    }

    fn job(rule: &str, state: JobState, updated: &str) -> Job {
        let mut j: Job = serde_json::from_str(
            r#"{"id":"1-2-3","kind":{"set":{"set":"s"}},"priority":0,"state":"queued","attempts":0,"drive":"0123-ABCD","created":"2026-11-13T00:00:00Z","updated":"2026-11-13T00:00:00Z"}"#,
        )
        .unwrap();
        let r = drive_rule("0123-ABCD", "");
        j.kind = JobKind::Copy {
            target: r.target,
            sets: r.sets,
            size: None,
            rule: Some(rule.into()),
        };
        j.state = state;
        j.updated = updated.parse().unwrap();
        j
    }

    #[test]
    fn rules_come_due() {
        let r = drive_rule("0123-ABCD", "");
        let now: Timestamp = "2026-11-14T12:00:00Z".parse().unwrap();
        let summary = |acts: Vec<Act>| -> Vec<String> {
            acts.into_iter()
                .map(|a| match a {
                    Act::Create(r) => format!("create {}", r.id),
                    Act::Retry(id) => format!("retry {id}"),
                })
                .collect()
        };
        let create = vec![format!("create {}", r.id)];
        let last = |t: &str| HashMap::from([(r.id.clone(), t.parse().unwrap())]);
        let rules = std::slice::from_ref(&r);

        assert_eq!(
            summary(due(rules, &[], &HashMap::new(), now)),
            create,
            "never ran"
        );
        assert_eq!(
            summary(due(rules, &[], &last("2026-11-13T12:00:00Z"), now)),
            create,
            "a day ago"
        );
        assert!(
            due(rules, &[], &last("2026-11-13T12:00:01Z"), now).is_empty(),
            "not yet"
        );
        assert!(
            due(rules, &[], &last("2026-11-15T00:00:00Z"), now).is_empty(),
            "clock went back"
        );

        let blocked = job(
            &r.id,
            JobState::Blocked(crate::queue::BlockReason::DriveAbsent),
            "2026-11-01T00:00:00Z",
        );
        assert!(
            due(rules, &[blocked], &HashMap::new(), now).is_empty(),
            "blocked waits for the drive"
        );
        let failed_old = job(&r.id, JobState::Failed, "2026-11-13T11:00:00Z");
        assert_eq!(
            summary(due(rules, &[failed_old], &HashMap::new(), now)),
            ["retry 1-2-3"]
        );
        let failed_new = job(&r.id, JobState::Failed, "2026-11-14T11:00:00Z");
        assert!(due(rules, &[failed_new], &HashMap::new(), now).is_empty());
        let done = job(&r.id, JobState::Done, "2026-11-14T11:00:00Z");
        assert_eq!(
            summary(due(rules, &[done], &HashMap::new(), now)),
            create,
            "finished jobs do not count"
        );
        let other = job("ffffffffffff", JobState::Queued, "2026-11-14T11:00:00Z");
        assert_eq!(summary(due(rules, &[other], &HashMap::new(), now)), create);
    }
}
