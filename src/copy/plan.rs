//! Auto-fit: what goes on the target, as a pure function of what the primary has, what the
//! target holds and how much room it has. Re-run every time, so a target that shrank (a
//! smaller `--size`, other files on the drive) sheds sets instead of failing.

use crate::public::gb;
use anyhow::{Result, bail};
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

/// The FAT32 file size limit: 4 GiB less one byte.
pub(crate) const FAT_MAX: u64 = 0xFFFF_FFFF;
pub(crate) const FAT_REASON: &str = "FAT32 4 GiB limit";

/// What the target filesystem allows.
#[derive(Debug, Clone)]
pub(crate) struct Limits {
    pub fs: String,
    pub max_file: Option<u64>,
    pub links: bool,
    /// Windows name rules, and names that differ only in case collide.
    pub windows: bool,
    pub cluster: u64,
}

impl Limits {
    pub(crate) fn of(fstype: &str, cluster: u64) -> Self {
        let fat = matches!(fstype, "vfat" | "fat" | "msdos");
        let windows = fat || matches!(fstype, "exfat" | "ntfs" | "ntfs3" | "ntfs-3g" | "fuseblk");
        Self {
            fs: fstype.to_string(),
            max_file: fat.then_some(FAT_MAX),
            links: !windows,
            windows,
            cluster: cluster.max(1),
        }
    }

    /// The space a file of `len` bytes takes: whole clusters.
    pub(crate) fn fp(&self, len: u64) -> u64 {
        len.div_ceil(self.cluster) * self.cluster
    }

    /// SET.toml and SHA256SUMS of a version with `n` files, roughly.
    fn meta(&self, n: u64) -> u64 {
        self.fp(400 * n + 1024) + self.fp(100 * n + 512)
    }

    /// The kit goes as one tar where links and names would not survive.
    pub(crate) fn kit_tar(&self) -> bool {
        self.windows
    }

    fn refuse(&self, rel: &str, len: u64) -> Option<String> {
        if self.max_file.is_some_and(|m| len > m) {
            return Some(FAT_REASON.to_string());
        }
        (self.windows && rel.split('/').any(bad_windows_name))
            .then(|| format!("name not allowed on {}", self.fs))
    }

    /// The files the filesystem takes; the rest go to `skipped` with the reason.
    pub(crate) fn admit(
        &self,
        files: &[FileEnt],
        prefix: &str,
        skipped: &mut Vec<(String, String)>,
    ) -> Vec<FileEnt> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for f in files {
            let reason = self.refuse(&f.rel, f.len).or_else(|| {
                (self.windows && !seen.insert(f.rel.to_lowercase()))
                    .then(|| "name differs only in case".to_string())
            });
            match reason {
                Some(r) => skipped.push((format!("{prefix}{}", f.rel), r)),
                None => out.push(f.clone()),
            }
        }
        out
    }
}

fn bad_windows_name(c: &str) -> bool {
    if c.chars()
        .any(|ch| ch.is_control() || r#"<>:"\|?*"#.contains(ch))
        || c.ends_with(['.', ' '])
    {
        return true;
    }
    let stem = c.split('.').next().unwrap_or(c).to_ascii_uppercase();
    let numbered = stem.len() == 4
        && (stem.starts_with("COM") || stem.starts_with("LPT"))
        && matches!(stem.as_bytes()[3], b'1'..=b'9');
    numbered || matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FileEnt {
    pub rel: String,
    pub len: u64,
    /// Empty for personal files: their hash is taken while copying.
    pub sha256: String,
}

/// A set version on the target.
#[derive(Debug, Clone, Default)]
pub(crate) struct Have {
    pub version: String,
    pub variant: String,
    pub bytes: u64,
    pub sums: HashMap<String, String>,
}

/// A selected catalog set: the primary's newest version and, per variant, its files.
#[derive(Debug, Clone)]
pub(crate) struct SetIn {
    pub name: String,
    /// Empty when the primary has no version of it.
    pub version: String,
    pub variants: Vec<(String, Vec<FileEnt>)>,
    pub have: Option<Have>,
    /// What a set dir with no visible version still holds (an interrupted first copy's
    /// stage): room that comes back when the set is replaced or deleted.
    pub stale: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct KitIn {
    /// What it takes on the target, tar or tree.
    pub bytes: u64,
    pub unchanged: bool,
    /// What the kit on the target takes now.
    pub have_bytes: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct Inputs {
    /// Personal files that need copying, already admitted.
    pub personal: Vec<FileEnt>,
    /// Personal files on the target that stay as they are.
    pub personal_kept: u64,
    /// `None`: not wanted. `Err`: wanted but impossible, with the reason.
    pub kit: Option<Result<KitIn, String>>,
    /// Selected sets in priority order.
    pub sets: Vec<SetIn>,
    /// Everything else under the target's `preserver/` that stays: unselected sets above all.
    pub other_kept: u64,
    pub free: u64,
    pub cap: Option<u64>,
    pub limits: Limits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Unchanged,
    New,
    /// `in_place`: there is no room for the new version beside the old, so the old one goes
    /// out of sight first. Either way no half-replaced version is ever visible.
    Replace {
        in_place: bool,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct SetStep {
    pub name: String,
    pub version: String,
    pub variant: String,
    pub files: Vec<FileEnt>,
    pub bytes: u64,
    pub action: Action,
}

#[derive(Debug, Clone)]
pub(crate) struct KitStep {
    pub tar: bool,
    pub action: Action,
    pub bytes: u64,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Plan {
    pub personal: Vec<FileEnt>,
    pub personal_bytes: u64,
    pub kit: Option<KitStep>,
    /// In the order they run: shrinking replacements first, so their room is free in time.
    pub sets: Vec<SetStep>,
    /// Selected sets (and `kit`) on the target that lost their place to higher priorities.
    pub deletes: Vec<String>,
    pub dropped: Vec<(String, String)>,
    pub skipped: Vec<(String, String)>,
    pub budget: u64,
    pub used: u64,
    /// Bytes to write this run.
    pub write: u64,
    /// Free bytes the copy never goes below while it works.
    pub reserve_floor: u64,
}

impl SetIn {
    /// What the set takes on the target now.
    fn held(&self) -> u64 {
        self.have.as_ref().map_or(0, |h| h.bytes) + self.stale
    }

    /// Admitted candidates, biggest first, with the variants that came out the same merged.
    fn candidates(&self, limits: &Limits, skipped: &mut Vec<(String, String)>) -> Vec<SetStep> {
        let mut out: Vec<(SetStep, Vec<(String, String)>)> = Vec::new();
        for (variant, files) in &self.variants {
            let mut sk = Vec::new();
            let files = limits.admit(files, &format!("{}/", self.name), &mut sk);
            if files.is_empty() {
                skipped.extend(sk);
                continue;
            }
            let bytes = files.iter().map(|f| limits.fp(f.len)).sum::<u64>()
                + limits.meta(files.len() as u64);
            out.push((
                SetStep {
                    name: self.name.clone(),
                    version: self.version.clone(),
                    variant: variant.clone(),
                    files,
                    bytes,
                    action: Action::New,
                },
                sk,
            ));
        }
        out.sort_by_key(|c| std::cmp::Reverse(c.0.bytes));
        let mut kept: Vec<(SetStep, Vec<(String, String)>)> = Vec::new();
        for c in out {
            if !kept.iter().any(|k| k.0.files == c.0.files) {
                kept.push(c);
            }
        }
        kept.into_iter().map(|(s, _)| s).collect()
    }
}

/// The room a step needs beside what is there, and the free space after it.
fn place(sim: &mut u64, side_cost: u64, new: u64, old: u64) -> bool {
    let in_place = side_cost > *sim;
    *sim = (*sim + old).saturating_sub(new);
    in_place
}

/// Greedy by priority: each set takes its biggest variant that still fits, a set that fits in
/// none is dropped and lower ones still get their chance. Personal files must fit, or the
/// copy fails: they are the reason the copy exists.
#[expect(
    clippy::too_many_lines,
    reason = "one greedy pass: budget, personal, kit, sets, then the order of writes"
)]
pub(crate) fn plan(inp: &Inputs) -> Result<Plan> {
    let lim = &inp.limits;
    let mut p = Plan::default();
    let mirrored = |s: &&SetIn| !s.version.is_empty();
    let replaceable: u64 = inp
        .sets
        .iter()
        .filter(mirrored)
        .map(SetIn::held)
        .sum::<u64>()
        + match &inp.kit {
            Some(Ok(k)) => k.have_bytes,
            _ => 0,
        };
    let unmirrored: u64 = inp
        .sets
        .iter()
        .filter(|s| s.version.is_empty())
        .map(SetIn::held)
        .sum();
    let avail = inp.free + replaceable;
    let fixed = inp.personal_kept + inp.other_kept + unmirrored;
    let base = inp
        .cap
        .map_or(avail, |c| avail.min(c.saturating_sub(fixed)));
    let reserve = base / 20;
    p.budget = base - reserve;
    p.reserve_floor = if base == avail { reserve } else { 0 };

    p.personal_bytes = inp.personal.iter().map(|f| lim.fp(f.len)).sum();
    if p.personal_bytes > p.budget {
        bail!(
            "personal files need {} but the target has room for {}: free space on it or give a bigger --size",
            gb(p.personal_bytes),
            gb(p.budget)
        );
    }
    p.personal.clone_from(&inp.personal);
    let mut left = p.budget - p.personal_bytes;
    p.used = p.personal_bytes;
    p.write = p.personal_bytes;
    let mut sim = inp.free.saturating_sub(p.reserve_floor);
    sim = sim.saturating_sub(p.personal_bytes);

    match &inp.kit {
        None => {}
        Some(Err(why)) => p.dropped.push(("kit".into(), why.clone())),
        Some(Ok(k)) => {
            let cost = if k.unchanged {
                k.have_bytes
            } else {
                lim.fp(k.bytes)
            };
            if cost <= left {
                left -= cost;
                p.used += cost;
                let new = lim.fp(k.bytes);
                let action = if k.unchanged {
                    Action::Unchanged
                } else {
                    // The tar is one file and a tree has no reusable parts worth tracking.
                    let in_place = place(&mut sim, new, new, k.have_bytes);
                    if k.have_bytes == 0 {
                        Action::New
                    } else {
                        Action::Replace { in_place }
                    }
                };
                if action != Action::Unchanged {
                    p.write += cost;
                }
                p.kit = Some(KitStep {
                    tar: lim.kit_tar(),
                    action,
                    bytes: cost,
                });
            } else {
                p.dropped.push((
                    "kit".into(),
                    format!("needs {}, {} left", gb(cost), gb(left)),
                ));
                if k.have_bytes > 0 {
                    p.deletes.push("kit".into());
                }
            }
        }
    }

    let mut chosen = Vec::new();
    for s in &inp.sets {
        if s.version.is_empty() {
            p.dropped
                .push((s.name.clone(), "no versioned files on the primary (git and repo mirror trees are not copied until phase 4)".into()));
            continue;
        }
        let mut sk = Vec::new();
        let cands = s.candidates(lim, &mut sk);
        if cands.is_empty() {
            let fat = !sk.is_empty() && sk.iter().all(|(_, r)| r == FAT_REASON);
            let why = if fat {
                "all files exceed the FAT32 4 GiB limit; format the target as exFAT".to_string()
            } else {
                format!("none of its files can go on {}", lim.fs)
            };
            p.dropped.push((s.name.clone(), why));
            if s.held() > 0 {
                p.deletes.push(s.name.clone());
            }
            continue;
        }
        let same = |c: &SetStep| {
            s.have
                .as_ref()
                .is_some_and(|h| h.version == c.version && h.variant == c.variant)
        };
        let cost = |c: &SetStep| {
            if same(c) {
                s.have.as_ref().map_or(c.bytes, |h| h.bytes)
            } else {
                c.bytes
            }
        };
        let Some(mut c) = cands.iter().find(|c| cost(c) <= left).cloned() else {
            let small = &cands[cands.len() - 1];
            p.dropped.push((
                s.name.clone(),
                format!(
                    "the smallest variant ({}) needs {}, {} left",
                    small.variant,
                    gb(small.bytes),
                    gb(left)
                ),
            ));
            if s.held() > 0 {
                p.deletes.push(s.name.clone());
            }
            continue;
        };
        // The skips of the chosen variant only: what a smaller one leaves out is not news.
        if let Some((_, files)) = s.variants.iter().find(|(v, _)| *v == c.variant) {
            lim.admit(files, &format!("{}/", s.name), &mut p.skipped);
        }
        let n = cost(&c);
        left -= n;
        p.used += n;
        c.bytes = n;
        c.action = if same(&c) {
            Action::Unchanged
        } else if s.have.is_some() {
            Action::Replace { in_place: false }
        } else {
            Action::New
        };
        chosen.push(c);
    }

    // Free space in the order things happen: deletions, then shrinking replacements.
    for d in &p.deletes {
        sim += if d == "kit" {
            match &inp.kit {
                Some(Ok(k)) => k.have_bytes,
                _ => 0,
            }
        } else {
            inp.sets
                .iter()
                .find(|s| s.name == *d)
                .map_or(0, SetIn::held)
        };
    }
    let have_of = |name: &str| {
        inp.sets
            .iter()
            .find(|s| s.name == name)
            .and_then(|s| s.have.clone())
            .unwrap_or_default()
    };
    chosen.sort_by_key(|c| {
        let shrinks =
            matches!(c.action, Action::Replace { .. }) && c.bytes <= have_of(&c.name).bytes;
        !shrinks
    });
    for c in &mut chosen {
        let have = have_of(&c.name);
        let reused: u64 = c
            .files
            .iter()
            .filter(|f| have.sums.get(&f.rel) == Some(&f.sha256))
            .map(|f| lim.fp(f.len))
            .sum();
        match c.action {
            Action::Unchanged => {}
            Action::New => {
                place(&mut sim, c.bytes, c.bytes, 0);
                p.write += c.bytes;
            }
            Action::Replace { .. } => {
                let side = if lim.links {
                    c.bytes - reused.min(c.bytes)
                } else {
                    c.bytes
                };
                let in_place = place(&mut sim, side, c.bytes, have.bytes);
                c.action = Action::Replace { in_place };
                p.write += if lim.links || in_place {
                    c.bytes - reused.min(c.bytes)
                } else {
                    c.bytes
                };
            }
        }
    }
    p.sets = chosen;
    p.skipped.sort();
    p.skipped.dedup();
    Ok(p)
}

/// The plan as `--dry-run` prints it, and as a run logs it before it starts.
pub(crate) fn render(p: &Plan, target: &str, lim: &Limits) -> String {
    let mut o = String::new();
    let _ = writeln!(
        o,
        "copy to {target} ({}, {} KiB clusters): budget {} (5% kept free), using {}, writing {}",
        lim.fs,
        lim.cluster >> 10,
        gb(p.budget),
        gb(p.used),
        gb(p.write)
    );
    let act = |a: Action| match a {
        Action::Unchanged => "unchanged",
        Action::New => "new",
        Action::Replace { in_place: false } => "replace",
        Action::Replace { in_place: true } => "replace in place",
    };
    let _ = writeln!(
        o,
        "  {:<16} {:>6} files {:>10}",
        "personal",
        p.personal.len(),
        gb(p.personal_bytes)
    );
    if let Some(k) = &p.kit {
        let what = if k.tar { "kit.tar" } else { "tree" };
        let _ = writeln!(
            o,
            "  {:<16} {what:>12} {:>10}  {}",
            "kit",
            gb(k.bytes),
            act(k.action)
        );
    }
    for s in &p.sets {
        let _ = writeln!(
            o,
            "  {:<16} {:<12} {:<10} {:>10}  {}",
            s.name,
            s.version,
            s.variant,
            gb(s.bytes),
            act(s.action)
        );
    }
    if !p.deletes.is_empty() {
        let _ = writeln!(o, "removing for room: {}", p.deletes.join(", "));
    }
    if !p.dropped.is_empty() {
        let _ = writeln!(o, "left out:");
        for (n, why) in &p.dropped {
            let _ = writeln!(o, "  {n}: {why}");
        }
    }
    if !p.skipped.is_empty() {
        let _ = writeln!(o, "files skipped:");
        for (rel, why) in &p.skipped {
            let _ = writeln!(o, "  {rel}: {why}");
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::Catalog;

    const GB: u64 = 1_000_000_000;

    /// The catalog as the primary would hold it, sized by its estimates: each source in pieces
    /// of at most 1 GB, so no limit but room decides.
    fn catalog_sets() -> Vec<SetIn> {
        let cat = Catalog::embedded().unwrap();
        let mut sets: Vec<_> = cat.sets.iter().collect();
        sets.sort_by_key(|s| s.priority);
        sets.into_iter()
            .map(|set| {
                let variants = set
                    .variants()
                    .into_iter()
                    .map(|v| {
                        let mut files = Vec::new();
                        for name in &v.sources {
                            let src = set.sources.iter().find(|s| s.name == *name).unwrap();
                            let est = if src.est > 0.0 {
                                src.est
                            } else {
                                set.estimate / f64::from(u32::try_from(set.sources.len()).unwrap())
                            };
                            #[expect(
                                clippy::cast_possible_truncation,
                                clippy::cast_sign_loss,
                                reason = "test sizes"
                            )]
                            let mut left = (est * 1e9) as u64;
                            let mut i = 0;
                            while left > 0 {
                                let len = left.min(GB);
                                files.push(FileEnt {
                                    rel: format!("{name}/p{i}"),
                                    len,
                                    sha256: format!("{name}-{i}"),
                                });
                                left -= len;
                                i += 1;
                            }
                        }
                        (v.name, files)
                    })
                    .collect();
                SetIn {
                    name: set.name.clone(),
                    version: "2026-11-01".into(),
                    variants,
                    have: None,
                    stale: 0,
                }
            })
            .collect()
    }

    fn inputs(free: u64, cap: Option<u64>) -> Inputs {
        Inputs {
            personal: vec![FileEnt {
                rel: "github-repos-personal/all.bundle.age".into(),
                len: GB,
                sha256: String::new(),
            }],
            personal_kept: 0,
            kit: Some(Ok(KitIn {
                bytes: GB / 2,
                unchanged: false,
                have_bytes: 0,
            })),
            sets: catalog_sets(),
            other_kept: 0,
            free,
            cap,
            limits: Limits::of("ext4", 4096),
        }
    }

    fn chosen(p: &Plan) -> Vec<(&str, &str)> {
        p.sets
            .iter()
            .map(|s| (s.name.as_str(), s.variant.as_str()))
            .collect()
    }

    /// What the target holds after `p` ran.
    fn applied(mut inp: Inputs, p: &Plan) -> Inputs {
        for s in &mut inp.sets {
            s.have = p.sets.iter().find(|c| c.name == s.name).map(|c| Have {
                version: c.version.clone(),
                variant: c.variant.clone(),
                bytes: c.bytes,
                sums: c
                    .files
                    .iter()
                    .map(|f| (f.rel.clone(), f.sha256.clone()))
                    .collect(),
            });
        }
        inp.personal_kept += p.personal_bytes;
        inp.personal.clear();
        if let Some(Ok(k)) = &mut inp.kit {
            k.have_bytes = p.kit.as_ref().map_or(0, |s| s.bytes);
            k.unchanged = k.have_bytes > 0;
        }
        inp
    }

    #[test]
    fn fits_sticks_cards_and_disks() {
        let biggest: u64 = {
            let inp = inputs(0, None);
            inp.sets
                .iter()
                .map(|s| s.candidates(&inp.limits, &mut Vec::new())[0].bytes)
                .sum()
        };
        let mut prev_count = 0;
        for size in [16 * GB, 32 * GB, 128 * GB, 2000 * GB] {
            let p = plan(&inputs(size, None)).unwrap();
            assert_eq!(p.budget, size - size / 20, "{size}");
            assert_eq!(p.reserve_floor, size / 20);
            assert!(p.used <= p.budget, "{size}: {} > {}", p.used, p.budget);
            assert_eq!(p.used, p.write, "an empty target writes all it uses");
            assert!(p.kit.is_some(), "{size}: the kit is small and early");
            let names: Vec<_> = p.sets.iter().map(|s| s.name.as_str()).collect();
            for top in ["keys", "specs", "kernel"] {
                assert!(names.contains(&top), "{size}: {top} missing from {names:?}");
            }
            assert!(p.sets.iter().all(|s| s.action == Action::New));
            assert_eq!(
                p.sets.len() + p.dropped.len(),
                inp_sets_len(),
                "every set accounted for"
            );
            assert!(
                p.sets.len() >= prev_count,
                "{size}: more room never means fewer sets"
            );
            prev_count = p.sets.len();
            no_set_lost_its_place_to_a_lower_one(&p);
            if size == 2000 * GB && biggest + 2 * GB < p.budget {
                assert!(
                    p.sets
                        .iter()
                        .all(|s| s.variant == candidates_first(&s.name)),
                    "{:?}",
                    chosen(&p)
                );
                assert!(p.dropped.is_empty(), "{:?}", p.dropped);
            }
            if size == 16 * GB {
                assert!(p.dropped.len() > 1, "a 16G stick cannot hold everything");
                let isos = p.sets.iter().find(|s| s.name == "isos");
                assert!(isos.is_none_or(|s| s.variant != "full"), "{:?}", chosen(&p));
            }
        }
    }

    /// Greedy by priority: a set is left out only when its smallest variant does not fit in what
    /// the sets above it left.
    fn no_set_lost_its_place_to_a_lower_one(p: &Plan) {
        let inp = inputs(0, None);
        let mut left = p.budget - p.personal_bytes - p.kit.as_ref().map_or(0, |k| k.bytes);
        for s in &inp.sets {
            if let Some(c) = p.sets.iter().find(|c| c.name == s.name) {
                left -= c.bytes;
            } else {
                let smallest = s
                    .candidates(&inp.limits, &mut Vec::new())
                    .last()
                    .unwrap()
                    .bytes;
                assert!(smallest > left, "{} was left out with {left} left", s.name);
            }
        }
    }

    fn inp_sets_len() -> usize {
        catalog_sets().len()
    }

    fn candidates_first(name: &str) -> String {
        let inp = inputs(0, None);
        let s = inp.sets.iter().find(|s| s.name == name).unwrap();
        s.candidates(&inp.limits, &mut Vec::new())[0]
            .variant
            .clone()
    }

    #[test]
    fn rerun_is_unchanged_and_shrinking_drops_low_priorities() {
        let first = inputs(128 * GB, None);
        let p1 = plan(&first).unwrap();
        let again = applied(first.clone(), &p1);
        let mut again_free = again.clone();
        again_free.free = 128 * GB - p1.used;
        let p2 = plan(&again_free).unwrap();
        assert_eq!(chosen(&p2), chosen(&p1));
        assert!(p2.sets.iter().all(|s| s.action == Action::Unchanged));
        assert_eq!(p2.write, 0);
        assert_eq!(p2.deletes, Vec::<String>::new());

        // The same drive, now capped at 32G.
        let mut small = again_free.clone();
        small.cap = Some(32 * GB);
        let p3 = plan(&small).unwrap();
        assert!(
            p3.used <= p3.budget
                && p3.budget == 32 * GB - p1.personal_bytes - (32 * GB - p1.personal_bytes) / 20
        );
        assert!(!p3.deletes.is_empty(), "something has to go");
        for d in &p3.deletes {
            assert!(
                p1.sets.iter().any(|s| s.name == *d),
                "only what was there is removed"
            );
            assert!(!p3.sets.iter().any(|s| s.name == *d));
        }
        let keys = p3.sets.iter().find(|s| s.name == "keys").unwrap();
        assert_eq!(keys.action, Action::Unchanged, "the top set stays put");
    }

    fn one_set(files: &[FileEnt], variants: &[(&str, &[&str])]) -> SetIn {
        SetIn {
            name: "s".into(),
            version: "v2".into(),
            variants: variants
                .iter()
                .map(|(n, srcs)| {
                    (
                        (*n).to_string(),
                        files
                            .iter()
                            .filter(|f| srcs.iter().any(|s| f.rel.starts_with(&format!("{s}/"))))
                            .cloned()
                            .collect(),
                    )
                })
                .collect(),
            have: None,
            stale: 0,
        }
    }

    fn f(rel: &str, len: u64) -> FileEnt {
        FileEnt {
            rel: rel.into(),
            len,
            sha256: rel.into(),
        }
    }

    fn bare(sets: Vec<SetIn>, free: u64, fs: &str) -> Inputs {
        Inputs {
            personal: Vec::new(),
            personal_kept: 0,
            kit: None,
            sets,
            other_kept: 0,
            free,
            cap: None,
            limits: Limits::of(fs, 1),
        }
    }

    #[test]
    fn fat_skips_big_files_and_says_so() {
        let files = vec![f("a/big.iso", FAT_MAX + 1), f("a/small", 10), f("b/x", 10)];
        let s = one_set(&files, &[("full", &["a", "b"])]);
        let p = plan(&bare(vec![s.clone()], 100 * GB, "vfat")).unwrap();
        assert_eq!(p.sets[0].files.len(), 2);
        assert_eq!(
            p.skipped,
            [("s/a/big.iso".to_string(), FAT_REASON.to_string())]
        );
        assert!(
            render(&p, "STICK", &Limits::of("vfat", 1)).contains("s/a/big.iso: FAT32 4 GiB limit")
        );

        let p = plan(&bare(vec![s], 100 * GB, "exfat")).unwrap();
        assert_eq!(p.sets[0].files.len(), 3, "exFAT has no such limit");

        let only_big = one_set(&[f("a/big", FAT_MAX + 1)], &[("full", &["a"])]);
        let p = plan(&bare(vec![only_big], 100 * GB, "vfat")).unwrap();
        assert!(p.sets.is_empty());
        assert!(
            p.dropped[0].1.contains("format the target as exFAT"),
            "{:?}",
            p.dropped
        );
    }

    #[test]
    fn windows_names_and_case() {
        let lim = Limits::of("exfat", 1);
        let mut sk = Vec::new();
        let files = [
            f("a/ok", 1),
            f("a/A:b", 1),
            f("a/con.txt", 1),
            f("a/OK", 1),
            f("a/dot.", 1),
            f("a/com0", 1),
        ];
        let got = lim.admit(&files, "", &mut sk);
        assert_eq!(
            got.iter().map(|f| f.rel.as_str()).collect::<Vec<_>>(),
            ["a/ok", "a/com0"]
        );
        assert_eq!(sk.len(), 4);
        assert!(
            sk.iter()
                .any(|(r, why)| r == "a/OK" && why == "name differs only in case")
        );
        assert_eq!(
            Limits::of("ext4", 1)
                .admit(&files, "", &mut Vec::new())
                .len(),
            6
        );
    }

    #[test]
    fn variants_shrink_and_equal_ones_merge() {
        let files = vec![f("a/1", 50), f("b/1", 30), f("c/1", 20)];
        let s = one_set(
            &files,
            &[
                ("small", &["a"]),
                ("same", &["a"]),
                ("full", &["a", "b", "c"]),
            ],
        );
        let lim = Limits::of("ext4", 1);
        let cands = s.candidates(&lim, &mut Vec::new());
        assert_eq!(
            cands.iter().map(|c| c.variant.as_str()).collect::<Vec<_>>(),
            ["full", "small"]
        );
        let room = |n: u64| n * 20 / 19 + 2;
        let meta = lim.meta(1);
        let p = plan(&bare(vec![s.clone()], room(50 + meta), "ext4")).unwrap();
        assert_eq!(chosen(&p), [("s", "small")]);
        let p = plan(&bare(vec![s.clone()], room(49), "ext4")).unwrap();
        assert!(p.sets.is_empty());
        assert!(
            p.dropped[0].1.contains("smallest variant (small)"),
            "{:?}",
            p.dropped
        );
    }

    #[test]
    fn replace_goes_in_place_only_without_room_beside() {
        let files = vec![f("a/1", 400), f("a/2", 400)];
        let mut s = one_set(&files, &[("full", &["a"])]);
        let lim = Limits::of("vfat", 1);
        let new = lim.fp(800) + lim.meta(2);
        s.have = Some(Have {
            version: "v1".into(),
            variant: "full".into(),
            bytes: new,
            sums: HashMap::new(),
        });
        // Free beyond the floor covers the new version beside the old.
        let p = plan(&bare(vec![s.clone()], 3 * new, "vfat")).unwrap();
        assert_eq!(p.sets[0].action, Action::Replace { in_place: false });
        // Room for it only once the old one is gone.
        let p = plan(&bare(vec![s], new / 2, "vfat")).unwrap();
        assert_eq!(p.sets[0].action, Action::Replace { in_place: true });
    }

    #[test]
    fn personal_must_fit_and_cap_counts_what_stays() {
        let mut inp = bare(Vec::new(), 100 * GB, "ext4");
        inp.personal = vec![f("local-personal/x", 10 * GB)];
        inp.cap = Some(10 * GB);
        let err = plan(&inp).unwrap_err().to_string();
        assert!(err.contains("personal files need"), "{err}");
        inp.cap = Some(20 * GB);
        inp.other_kept = 5 * GB;
        let p = plan(&inp).unwrap();
        assert_eq!(p.budget, 15 * GB - 15 * GB / 20);
        assert_eq!(
            p.reserve_floor, 0,
            "a cap below the free space needs no floor of its own"
        );
    }

    #[test]
    fn unmirrored_and_impossible_kit() {
        let mut s = one_set(&[], &[]);
        s.version.clear();
        let mut inp = bare(vec![s], GB, "ext4");
        inp.kit = Some(Err("not on the primary yet".into()));
        let p = plan(&inp).unwrap();
        assert_eq!(
            p.dropped,
            [
                ("kit".to_string(), "not on the primary yet".to_string()),
                ("s".to_string(), "no versioned files on the primary (git and repo mirror trees are not copied until phase 4)".to_string())
            ]
        );
        assert!(render(&p, "T", &inp.limits).contains("left out:"));
    }
}
