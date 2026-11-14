//! `preserver copy`: the primary's `preserver/` tree onto another drive or a directory, fitted
//! to the room there (`plan.rs`), written so nothing is visible before it read back right
//! (`exec.rs`), once or on a schedule (`rules.rs`). Copy jobs run in their own daemon lane, so
//! a long copy never holds up downloads.

mod exec;
pub(crate) mod plan;
pub(crate) mod rules;

use crate::actions;
use crate::catalog::Catalog;
use crate::config::{Config, DriveId};
use crate::paths::Paths;
use crate::personal::local::escapes;
use crate::platform::{self, DriveAt, FsInfo};
use crate::public::index;
use crate::public::versioned::{plain_dirs, read_meta, read_set_file, read_sums, version_dirs};
use crate::queue::{
    BlockReason, Halt, Job, JobKind, JobState, Lane, Pass, Store, Target, apply_control,
    halt_requested, reset, runnable,
};
use crate::status::{self, Status};
use anyhow::{Context, Result, anyhow, bail};
use exec::{Ctx, Halted, KitKind, Prog, Vanished};
use jiff::Timestamp;
use plan::{FileEnt, Have, Inputs, KitIn, Limits, Plan, SetIn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, UNIX_EPOCH};

const STATE: &str = ".state/copy.json";
const PERSONAL: [&str; 2] = ["github-repos-personal", "local-personal"];
/// One-off copies go before the ones a rule makes.
const ONE_OFF_PRIORITY: u32 = 10;
const RULE_PRIORITY: u32 = 20;

/// `<target>/preserver/.state/copy.json`: marks the tree as a copy's, and remembers what the
/// personal files and the kit were when they were copied.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct State {
    personal: BTreeMap<String, Copied>,
    kit: String,
    last: Option<Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Copied {
    size: u64,
    mtime_ns: u64,
    sha256: String,
}

/// Everything the lane needs from the OS, so tests can stand in for drives.
pub(crate) struct Env<'a> {
    /// Where a filesystem is; the lane never mounts one.
    pub drive: &'a (dyn Fn(&DriveId) -> DriveAt + Sync),
    pub fstype: &'a (dyn Fn(&Target, &Path) -> String + Sync),
    pub free: &'a (dyn Fn(&Path) -> io::Result<(u64, u64)> + Sync),
    pub cluster: &'a (dyn Fn(&Path) -> u64 + Sync),
    pub say: &'a (dyn Fn(&str) + Sync),
}

fn real_fstype(target: &Target, root: &Path) -> String {
    if let Target::Drive { id, .. } = target {
        let listed = platform::list_filesystems()
            .ok()
            .and_then(|fs| fs.into_iter().find(|f| id.matches(&f.id)))
            .map(|f| f.fstype)
            .filter(|t| !t.is_empty());
        if let Some(t) = listed {
            return t;
        }
    }
    platform::fs_type(root).unwrap_or_else(|_| "other".into())
}

fn with_real_env<T>(say: &(dyn Fn(&str) + Sync), f: impl FnOnce(&Env) -> T) -> T {
    f(&Env {
        drive: &platform::locate,
        fstype: &real_fstype,
        free: &platform::disk_free,
        cluster: &|p| platform::block_size(p).unwrap_or(4096),
        say,
    })
}

/// A drive's mount point, or why a job has to wait for it.
fn mounted(env: &Env, id: &DriveId) -> Result<PathBuf, BlockReason> {
    match (env.drive)(id) {
        DriveAt::Mounted(p) => Ok(p),
        DriveAt::Unmounted => Err(BlockReason::Unmounted),
        DriveAt::Absent => Err(BlockReason::DriveAbsent),
    }
}

/// Where the target's files go, or why it is not there. A drive's subdirectory is created on
/// first use; a plain directory must exist already.
fn target_root(env: &Env, target: &Target, create: bool) -> Result<Result<PathBuf, BlockReason>> {
    match target {
        Target::Drive { id, subdir, .. } => {
            let mnt = match mounted(env, id) {
                Ok(m) => m,
                Err(r) => return Ok(Err(r)),
            };
            if create {
                return exec::ensure_dir(&mnt, subdir).map(Ok);
            }
            Ok(Ok(mnt.join(subdir)))
        }
        Target::Dir { path } if path.is_dir() => Ok(Ok(path.clone())),
        Target::Dir { .. } => Ok(Err(BlockReason::DriveAbsent)),
    }
}

/// Refuses to write into a `preserver/` tree no copy made: the primary itself under another
/// name, or someone's other archive.
fn check_owned(archive: &Path) -> Result<()> {
    let has_entries = std::fs::read_dir(archive).is_ok_and(|mut d| d.next().is_some());
    if has_entries && std::fs::symlink_metadata(archive.join(STATE)).is_err() {
        bail!(
            "{} holds a preserver archive that 'preserver copy' did not make (the primary, or another backup?); refusing to write into it",
            archive.display()
        );
    }
    Ok(())
}

fn mtime_ns(m: &std::fs::Metadata) -> u64 {
    m.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .and_then(|d| u64::try_from(d.as_nanos()).ok())
        .unwrap_or_default()
}

/// Regular files under `dir`, without following links: `(rel, len, mtime_ns)`. Files a
/// writer is still busy with (`.tmp`, `.copying`) are left for the next run.
fn walk(dir: &Path, rel: &str, out: &mut Vec<(String, u64, u64)>) -> Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        r => r.with_context(|| dir.display().to_string())?,
    };
    for e in entries {
        let e = e?;
        let Some(name) = e.file_name().to_str().map(str::to_string) else {
            tracing::warn!("{}: skipping a name that is not UTF-8", dir.display());
            continue;
        };
        let rel = if rel.is_empty() {
            name.clone()
        } else {
            format!("{rel}/{name}")
        };
        let t = e.file_type()?;
        if t.is_dir() {
            walk(&e.path(), &rel, out)?;
        } else if t.is_file()
            && !Path::new(&name)
                .extension()
                .is_some_and(|x| x == "tmp" || x == "copying")
        {
            let m = e.metadata()?;
            out.push((rel, m.len(), mtime_ns(&m)));
        }
    }
    Ok(())
}

fn tree_bytes(dir: &Path, lim: &Limits) -> Result<u64> {
    let mut files = Vec::new();
    walk(dir, "", &mut files)?;
    Ok(files.iter().map(|(_, len, _)| lim.fp(*len)).sum())
}

/// The kit on the primary, in order, links that would leave it left out.
fn scan_kit(dir: &Path, rel: &str, out: &mut Vec<(String, KitKind)>) -> Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| dir.display().to_string())?
        .collect::<io::Result<_>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for e in entries {
        let Some(name) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let rel = if rel.is_empty() {
            name
        } else {
            format!("{rel}/{name}")
        };
        let t = e.file_type()?;
        if t.is_dir() {
            out.push((rel.clone(), KitKind::Dir));
            scan_kit(&e.path(), &rel, out)?;
        } else if t.is_file() {
            out.push((rel, KitKind::File(e.metadata()?.len())));
        } else if t.is_symlink() {
            let target = std::fs::read_link(e.path())?;
            if escapes(Path::new(&rel), &target) {
                tracing::warn!("kit: leaving out {rel}, a link out of the kit");
            } else {
                out.push((rel, KitKind::Link(target)));
            }
        }
    }
    Ok(())
}

/// What a run needs beyond the planner's inputs.
struct Scan {
    kit: Vec<(String, KitKind)>,
    kit_mark: String,
    personal_meta: HashMap<String, (u64, u64)>,
    haves: HashMap<String, Have>,
    /// Personal files the target cannot hold, with the reason.
    skipped: Vec<(String, String)>,
}

/// Reads the primary and the target (`None`: an empty, absent target) into planner inputs.
/// Read-only, so `--dry-run` can call it.
#[expect(
    clippy::too_many_lines,
    reason = "one pass over both trees, in plan order"
)]
fn scan(
    cat: &Catalog,
    src: &Path,
    dst: Option<&Path>,
    sets: &[String],
    free: u64,
    cap: Option<u64>,
    limits: Limits,
) -> Result<(Inputs, Scan)> {
    let state: State = dst
        .and_then(|d| read_meta(&d.join(STATE)).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let mut skipped = Vec::new();
    let mut other_kept = 0;
    if let Some(d) = dst {
        plain_dirs(&[d, &d.join("public"), &d.join(".state")])?;
    }

    let mut personal = Vec::new();
    let mut personal_kept = 0;
    let mut personal_meta = HashMap::new();
    for tree in PERSONAL {
        plain_dirs(&[&src.join(tree)])?;
        let mut files = Vec::new();
        walk(&src.join(tree), tree, &mut files)?;
        let mut on_target = HashMap::new();
        if let Some(d) = dst {
            plain_dirs(&[&d.join(tree)])?;
            let mut t = Vec::new();
            walk(&d.join(tree), tree, &mut t)?;
            on_target = t.into_iter().map(|(r, len, _)| (r, len)).collect();
        }
        let want = sets.iter().any(|s| s == "personal");
        let ents: Vec<FileEnt> = files
            .iter()
            .map(|(rel, len, _)| FileEnt {
                rel: rel.clone(),
                len: *len,
                sha256: String::new(),
            })
            .collect();
        let admitted = if want {
            limits.admit(&ents, "", &mut skipped)
        } else {
            Vec::new()
        };
        for (rel, len, mtime) in &files {
            personal_meta.insert(rel.clone(), (*len, *mtime));
        }
        for f in admitted {
            let (len, mtime) = personal_meta[&f.rel];
            let same = state
                .personal
                .get(&f.rel)
                .is_some_and(|c| c.size == len && c.mtime_ns == mtime)
                && on_target.get(&f.rel) == Some(&len);
            if !same {
                on_target.remove(&f.rel);
                personal.push(f);
            }
        }
        personal_kept += on_target.values().map(|l| limits.fp(*l)).sum::<u64>();
    }

    let kit_dir = src.join("kit");
    plain_dirs(&[&kit_dir])?;
    let mut kit_entries = Vec::new();
    let mut kit_mark = String::new();
    let kit_have = match dst {
        Some(d) => {
            plain_dirs(&[&d.join("kit")])?;
            let tar = std::fs::symlink_metadata(d.join("kit.tar"))
                .ok()
                .filter(std::fs::Metadata::is_file)
                .map_or(0, |m| limits.fp(m.len()));
            tar + tree_bytes(&d.join("kit"), &limits)?
        }
        None => 0,
    };
    let kit = if !sets.iter().any(|s| s == "kit") {
        other_kept += kit_have;
        None
    } else if !kit_dir.is_dir() {
        Some(Err("not on the primary yet".to_string()))
    } else {
        scan_kit(&kit_dir, "", &mut kit_entries)?;
        let mut h = Sha256::new();
        let mut bytes = 1024;
        for (rel, kind) in &kit_entries {
            let (len, mtime) = match kind {
                KitKind::File(len) => (
                    *len,
                    std::fs::symlink_metadata(kit_dir.join(rel)).map_or(0, |m| mtime_ns(&m)),
                ),
                _ => (0, 0),
            };
            h.update(format!("{rel}\t{kind:?}\t{len}\t{mtime}\n"));
            bytes += if limits.kit_tar() {
                512 + len.div_ceil(512) * 512
            } else {
                limits.fp(len)
            };
        }
        let mode = if limits.kit_tar() { "tar" } else { "tree" };
        kit_mark = format!("{}:{mode}", crate::resolve::hex(&h.finalize()));
        let present = dst.is_some_and(|d| {
            if limits.kit_tar() {
                d.join("kit.tar").is_file()
            } else {
                d.join("kit").is_dir()
            }
        });
        if limits.kit_tar() && limits.max_file.is_some_and(|m| bytes > m) {
            Some(Err(
                "kit.tar would exceed the FAT32 4 GiB limit; format the target as exFAT".into(),
            ))
        } else {
            Some(Ok(KitIn {
                bytes,
                unchanged: present && state.kit == kit_mark,
                have_bytes: kit_have,
            }))
        }
    };

    let mut selected: Vec<_> = cat.sets.iter().filter(|s| sets.contains(&s.name)).collect();
    selected.sort_by_key(|s| s.priority);
    let mut set_ins = Vec::new();
    let mut haves = HashMap::new();
    for set in selected {
        let dir = src.join("public").join(&set.name);
        plain_dirs(&[&dir])?;
        let have = match dst {
            Some(d) => {
                let tdir = d.join("public").join(&set.name);
                plain_dirs(&[&tdir])?;
                version_dirs(&tdir).first().map(|v| {
                    plain_dirs(&[&tdir.join(v)])?;
                    let sf = read_set_file(&tdir.join(v).join("SET.toml"));
                    Ok::<_, anyhow::Error>(Have {
                        version: v.clone(),
                        variant: if sf.variant.is_empty() {
                            "full".into()
                        } else {
                            sf.variant
                        },
                        bytes: tree_bytes(&tdir, &limits)?,
                        sums: read_sums(&tdir.join(v).join("SHA256SUMS")),
                    })
                })
            }
            None => None,
        }
        .transpose()?;
        if let Some(h) = &have {
            haves.insert(set.name.clone(), h.clone());
        }
        let leftover = match (dst, &have) {
            (Some(d), None) => tree_bytes(&d.join("public").join(&set.name), &limits)?,
            _ => 0,
        };
        let Some(version) = version_dirs(&dir).into_iter().next() else {
            set_ins.push(SetIn {
                name: set.name.clone(),
                version: String::new(),
                variants: Vec::new(),
                have,
                stale: leftover,
            });
            continue;
        };
        let vdir = dir.join(&version);
        plain_dirs(&[&vdir])?;
        if !exec::safe_rel(&version) || version.contains('/') {
            bail!("bad version name {version:?} in {}", dir.display());
        }
        let mut files = Vec::new();
        for (rel, sha) in read_sums(&vdir.join("SHA256SUMS")) {
            if rel == "SET.toml" {
                continue;
            }
            let hex_ok = sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit());
            if !exec::safe_rel(&rel) || !rel.contains('/') || !hex_ok {
                bail!("{}: bad SHA256SUMS line for {rel:?}", vdir.display());
            }
            let len = match std::fs::symlink_metadata(vdir.join(&rel)) {
                Ok(m) if m.is_file() => m.len(),
                Ok(_) => bail!("{}/{rel} is not a regular file", vdir.display()),
                Err(_) => return Err(anyhow!(Vanished(format!("{}/{version}/{rel}", set.name)))),
            };
            files.push(FileEnt {
                rel,
                len,
                sha256: sha,
            });
        }
        files.sort_by(|a, b| a.rel.cmp(&b.rel));
        let variants = set
            .variants()
            .into_iter()
            .map(|v| {
                let picked = files
                    .iter()
                    .filter(|f| {
                        f.rel
                            .split('/')
                            .next()
                            .is_some_and(|s| v.sources.contains(&s.to_string()))
                    })
                    .cloned()
                    .collect();
                (v.name, picked)
            })
            .collect();
        set_ins.push(SetIn {
            name: set.name.clone(),
            version,
            variants,
            have,
            stale: leftover,
        });
    }
    // Sets on the target the copy does not select stay, and take their room.
    if let Some(d) = dst {
        for e in std::fs::read_dir(d.join("public"))
            .into_iter()
            .flatten()
            .flatten()
        {
            let name = e.file_name().to_string_lossy().into_owned();
            if e.file_type().is_ok_and(|t| t.is_dir()) && !sets.contains(&name) {
                other_kept += tree_bytes(&e.path(), &limits)?;
            }
        }
        if !sets.iter().any(|s| s == "personal") {
            other_kept += personal_kept;
            personal_kept = 0;
        }
    }
    Ok((
        Inputs {
            personal,
            personal_kept,
            kit,
            sets: set_ins,
            other_kept,
            free,
            cap,
            limits,
        },
        Scan {
            kit: kit_entries,
            kit_mark,
            personal_meta,
            haves,
            skipped,
        },
    ))
}

/// Plans a copy and runs it. `Ok(Some(_))`: a drive is not there, and why.
#[expect(clippy::too_many_lines, reason = "the run in plan order")]
fn execute(
    job: &Job,
    env: &Env,
    stop: &(dyn Fn() -> bool + Sync),
    prog: &Prog,
) -> Result<Option<BlockReason>> {
    let JobKind::Copy {
        target, sets, size, ..
    } = &job.kind
    else {
        bail!("not a copy job");
    };
    target.validate()?;
    let primary = match mounted(env, &job.drive) {
        Ok(p) => p,
        Err(r) => return Ok(Some(r)),
    };
    let root = match target_root(env, target, true)? {
        Ok(r) => r,
        Err(r) => return Ok(Some(r)),
    };
    let (Ok(p), Ok(r)) = (primary.canonicalize(), root.canonicalize()) else {
        return Ok(Some(BlockReason::DriveAbsent));
    };
    if p.starts_with(&r) || r.starts_with(&p) {
        bail!("{} overlaps the primary drive", r.display());
    }
    let src = primary.join("preserver");
    let dst = root.join("preserver");
    plain_dirs(&[&src, &dst])?;
    check_owned(&dst)?;
    exec::ensure_dir(&root, "preserver/.state")?;
    let state_file = dst.join(STATE);
    let mut state: State = read_meta(&state_file)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    if std::fs::symlink_metadata(&state_file).is_err() {
        // Marked as a copy's before anything else lands, so an interrupted first run resumes.
        platform::write_private(&state_file, &serde_json::to_vec_pretty(&state)?)?;
    }
    let limits = Limits::of(&(env.fstype)(target, &root), (env.cluster)(&root));
    let cat = Catalog::embedded()?;
    let free = (env.free)(&root)?.0;
    let (inputs, scanned) = scan(&cat, &src, Some(&dst), sets, free, *size, limits.clone())?;
    let mut plan: Plan = plan::plan(&inputs)?;
    plan.skipped.splice(0..0, scanned.skipped.iter().cloned());
    (env.say)(&plan::render(&plan, &target.name(), &limits));
    prog.bytes_total.store(plan.write, Ordering::Relaxed);
    let files_total = plan.personal.len()
        + plan
            .sets
            .iter()
            .filter(|s| s.action != plan::Action::Unchanged)
            .map(|s| s.files.len())
            .sum::<usize>()
        + plan
            .kit
            .as_ref()
            .filter(|k| k.action != plan::Action::Unchanged)
            .map_or(0, |_| scanned.kit.len());
    prog.files_total
        .store(files_total as u64, Ordering::Relaxed);
    let ctx = Ctx {
        stop,
        prog,
        free: env.free,
        floor: plan.reserve_floor,
        root: &root,
    };

    for d in &plan.deletes {
        if d == "kit" {
            exec::delete_kit(&dst)?;
            state.kit.clear();
        } else {
            exec::delete_set(&dst, d)?;
        }
    }
    let written = exec::copy_personal(&ctx, &src, &dst, &plan.personal)?;
    for (rel, sha256) in written {
        let (size, mtime_ns) = scanned.personal_meta[&rel];
        state.personal.insert(
            rel,
            Copied {
                size,
                mtime_ns,
                sha256,
            },
        );
    }
    write_state(&state_file, &state)?;
    if let Some(k) = &plan.kit
        && k.action != plan::Action::Unchanged
    {
        let in_place = matches!(k.action, plan::Action::Replace { in_place: true });
        let kit_src = src.join("kit");
        if k.tar {
            exec::copy_kit_tar(&ctx, &kit_src, &dst, &scanned.kit, in_place)?;
        } else {
            exec::copy_kit_tree(&ctx, &kit_src, &dst, &scanned.kit, in_place)?;
        }
        state.kit.clone_from(&scanned.kit_mark);
        write_state(&state_file, &state)?;
    }
    for step in &plan.sets {
        let set_dir = exec::ensure_dir(&dst, &format!("public/{}", step.name))?;
        exec::copy_set(
            &ctx,
            &src.join("public").join(&step.name).join(&step.version),
            &set_dir,
            step,
            scanned.haves.get(&step.name),
            limits.links,
        )?;
    }
    state.last = Some(Timestamp::now());
    write_state(&state_file, &state)?;
    let _ = std::fs::remove_file(dst.join(".INDEX.html.tmp"));
    index::write(&cat, &dst)?;
    platform::sync_fs(&dst)?;
    if !scanned.skipped.is_empty() {
        let names: Vec<&str> = scanned
            .skipped
            .iter()
            .take(5)
            .map(|(n, _)| n.as_str())
            .collect();
        bail!(
            "{} personal files cannot go on this target ({}), so it is not a complete backup: {}; format it as exFAT or use another target",
            scanned.skipped.len(),
            scanned.skipped[0].1,
            names.join(", ")
        );
    }
    Ok(None)
}

fn write_state(file: &Path, state: &State) -> Result<()> {
    platform::write_private(file, &serde_json::to_vec_pretty(state)?)
        .with_context(|| file.display().to_string())
}

/// Removes what a canceled job left on the target: stages and half-written files.
fn clean_up(env: &Env, job: &Job) {
    let JobKind::Copy { target, sets, .. } = &job.kind else {
        return;
    };
    let Ok(Ok(root)) = target_root(env, target, false) else {
        return;
    };
    let dst = root.join("preserver");
    for s in sets {
        let stage = dst.join("public").join(s).join(".staging");
        if plain_dirs(&[&dst.join("public").join(s), &stage]).is_ok() && stage.exists() {
            let _ = std::fs::remove_dir_all(&stage);
        }
    }
    let _ = std::fs::remove_file(dst.join("kit.tar.copying"));
    if plain_dirs(&[&dst.join(".kit-staging")]).is_ok() {
        let _ = std::fs::remove_dir_all(dst.join(".kit-staging"));
    }
}

/// Runs one job on a thread while this one applies pause and cancel within a second and saves
/// progress. A missing drive blocks the job without counting an attempt; a run that found the
/// primary pruned under it re-plans once.
fn run_job(store: &Store, env: &Env, mut job: Job) -> Result<()> {
    job.state = JobState::Running {
        pid: std::process::id(),
    };
    job.attempts += 1;
    job.error = None;
    job.progress = crate::queue::Progress::default();
    store.save(&mut job)?;

    let prog = Prog::default();
    let mut halt = None;
    let stop = || prog.stop.load(Ordering::Relaxed);
    let result = std::thread::scope(|s| {
        let (tx, rx) = mpsc::channel::<()>();
        let worker = s.spawn(|| {
            let r = match execute(&job, env, &stop, &prog) {
                Err(e) if e.is::<Vanished>() => {
                    tracing::info!("copy: {e:#}; planning again");
                    execute(&job, env, &stop, &prog)
                }
                r => r,
            };
            drop(tx);
            r
        });
        while let Err(RecvTimeoutError::Timeout) = rx.recv_timeout(Duration::from_secs(1)) {
            if let Some(h) = halt_requested(store, &job.id) {
                halt = Some(h);
                prog.stop.store(true, Ordering::Relaxed);
            }
            let mut j = job.clone();
            j.progress.bytes_done = prog.bytes.load(Ordering::Relaxed);
            j.progress.bytes_total = prog.bytes_total.load(Ordering::Relaxed);
            j.progress.files_done = prog.files.load(Ordering::Relaxed);
            j.progress.files_total = prog.files_total.load(Ordering::Relaxed);
            if let Err(e) = store.save(&mut j) {
                tracing::warn!("progress: {e:#}");
            }
        }
        worker.join()
    });
    let result = result.unwrap_or_else(|_| Err(anyhow!("the copy thread panicked")));
    job.progress.bytes_done = prog.bytes.load(Ordering::Relaxed);
    job.progress.bytes_total = prog.bytes_total.load(Ordering::Relaxed);
    job.progress.files_done = prog.files.load(Ordering::Relaxed);
    job.progress.files_total = prog.files_total.load(Ordering::Relaxed);
    let gone = |job: &Job| {
        let JobKind::Copy { target, .. } = &job.kind else {
            return None;
        };
        match mounted(env, &job.drive) {
            Err(r) => return Some(r),
            Ok(p) if !p.exists() => return Some(BlockReason::DriveAbsent),
            Ok(_) => {}
        }
        match target_root(env, target, false) {
            Ok(Err(r)) => Some(r),
            Ok(Ok(r)) if r.exists() => None,
            _ => Some(BlockReason::DriveAbsent),
        }
    };
    job.state = match result {
        Ok(None) => JobState::Done,
        Err(e) if e.is::<Halted>() => {
            if halt == Some(Halt::Cancel) {
                clean_up(env, &job);
                JobState::Canceled
            } else {
                JobState::Paused
            }
        }
        // Unplugging is not the job's fault.
        Ok(Some(r)) => {
            job.attempts -= 1;
            JobState::Blocked(r)
        }
        Err(e) => {
            if let Some(r) = gone(&job) {
                job.attempts -= 1;
                JobState::Blocked(r)
            } else {
                job.error = Some(format!("{e:#}"));
                JobState::Failed
            }
        }
    };
    store.save(&mut job)
}

/// The copy lane's worker: runs queued copy jobs until none is runnable. The caller holds
/// the `copy-queue` lock, so a job left Running is a crashed worker's.
pub(crate) fn work(store: &Store, env: &Env, pass: Pass) -> Result<()> {
    reset(store, Lane::Copy, pass)?;
    loop {
        let paused = store.control(None).pause;
        let mut jobs: Vec<Job> = store
            .jobs()?
            .into_iter()
            .filter(|j| j.kind.lane() == Lane::Copy)
            .collect();
        for job in &mut jobs {
            if apply_control(store, job) {
                store.save(job)?;
            }
        }
        jobs.sort_by(|a, b| (a.priority, a.created, &a.id).cmp(&(b.priority, b.created, &b.id)));
        match jobs.into_iter().find(|j| j.state == JobState::Queued) {
            Some(job) if !paused => run_job(store, env, job)?,
            _ => return Ok(()),
        }
    }
}

/// Writes the outcome of every copy job that stopped since `start` into `status/copy.json`,
/// one line per rule (or one-off job), then forgets the finished ones. The status goes first:
/// the scheduler reads the jobs and then the status, so it never sees a rule with neither.
fn record(store: &Store, file: &Path, start: Timestamp) -> Result<Vec<String>> {
    let mut st = Status::read(file);
    let mut errs = Vec::new();
    let mut finished = Vec::new();
    for j in store.jobs()? {
        let JobKind::Copy { target, rule, .. } = &j.kind else {
            continue;
        };
        let state = match j.state {
            JobState::Done => "ok",
            JobState::Failed => "failed",
            JobState::Blocked(_) => "blocked",
            JobState::Canceled => "canceled",
            _ => continue,
        };
        if matches!(j.state, JobState::Done | JobState::Canceled) {
            finished.push(j.id.clone());
        }
        if j.updated < start {
            continue;
        }
        let name = rule
            .clone()
            .unwrap_or_else(|| format!("once-{}", rules::rule_id(target)));
        st.sets.retain(|v| v["name"] != name.as_str());
        st.sets.push(serde_json::json!({
            "name": name,
            "target": target.name(),
            "state": state,
            "time": Timestamp::now().to_string(),
            "error": j.error.clone().unwrap_or_default(),
        }));
        if j.state == JobState::Failed {
            errs.push(format!(
                "copy to {}: {}",
                target.name(),
                j.error.as_deref().unwrap_or_default()
            ));
        }
    }
    st.write(file)?;
    for id in finished {
        store.remove(&id)?;
    }
    Ok(errs)
}

/// When each rule last ran, from `status/copy.json`.
fn last_runs(file: &Path) -> HashMap<String, Timestamp> {
    Status::read(file)
        .sets
        .iter()
        .filter(|v| v["state"] != "blocked")
        .filter_map(|v| {
            Some((
                v["name"].as_str()?.to_string(),
                v["time"].as_str()?.parse().ok()?,
            ))
        })
        .collect()
}

/// One pass of the daemon's copy lane; like the download lane it skips without a word when
/// a CLI run holds the queue or nothing is runnable. Lock order: `copy-queue`, then `copy`.
pub(crate) fn daemon_pass(paths: &Paths, pass: Pass) -> Result<()> {
    let Some(_lock) = status::try_lock(&paths.lock_file("copy-queue"))? else {
        return Ok(());
    };
    let store = Store::new(paths.queue.clone());
    if !runnable(&store, Lane::Copy, pass)? {
        return Ok(());
    }
    let start = Timestamp::now();
    status::job(&mut paths.clone(), "copy", |paths| {
        with_real_env(&|s| tracing::info!("{s}"), |env| work(&store, env, pass))?;
        let errs = record(&store, &paths.status_file("copy"), start)?;
        if errs.is_empty() {
            return Ok(());
        }
        let msg = errs.join("; ");
        platform::notify(true, "Copy failed", &msg);
        bail!(msg)
    })
}

/// Turns due rules into jobs; the daemon calls it before every pass.
pub(crate) fn schedule(paths: &Paths, now: Timestamp) -> Result<()> {
    let cat = Catalog::embedded()?;
    let rules: Vec<rules::Rule> = rules::load(&paths.copy_rules)?
        .into_iter()
        .filter(|r| {
            let ok = rules::rule_sets(&cat, r);
            if let Err(e) = &ok {
                tracing::warn!("copy rule {} skipped: {e:#}", r.id);
            }
            ok.is_ok()
        })
        .collect();
    if rules.is_empty() {
        return Ok(());
    }
    let store = Store::new(paths.queue.clone());
    let jobs = store.jobs()?;
    let last = last_runs(&paths.status_file("copy"));
    let acts = rules::due(&rules, &jobs, &last, now);
    if acts.is_empty() {
        return Ok(());
    }
    let primary = Config::load(&paths.cfg)?.primary_uuid;
    for act in acts {
        match act {
            rules::Act::Create(r) => {
                let kind = JobKind::Copy {
                    sets: rules::rule_sets(&cat, &r)?,
                    target: r.target,
                    size: r.size,
                    rule: Some(r.id),
                };
                store.create(&kind, &primary, RULE_PRIORITY)?;
            }
            rules::Act::Retry(id) => store.edit_control(Some(&id), |c| c.retry += 1)?,
        }
    }
    Ok(())
}

/// Turns the command-line target into a `Target`: an existing directory (a drive's when it
/// sits on a removable mount), a filesystem id, or a label; an id nothing lists is a drive
/// that is not plugged in. The primary is never a target.
fn resolve_target(
    arg: &str,
    fss: &[FsInfo],
    primary: &DriveId,
    primary_mount: Option<&Path>,
) -> Result<Target> {
    let path = Path::new(arg);
    if path.is_dir() {
        let path = path
            .canonicalize()
            .with_context(|| path.display().to_string())?;
        let on = fss
            .iter()
            .filter_map(|f| Some((f, f.mount.as_ref()?.canonicalize().ok()?)))
            .filter(|(_, m)| path.starts_with(m))
            .max_by_key(|(_, m)| m.components().count());
        if let Some((f, _)) = on.as_ref().filter(|(f, _)| primary.matches(&f.id)) {
            bail!("{} is on the primary drive ({})", path.display(), f.id);
        }
        if let Some(pm) = primary_mount.and_then(|p| p.canonicalize().ok())
            && (path.starts_with(&pm) || pm.starts_with(&path))
        {
            bail!("{} overlaps the primary drive", path.display());
        }
        let removable = |f: &FsInfo, m: &Path| {
            f.removable || m.starts_with("/run/media") || m.starts_with("/media")
        };
        if let Some((f, m)) = on.filter(|(f, m)| removable(f, m))
            && let Ok(id) = f.id.parse::<DriveId>()
        {
            let subdir = path
                .strip_prefix(&m)
                .unwrap_or(Path::new(""))
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            let t = Target::Drive {
                id,
                subdir,
                label: f.label.clone(),
            };
            t.validate()?;
            return Ok(t);
        }
        return Ok(Target::Dir { path });
    }
    let drive = |f: &FsInfo| -> Result<Target> {
        if primary.matches(&f.id) {
            bail!("{arg} is the primary drive; copy to another one");
        }
        Ok(Target::Drive {
            id: f.id.parse()?,
            subdir: String::new(),
            label: f.label.clone(),
        })
    };
    if let Some(f) = fss
        .iter()
        .find(|f| !f.id.is_empty() && f.id.parse::<DriveId>().is_ok_and(|id| id.matches(arg)))
    {
        return drive(f);
    }
    let labeled: Vec<&FsInfo> = fss
        .iter()
        .filter(|f| !f.label.is_empty() && f.label == arg)
        .collect();
    match labeled.as_slice() {
        [f] => return drive(f),
        [] => {}
        _ => bail!("more than one filesystem is labeled {arg:?}; give its id ('preserver drives')"),
    }
    match arg.parse::<DriveId>() {
        Ok(id) if primary.matches(arg) => bail!("{id} is the primary drive; copy to another one"),
        Ok(id) => Ok(Target::Drive {
            id,
            subdir: String::new(),
            label: String::new(),
        }),
        Err(_) => bail!("no such directory or drive: {arg}"),
    }
}

/// `--dry-run`: the plan against the target as it is, or, for a drive that is not plugged in,
/// against an empty one of `--size` (assumed exFAT, as sticks and cards ship).
fn dry_run(
    env: &Env,
    primary: &DriveId,
    target: &Target,
    sets: &[String],
    size: Option<u64>,
) -> Result<String> {
    let Ok(pm) = mounted(env, primary) else {
        bail!("the primary drive ({primary}) is not mounted; the plan needs its sizes");
    };
    let src = pm.join("preserver");
    let cat = Catalog::embedded()?;
    let (inputs, skipped, limits, note) = match target_root(env, target, false)? {
        Ok(root) if root.exists() => {
            let dst = root.join("preserver");
            check_owned(&dst)?;
            let limits = Limits::of(&(env.fstype)(target, &root), (env.cluster)(&root));
            let free = (env.free)(&root)?.0;
            let dst = dst.is_dir().then_some(dst);
            let (i, s) = scan(&cat, &src, dst.as_deref(), sets, free, size, limits.clone())?;
            (i, s.skipped, limits, String::new())
        }
        _ => {
            let Some(size) = size else {
                bail!(
                    "{} is not connected: give --size to plan for it",
                    target.name()
                );
            };
            let limits = Limits::of("exfat", 128 << 10);
            let (i, s) = scan(&cat, &src, None, sets, size, Some(size), limits.clone())?;
            let note = format!(
                "note: {} is not connected; planned for an empty {} exFAT target\n",
                target.name(),
                crate::public::gb(size)
            );
            (i, s.skipped, limits, note)
        }
    };
    let mut p = plan::plan(&inputs)?;
    p.skipped.splice(0..0, skipped);
    Ok(format!(
        "{note}{}",
        plan::render(&p, &target.name(), &limits)
    ))
}

fn list_text(rules: &[rules::Rule], jobs: &[Job], last: &HashMap<String, Timestamp>) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    if rules.is_empty() {
        o.push_str("no copy rules; 'preserver copy TARGET -t 24:00:00' adds one\n");
    }
    for r in rules {
        let sets = if r.sets.is_empty() {
            "all".to_string()
        } else {
            r.sets.join(",")
        };
        let _ = writeln!(
            o,
            "{}  every {:<10} to {}  sets {sets}{}  last {}",
            r.id,
            rules::show_interval(r.interval),
            r.target.name(),
            r.size
                .map(|s| format!("  size {}", crate::public::gb(s)))
                .unwrap_or_default(),
            last.get(&r.id)
                .map_or_else(|| "never".to_string(), ToString::to_string)
        );
    }
    for j in jobs {
        if let JobKind::Copy { target, .. } = &j.kind {
            let _ = writeln!(o, "job {}  {}  to {}", j.id, j.state, target.name());
        }
    }
    o
}

pub(crate) struct Args {
    pub target: Option<String>,
    pub every: Option<String>,
    pub sets: Vec<String>,
    pub size: Option<String>,
    pub dry_run: bool,
    pub list: bool,
    pub remove: Option<String>,
    pub foreground: bool,
}

/// `copy --remove`: a rule id removes the rule and cancels its jobs; a job id cancels the job.
pub(crate) fn remove(paths: &Paths, store: &Store, id: &str) -> Result<String> {
    if rules::is_rule_id(id) {
        if !rules::remove(&paths.copy_rules, id)? {
            bail!("no rule {id}; 'preserver copy --list' shows them");
        }
        for j in store.jobs()? {
            if matches!(&j.kind, JobKind::Copy { rule: Some(r), .. } if r == id) {
                store.edit_control(Some(&j.id), |c| c.cancel = true)?;
            }
        }
        return Ok(format!("removed rule {id}"));
    }
    let job = store
        .job(id)
        .map_err(|_| anyhow!("no rule or copy job {id}"))?;
    if job.kind.lane() != Lane::Copy {
        bail!("{id} is not a copy job");
    }
    store.edit_control(Some(id), |c| c.cancel = true)?;
    Ok(format!("canceling copy job {id}"))
}

/// Adds the rule, or replaces the one for the same target; true when it replaced one.
pub(crate) fn add_rule(paths: &Paths, rule: rules::Rule) -> Result<(rules::Rule, bool)> {
    let replaced = rules::upsert(&paths.copy_rules, rule.clone())?;
    Ok((rule, replaced))
}

/// `preserver copy`.
pub(crate) fn cli(paths: &mut Paths, cfg: &Config, a: Args) -> Result<()> {
    let store = Store::new(paths.queue.clone());
    if a.list {
        let rules = rules::load(&paths.copy_rules)?;
        print!(
            "{}",
            list_text(
                &rules,
                &store.jobs()?,
                &last_runs(&paths.status_file("copy"))
            )
        );
        return Ok(());
    }
    if let Some(id) = a.remove {
        println!("{}", remove(paths, &store, &id)?);
        return Ok(());
    }
    let Some(arg) = a.target else {
        bail!("give a target drive or directory, or --list");
    };
    let cat = Catalog::embedded()?;
    let sets = rules::resolve_sets(&cat, &a.sets)?;
    let size = a.size.as_deref().map(rules::parse_size).transpose()?;
    let interval = a.every.as_deref().map(rules::parse_interval).transpose()?;
    let fss = platform::list_filesystems().unwrap_or_else(|e| {
        println!("note: udisks2: {e:#}; only directories and ids work");
        Vec::new()
    });
    let primary_mount = fss
        .iter()
        .find(|f| cfg.primary_uuid.matches(&f.id))
        .and_then(|f| f.mount.clone())
        .or_else(|| platform::is_mounted(&paths.mnt).then(|| paths.mnt.clone()));
    let target = resolve_target(&arg, &fss, &cfg.primary_uuid, primary_mount.as_deref())?;
    let say = |s: &str| print!("{s}");
    if a.dry_run {
        let text = with_real_env(&say, |e| {
            dry_run(e, &cfg.primary_uuid, &target, &sets, size)
        })?;
        print!("{text}");
        return Ok(());
    }
    let rule = match interval {
        Some(interval) => {
            let (r, replaced) = add_rule(
                paths,
                rules::Rule {
                    id: rules::rule_id(&target),
                    interval,
                    sets: a.sets.clone(),
                    size,
                    target: target.clone(),
                },
            )?;
            println!(
                "{} rule {}: every {} to {}",
                if replaced { "replaced" } else { "added" },
                r.id,
                rules::show_interval(interval),
                target.name()
            );
            Some(r.id)
        }
        None => None,
    };
    actions::mount(&cfg.primary_uuid);
    if let Target::Drive { id, .. } = &target {
        actions::mount(id);
    }
    let pri = if rule.is_some() {
        RULE_PRIORITY
    } else {
        ONE_OFF_PRIORITY
    };
    let kind = JobKind::Copy {
        target,
        sets,
        size,
        rule,
    };
    let Some((_lock, ids)) = actions::handoff(paths, "copy-queue", a.foreground, |tidy| {
        Ok(vec![store.enqueue(&kind, &cfg.primary_uuid, pri, tidy)?])
    })?
    else {
        return Ok(());
    };
    run_here(paths, &store, &ids[0])
}

/// Runs the copy lane here, under the `copy-queue` lock the caller holds, and reports the job.
fn run_here(paths: &mut Paths, store: &Store, id: &str) -> Result<()> {
    let start = Timestamp::now();
    status::job(paths, "copy", |paths| {
        with_real_env(&|s| print!("{s}"), |e| work(store, e, Pass::FRESH))?;
        let job = store.job(id).ok();
        record(store, &paths.status_file("copy"), start)?;
        match job.map(|j| (j.state, j.error)) {
            Some((JobState::Done, _)) | None => {
                println!("copy done");
                Ok(())
            }
            Some((s @ JobState::Blocked(_), _)) => {
                println!("copy {s}; it runs once the drive is mounted (job {id})");
                Ok(())
            }
            Some((JobState::Failed, e)) => bail!(e.unwrap_or_default()),
            Some((s, _)) => {
                println!("copy {s} (job {id})");
                Ok(())
            }
        }
    })
}

#[cfg(test)]
mod tests;
