use crate::paths::Paths;
use crate::status::Status;
use anyhow::{Context, Result, bail};
use std::io::Write;
use std::path::{Path, PathBuf};

enum Step {
    Move(PathBuf, PathBuf),
    Mkdir(PathBuf),
    ConvertLastOk { last_ok: PathBuf, status: PathBuf },
}

impl Step {
    fn describe(&self) -> String {
        match self {
            Self::Move(src, dst) => format!("move {} -> {}", src.display(), dst.display()),
            Self::Mkdir(dir) => format!("mkdir {}", dir.display()),
            Self::ConvertLastOk { last_ok, status } => {
                format!("convert {} to {}", last_ok.display(), status.display())
            }
        }
    }

    fn run(&self) -> Result<()> {
        match self {
            Self::Move(src, dst) => {
                if let Some(parent) = dst.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::rename(src, dst)?;
            }
            Self::Mkdir(dir) => std::fs::create_dir_all(dir)?,
            Self::ConvertLastOk { last_ok, status } => {
                let day: jiff::civil::Date = std::fs::read_to_string(last_ok)?.trim().parse()?;
                let at = day.to_zoned(jiff::tz::TimeZone::system())?.timestamp();
                Status {
                    last_ok: Some(at),
                    last_run: Some(at),
                    ..Status::default()
                }
                .write(status)?;
                std::fs::remove_file(last_ok)?;
            }
        }
        Ok(())
    }
}

fn exists(path: &Path) -> bool {
    path.symlink_metadata().is_ok()
}
struct Plan {
    steps: Vec<Step>,
    refuse: Vec<String>,
}

impl Plan {
    fn rename(&mut self, src: PathBuf, dst: PathBuf, out: &mut dyn Write) -> Result<()> {
        if !exists(&src) {
            writeln!(out, "skip: {} does not exist", src.display())?;
        } else if exists(&dst) {
            self.refuse.push(format!(
                "{} exists, so {} cannot move there",
                dst.display(),
                src.display()
            ));
        } else {
            self.steps.push(Step::Move(src, dst));
        }
        Ok(())
    }
}

/// Moves the gh-backup layout to the code-archive one with same-filesystem renames only.
/// Every step is skipped when its work is already done, and nothing runs if any target is in the way.
/// The caller mounts the drive first, except for a dry run.
pub(crate) fn migrate(p: &Paths, dry: bool, out: &mut dyn Write) -> Result<()> {
    let mut plan = Plan {
        steps: Vec::new(),
        refuse: Vec::new(),
    };

    if dry && !exists(&p.mnt) {
        writeln!(
            out,
            "drive {} is not mounted: drive steps not checked (dry-run does not mount)",
            p.mnt.display()
        )?;
    } else {
        let ca = p.archive();
        let mut old = ca.clone().into_os_string();
        old.push(".kit-old");
        let old = PathBuf::from(old);
        let kit = ca.join("kit");
        if exists(&old) && exists(&kit) {
            plan.refuse.push(format!(
                "both {} and {} exist",
                old.display(),
                kit.display()
            ));
        } else if exists(&kit) || exists(&p.gh_dest()) {
            writeln!(out, "skip: kit already in {}", ca.display())?;
        } else if exists(&old) || exists(&ca) {
            if !exists(&old) {
                plan.steps.push(Step::Move(ca.clone(), old.clone()));
            }
            plan.steps.push(Step::Mkdir(ca));
            plan.steps.push(Step::Move(old, kit));
        } else {
            writeln!(out, "skip: no old kit at {}", ca.display())?;
        }
        plan.rename(p.mnt.join("gh-backup"), p.gh_dest(), out)?;
    }

    let last_ok = p.github.join("last-ok");
    let had_last_ok = exists(&p.old_state.join("last-ok")) || exists(&last_ok);
    plan.rename(p.old_cfg.clone(), p.personal.clone(), out)?;
    plan.rename(p.old_state.clone(), p.github.clone(), out)?;
    plan.rename(p.old_cache.clone(), p.mirrors.clone(), out)?;
    let status = p.status_file("github");
    if had_last_ok && !exists(&status) {
        plan.steps.push(Step::ConvertLastOk { last_ok, status });
    }

    if !plan.refuse.is_empty() {
        bail!("refusing, nothing changed:\n  {}", plan.refuse.join("\n  "));
    }
    if plan.steps.is_empty() {
        writeln!(out, "nothing to do")?;
    }
    for step in &plan.steps {
        let desc = step.describe();
        if dry {
            writeln!(out, "would {desc}")?;
            continue;
        }
        writeln!(out, "{desc}")?;
        step.run().context(desc)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, paths};

    fn touch(path: &Path, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn count_files(root: &Path) -> usize {
        std::fs::read_dir(root)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                if e.file_type().unwrap().is_dir() {
                    count_files(&e.path())
                } else {
                    1
                }
            })
            .sum()
    }

    fn run(p: &Paths, dry: bool) -> Result<String> {
        let mut out = Vec::new();
        migrate(p, dry, &mut out)?;
        Ok(String::from_utf8(out).unwrap())
    }

    #[test]
    fn moves_the_old_layout_once() {
        let tmp = TempDir::new();
        let p = paths(tmp.path());
        touch(&p.mnt.join("code-archive/RECOVERY.txt"), "kit");
        touch(&p.mnt.join("gh-backup/o/r/2026-11-13.bundle.age"), "b");
        touch(&p.old_cfg.join("recipient.txt"), "age1x");
        touch(&p.old_state.join("o/r.refs"), "x\n");
        touch(&p.old_state.join("last-ok"), "2026-11-13\n");
        touch(&p.old_cache.join("o/r.git/HEAD"), "ref");
        let before = count_files(tmp.path());

        let out = run(&p, true).unwrap();
        assert!(out.contains("would move"), "{out}");
        assert_eq!(count_files(tmp.path()), before, "dry run changed the tree");
        assert!(p.mnt.join("gh-backup").exists());

        run(&p, false).unwrap();
        for f in [
            p.mnt.join("code-archive/kit/RECOVERY.txt"),
            p.gh_dest().join("o/r/2026-11-13.bundle.age"),
            p.personal.join("recipient.txt"),
            p.github.join("o/r.refs"),
            p.mirrors.join("o/r.git/HEAD"),
            p.status_file("github"),
        ] {
            assert!(f.exists(), "missing {}", f.display());
        }
        for f in [
            p.github.join("last-ok"),
            p.mnt.join("gh-backup"),
            p.old_state.clone(),
        ] {
            assert!(!f.exists(), "left behind {}", f.display());
        }
        let st = Status::read(&p.status_file("github"));
        let day = st
            .last_ok
            .unwrap()
            .to_zoned(jiff::tz::TimeZone::system())
            .date();
        assert_eq!(day.to_string(), "2026-11-13");

        let out = run(&p, false).unwrap();
        assert!(out.contains("nothing to do"), "{out}");

        touch(&p.old_cache.join("again"), "x");
        let err = run(&p, false).unwrap_err();
        assert!(err.to_string().contains("refusing"), "{err}");
        assert!(p.old_cache.join("again").exists());
    }

    #[test]
    fn dry_run_without_the_drive_checks_home_only() {
        let tmp = TempDir::new();
        let mut p = paths(tmp.path());
        p.mnt = tmp.path().join("unmounted");
        touch(&p.old_cfg.join("recipient.txt"), "age1x");
        let out = run(&p, true).unwrap();
        assert!(out.contains("is not mounted"), "{out}");
        assert!(out.contains("would move"), "{out}");
        assert!(p.old_cfg.exists());
    }
}
