use crate::config::DriveId;
use crate::platform;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// The error of a failed mount; the nightly local run treats it as "skip", not as a failure.
#[derive(Debug)]
pub(crate) struct NoDrive(String);

impl std::fmt::Display for NoDrive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "backup drive is not connected ({})", self.0)
    }
}

/// Every name here is the Go code-archive layout, so existing state is picked up as is.
#[derive(Debug, Clone)]
pub(crate) struct Paths {
    pub cfg: PathBuf,
    pub personal: PathBuf,
    pub drives_d: PathBuf,
    pub github: PathBuf,
    pub status: PathBuf,
    pub local_state: PathBuf,
    pub mirrors: PathBuf,
    pub runtime: PathBuf,
    pub mnt: PathBuf,
    pub old_cfg: PathBuf,
    pub old_state: PathBuf,
    pub old_cache: PathBuf,
    user: String,
}

impl Paths {
    pub(crate) fn from_env() -> Result<Self> {
        Self::resolve(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
    }

    pub(crate) fn resolve(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let home = PathBuf::from(get("HOME").context("HOME is not set")?);
        let runtime = get("XDG_RUNTIME_DIR").context("XDG_RUNTIME_DIR is not set")?;
        let user = get("USER").context("USER is not set")?;
        let dir =
            |var: &str, fallback: &str| get(var).map_or_else(|| home.join(fallback), PathBuf::from);
        let cfg = dir("XDG_CONFIG_HOME", ".config");
        let state = dir("XDG_STATE_HOME", ".local/state");
        let cache = dir("XDG_CACHE_HOME", ".cache");
        Ok(Self {
            personal: cfg.join("code-archive/personal"),
            drives_d: cfg.join("code-archive/drives.d"),
            github: state.join("code-archive/github"),
            status: state.join("code-archive/status"),
            local_state: state.join("code-archive/local"),
            mirrors: cache.join("code-archive/mirrors"),
            old_cfg: cfg.join("gh-backup"),
            old_state: state.join("gh-backup"),
            old_cache: cache.join("gh-backup"),
            cfg: cfg.join("code-archive"),
            runtime: PathBuf::from(runtime),
            mnt: PathBuf::new(),
            user,
        })
    }

    pub(crate) fn set_drive(&mut self, id: &DriveId) {
        self.mnt = Path::new("/run/media").join(&self.user).join(id.as_str());
    }

    pub(crate) fn archive(&self) -> PathBuf {
        self.mnt.join("code-archive")
    }

    pub(crate) fn gh_dest(&self) -> PathBuf {
        self.archive().join("github-repos-personal")
    }

    pub(crate) fn local_dest(&self) -> PathBuf {
        self.archive().join("local-personal")
    }

    pub(crate) fn status_file(&self, job: &str) -> PathBuf {
        self.status.join(format!("{job}.json"))
    }

    pub(crate) fn lock_file(&self, job: &str) -> PathBuf {
        self.runtime.join(format!("code-archive-{job}.lock"))
    }

    /// Mounts the drive, or finds where it already is. The path always comes from udisks by id:
    /// it may differ from the expected place (udisks prefers the label), and another device can
    /// sit at the expected place.
    pub(crate) fn mount(&mut self, id: &DriveId) -> Result<()> {
        self.mnt = platform::mount(id).map_err(|e| e.context(NoDrive(id.to_string())))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            vars.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_string())
        }
    }

    const BASE: [(&str, &str); 3] = [
        ("HOME", "/home/u"),
        ("XDG_RUNTIME_DIR", "/run/user/1000"),
        ("USER", "u"),
    ];
    const MNT: &str = "/run/media/u/0123abcd-0000-4000-8000-0123456789ab";

    #[test]
    fn layout_matches_go() {
        let mut p = Paths::resolve(lookup(&BASE)).unwrap();
        p.set_drive(&"0123abcd-0000-4000-8000-0123456789ab".parse().unwrap());
        let cases = [
            ("cfg", p.cfg.clone(), "/home/u/.config/code-archive".into()),
            (
                "personal",
                p.personal.clone(),
                "/home/u/.config/code-archive/personal".into(),
            ),
            (
                "drives.d",
                p.drives_d.clone(),
                "/home/u/.config/code-archive/drives.d".into(),
            ),
            (
                "github",
                p.github.clone(),
                "/home/u/.local/state/code-archive/github".into(),
            ),
            (
                "status",
                p.status.clone(),
                "/home/u/.local/state/code-archive/status".into(),
            ),
            (
                "mirrors",
                p.mirrors.clone(),
                "/home/u/.cache/code-archive/mirrors".into(),
            ),
            ("runtime", p.runtime.clone(), "/run/user/1000".into()),
            ("mnt", p.mnt.clone(), MNT.to_string()),
            ("archive", p.archive(), format!("{MNT}/code-archive")),
            (
                "gh_dest",
                p.gh_dest(),
                format!("{MNT}/code-archive/github-repos-personal"),
            ),
            (
                "local_state",
                p.local_state.clone(),
                "/home/u/.local/state/code-archive/local".into(),
            ),
            (
                "local_dest",
                p.local_dest(),
                format!("{MNT}/code-archive/local-personal"),
            ),
            (
                "old_cfg",
                p.old_cfg.clone(),
                "/home/u/.config/gh-backup".into(),
            ),
            (
                "old_state",
                p.old_state.clone(),
                "/home/u/.local/state/gh-backup".into(),
            ),
            (
                "old_cache",
                p.old_cache.clone(),
                "/home/u/.cache/gh-backup".into(),
            ),
            (
                "status_file",
                p.status_file("github"),
                "/home/u/.local/state/code-archive/status/github.json".into(),
            ),
            (
                "lock_file",
                p.lock_file("github"),
                "/run/user/1000/code-archive-github.lock".into(),
            ),
        ];
        for (name, got, want) in cases {
            let want: String = want;
            assert_eq!(got, Path::new(&want), "{name}");
        }
    }

    #[test]
    fn xdg_overrides() {
        let mut vars = BASE.to_vec();
        vars.extend([
            ("XDG_CONFIG_HOME", "/c"),
            ("XDG_STATE_HOME", "/s"),
            ("XDG_CACHE_HOME", "/k"),
        ]);
        let p = Paths::resolve(lookup(&vars)).unwrap();
        assert_eq!(p.personal, Path::new("/c/code-archive/personal"));
        assert_eq!(p.github, Path::new("/s/code-archive/github"));
        assert_eq!(p.mirrors, Path::new("/k/code-archive/mirrors"));
        assert_eq!(p.old_cache, Path::new("/k/gh-backup"));
    }

    #[test]
    fn missing_variable_is_an_error() {
        for missing in ["HOME", "XDG_RUNTIME_DIR", "USER"] {
            let vars: Vec<_> = BASE
                .iter()
                .copied()
                .filter(|(k, _)| *k != missing)
                .collect();
            assert!(Paths::resolve(lookup(&vars)).is_err(), "{missing}");
        }
    }
}
