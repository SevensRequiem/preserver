use crate::paths::Paths;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

static NEXT: AtomicU32 = AtomicU32::new(0);

pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new() -> Self {
        // Relaxed: the counter only has to hand out distinct numbers.
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("preserver-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The whole layout under `root`, with the drive "mounted" at `root/mnt`.
pub(crate) fn paths(root: &Path) -> Paths {
    let home = root.join("home").display().to_string();
    let run = root.join("run");
    std::fs::create_dir_all(&run).unwrap();
    let run = run.display().to_string();
    let mut p = Paths::resolve(|k| match k {
        "HOME" => Some(home.clone()),
        "XDG_RUNTIME_DIR" => Some(run.clone()),
        "USER" => Some("u".to_string()),
        _ => None,
    })
    .unwrap();
    p.mnt = root.join("mnt");
    std::fs::create_dir_all(&p.mnt).unwrap();
    p
}

/// Runs git with the user's config out of the picture and returns trimmed stdout.
pub(crate) fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}
