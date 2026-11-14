use crate::crypt::{self, Identities};
use crate::paths::Paths;
use crate::personal::local;
use crate::platform;
use age::secrecy::SecretString;
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub(crate) fn check_target(dir: &Path) -> Result<()> {
    match std::fs::read_dir(dir) {
        Ok(mut entries) => {
            if entries.next().is_some() {
                bail!("{} is not empty", dir.display());
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| dir.display().to_string()),
    }
}

fn git(args: &[&std::ffi::OsStr], what: &str) -> Result<()> {
    let status = Command::new("git")
        .args(args)
        .stdin(Stdio::null())
        .status()
        .context("run git")?;
    if !status.success() {
        bail!("{what}: {status}");
    }
    Ok(())
}

/// Decrypts a `.bundle.age` and clones it into `dir`, which must be empty or absent.
pub(crate) fn restore_bundle(identities: &Identities, file: &Path, dir: &Path) -> Result<()> {
    check_target(dir)?;
    // The plain bundle goes next to the target: that filesystem has to hold the repo anyway,
    // and the runtime dir is RAM.
    let parent = dir
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    // A fresh directory, so a name someone else planted next to the target is refused, not reused.
    let scratch = parent.join(format!(".preserver-restore-{}", std::process::id()));
    platform::private_dir_new(&scratch).with_context(|| scratch.display().to_string())?;
    let tmp = scratch.join("repo.bundle");
    let result = (|| {
        let sealed = std::fs::File::open(file).with_context(|| file.display().to_string())?;
        let mut plain = crypt::decrypt(identities, std::io::BufReader::new(sealed))
            .context("decrypt (is this the key the backup was made for?)")?;
        std::io::copy(&mut plain, &mut platform::private_file_new(&tmp)?).context("decrypt")?;
        git(
            &[
                "clone".as_ref(),
                "-q".as_ref(),
                "--".as_ref(),
                tmp.as_os_str(),
                dir.as_os_str(),
            ],
            "clone",
        )?;
        git(
            &[
                "-C".as_ref(),
                dir.as_os_str(),
                "remote".as_ref(),
                "remove".as_ref(),
                "origin".as_ref(),
            ],
            "remote remove",
        )
    })();
    let _ = std::fs::remove_dir_all(&scratch);
    result
}

/// The locked key for a backup file: the one stored with the backup (the bundle's own tree or the
/// archive root's github-repos-personal, so an old drive or copy restores by itself), then the primary drive's, then the home copy.
fn identity_file(paths: &Paths, file: &Path) -> PathBuf {
    let drive = paths.gh_dest().join("identity.age");
    file.ancestors()
        .skip(1)
        .take(4)
        .flat_map(|d| {
            [
                d.join("identity.age"),
                d.join("github-repos-personal/identity.age"),
            ]
        })
        .chain((!paths.mnt.as_os_str().is_empty()).then_some(drive))
        .find(|f| f.is_file())
        .unwrap_or_else(|| paths.personal.join("identity.age"))
}

pub(crate) fn run(paths: &Paths, file: &Path, dir: &Path) -> Result<()> {
    check_target(dir)?;
    let id_file = identity_file(paths, file);
    let locked = std::fs::read(&id_file).with_context(|| id_file.display().to_string())?;
    let passphrase = SecretString::from(
        rpassword::prompt_password(format!("Restore password for {}: ", id_file.display()))
            .context("read the password")?,
    );
    let identities = crypt::unlock(&locked, passphrase)?;
    let mut skipped = 0;
    if file.to_string_lossy().ends_with(".tar.zst.age") {
        let list = local::restore(&identities, file, dir)
            .with_context(|| format!("restore stopped; {} is incomplete", dir.display()))?;
        for entry in &list {
            eprintln!("skipped: {entry}");
        }
        skipped = list.len();
    } else {
        restore_bundle(&identities, file, dir)?;
    }
    println!("Restored into {}", dir.display());
    if skipped > 0 {
        bail!("{skipped} entries were not restored (see the skipped lines above)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, git as tgit};
    use age::x25519;
    use std::io::Write;

    fn sealed_bundle(tmp: &Path, recipient: x25519::Recipient) -> std::path::PathBuf {
        let work = tmp.join("work");
        std::fs::create_dir(&work).unwrap();
        tgit(&work, &["init", "-q", "-b", "main"]);
        std::fs::write(work.join("f.txt"), "content").unwrap();
        tgit(&work, &["add", "."]);
        tgit(&work, &["commit", "-q", "-m", "one"]);
        tgit(&work, &["branch", "side"]);
        tgit(&work, &["bundle", "create", "-q", "plain.bundle", "--all"]);
        let file = tmp.join("r.bundle.age");
        let mut w = crypt::encrypt(&[recipient], std::fs::File::create(&file).unwrap()).unwrap();
        w.write_all(&std::fs::read(work.join("plain.bundle")).unwrap())
            .unwrap();
        w.finish().unwrap();
        file
    }

    #[test]
    fn restores_a_bundle_that_passes_fsck() {
        let tmp = TempDir::new();
        let id = x25519::Identity::generate();
        let file = sealed_bundle(tmp.path(), id.to_public());
        let ids: Identities = vec![Box::new(id)];
        let out = tmp.path().join("out/repo");

        restore_bundle(&ids, &file, &out).unwrap();
        tgit(&out, &["fsck", "--strict"]);
        assert_eq!(
            std::fs::read_to_string(out.join("f.txt")).unwrap(),
            "content"
        );
        assert_eq!(tgit(&out, &["remote"]), "");
        assert_eq!(tgit(&out, &["branch", "--show-current"]), "main");
        let left: Vec<_> = std::fs::read_dir(tmp.path().join("out"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, ["repo"], "the plain bundle is removed");
    }

    #[test]
    fn restores_a_bundle_from_outside_the_current_layout() {
        let tmp = TempDir::new();
        let id = x25519::Identity::generate();
        let sealed = sealed_bundle(tmp.path(), id.to_public());
        let old = tmp.path().join("drive/old-tool/github-repos-personal");
        std::fs::create_dir_all(old.join("o/r")).unwrap();
        let file = old.join("o/r/2026-01-01.bundle.age");
        std::fs::rename(&sealed, &file).unwrap();
        std::fs::write(old.join("identity.age"), "locked").unwrap();

        let mut p = crate::testutil::paths(tmp.path());
        p.mnt = tmp.path().join("drive");
        assert_eq!(identity_file(&p, &file), old.join("identity.age"));

        let ids: Identities = vec![Box::new(id)];
        let out = tmp.path().join("out/repo");
        restore_bundle(&ids, &file, &out).unwrap();
        tgit(&out, &["fsck", "--strict"]);
        assert!(out.join("f.txt").exists());
    }

    #[test]
    fn a_local_archive_finds_the_key_stored_on_its_drive() {
        let tmp = TempDir::new();
        let mut p = crate::testutil::paths(tmp.path());
        p.mnt = PathBuf::new();
        let archive = tmp.path().join("old/preserver");
        let key = archive.join("github-repos-personal/identity.age");
        std::fs::create_dir_all(key.parent().unwrap()).unwrap();
        std::fs::write(&key, "locked").unwrap();
        let file = archive.join("local-personal/docs/2026-11/L0.tar.zst.age");
        assert_eq!(identity_file(&p, &file), key);
    }

    #[test]
    fn identity_falls_back_to_the_drive_then_home() {
        let tmp = TempDir::new();
        let mut p = crate::testutil::paths(tmp.path());
        let file = tmp.path().join("elsewhere/x.bundle.age");
        assert_eq!(identity_file(&p, &file), p.personal.join("identity.age"));
        std::fs::create_dir_all(p.gh_dest()).unwrap();
        std::fs::write(p.gh_dest().join("identity.age"), "locked").unwrap();
        assert_eq!(identity_file(&p, &file), p.gh_dest().join("identity.age"));
        p.mnt = PathBuf::new();
        assert_eq!(identity_file(&p, &file), p.personal.join("identity.age"));
    }

    #[test]
    fn restores_into_an_existing_empty_dir() {
        let tmp = TempDir::new();
        let id = x25519::Identity::generate();
        let file = sealed_bundle(tmp.path(), id.to_public());
        let ids: Identities = vec![Box::new(id)];
        let out = tmp.path().join("out");
        std::fs::create_dir(&out).unwrap();
        restore_bundle(&ids, &file, &out).unwrap();
        assert!(out.join("f.txt").exists());
    }

    #[test]
    fn refuses_a_non_empty_dir_and_leaves_it_alone() {
        let tmp = TempDir::new();
        let id = x25519::Identity::generate();
        let file = sealed_bundle(tmp.path(), id.to_public());
        let ids: Identities = vec![Box::new(id)];
        let out = tmp.path().join("out");
        std::fs::create_dir(&out).unwrap();
        std::fs::write(out.join("keep"), "mine").unwrap();

        let err = restore_bundle(&ids, &file, &out).unwrap_err();
        assert!(err.to_string().contains("not empty"), "{err}");
        assert_eq!(std::fs::read_to_string(out.join("keep")).unwrap(), "mine");
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 1);

        std::fs::write(tmp.path().join("plainfile"), "x").unwrap();
        assert!(restore_bundle(&ids, &file, &tmp.path().join("plainfile")).is_err());
    }

    #[test]
    fn wrong_key_restores_nothing() {
        let tmp = TempDir::new();
        let file = sealed_bundle(tmp.path(), x25519::Identity::generate().to_public());
        let ids: Identities = vec![Box::new(x25519::Identity::generate())];
        let out = tmp.path().join("out/repo");
        assert!(restore_bundle(&ids, &file, &out).is_err());
        assert!(!out.exists());
        assert_eq!(
            std::fs::read_dir(tmp.path().join("out")).unwrap().count(),
            0
        );
    }
}
