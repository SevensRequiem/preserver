use crate::crypt::{self, Identities};
use crate::paths::Paths;
use crate::platform;
use age::secrecy::SecretString;
use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::{Command, Stdio};

fn check_target(dir: &Path) -> Result<()> {
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

pub(crate) fn run(paths: &Paths, file: &Path, dir: &Path) -> Result<()> {
    let name = file.to_string_lossy();
    if name.ends_with(".tar.zst.age") {
        bail!("local-folder archives are not implemented yet (phase 1b)");
    }
    check_target(dir)?;
    let on_drive = paths.gh_dest().join("identity.age");
    let id_file = if !paths.mnt.as_os_str().is_empty() && on_drive.exists() {
        on_drive
    } else {
        paths.personal.join("identity.age")
    };
    let locked = std::fs::read(&id_file).with_context(|| id_file.display().to_string())?;
    let passphrase = SecretString::from(
        rpassword::prompt_password(format!("Restore password for {}: ", id_file.display()))
            .context("read the password")?,
    );
    let identities = crypt::unlock(&locked, passphrase)?;
    restore_bundle(&identities, file, dir)?;
    println!("Restored into {}", dir.display());
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
