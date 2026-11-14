pub(crate) mod github;
pub(crate) mod local;
pub(crate) mod restore;

use crate::config::{Config, Transport};
use crate::paths::{NoDrive, Paths};
use crate::{crypt, platform, status};
use age::secrecy::{ExposeSecret, SecretString};
use anyhow::{Context, Result, anyhow, bail};
use std::path::Path;

pub(crate) fn run(
    paths: &mut Paths,
    cfg: &Config,
    local_only: bool,
    transport: Transport,
) -> Result<()> {
    let recipient = paths.personal.join("recipient.txt");
    if std::fs::metadata(&recipient).map_or(true, |m| m.len() == 0) {
        bail!("run 'preserver init' first");
    }
    let github = if local_only {
        Ok(())
    } else {
        status::job(paths, "github", |p| github::run(p, cfg, transport))
    };
    // The folders are backed up even when GitHub failed: the two have nothing in common.
    let local = status::job(paths, "local", |p| local::run(p, cfg));
    let result = match (github, local) {
        (Err(github), Err(local)) => Err(anyhow!("{github:#}; local folders: {local:#}")),
        (github, local) => github.and(local),
    };
    match result {
        // The nightly run finds the drive unplugged most days: no notification for that. The failure
        // is still in the status file, so the tray shows it until a run finds the drive.
        Err(e) if local_only && e.is::<NoDrive>() => {
            tracing::warn!("local backup skipped: {e:#}");
            Ok(())
        }
        Err(e) => {
            platform::notify(true, "Personal backup failed", &format!("{e:#}"));
            Err(e)
        }
        Ok(()) => Ok(()),
    }
}

/// Stores a locked private key and its recipient. The locked key goes to the drive and to home,
/// and the recipient to home last: its presence is what marks the setup as done.
fn write_keys(paths: &Paths, locked: &[u8], recipient: &str) -> Result<()> {
    let dest = paths.gh_dest();
    let identities = [
        dest.join("identity.age"),
        paths.personal.join("identity.age"),
    ];
    // A different key cannot open existing backups, so a stored one is never replaced.
    if let Some(existing) = identities.iter().find(|f| f.exists()) {
        bail!(
            "{} already exists; restore recipient.txt from it instead of creating a new key",
            existing.display()
        );
    }
    for file in &identities {
        platform::write_private(file, locked).with_context(|| file.display().to_string())?;
    }
    for file in [
        dest.join("recipient.txt"),
        paths.personal.join("recipient.txt"),
    ] {
        platform::write_private(&file, recipient.as_bytes())
            .with_context(|| file.display().to_string())?;
    }
    println!(
        "Key ready. Copies of the locked private key: {} and {}",
        identities[0].display(),
        identities[1].display()
    );
    Ok(())
}

/// Takes over an existing locked identity after checking that the password opens it.
fn import_keys(paths: &Paths, file: &Path, passphrase: SecretString) -> Result<()> {
    let locked = std::fs::read(file).with_context(|| file.display().to_string())?;
    let recipient = crypt::recipients_of(&locked, passphrase)?;
    write_keys(paths, &locked, &recipient)
}

fn generate_keys(paths: &Paths, passphrase: SecretString) -> Result<()> {
    let (locked, public) = crypt::generate(passphrase)?;
    write_keys(paths, &locked, &format!("{public}\n"))
}

pub(crate) fn init(paths: &mut Paths, cfg: &Config, import: Option<&Path>) -> Result<()> {
    let recipient = paths.personal.join("recipient.txt");
    if recipient.exists() {
        bail!("already initialised ({})", recipient.display());
    }
    paths.mount(&cfg.primary_uuid)?;
    let ask = |prompt: &str| rpassword::prompt_password(prompt).map(SecretString::from);
    let passphrase = ask("Restore password: ").context("read the password")?;
    if let Some(file) = import {
        return import_keys(paths, file, passphrase);
    }
    if passphrase.expose_secret().is_empty() {
        bail!("the password is empty");
    }
    let again = ask("Restore password again: ").context("read the password")?;
    if passphrase.expose_secret() != again.expose_secret() {
        bail!("the passwords differ");
    }
    generate_keys(paths, passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, paths};
    use std::io::{Read, Write};

    #[test]
    fn init_writes_keys_that_open_a_backup() {
        let tmp = TempDir::new();
        let p = paths(tmp.path());
        generate_keys(&p, SecretString::from("pw".to_string())).unwrap();

        let on_drive = std::fs::read(p.gh_dest().join("identity.age")).unwrap();
        let at_home = std::fs::read(p.personal.join("identity.age")).unwrap();
        assert_eq!(on_drive, at_home);
        assert!(
            !on_drive
                .windows(14)
                .any(|w| w.eq_ignore_ascii_case(b"AGE-SECRET-KEY")),
            "the key is stored locked"
        );
        assert_eq!(
            std::fs::read(p.gh_dest().join("recipient.txt")).unwrap(),
            std::fs::read(p.personal.join("recipient.txt")).unwrap()
        );

        let recipients = crypt::read_recipients(&p.personal.join("recipient.txt")).unwrap();
        let mut w = crypt::encrypt(&recipients, Vec::new()).unwrap();
        w.write_all(b"data").unwrap();
        let sealed = w.finish().unwrap();
        let ids = crypt::unlock(&at_home, SecretString::from("pw".to_string())).unwrap();
        let mut plain = Vec::new();
        crypt::decrypt(&ids, &sealed[..])
            .unwrap()
            .read_to_end(&mut plain)
            .unwrap();
        assert_eq!(plain, b"data");
    }

    #[test]
    fn init_never_replaces_an_existing_identity() {
        for on_drive in [true, false] {
            let tmp = TempDir::new();
            let p = paths(tmp.path());
            let existing = if on_drive {
                p.gh_dest().join("identity.age")
            } else {
                p.personal.join("identity.age")
            };
            platform::write_private(&existing, b"old key").unwrap();
            assert!(generate_keys(&p, SecretString::from("pw".to_string())).is_err());
            assert_eq!(std::fs::read(&existing).unwrap(), b"old key");
            assert!(!p.personal.join("recipient.txt").exists());
        }
    }

    #[test]
    fn import_keeps_the_key_and_derives_the_recipient() {
        let tmp = TempDir::new();
        let p = paths(tmp.path());
        let (locked, public) = crypt::generate(SecretString::from("pw".to_string())).unwrap();
        let src = tmp.path().join("identity.age");
        std::fs::write(&src, &locked).unwrap();

        let wrong = import_keys(&p, &src, SecretString::from("nope".to_string()));
        assert!(wrong.is_err());
        assert!(
            !p.personal.join("identity.age").exists(),
            "nothing stored on a bad password"
        );

        import_keys(&p, &src, SecretString::from("pw".to_string())).unwrap();
        for dir in [p.gh_dest(), p.personal.clone()] {
            assert_eq!(std::fs::read(dir.join("identity.age")).unwrap(), locked);
            assert_eq!(
                std::fs::read_to_string(dir.join("recipient.txt")).unwrap(),
                format!("{public}\n")
            );
        }
    }

    #[test]
    fn personal_needs_init_first() {
        let tmp = TempDir::new();
        let mut p = paths(tmp.path());
        let cfg = Config::parse("owners = []\nprimary_uuid = \"0123-abcd\"\n").unwrap();
        let err = run(&mut p, &cfg, false, Transport::Ssh).unwrap_err();
        assert!(err.to_string().contains("init"), "{err}");
        assert!(!p.status_file("github").exists());
    }
}
