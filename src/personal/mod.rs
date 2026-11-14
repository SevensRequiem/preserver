pub(crate) mod github;
pub(crate) mod lane;
pub(crate) mod local;
pub(crate) mod restore;

use crate::config::Config;
use crate::paths::Paths;
use crate::{crypt, platform};
use age::secrecy::{ExposeSecret, SecretString};
use anyhow::{Context, Result, bail};
use std::path::Path;

/// How a run reports each repo or folder and learns, between them, that it should stop.
pub(crate) struct Hooks<'a> {
    pub on_item: &'a (dyn Fn(usize, usize, &str) + Sync),
    pub stop: &'a (dyn Fn() -> bool + Sync),
}

impl Hooks<'_> {
    #[cfg(test)]
    pub(crate) const NONE: Hooks<'static> = Hooks {
        on_item: &|_, _, _| {},
        stop: &|| false,
    };
}

/// A run ended early because its job was paused or canceled.
#[derive(Debug)]
pub(crate) struct Stopped;

impl std::fmt::Display for Stopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("stopped")
    }
}

impl std::error::Error for Stopped {}

pub(crate) fn require_init(paths: &Paths) -> Result<()> {
    let recipient = paths.personal.join("recipient.txt");
    if std::fs::metadata(&recipient).map_or(true, |m| m.len() == 0) {
        bail!("run 'preserver init' first");
    }
    Ok(())
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
        let p = paths(tmp.path());
        let err = require_init(&p).unwrap_err();
        assert!(err.to_string().contains("init"), "{err}");
        platform::write_private(&p.personal.join("recipient.txt"), b"age1x\n").unwrap();
        require_init(&p).unwrap();
    }
}
