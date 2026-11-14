use age::secrecy::{ExposeSecret, SecretString};
use age::stream::{StreamReader, StreamWriter};
use age::{Decryptor, Encryptor, Identity, IdentityFile, Recipient, scrypt, x25519};
use anyhow::{Context, Result, anyhow, bail};
use std::io::{Read, Write};
use std::path::Path;

pub(crate) type Identities = Vec<Box<dyn Identity + Send + Sync>>;

/// 18 is age's own default for passphrase files; 22 is the most `unlock` accepts when reading.
const SCRYPT_WORK_FACTOR: u8 = 18;
const SCRYPT_MAX_WORK_FACTOR: u8 = 22;

/// Reads `recipient.txt`: one `age1…` key per line, `#` comments allowed.
pub(crate) fn read_recipients(file: &Path) -> Result<Vec<x25519::Recipient>> {
    let text = std::fs::read_to_string(file)
        .with_context(|| format!("{}: run 'preserver init' first", file.display()))?;
    let recipients = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            l.parse::<x25519::Recipient>()
                .map_err(|e| anyhow!("{}: {e}", file.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    if recipients.is_empty() {
        bail!("{} is empty: run 'preserver init' first", file.display());
    }
    Ok(recipients)
}

/// Wraps `out` so that what is written comes out encrypted. The caller must `finish()` the writer.
pub(crate) fn encrypt<W: Write>(
    recipients: &[x25519::Recipient],
    out: W,
) -> Result<StreamWriter<W>> {
    Ok(
        Encryptor::with_recipients(recipients.iter().map(|r| r as &dyn Recipient))?
            .wrap_output(out)?,
    )
}

pub(crate) fn decrypt<R: Read>(identities: &Identities, input: R) -> Result<StreamReader<R>> {
    Ok(Decryptor::new(input)?.decrypt(identities.iter().map(|i| i.as_ref() as &dyn Identity))?)
}

/// Opens a passphrase-locked `identity.age` and returns the keys inside.
pub(crate) fn unlock(locked: &[u8], passphrase: SecretString) -> Result<Identities> {
    let mut key = scrypt::Identity::new(passphrase);
    key.set_max_work_factor(SCRYPT_MAX_WORK_FACTOR);
    let mut text = String::new();
    Decryptor::new_buffered(locked)?
        .decrypt(std::iter::once(&key as &dyn Identity))
        .context("wrong passphrase, or not a passphrase-locked age file")?
        .read_to_string(&mut text)?;
    let text = SecretString::from(text);
    Ok(IdentityFile::from_buffer(text.expose_secret().as_bytes())?.into_identities()?)
}

/// Opens a locked identity file to prove the passphrase fits, and returns the `recipient.txt`
/// text for the keys inside.
pub(crate) fn recipients_of(locked: &[u8], passphrase: SecretString) -> Result<String> {
    let mut key = scrypt::Identity::new(passphrase);
    key.set_max_work_factor(SCRYPT_MAX_WORK_FACTOR);
    let mut text = String::new();
    Decryptor::new_buffered(locked)?
        .decrypt(std::iter::once(&key as &dyn Identity))
        .context("wrong passphrase, or not a passphrase-locked age file")?
        .read_to_string(&mut text)?;
    let text = SecretString::from(text);
    let mut out = Vec::new();
    IdentityFile::from_buffer(text.expose_secret().as_bytes())?
        .write_recipients_file(&mut out)
        .map_err(|e| anyhow!("{e}"))?;
    Ok(String::from_utf8(out)?)
}

/// Generates a key pair and returns the passphrase-locked identity file and the public recipient.
/// The secret key only ever leaves this function encrypted.
pub(crate) fn generate(passphrase: SecretString) -> Result<(Vec<u8>, String)> {
    let identity = x25519::Identity::generate();
    let public = identity.to_public().to_string();
    let mut lock = scrypt::Recipient::new(passphrase);
    lock.set_work_factor(SCRYPT_WORK_FACTOR);
    let mut out = Encryptor::with_recipients(std::iter::once(&lock as &dyn Recipient))?
        .wrap_output(Vec::new())?;
    // The layout age-keygen writes, so `age -d identity.age` yields a usable key file.
    write!(
        out,
        "# created: {}\n# public key: {public}\n",
        jiff::Timestamp::now()
    )?;
    out.write_all(identity.to_string().expose_secret().as_bytes())?;
    out.write_all(b"\n")?;
    Ok((out.finish()?, public))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::process::{Command, Stdio};

    fn secret(s: &str) -> SecretString {
        SecretString::from(s.to_string())
    }

    #[test]
    fn generated_identity_round_trips() {
        let (locked, public) = generate(secret("correct horse")).unwrap();
        let header = String::from_utf8_lossy(&locked[..locked.len().min(120)]).into_owned();
        assert!(
            header.starts_with("age-encryption.org/v1\n-> scrypt "),
            "{header}"
        );
        assert!(
            header.lines().nth(1).unwrap().ends_with(" 18"),
            "work factor: {header}"
        );

        let tmp = TempDir::new();
        let file = tmp.path().join("recipient.txt");
        std::fs::write(&file, format!("# backup key\n{public}\n")).unwrap();
        let recipients = read_recipients(&file).unwrap();

        let mut w = encrypt(&recipients, Vec::new()).unwrap();
        w.write_all(b"payload").unwrap();
        let sealed = w.finish().unwrap();
        assert!(!sealed.windows(7).any(|w| w == b"payload"));

        let ids = unlock(&locked, secret("correct horse")).unwrap();
        let mut plain = Vec::new();
        decrypt(&ids, &sealed[..])
            .unwrap()
            .read_to_end(&mut plain)
            .unwrap();
        assert_eq!(plain, b"payload");
    }

    #[test]
    fn recipients_come_from_the_locked_identity() {
        let (locked, public) = generate(secret("pw")).unwrap();
        assert_eq!(
            recipients_of(&locked, secret("pw")).unwrap(),
            format!("{public}\n")
        );
        assert!(recipients_of(&locked, secret("nope")).is_err());
    }

    #[test]
    fn wrong_passphrase_and_wrong_key_fail() {
        let (locked, public) = generate(secret("right")).unwrap();
        assert!(unlock(&locked, secret("wrong")).is_err());
        assert!(unlock(b"not an age file", secret("right")).is_err());

        let recipient: x25519::Recipient = public.parse().unwrap();
        let mut w = encrypt(&[recipient], Vec::new()).unwrap();
        w.write_all(b"payload").unwrap();
        let sealed = w.finish().unwrap();
        let other: Identities = vec![Box::new(x25519::Identity::generate())];
        assert!(decrypt(&other, &sealed[..]).is_err());
    }

    #[test]
    fn truncated_ciphertext_fails() {
        let id = x25519::Identity::generate();
        let mut w = encrypt(&[id.to_public()], Vec::new()).unwrap();
        w.write_all(&vec![7u8; 100_000]).unwrap();
        let sealed = w.finish().unwrap();
        let ids: Identities = vec![Box::new(id)];
        let mut plain = Vec::new();
        let cut = &sealed[..sealed.len() - 10];
        assert!(decrypt(&ids, cut).unwrap().read_to_end(&mut plain).is_err());
    }

    #[test]
    fn recipient_file_rejects_junk() {
        let tmp = TempDir::new();
        let file = tmp.path().join("recipient.txt");
        assert!(read_recipients(&file).is_err(), "absent");
        for (name, text) in [
            ("empty", ""),
            ("comment only", "# nothing\n"),
            ("not a key", "age1notakey\n"),
        ] {
            std::fs::write(&file, text).unwrap();
            assert!(read_recipients(&file).is_err(), "{name}");
        }
    }

    #[test]
    fn interoperates_with_the_age_cli() {
        const AGE: &str = "/usr/bin/age";
        if !Path::new(AGE).exists() {
            eprintln!("skipped: {AGE} is not installed");
            return;
        }
        let tmp = TempDir::new();
        let id = x25519::Identity::generate();
        let key = tmp.path().join("key.txt");
        std::fs::write(&key, format!("{}\n", id.to_string().expose_secret())).unwrap();

        let ours = tmp.path().join("ours.age");
        let mut w = encrypt(&[id.to_public()], std::fs::File::create(&ours).unwrap()).unwrap();
        w.write_all(b"from preserver").unwrap();
        w.finish().unwrap();
        let out = Command::new(AGE)
            .arg("-d")
            .arg("-i")
            .arg(&key)
            .arg("--")
            .arg(&ours)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"from preserver");

        let plain_file = tmp.path().join("plain");
        std::fs::write(&plain_file, "from the cli").unwrap();
        let theirs = tmp.path().join("theirs.age");
        let status = Command::new(AGE)
            .args(["-r", &id.to_public().to_string(), "-o"])
            .arg(&theirs)
            .arg("--")
            .arg(&plain_file)
            .status()
            .unwrap();
        assert!(status.success());
        let ids: Identities = vec![Box::new(id)];
        let mut plain = String::new();
        decrypt(&ids, std::fs::File::open(&theirs).unwrap())
            .unwrap()
            .read_to_string(&mut plain)
            .unwrap();
        assert_eq!(plain, "from the cli");
    }
}
