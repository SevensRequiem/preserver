//! `OpenPGP` signature checks on rpgp.
//!
//! The verdict follows what `gpgv` reports as VALIDSIG with a zero exit: every signature in the
//! file must verify under a key of the keyring, an expired key still counts (upstreams keep
//! signing past expiry and old releases stay valid), an expired signature or one older than
//! its key does not, a post-dated one is accepted, and a signing subkey needs a valid, cross-certified binding. One rule is stricter than
//! gpgv: a key or subkey its owner revoked is refused.

use anyhow::{Context, Result, bail};
use pgp::composed::{
    CleartextSignedMessage, Deserializable, DetachedSignature, SignedPublicKey, SignedPublicSubKey,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::packet::{Signature, SignatureType};
use pgp::types::{KeyDetails, Timestamp};
use std::io::Read;

const ARMOR_BEGIN: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
const ARMOR_END: &str = "-----END PGP PUBLIC KEY BLOCK-----";
const SIGNATURE_END: &str = "-----END PGP SIGNATURE-----";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Signer {
    /// Fingerprint of the key that made the signature, upper-case hex.
    pub key: String,
    /// Fingerprint of its primary key: the same for a signature by the primary.
    pub primary: String,
}

impl Signer {
    /// With pins, the signing key or its primary must be one of them.
    pub(crate) fn pinned(&self, signers: &[String]) -> Result<()> {
        if signers.is_empty() || signers.iter().any(|p| *p == self.key || *p == self.primary) {
            return Ok(());
        }
        bail!("signed by {}, which is not a pinned signer", self.primary)
    }
}

fn fpr(k: &impl KeyDetails) -> String {
    format!("{:X}", k.fingerprint())
}

/// The keys that parse, from one binary block. A key that doesn't parse is skipped: one
/// ancient key must not take the whole keyring down.
fn binary(bytes: &[u8], out: &mut Vec<SignedPublicKey>) {
    let Ok(keys) = SignedPublicKey::from_bytes_many(bytes) else {
        return;
    };
    for k in keys {
        match k {
            Ok(k) => out.push(k),
            Err(e) => tracing::debug!("keyring: skipping a key: {e}"),
        }
    }
}

/// Every public key in a keyring file: binary, or any number of armored blocks.
pub(crate) fn keyring(bytes: &[u8]) -> Vec<SignedPublicKey> {
    let mut out = Vec::new();
    // A binary packet stream starts with a tag byte, which has its top bit set.
    if bytes.first().is_some_and(|b| b & 0x80 != 0) {
        binary(bytes, &mut out);
        return out;
    }
    let text = String::from_utf8_lossy(bytes);
    let mut rest = &*text;
    while let Some(start) = rest.find(ARMOR_BEGIN) {
        let block = &rest[start..];
        let end = block
            .find(ARMOR_END)
            .map_or(block.len(), |e| e + ARMOR_END.len());
        match SignedPublicKey::from_armor_many(&block.as_bytes()[..end]) {
            Ok((keys, _)) => {
                for k in keys {
                    match k {
                        Ok(k) => out.push(k),
                        Err(e) => tracing::debug!("keyring: skipping a key: {e}"),
                    }
                }
            }
            Err(e) => tracing::debug!("keyring: skipping an armor block: {e}"),
        }
        rest = &block[end..];
    }
    out
}

/// The primary key fingerprints of a keyring file, sorted.
pub(crate) fn primary_fingerprints(bytes: &[u8]) -> Vec<String> {
    let mut f: Vec<String> = keyring(bytes).iter().map(fpr).collect();
    f.sort();
    f.dedup();
    f
}

fn revoked(key: &SignedPublicKey) -> bool {
    key.details.revocation_signatures.iter().any(|s| {
        s.typ() == Some(SignatureType::KeyRevocation) && s.verify_key(&key.primary_key).is_ok()
    })
}

/// The fingerprints of the keys and subkeys of a keyring file that carry a revocation made by
/// their own primary key: what an upstream publishes when a signing key is stolen.
pub(crate) fn revocations(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for key in keyring(bytes) {
        if revoked(&key) {
            out.push(fpr(&key.primary_key));
        }
        for sub in &key.public_subkeys {
            let gone = sub.signatures.iter().any(|s| {
                s.typ() == Some(SignatureType::SubkeyRevocation)
                    && s.verify_subkey_binding(&key.primary_key, &sub.key).is_ok()
            });
            if gone {
                out.push(fpr(&sub.key));
            }
        }
    }
    out
}

/// A subkey may sign when one of its bindings is valid, carries the signing flag and holds
/// the subkey's own signature back over the primary; a valid revocation ends that.
fn subkey_usable(key: &SignedPublicKey, sub: &SignedPublicSubKey) -> Result<()> {
    let valid = |s: &&Signature| s.verify_subkey_binding(&key.primary_key, &sub.key).is_ok();
    let of = |t: SignatureType| sub.signatures.iter().filter(move |s| s.typ() == Some(t));
    if of(SignatureType::SubkeyRevocation).any(|s| valid(&s)) {
        bail!("subkey {} is revoked", fpr(&sub.key));
    }
    let bound = of(SignatureType::SubkeyBinding).any(|s| {
        valid(&s)
            && s.key_flags().sign()
            && s.embedded_signature().is_some_and(|back| {
                back.verify_primary_key_binding(&sub.key, &key.primary_key)
                    .is_ok()
            })
    });
    if !bound {
        bail!(
            "subkey {} has no valid cross-certified signing binding",
            fpr(&sub.key)
        );
    }
    Ok(())
}

fn times(sig: &Signature, key_created: Timestamp) -> Result<()> {
    let created = sig.created().context("signature has no creation time")?;
    let now = Timestamp::now();
    if created < key_created {
        bail!("signature is older than its key");
    }
    if let Some(d) = sig.signature_expiration_time() {
        let life = std::time::Duration::from(d).as_secs();
        if life > 0 && u64::from(created.as_secs()) + life < u64::from(now.as_secs()) {
            bail!("signature has expired");
        }
    }
    Ok(())
}

/// Verifies one signature over the bytes `open` yields and names its signer.
fn check(
    ring: &[SignedPublicKey],
    sig: &Signature,
    open: &mut dyn FnMut() -> Result<Box<dyn Read>>,
) -> Result<Signer> {
    if sig.hash_alg() == Some(HashAlgorithm::Md5) {
        bail!("MD5 signature");
    }
    let fps = sig.issuer_fingerprint();
    let ids = sig.issuer_key_id();
    if fps.is_empty() && ids.is_empty() {
        bail!("signature does not name its issuer");
    }
    // The fingerprint when the signature has one; the 64-bit key id only as a fallback.
    let issued = |fp: pgp::types::Fingerprint, id: pgp::types::KeyId| {
        if fps.is_empty() {
            ids.iter().any(|i| **i == id)
        } else {
            fps.iter().any(|f| **f == fp)
        }
    };
    let mut last = None;
    for key in ring {
        let primary = &key.primary_key;
        if issued(primary.fingerprint(), primary.legacy_key_id()) {
            let r = (|| {
                if revoked(key) {
                    bail!("key {} is revoked", fpr(primary));
                }
                times(sig, primary.created_at())?;
                sig.verify(primary, open()?)
                    .map_err(|e| anyhow::anyhow!("{e}"))
            })();
            match r {
                Ok(()) => {
                    return Ok(Signer {
                        key: fpr(primary),
                        primary: fpr(primary),
                    });
                }
                Err(e) => last = Some(e),
            }
        }
        for sub in &key.public_subkeys {
            if !issued(sub.key.fingerprint(), sub.key.legacy_key_id()) {
                continue;
            }
            let r = (|| {
                if revoked(key) {
                    bail!("key {} is revoked", fpr(primary));
                }
                subkey_usable(key, sub)?;
                times(sig, sub.key.created_at())?;
                sig.verify(&sub.key, open()?)
                    .map_err(|e| anyhow::anyhow!("{e}"))
            })();
            match r {
                Ok(()) => {
                    return Ok(Signer {
                        key: fpr(&sub.key),
                        primary: fpr(primary),
                    });
                }
                Err(e) => last = Some(e),
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("the signing key is not in the keyring")))
}

/// Checks a detached signature file (binary or armored) over the bytes `open` yields. Every
/// signature in it must verify; the last one names the signer, as with gpgv.
pub(crate) fn detached(
    ring: &[SignedPublicKey],
    sig: &[u8],
    open: &mut dyn FnMut() -> Result<Box<dyn Read>>,
) -> Result<Signer> {
    let (sigs, _) = DetachedSignature::from_reader_many(sig)
        .map_err(|e| anyhow::anyhow!("unreadable signature: {e}"))?;
    let mut signer = None;
    for s in sigs {
        let s = s.map_err(|e| anyhow::anyhow!("unreadable signature: {e}"))?;
        signer = Some(check(ring, &s.signature, open).context("bad signature")?);
    }
    signer.context("bad signature: the file holds no signature")
}

/// Checks a clearsigned document and returns the signer with the text the signature covers.
/// Only that text may be trusted: whatever surrounds the signed block is not returned.
pub(crate) fn clearsigned(ring: &[SignedPublicKey], doc: &[u8]) -> Result<(Signer, String)> {
    let text = std::str::from_utf8(doc).context("clearsigned file is not text")?;
    let start = text
        .find("-----BEGIN PGP SIGNED MESSAGE-----")
        .context("not a clearsigned file")?;
    let end = text[start..]
        .find(SIGNATURE_END)
        .map_or(text.len(), |e| start + e + SIGNATURE_END.len());
    let (msg, _) = CleartextSignedMessage::from_string(&text[start..end])
        .map_err(|e| anyhow::anyhow!("unreadable clearsigned file: {e}"))?;
    let covered = msg.signed_text();
    let mut signer = None;
    for s in msg.signatures() {
        let mut open = || Ok(Box::new(std::io::Cursor::new(covered.clone())) as Box<dyn Read>);
        signer = Some(check(ring, s, &mut open).context("bad signature")?);
    }
    Ok((
        signer.context("bad signature: the file holds no signature")?,
        covered,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys;
    use crate::testutil::TempDir;
    use crate::verify::testkey::TestKey;
    use ::pgp::ser::Serialize;
    use std::io::Cursor;
    use std::path::Path;
    use std::process::Command;

    const DATA: &[u8] = b"the release tarball\n";

    /// In gnu-keyring but not usable: RSA keys of 9888 and 15424 bits, above rpgp's limit
    /// without its `large-rsa` feature. Signatures by them fail closed.
    const OVERSIZED: [&str; 2] = [
        "904AD2F81FB16978E7536F726DEA2BA30BC39EB6",
        "CDA01A4208C4F74506107E7BD1AB451688888888",
    ];

    fn verify(ring: &[u8], sig: &[u8], data: &[u8]) -> Result<Signer> {
        let data = data.to_vec();
        let mut open = move || Ok(Box::new(Cursor::new(data.clone())) as Box<dyn Read>);
        detached(&keyring(ring), sig, &mut open)
    }

    fn now() -> u32 {
        Timestamp::now().as_secs()
    }

    #[test]
    fn embedded_keyrings_match_the_fingerprints_file() {
        let listed = include_str!("../../keys/FINGERPRINTS");
        for (name, bytes) in keys::EMBEDDED {
            let want: Vec<&str> = listed
                .lines()
                .filter_map(|l| l.split_once(' '))
                .filter(|(file, _)| file.strip_suffix(".gpg") == Some(name))
                .map(|(_, f)| f)
                .collect();
            assert!(!want.is_empty(), "{name} is not in keys/FINGERPRINTS");
            let usable: Vec<&str> = want
                .iter()
                .copied()
                .filter(|f| !OVERSIZED.contains(f))
                .collect();
            assert_eq!(primary_fingerprints(bytes), usable, "{name}");
        }
        let files: std::collections::BTreeSet<&str> = listed
            .lines()
            .filter_map(|l| l.split_once(' '))
            .map(|(f, _)| f)
            .collect();
        assert_eq!(
            files.len(),
            keys::EMBEDDED.len(),
            "a listed keyring is not embedded"
        );
    }

    #[test]
    fn detached_signatures() {
        let key = TestKey::new();
        let other = TestKey::new();
        let sig = key.sign(DATA);

        let s = verify(&key.public(), &sig, DATA).unwrap();
        assert_eq!(
            (s.key.as_str(), s.primary.as_str()),
            (&*key.fingerprint(), &*key.fingerprint())
        );
        let s = verify(&key.public(), key.sign_armored(DATA).as_bytes(), DATA).unwrap();
        assert_eq!(s.primary, key.fingerprint());

        assert!(
            verify(&key.public(), &sig, b"the release tarball!\n").is_err(),
            "tampered data"
        );
        let err = verify(&other.public(), &sig, DATA).unwrap_err();
        assert!(format!("{err:#}").contains("not in the keyring"), "{err:#}");
        assert!(verify(&key.public(), b"not a signature", DATA).is_err());
        assert!(
            verify(&key.public(), b"", DATA).is_err(),
            "no signature at all"
        );
        assert!(verify(b"", &sig, DATA).is_err(), "empty keyring");

        // Two signatures in one file: both must verify.
        let both = [sig.clone(), other.sign(DATA)].concat();
        assert!(verify(&key.public(), &both, DATA).is_err());
        let ring = [key.public(), other.public()].concat();
        assert_eq!(
            verify(&ring, &both, DATA).unwrap().primary,
            other.fingerprint()
        );
    }

    #[test]
    fn pins_match_the_primary_or_the_subkey() {
        let key = TestKey::make(3600, true);
        let sig = key.sign_with_subkey(DATA);
        let s = verify(&key.public(), &sig, DATA).unwrap();
        assert_eq!(s.key, key.subkey_fingerprint());
        assert_eq!(s.primary, key.fingerprint());
        s.pinned(&[]).unwrap();
        s.pinned(&[key.fingerprint()]).unwrap();
        s.pinned(&["0".repeat(40), key.subkey_fingerprint()])
            .unwrap();
        let err = s.pinned(&[TestKey::new().fingerprint()]).unwrap_err();
        assert!(err.to_string().contains("not a pinned signer"), "{err}");
    }

    #[test]
    fn a_subkey_without_its_binding_is_refused() {
        let key = TestKey::make(3600, true);
        let sig = key.sign_with_subkey(DATA);
        // A binding that claims the signing flag without the subkey's signature back.
        let primary = &key.secret.primary_key;
        let mut flags = ::pgp::packet::KeyFlags::default();
        flags.set_sign(true);
        let bare = key.secret.secret_subkeys[0]
            .key
            .sign(
                rsa::rand_core::OsRng,
                primary,
                primary.public_key(),
                &::pgp::types::Password::empty(),
                flags,
                None,
            )
            .unwrap();
        let mut public = key.secret.to_public_key();
        public.public_subkeys[0].signatures = vec![bare];
        let ring = public.to_bytes().unwrap();
        let err = verify(&ring, &sig, DATA).unwrap_err();
        assert!(format!("{err:#}").contains("cross-certified"), "{err:#}");
        // And a subkey from another key grafted on has no binding at all.
        let thief = TestKey::make(3600, true);
        let mut graft = thief.secret.to_public_key();
        graft.public_subkeys = key.secret.to_public_key().public_subkeys;
        assert!(verify(&graft.to_bytes().unwrap(), &sig, DATA).is_err());
    }

    #[test]
    fn key_and_signature_lifetimes() {
        // An expired key still verifies, as with gpgv.
        let mut old = TestKey::make(10 * 86400, false);
        old.expire_after(86400);
        verify(&old.public(), &old.sign(DATA), DATA).unwrap();

        let mut gone = TestKey::new();
        let sig = gone.sign(DATA);
        gone.revoke();
        let err = verify(&gone.public(), &sig, DATA).unwrap_err();
        assert!(format!("{err:#}").contains("revoked"), "{err:#}");

        let key = TestKey::new();
        let cases = [
            ("valid for a day", now() - 60, Some(86400), true),
            ("expired", now() - 7200, Some(3600), false),
            ("from the future", now() + 86400, None, true),
            ("older than its key", now() - 86400, None, false),
        ];
        for (name, created, life, want) in cases {
            let sig = key.sign_at(DATA, created, life);
            let got = verify(&key.public(), &sig, DATA);
            assert_eq!(got.is_ok(), want, "{name}: {got:?}");
        }
    }

    #[test]
    fn clearsigned_documents() {
        let key = TestKey::new();
        let text = "aaaa  one.iso\nbbbb  two.iso\n";
        let doc = key.clearsign(text);
        let ring = keyring(&key.public());
        let (signer, covered) = clearsigned(&ring, doc.as_bytes()).unwrap();
        assert_eq!(signer.primary, key.fingerprint());
        assert!(covered.contains("aaaa  one.iso"));

        // Lines around the signed block are not part of what is returned.
        let wrapped = format!("cccc  evil.iso\n{doc}dddd  evil.iso\n");
        let (_, covered) = clearsigned(&ring, wrapped.as_bytes()).unwrap();
        assert!(!covered.contains("evil"), "{covered}");

        let tampered = doc.replace("aaaa", "aaab");
        assert!(clearsigned(&ring, tampered.as_bytes()).is_err());
        assert!(clearsigned(&keyring(&TestKey::new().public()), doc.as_bytes()).is_err());
        assert!(
            clearsigned(&ring, text.as_bytes()).is_err(),
            "unsigned text"
        );
    }

    #[test]
    fn keyring_formats() {
        let (a, b) = (TestKey::new(), TestKey::new());
        let mut want = vec![a.fingerprint(), b.fingerprint()];
        want.sort();
        let binary = [a.public(), b.public()].concat();
        assert_eq!(primary_fingerprints(&binary), want);
        // Several armored blocks, with text around them, as key servers and release pages serve.
        let armored = format!("<pre>\n{}\nsome text\n{}</pre>\n", a.armored(), b.armored());
        assert_eq!(primary_fingerprints(armored.as_bytes()), want);
        assert_eq!(primary_fingerprints(b"no keys here"), Vec::<String>::new());
    }

    /// Name, keyring, signature, data.
    type Case<'a> = (&'a str, Vec<u8>, Vec<u8>, &'a [u8]);

    /// gpgv's verdict: exit status zero and a VALIDSIG line.
    fn gpgv(dir: &Path, ring: &[u8], sig: &[u8], data: &[u8]) -> bool {
        let (r, s, d) = (dir.join("ring.gpg"), dir.join("f.sig"), dir.join("f"));
        std::fs::write(&r, ring).unwrap();
        std::fs::write(&s, sig).unwrap();
        std::fs::write(&d, data).unwrap();
        let out = Command::new("/usr/bin/gpgv")
            .env("GNUPGHOME", dir)
            .args(["--status-fd", "1", "--keyring"])
            .arg(&r)
            .arg("--")
            .args([&s, &d])
            .output()
            .unwrap();
        out.status.success() && String::from_utf8_lossy(&out.stdout).contains("VALIDSIG")
    }

    #[test]
    fn same_verdicts_as_gpgv() {
        if !Path::new("/usr/bin/gpgv").exists() {
            eprintln!("skipped: no /usr/bin/gpgv");
            return;
        }
        let tmp = TempDir::new();
        let key = TestKey::new();
        let other = TestKey::new();
        let sub = TestKey::make(3600, true);
        let mut expired = TestKey::make(10 * 86400, false);
        expired.expire_after(86400);
        let good = key.sign(DATA);
        let two_rings = [other.public(), key.public()].concat();
        let two_sigs = [good.clone(), other.sign(DATA)].concat();
        let cases: Vec<Case> = vec![
            ("good", key.public(), good.clone(), DATA),
            (
                "good, armored",
                key.public(),
                key.sign_armored(DATA).into_bytes(),
                DATA,
            ),
            (
                "tampered data",
                key.public(),
                good.clone(),
                b"something else\n",
            ),
            ("wrong signer", other.public(), good.clone(), DATA),
            (
                "second key of the ring",
                two_rings.clone(),
                good.clone(),
                DATA,
            ),
            (
                "signing subkey",
                sub.public(),
                sub.sign_with_subkey(DATA),
                DATA,
            ),
            ("expired key", expired.public(), expired.sign(DATA), DATA),
            (
                "expired signature",
                key.public(),
                key.sign_at(DATA, now() - 7200, Some(3600)),
                DATA,
            ),
            (
                "unexpired signature",
                key.public(),
                key.sign_at(DATA, now() - 60, Some(3600)),
                DATA,
            ),
            (
                "signature from the future",
                key.public(),
                key.sign_at(DATA, now() + 86400, None),
                DATA,
            ),
            (
                "signature older than its key",
                key.public(),
                key.sign_at(DATA, now() - 86400, None),
                DATA,
            ),
            (
                "two signatures, one unknown signer",
                key.public(),
                two_sigs.clone(),
                DATA,
            ),
            ("two signatures, both known", two_rings, two_sigs, DATA),
            (
                "truncated signature",
                key.public(),
                good[..good.len() - 3].to_vec(),
                DATA,
            ),
        ];
        let mut diffs = Vec::new();
        for (i, (name, ring, sig, data)) in cases.iter().enumerate() {
            let dir = tmp.path().join(i.to_string());
            std::fs::create_dir(&dir).unwrap();
            let theirs = gpgv(&dir, ring, sig, data);
            let ours = verify(ring, sig, data);
            if ours.is_ok() != theirs {
                diffs.push(format!("{name}: gpgv {theirs}, rpgp {ours:?}"));
            }
        }
        assert!(diffs.is_empty(), "{diffs:#?}");

        // The one deliberate difference: gpgv still reports VALIDSIG for a revoked key.
        let mut revoked = TestKey::new();
        let sig = revoked.sign(DATA);
        revoked.revoke();
        assert!(verify(&revoked.public(), &sig, DATA).is_err());
    }
}
