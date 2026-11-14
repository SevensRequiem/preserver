//! Decides whether a downloaded file may become visible, and says how it was trusted.

pub(crate) mod pgp;
mod sums;
#[cfg(test)]
pub(crate) mod testkey;

use crate::catalog::{SigOver, Source};
use crate::keys::{self, Keyring};
use crate::platform;
use crate::resolve::{Item, hex, url_base};
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256, Sha512};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};

/// Signatures, sums files and keys are read whole; nothing honest comes near this.
pub(crate) const SIDE_LIMIT: u64 = 16 << 20;
/// Decoder memory for a signed `.xz`, in KiB: four times what `xz -9` needs (64 MiB).
/// Most an honest tarball inflates by under xz.
const XZ_RATIO: u64 = 64;
const XZ_MEM_KIB: u32 = 256 << 10;

pub(crate) struct Verifier<'a> {
    pub keys: &'a [Keyring<'a>],
    /// `tofu.json`: the hash first seen for each url that nothing else vouches for.
    pub tofu: &'a Path,
    /// Raises a desktop notification: urgent, title, body.
    pub note: &'a (dyn Fn(bool, &str, &str) + Sync),
}

/// Where a signature or sums file sits: next to the file it belongs to, under its own name.
pub(crate) fn side(file: &Path, url: &str) -> PathBuf {
    file.with_file_name(url_base(url))
}

fn read_side(path: &Path) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    File::open(path)
        .with_context(|| path.display().to_string())?
        .take(SIDE_LIMIT + 1)
        .read_to_end(&mut out)?;
    if out.len() as u64 > SIDE_LIMIT {
        bail!("{} is larger than {SIDE_LIMIT} bytes", path.display());
    }
    Ok(out)
}

fn hash_file(path: &Path) -> Result<(String, String)> {
    let mut f = File::open(path).with_context(|| path.display().to_string())?;
    let (mut a, mut b) = (Sha256::new(), Sha512::new());
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            return Ok((hex(&a.finalize()), hex(&b.finalize())));
        }
        a.update(&buf[..n]);
        b.update(&buf[..n]);
    }
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

impl Verifier<'_> {
    /// The source's keyring, parsed. A missing keyring fails closed.
    fn ring(&self, s: &Source) -> Result<Vec<::pgp::composed::SignedPublicKey>> {
        if s.keyring.is_empty() {
            bail!("source has a signature but no keyring");
        }
        let bytes = keys::find(self.keys, &s.keyring).with_context(|| {
            format!(
                "keyring {:?} is not in keys/ (fetch and pin it, see keys/fetch.sh)",
                s.keyring
            )
        })?;
        let ring = pgp::keyring(bytes);
        if ring.is_empty() {
            bail!("keyring {:?} holds no usable key", s.keyring);
        }
        Ok(ring)
    }

    /// Checks the detached signature `sig` over `data` and returns the signer's label.
    fn check_sig(&self, s: &Source, sig: &Path, data: &Path) -> Result<String> {
        if !s.minisign.is_empty() {
            let key = minisign_verify::PublicKey::from_base64(&s.minisign)
                .map_err(|e| anyhow::anyhow!("bad minisign key in catalog: {e}"))?;
            let text = String::from_utf8(read_side(sig)?).context("minisign signature")?;
            let sig = minisign_verify::Signature::decode(&text)
                .map_err(|e| anyhow::anyhow!("minisign: {e}"))?;
            let mut v = key
                .verify_stream(&sig)
                .map_err(|e| anyhow::anyhow!("minisign: {e}"))?;
            let mut f = File::open(data)?;
            let mut buf = vec![0u8; 1 << 16];
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                v.update(&buf[..n]);
            }
            v.finalize()
                .map_err(|e| anyhow::anyhow!("bad signature: minisign: {e}"))?;
            return Ok("minisign".into());
        }
        let ring = self.ring(s)?;
        let xz_cap = std::fs::metadata(data)?.len().saturating_mul(XZ_RATIO);
        let mut open = || -> Result<Box<dyn Read>> {
            let f = BufReader::new(File::open(data)?);
            Ok(match s.sig_over {
                // kernel.org signs the tar, not the .tar.xz that is published. The file is
                // still untrusted here, so its dictionary may not ask for unbounded memory.
                // Its output is capped too, or a small file could stream out for ever; a
                // cut-off tar fails the signature.
                Some(SigOver::Xz) => {
                    Box::new(lzma_rust2::XzReader::new_mem_limit(f, true, XZ_MEM_KIB).take(xz_cap))
                }
                None => Box::new(f),
            })
        };
        let signer = pgp::detached(&ring, &read_side(sig)?, &mut open)?;
        signer.pinned(&s.signers)?;
        Ok(format!("gpg:{}", signer.primary))
    }

    /// The published hash for `it` from its sums file, after checking the sums file's own
    /// signature when the source has one.
    fn sums(&self, s: &Source, it: &Item, sums_url: &str, file: &Path) -> Result<String> {
        let sf = side(file, sums_url);
        let name = file_name(&sf);
        let text = if s.sums_sig == "clear" {
            let (signer, covered) =
                pgp::clearsigned(&self.ring(s)?, &read_side(&sf)?).with_context(|| name.clone())?;
            signer.pinned(&s.signers).with_context(|| name.clone())?;
            covered
        } else {
            if let Some(sig_url) = &it.sums_sig_url {
                self.check_sig(s, &side(file, sig_url), &sf)
                    .with_context(|| name.clone())?;
            }
            String::from_utf8_lossy(&read_side(&sf)?).into_owned()
        };
        sums::find_sum(&text, &it.name)
            .map(str::to_string)
            .with_context(|| format!("{name} has no entry for {}", it.name))
    }

    /// A re-fetched key file must hold exactly the primary keys of the keyring compiled in.
    /// The compiled-in keyring is what verifies; a difference only raises the alarm.
    fn check_stored_key(&self, s: &Source, file: &Path) -> Result<()> {
        let stored = keys::find(self.keys, &s.stored)
            .with_context(|| format!("keyring {:?} is not in keys/", s.stored))?;
        let fetched = std::fs::read(file)?;
        let gone = pgp::revocations(&fetched);
        if !gone.is_empty() {
            let msg = format!("key {} revoked upstream: {gone:?}", s.stored);
            (self.note)(true, "Signing key revoked", &msg);
            bail!(msg);
        }
        let have = pgp::primary_fingerprints(&fetched);
        let want = pgp::primary_fingerprints(stored);
        if want.is_empty() {
            bail!("keyring {:?} holds no usable key", s.stored);
        }
        if have != want {
            let msg = format!(
                "key {} changed upstream: stored {want:?}, fetched {have:?}",
                s.stored
            );
            (self.note)(true, "Signing key changed", &msg);
            bail!(msg);
        }
        if let Some(p) = s.signers.iter().find(|p| !have.contains(p)) {
            bail!("key {} lacks pinned fingerprint {p}", s.stored);
        }
        Ok(())
    }

    /// Trust on first use: records the hash of a url nothing else vouches for, and refuses a
    /// different hash for it from then on. The server's `ETag` or `Last-Modified` is not part of
    /// the key, since whoever swaps the file also chooses those. To accept a change, delete
    /// the url's line from `tofu.json`.
    fn tofu(&self, url: &str, hash: &str) -> Result<()> {
        let mut seen: BTreeMap<String, String> = match std::fs::read(self.tofu) {
            Ok(b) => serde_json::from_slice(&b).context("tofu store")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e).context("tofu store"),
        };
        if let Some(old) = seen.get(url) {
            if old == hash {
                return Ok(());
            }
            let msg = format!(
                "{url} changed: recorded {old}, now {hash}; delete its line from {} to accept",
                self.tofu.display()
            );
            (self.note)(true, "Unsigned download changed", &msg);
            bail!("tofu: {msg}");
        }
        seen.insert(url.to_string(), hash.to_string());
        let mut out = Vec::new();
        let fmt = serde_json::ser::PrettyFormatter::with_indent(b" ");
        serde::Serialize::serialize(
            &seen,
            &mut serde_json::Serializer::with_formatter(&mut out, fmt),
        )?;
        if let Some(dir) = self.tofu.parent() {
            platform::private_dir_all(dir)?;
        }
        platform::write_private(self.tofu, &out).context("tofu store")
    }

    /// Checks the downloaded `file` of `it` against everything its source publishes: index
    /// hashes, a sums file, a signature, a pinned key. With none of those it is trust on first
    /// use. Returns how it was trusted and its sha256. Signature and sums files are read from
    /// next to `file`.
    pub(crate) fn item(&self, s: &Source, it: &Item, file: &Path) -> Result<(String, String)> {
        let (h256, h512) = hash_file(file)?;
        let mut how: Vec<String> = Vec::new();
        if !it.sha256.is_empty() || !it.sha512.is_empty() {
            let ok = |want: &str, have: &str| want.is_empty() || want.eq_ignore_ascii_case(have);
            if !ok(&it.sha256, &h256) || !ok(&it.sha512, &h512) {
                bail!("{}: hash does not match the published one", it.name);
            }
            how.push("hash".into());
        }
        if let Some(sums_url) = &it.sums_url {
            let want = self.sums(s, it, sums_url, file)?;
            if !want.eq_ignore_ascii_case(&h256) && !want.eq_ignore_ascii_case(&h512) {
                bail!("{}: hash does not match {}", it.name, url_base(sums_url));
            }
            how.push("sums".into());
        }
        if let Some(sig_url) = &it.sig_url {
            let signer = self
                .check_sig(s, &side(file, sig_url), file)
                .with_context(|| it.name.clone())?;
            how.push(signer);
        }
        if !s.stored.is_empty() {
            self.check_stored_key(s, file)?;
            how.push("pinned-key".into());
        }
        if how.is_empty() {
            self.tofu(&it.url, &h256)?;
            how.push("tofu".into());
        }
        Ok((how.join("+"), h256))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::{Kind, Resolve};
    use crate::testutil::TempDir;
    use std::sync::Mutex;
    use testkey::TestKey;

    const DATA: &[u8] = b"a release\n";

    struct Env {
        tmp: TempDir,
        notes: Mutex<Vec<String>>,
    }

    impl Env {
        fn new() -> Self {
            Self {
                tmp: TempDir::new(),
                notes: Mutex::new(Vec::new()),
            }
        }

        fn write(&self, name: &str, data: &[u8]) -> PathBuf {
            let p = self.tmp.path().join(name);
            std::fs::write(&p, data).unwrap();
            p
        }

        fn notes(&self) -> Vec<String> {
            self.notes.lock().unwrap().clone()
        }

        /// Runs `f` with a verifier over `keys` whose notifications land in `notes`.
        fn with<R>(&self, keys: &[Keyring], f: impl FnOnce(&Verifier) -> R) -> R {
            let tofu = self.tmp.path().join("state/tofu.json");
            let note = |_: bool, title: &str, body: &str| {
                self.notes.lock().unwrap().push(format!("{title}: {body}"));
            };
            f(&Verifier {
                keys,
                tofu: &tofu,
                note: &note,
            })
        }
    }

    fn source() -> Source {
        Source {
            name: "s".into(),
            kind: Some(Kind::Http),
            resolve: Some(Resolve::Static),
            ..Source::default()
        }
    }

    fn item(name: &str) -> Item {
        Item {
            name: name.into(),
            url: format!("https://example.invalid/d/{name}"),
            version: "1".into(),
            ..Item::default()
        }
    }

    fn sha256(b: &[u8]) -> String {
        hex(&Sha256::digest(b))
    }

    #[test]
    fn published_hashes() {
        let env = Env::new();
        let file = env.write("f.bin", DATA);
        env.with(&[], |v| {
            let mut it = item("f.bin");
            it.sha256 = sha256(DATA).to_uppercase();
            let (how, sum) = v.item(&source(), &it, &file).unwrap();
            assert_eq!((how.as_str(), sum), ("hash", sha256(DATA)));
            it.sha512 = hex(&Sha512::digest(DATA));
            assert_eq!(v.item(&source(), &it, &file).unwrap().0, "hash");
            it.sha512 = hex(&Sha512::digest(b"other"));
            assert!(v.item(&source(), &it, &file).is_err(), "sha512 differs");
            it.sha512.clear();
            it.sha256 = sha256(b"other");
            let err = v.item(&source(), &it, &file).unwrap_err();
            assert!(err.to_string().contains("published one"), "{err}");
        });
        assert!(!env.tmp.path().join("state/tofu.json").exists());
    }

    #[test]
    fn signed_file_and_pins() {
        let env = Env::new();
        let key = TestKey::new();
        let ring = key.public();
        let file = env.write("f.tar", DATA);
        env.write("f.tar.sig", &key.sign(DATA));
        let mut s = source();
        s.sig = ".sig".into();
        s.keyring = "test".into();
        let mut it = item("f.tar");
        it.sig_url = Some(format!("{}.sig", it.url));
        env.with(&[("test", &ring)], |v| {
            let (how, sum) = v.item(&s, &it, &file).unwrap();
            assert_eq!(how, format!("gpg:{}", key.fingerprint()));
            assert_eq!(sum, sha256(DATA));

            s.signers = vec![key.fingerprint()];
            v.item(&s, &it, &file).unwrap();
            s.signers = vec![TestKey::new().fingerprint()];
            let err = v.item(&s, &it, &file).unwrap_err();
            assert!(
                format!("{err:#}").contains("not a pinned signer"),
                "{err:#}"
            );
            s.signers.clear();

            std::fs::write(&file, b"a release, tampered\n").unwrap();
            let err = v.item(&s, &it, &file).unwrap_err();
            assert!(format!("{err:#}").contains("bad signature"), "{err:#}");
        });
        // A missing keyring fails closed, whether unnamed or not compiled in.
        std::fs::write(&file, DATA).unwrap();
        env.with(&[], |v| {
            let err = v.item(&s, &it, &file).unwrap_err();
            assert!(format!("{err:#}").contains("not in keys/"), "{err:#}");
            s.keyring.clear();
            let err = v.item(&s, &it, &file).unwrap_err();
            assert!(format!("{err:#}").contains("no keyring"), "{err:#}");
        });
        assert!(!env.tmp.path().join("state/tofu.json").exists());
    }

    #[test]
    fn signature_over_the_uncompressed_tar() {
        // `printf 'kernel tar bytes\n' | xz -9`
        const XZ: [u8; 84] = [
            0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46, 0x04, 0xc0,
            0x15, 0x11, 0x21, 0x01, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x7b, 0x88, 0xfe, 0x48, 0x01, 0x00, 0x10, 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x20,
            0x74, 0x61, 0x72, 0x20, 0x62, 0x79, 0x74, 0x65, 0x73, 0x0a, 0x00, 0x00, 0x00, 0x00,
            0x81, 0xd3, 0x8e, 0x1d, 0x2a, 0xb2, 0x4b, 0xcf, 0x00, 0x01, 0x31, 0x11, 0x6b, 0x92,
            0x6b, 0x8c, 0x1f, 0xb6, 0xf3, 0x7d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x59, 0x5a,
        ];
        let env = Env::new();
        let key = TestKey::new();
        let ring = key.public();
        let file = env.write("linux.tar.xz", &XZ);
        let mut s = source();
        s.sig_over = Some(SigOver::Xz);
        s.keyring = "test".into();
        let mut it = item("linux.tar.xz");
        it.sig_url = Some("https://example.invalid/d/linux.tar.sign".into());
        env.with(&[("test", &ring)], |v| {
            env.write("linux.tar.sign", &key.sign(b"kernel tar bytes\n"));
            assert!(v.item(&s, &it, &file).unwrap().0.starts_with("gpg:"));
            // A signature over the compressed bytes is not what kernel.org publishes.
            env.write("linux.tar.sign", &key.sign(&XZ));
            assert!(v.item(&s, &it, &file).is_err());
            // A file that isn't xz at all is an error, not a pass.
            env.write("linux.tar.sign", &key.sign(b"plain"));
            std::fs::write(&file, b"plain").unwrap();
            assert!(v.item(&s, &it, &file).is_err());
        });
    }

    #[test]
    fn sums_files() {
        let env = Env::new();
        let key = TestKey::new();
        let ring = key.public();
        let file = env.write("f.iso", DATA);
        let good = format!("{}  other.iso\n{}  f.iso\n", sha256(b"x"), sha256(DATA));
        let mut s = source();
        s.sums = "SUMS".into();
        let mut it = item("f.iso");
        it.sums_url = Some("https://example.invalid/d/SUMS".into());
        env.with(&[("test", &ring)], |v| {
            // Unsigned: only as good as the transport, and labelled as such.
            env.write("SUMS", good.as_bytes());
            assert_eq!(v.item(&s, &it, &file).unwrap().0, "sums");
            env.write("SUMS", format!("{}  f.iso\n", sha256(b"x")).as_bytes());
            let err = v.item(&s, &it, &file).unwrap_err();
            assert!(err.to_string().contains("does not match SUMS"), "{err}");
            env.write("SUMS", format!("{}  other.iso\n", sha256(DATA)).as_bytes());
            let err = v.item(&s, &it, &file).unwrap_err();
            assert!(format!("{err:#}").contains("no entry"), "{err:#}");

            // Detached signature over the sums file.
            s.sums_sig = ".sign".into();
            s.keyring = "test".into();
            it.sums_sig_url = Some("https://example.invalid/d/SUMS.sign".into());
            env.write("SUMS", good.as_bytes());
            env.write("SUMS.sign", &key.sign(good.as_bytes()));
            assert_eq!(v.item(&s, &it, &file).unwrap().0, "sums");
            env.write(
                "SUMS",
                format!("{good}{}  f.iso\n", sha256(b"x")).as_bytes(),
            );
            assert!(
                v.item(&s, &it, &file).is_err(),
                "sums file changed after signing"
            );

            // Clearsigned: only the signed text counts.
            s.sums_sig = "clear".into();
            it.sums_sig_url = None;
            let signed = key.clearsign(&good);
            env.write("SUMS", signed.as_bytes());
            assert_eq!(v.item(&s, &it, &file).unwrap().0, "sums");
            std::fs::write(&file, b"swapped\n").unwrap();
            let forged = format!("{}  f.iso\n{signed}", sha256(b"swapped\n"));
            env.write("SUMS", forged.as_bytes());
            let err = v.item(&s, &it, &file).unwrap_err();
            assert!(err.to_string().contains("does not match SUMS"), "{err}");
            env.write("SUMS", good.as_bytes());
            assert!(v.item(&s, &it, &file).is_err(), "not clearsigned at all");
        });
    }

    #[test]
    fn minisign_known_answer() {
        // The prehashed test vector of the minisign-verify crate: a signature over "test".
        const KEY: &str = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
        const SIG: &str = "untrusted comment: signature from minisign secret key\nRUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\ntrusted comment: timestamp:1556193335\tfile:test\ny/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg==\n";
        let env = Env::new();
        let file = env.write("zig.tar.xz", b"test");
        env.write("zig.tar.xz.minisig", SIG.as_bytes());
        let mut s = source();
        s.sig = ".minisig".into();
        s.minisign = KEY.into();
        let mut it = item("zig.tar.xz");
        it.sig_url = Some(format!("{}.minisig", it.url));
        env.with(&[], |v| {
            assert_eq!(v.item(&s, &it, &file).unwrap().0, "minisign");
            std::fs::write(&file, b"Test").unwrap();
            let err = v.item(&s, &it, &file).unwrap_err();
            assert!(format!("{err:#}").contains("bad signature"), "{err:#}");
        });
    }

    #[test]
    fn stored_key_change_raises_an_alert() {
        let env = Env::new();
        let (key, other) = (TestKey::new(), TestKey::new());
        let ring = key.public();
        let mut s = source();
        s.stored = "test".into();
        let it = item("key.asc");
        env.with(&[("test", &ring)], |v| {
            // Upstream serves it armored; the stored copy is binary.
            let file = env.write("key.asc", key.armored().as_bytes());
            assert_eq!(v.item(&s, &it, &file).unwrap().0, "pinned-key");
            s.signers = vec![other.fingerprint()];
            let err = v.item(&s, &it, &file).unwrap_err();
            assert!(err.to_string().contains("lacks pinned"), "{err}");
            s.signers.clear();
            assert_eq!(env.notes(), Vec::<String>::new());

            for (name, body) in [
                ("replaced", other.armored()),
                ("extended", format!("{}{}", key.armored(), other.armored())),
                ("emptied", "nothing".to_string()),
            ] {
                let file = env.write("key.asc", body.as_bytes());
                let err = v.item(&s, &it, &file).unwrap_err();
                assert!(
                    err.to_string().contains("changed upstream"),
                    "{name}: {err}"
                );
            }
        });
        let notes = env.notes();
        assert_eq!(notes.len(), 3, "{notes:?}");
        assert!(notes[0].starts_with("Signing key changed: key test changed upstream"));
    }

    #[test]
    fn upstream_revocation_of_a_stored_key_raises_an_alert() {
        let env = Env::new();
        let mut key = TestKey::new();
        let ring = key.public();
        key.revoke();
        let mut s = source();
        s.stored = "test".into();
        env.with(&[("test", &ring)], |v| {
            let file = env.write("key.asc", key.armored().as_bytes());
            let err = v.item(&s, &item("key.asc"), &file).unwrap_err();
            assert!(err.to_string().contains("revoked upstream"), "{err}");
        });
        let notes = env.notes();
        assert!(notes[0].starts_with("Signing key revoked"), "{notes:?}");
    }

    #[test]
    fn tofu_records_first_use_and_refuses_a_change() {
        let env = Env::new();
        let file = env.write("f.bin", DATA);
        let it = item("f.bin");
        let store = env.tmp.path().join("state/tofu.json");
        env.with(&[], |v| {
            assert_eq!(v.item(&source(), &it, &file).unwrap().0, "tofu");
            let want = format!(
                "{{\n \"https://example.invalid/d/f.bin\": \"{}\"\n}}",
                sha256(DATA)
            );
            assert_eq!(std::fs::read_to_string(&store).unwrap(), want);
            assert_eq!(
                v.item(&source(), &it, &file).unwrap().0,
                "tofu",
                "same hash again"
            );
            assert_eq!(env.notes(), Vec::<String>::new());

            std::fs::write(&file, b"changed\n").unwrap();
            let err = v.item(&source(), &it, &file).unwrap_err();
            assert!(err.to_string().starts_with("tofu: "), "{err}");
            assert_eq!(
                std::fs::read_to_string(&store).unwrap(),
                want,
                "the record is kept"
            );

            // A new ETag or Last-Modified from the server changes nothing: the url is the key.
            let mut next = it.clone();
            next.version = "2".into();
            let err = v.item(&source(), &next, &file).unwrap_err();
            assert!(err.to_string().starts_with("tofu: "), "{err}");
            let m: BTreeMap<String, String> =
                serde_json::from_slice(&std::fs::read(&store).unwrap()).unwrap();
            assert_eq!(m.len(), 1);

            // A damaged store is an error, never a silent reset.
            std::fs::write(&store, b"{").unwrap();
            assert!(v.item(&source(), &it, &file).is_err());
        });
        let notes = env.notes();
        assert_eq!(notes.len(), 2, "{notes:?}");
        assert!(
            notes[0].starts_with("Unsigned download changed: "),
            "{}",
            notes[0]
        );
    }
}
