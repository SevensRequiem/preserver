//! Alpine repositories: `APKINDEX.tar.gz` is two gzip members, a tar holding one RSA signature
//! and a tar holding the index, signed over the raw bytes of the second member. An apk is three
//! members (signature, control, data); the signed index pins the control member by its `Q1`
//! SHA-1, and `.PKGINFO` in the control member pins the data member by `datahash`.
//! Nothing here reads the network or the disk except through the reader it is handed.

use crate::catalog::valid_name;
use crate::keys::RsaKey;
use crate::resolve::{hex, valid_file_name};
use anyhow::{Context, Result, bail, ensure};
use base64ct::{Base64, Encoding};
use flate2::bufread::GzDecoder;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use sha1_checked::Sha1;
use sha2::{Digest, Sha256};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};

/// Keys below this are refused however they were pinned.
const MIN_RSA_BITS: u64 = 2048;
/// `APKINDEX` in the index tar, by its header size.
const INDEX_CAP: u64 = 256 << 20;
/// The index member's whole output, tar padding and skipped entries included.
const INDEX_INFLATE_CAP: u64 = 512 << 20;
/// The signature member, inflated.
const SIG_INFLATE_CAP: u64 = 64 << 10;
/// A signature is a modulus-sized number: 16384 bits at most.
const SIG_MAX: u64 = 2048;
/// The control member, inflated and as stored.
const CONTROL_CAP: u64 = 16 << 20;
const PKGINFO_CAP: u64 = 1 << 20;

/// The DER `DigestInfo` that goes in front of the digest in a PKCS#1 v1.5 signature.
const SHA1_PREFIX: [u8; 15] = [
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
];
const SHA256_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hash {
    Sha1,
    Sha256,
}

/// One stanza of an `APKINDEX`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Package {
    pub name: String,
    pub version: String,
    pub arch: String,
    pub size: u64,
    /// The SHA-1 of the apk's control member (`C:Q1<base64>`).
    pub q1: [u8; 20],
}

impl Package {
    pub(crate) fn file(&self) -> String {
        format!("{}-{}.apk", self.name, self.version)
    }
}

/// Counts the bytes taken from the reader, which is how a gzip member's length is learned.
struct Counted<R> {
    inner: R,
    n: u64,
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let k = self.inner.read(buf)?;
        self.n += k as u64;
        Ok(k)
    }
}

impl<R: BufRead> BufRead for Counted<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.n += amt as u64;
        self.inner.consume(amt);
    }
}

type Ar<'a> = tar::Archive<&'a mut (dyn Read + 'a)>;

/// Runs `f` on the tar inside the gzip member at the front of `c`, then reads the member to its
/// end so `c.n` is where the next one starts. Output past `cap` bytes fails.
fn read_tar<R: BufRead, T>(
    c: &mut Counted<R>,
    cap: u64,
    f: impl FnOnce(&mut Ar<'_>) -> Result<T>,
) -> Result<T> {
    let mut out = GzDecoder::new(&mut *c).take(cap + 1);
    let found = f(&mut tar::Archive::new(&mut out as &mut dyn Read))?;
    io::copy(&mut out, &mut io::sink()).context("gzip member")?;
    ensure!(out.limit() > 0, "a member inflates past {cap} bytes");
    Ok(found)
}

/// Where the gzip member at the front of `data` ends.
pub(crate) fn first_member(data: &[u8], cap: u64) -> Result<usize> {
    let mut c = Counted { inner: data, n: 0 };
    read_tar(&mut c, cap, |_| Ok(()))?;
    Ok(usize::try_from(c.n)?)
}

/// The name and size of a regular entry; anything else is refused.
fn regular(e: &tar::Entry<'_, impl Read>) -> Result<String> {
    ensure!(
        e.header().entry_type().is_file(),
        "an entry that is not a file"
    );
    Ok(e.path()?
        .to_str()
        .context("entry name is not UTF-8")?
        .to_owned())
}

/// The hash, key name and signature of a signature member: exactly one `.SIGN.RSA.<key>` or
/// `.SIGN.RSA256.<key>` entry.
fn signature(member: &[u8]) -> Result<(Hash, String, Vec<u8>)> {
    let mut c = Counted {
        inner: member,
        n: 0,
    };
    read_tar(&mut c, SIG_INFLATE_CAP, |ar| {
        let mut found = None;
        for e in ar.entries()? {
            let mut e = e?;
            ensure!(found.is_none(), "more than one signature");
            let name = regular(&e)?;
            let (hash, key) = if let Some(k) = name.strip_prefix(".SIGN.RSA256.") {
                (Hash::Sha256, k)
            } else if let Some(k) = name.strip_prefix(".SIGN.RSA.") {
                (Hash::Sha1, k)
            } else {
                bail!("unsupported signature {name:?}");
            };
            ensure!(e.size() <= SIG_MAX, "signature of {} bytes", e.size());
            let mut sig = Vec::new();
            e.read_to_end(&mut sig)?;
            found = Some((hash, key.to_owned(), sig));
        }
        found.context("no signature")
    })
}

fn verify(key: &RsaKey<'_>, hash: Hash, signed: &[u8], sig: &[u8]) -> Result<()> {
    let public = RsaPublicKey::from_public_key_pem(key.pem).context("pinned key")?;
    ensure!(
        public.n().bits() as u64 >= MIN_RSA_BITS,
        "key {} is under {MIN_RSA_BITS} bits",
        key.name
    );
    ensure!(
        sig.len() == public.size(),
        "signature of {} bytes for a {}-byte key",
        sig.len(),
        public.size()
    );
    let (digest, prefix): (Vec<u8>, &[u8]) = match hash {
        Hash::Sha1 => {
            let d = Sha1::try_digest(signed);
            ensure!(
                !d.has_collision(),
                "SHA-1 collision attack in the signed bytes"
            );
            (d.hash().to_vec(), &SHA1_PREFIX)
        }
        Hash::Sha256 => (Sha256::digest(signed).to_vec(), &SHA256_PREFIX),
    };
    let scheme = Pkcs1v15Sign {
        hash_len: Some(digest.len()),
        prefix: prefix.into(),
    };
    public
        .verify(scheme, &digest, sig)
        .map_err(|_| anyhow::anyhow!("bad signature by {}", key.name))
}

/// The `APKINDEX` text of the index member, which must run to the end of `member`.
fn apkindex(member: &[u8], cap: u64) -> Result<Vec<u8>> {
    let mut c = Counted {
        inner: member,
        n: 0,
    };
    let text = read_tar(&mut c, cap, |ar| {
        let (mut index, mut description) = (None, false);
        for e in ar.entries()? {
            let mut e = e?;
            match regular(&e)?.as_str() {
                "APKINDEX" => {
                    ensure!(index.is_none(), "two APKINDEX entries");
                    ensure!(e.size() < INDEX_CAP, "APKINDEX of {} bytes", e.size());
                    let mut text = Vec::new();
                    e.read_to_end(&mut text)?;
                    index = Some(text);
                }
                "DESCRIPTION" => {
                    ensure!(!description, "two DESCRIPTION entries");
                    description = true;
                }
                _ => {}
            }
        }
        index.context("no APKINDEX in the index")
    })?;
    ensure!(c.n == member.len() as u64, "data after the index member");
    Ok(text)
}

/// The packages of a signed `APKINDEX.tar.gz` for `arch`. The signature is checked before the
/// second member is inflated.
pub(crate) fn index(data: &[u8], keys: &[RsaKey<'_>], arch: &str) -> Result<Vec<Package>> {
    let (first, signed) = data.split_at(first_member(data, SIG_INFLATE_CAP)?);
    let (hash, name, sig) = signature(first)?;
    let key = keys
        .iter()
        .find(|k| k.name == name && k.arches.contains(&arch))
        .with_context(|| format!("no pinned key {name:?} for {arch}"))?;
    verify(key, hash, signed, &sig)?;
    parse(&apkindex(signed, INDEX_INFLATE_CAP)?)
}

/// Stanzas of `X:value` lines, a blank line between them. Every package needs `P`, `V`, `A`,
/// `S` and `C` (a `Q1` hash); other fields are left alone.
pub(crate) fn parse(text: &[u8]) -> Result<Vec<Package>> {
    #[derive(Default, Clone, Copy)]
    struct Fields<'a> {
        p: Option<&'a str>,
        v: Option<&'a str>,
        a: Option<&'a str>,
        s: Option<&'a str>,
        c: Option<&'a str>,
    }
    fn finish(f: Fields<'_>) -> Result<Package> {
        let (Some(name), Some(version), Some(arch), Some(size), Some(q1)) =
            (f.p, f.v, f.a, f.s, f.c)
        else {
            bail!("a package without P, V, A, S and C");
        };
        let package = Package {
            name: name.to_owned(),
            version: version.to_owned(),
            arch: arch.to_owned(),
            size: size.parse().with_context(|| format!("size {size:?}"))?,
            q1: q1_of(q1)?,
        };
        ensure!(package.size > 0, "{name}: empty package");
        ensure!(valid_name(arch), "{name}: bad arch {arch:?}");
        ensure!(
            valid_file_name(&package.file()),
            "bad package name {:?}",
            package.file()
        );
        Ok(package)
    }

    let text = std::str::from_utf8(text).context("the index is not UTF-8")?;
    let mut out = Vec::new();
    let mut cur = Fields::default();
    let mut any = false;
    for line in text.lines() {
        if line.is_empty() {
            if any {
                out.push(finish(std::mem::take(&mut cur))?);
                any = false;
            }
            continue;
        }
        let (Some(key), Some(value)) = (line.get(..1), line.strip_prefix(|_| true)) else {
            bail!("bad index line {line:?}");
        };
        let Some(value) = value.strip_prefix(':') else {
            bail!("bad index line {line:?}");
        };
        any = true;
        let slot = match key {
            "P" => &mut cur.p,
            "V" => &mut cur.v,
            "A" => &mut cur.a,
            "S" => &mut cur.s,
            "C" => &mut cur.c,
            _ => continue,
        };
        ensure!(
            slot.replace(value).is_none(),
            "{key}: given twice in one package"
        );
    }
    if any {
        out.push(finish(cur)?);
    }
    Ok(out)
}

fn q1_of(c: &str) -> Result<[u8; 20]> {
    let b64 = c
        .strip_prefix("Q1")
        .with_context(|| format!("checksum {c:?} is not Q1"))?;
    let mut buf = [0u8; 32];
    let raw = Base64::decode(b64, &mut buf).map_err(|_| anyhow::anyhow!("bad Q1 {c:?}"))?;
    raw.try_into()
        .map_err(|_| anyhow::anyhow!("Q1 is not 20 bytes: {c:?}"))
}

/// Feeds `len` bytes of `r` from `from` to `f`.
fn feed<R: Read + Seek>(r: &mut R, from: u64, len: u64, mut f: impl FnMut(&[u8])) -> Result<()> {
    r.seek(SeekFrom::Start(from))?;
    let mut buf = vec![0u8; 64 << 10];
    let mut left = len;
    while left > 0 {
        let want = usize::try_from(left).unwrap_or(buf.len()).min(buf.len());
        let n = r.read(&mut buf[..want])?;
        ensure!(n > 0, "the apk ends early");
        f(&buf[..n]);
        left -= n as u64;
    }
    Ok(())
}

/// The `datahash` of a `.PKGINFO`, exactly one.
fn datahash(pkginfo: &str) -> Result<&str> {
    let mut found = None;
    for line in pkginfo.lines() {
        if let Some(v) = line.strip_prefix("datahash = ") {
            ensure!(found.replace(v.trim()).is_none(), "two datahash lines");
        }
    }
    found.context("no datahash in .PKGINFO")
}

/// Checks an apk against the `Q1` its signed index gave: the control member hashes to it, and
/// the data member, taken as raw bytes to the end of the file and never inflated, hashes to
/// the `datahash` the control member carries.
pub(crate) fn check_apk<R: Read + Seek>(file: R, q1: &[u8; 20]) -> Result<()> {
    let mut r = BufReader::new(file);
    let size = r.seek(SeekFrom::End(0))?;
    r.rewind()?;
    let mut c = Counted { inner: r, n: 0 };
    read_tar(&mut c, SIG_INFLATE_CAP, |_| Ok(()))?;
    let control_start = c.n;
    let pkginfo = read_tar(&mut c, CONTROL_CAP, |ar| {
        let mut found = None;
        for e in ar.entries()? {
            let mut e = e?;
            if regular(&e)? != ".PKGINFO" {
                continue;
            }
            ensure!(found.is_none(), "two .PKGINFO entries");
            ensure!(e.size() <= PKGINFO_CAP, ".PKGINFO of {} bytes", e.size());
            let mut text = String::new();
            e.read_to_string(&mut text).context(".PKGINFO")?;
            found = Some(text);
        }
        found.context("no .PKGINFO")
    })?;
    let (control_end, mut r) = (c.n, c.inner);
    ensure!(
        control_end - control_start <= CONTROL_CAP,
        "control member over {CONTROL_CAP} bytes"
    );

    let mut sha1 = Sha1::new();
    feed(&mut r, control_start, control_end - control_start, |b| {
        Digest::update(&mut sha1, b);
    })?;
    let got = sha1.try_finalize();
    ensure!(
        !got.has_collision(),
        "SHA-1 collision attack in the control member"
    );
    ensure!(
        got.hash().as_slice() == q1,
        "control member does not match its Q1"
    );

    ensure!(size > control_end + 2, "no data member");
    let mut magic = [0u8; 2];
    r.seek(SeekFrom::Start(control_end))?;
    r.read_exact(&mut magic)?;
    ensure!(magic == [0x1f, 0x8b], "the data member is not gzip");
    let mut sha256 = Sha256::new();
    feed(&mut r, control_end, size - control_end, |b| {
        Digest::update(&mut sha256, b);
    })?;
    ensure!(
        hex(&sha256.finalize()) == datahash(&pkginfo)?.to_ascii_lowercase(),
        "data member does not match datahash"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::{EncodePublicKey, LineEnding};
    use rsa::rand_core::OsRng;
    use std::io::{Cursor, Write};
    use std::sync::LazyLock;

    struct Key {
        private: RsaPrivateKey,
        pem: String,
    }

    fn make(bits: usize) -> Key {
        let private = RsaPrivateKey::new(&mut OsRng, bits).unwrap();
        let pem = private
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        Key { private, pem }
    }

    static K2048: LazyLock<Key> = LazyLock::new(|| make(2048));
    static K1024: LazyLock<Key> = LazyLock::new(|| make(1024));

    const NAME: &str = "test@example.invalid-5f3a.rsa.pub";

    fn ring(k: &Key) -> RsaKey<'_> {
        RsaKey {
            name: NAME,
            arches: &["x86_64"],
            pem: &k.pem,
        }
    }

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::fast());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn tar_of(entries: &[(&str, tar::EntryType, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (name, ty, data) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(*ty);
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            if *ty == tar::EntryType::Symlink {
                h.set_link_name("x").unwrap();
            }
            b.append_data(&mut h, name, *data).unwrap();
        }
        let mut t = b.into_inner().unwrap();
        // abuild leaves the end-of-archive blocks off the signature and control members
        t.truncate(t.len() - 1024);
        t
    }

    fn member(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let all: Vec<_> = entries
            .iter()
            .map(|(n, d)| (*n, tar::EntryType::Regular, *d))
            .collect();
        gz(&tar_of(&all))
    }

    fn sign(k: &Key, hash: Hash, data: &[u8], bare: bool) -> Vec<u8> {
        let (digest, prefix): (Vec<u8>, &[u8]) = match hash {
            Hash::Sha1 => (Sha1::try_digest(data).hash().to_vec(), &SHA1_PREFIX),
            Hash::Sha256 => (Sha256::digest(data).to_vec(), &SHA256_PREFIX),
        };
        let scheme = Pkcs1v15Sign {
            hash_len: Some(digest.len()),
            prefix: if bare { Box::default() } else { prefix.into() },
        };
        k.private.sign(scheme, &digest).unwrap()
    }

    const TEXT: &str = "C:Q1pcfTfDNEbNKQc2s1tia7da05M8Q=\nP:musl\nV:1.2.5-r9\nA:x86_64\nS:393108\nI:622592\nT:the musl c library\n\nC:Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA=\nP:busybox\nV:1.37.0-r0\nA:x86_64\nS:924836\n\n";

    fn second() -> Vec<u8> {
        member(&[("APKINDEX", TEXT.as_bytes()), ("DESCRIPTION", b"main")])
    }

    fn signed(k: &Key, hash: Hash, entry: &str, second: &[u8]) -> Vec<u8> {
        let sig = sign(k, hash, second, false);
        [member(&[(entry, &sig)]), second.to_vec()].concat()
    }

    fn entry(hash: Hash) -> String {
        match hash {
            Hash::Sha1 => format!(".SIGN.RSA.{NAME}"),
            Hash::Sha256 => format!(".SIGN.RSA256.{NAME}"),
        }
    }

    #[test]
    fn rsa_and_rsa256_indexes_are_accepted() {
        let k = &*K2048;
        for hash in [Hash::Sha1, Hash::Sha256] {
            let data = signed(k, hash, &entry(hash), &second());
            let got =
                index(&data, &[ring(k)], "x86_64").unwrap_or_else(|e| panic!("{hash:?}: {e:#}"));
            assert_eq!(got.len(), 2, "{hash:?}");
            assert_eq!(got[0].file(), "musl-1.2.5-r9.apk");
        }
    }

    #[test]
    fn refused_indexes() {
        let k = &*K2048;
        let good = signed(k, Hash::Sha256, &entry(Hash::Sha256), &second());
        let sig = sign(k, Hash::Sha256, &second(), false);
        let sig_entry = entry(Hash::Sha256);
        let mut flipped = good.clone();
        let last = flipped.len() - 12;
        flipped[last] ^= 1;
        let bare = sign(k, Hash::Sha256, &second(), true);
        let short = &sig[..sig.len() - 1];
        let junk = [second(), b"junk".to_vec()].concat();
        let cases: Vec<(&str, Vec<u8>, &str)> = vec![
            ("a flipped byte", flipped, "x86_64"),
            (
                "an appended member",
                [good.clone(), second()].concat(),
                "x86_64",
            ),
            (
                "an unknown key",
                [member(&[(".SIGN.RSA256.other.rsa.pub", &sig)]), second()].concat(),
                "x86_64",
            ),
            ("another arch's key", good.clone(), "aarch64"),
            (
                "RSA512",
                [member(&[(&format!(".SIGN.RSA512.{NAME}"), &sig)]), second()].concat(),
                "x86_64",
            ),
            (
                "two signature entries",
                [member(&[(&sig_entry, &sig), (&sig_entry, &sig)]), second()].concat(),
                "x86_64",
            ),
            ("non-gzip input", b"not gzip at all".to_vec(), "x86_64"),
            (
                "ADB magic",
                b"ADB.\x00\x00\x00\x00 rest of an apk v3 index".to_vec(),
                "x86_64",
            ),
            (
                "a bare digest",
                [member(&[(&sig_entry, &bare)]), second()].concat(),
                "x86_64",
            ),
            (
                "a short signature",
                [member(&[(&sig_entry, short)]), second()].concat(),
                "x86_64",
            ),
            (
                "bytes after the signed member",
                signed(k, Hash::Sha256, &sig_entry, &junk),
                "x86_64",
            ),
            (
                "a second APKINDEX",
                signed(
                    k,
                    Hash::Sha256,
                    &sig_entry,
                    &member(&[("APKINDEX", b""), ("APKINDEX", b"")]),
                ),
                "x86_64",
            ),
            (
                "a second DESCRIPTION",
                signed(
                    k,
                    Hash::Sha256,
                    &sig_entry,
                    &member(&[
                        ("APKINDEX", b""),
                        ("DESCRIPTION", b""),
                        ("DESCRIPTION", b""),
                    ]),
                ),
                "x86_64",
            ),
            (
                "no APKINDEX",
                signed(
                    k,
                    Hash::Sha256,
                    &sig_entry,
                    &member(&[("DESCRIPTION", b"")]),
                ),
                "x86_64",
            ),
        ];
        for (name, data, arch) in cases {
            assert!(index(&data, &[ring(k)], arch).is_err(), "{name}");
        }
    }

    #[test]
    fn small_keys_are_refused() {
        let k = &*K1024;
        let data = signed(k, Hash::Sha256, &entry(Hash::Sha256), &second());
        let err = index(&data, &[ring(k)], "x86_64").unwrap_err();
        assert!(err.to_string().contains("under 2048"), "{err:#}");
    }

    #[test]
    fn index_tar_caps() {
        let k = &*K2048;
        let sig_entry = entry(Hash::Sha256);
        let tar = |entries: &[(&str, tar::EntryType, &[u8])]| gz(&tar_of(entries));
        let reg = tar::EntryType::Regular;
        let link = tar::EntryType::Symlink;
        let cases = [(
            "a symlink",
            tar(&[("APKINDEX", reg, b""), ("DESCRIPTION", link, b"")]),
            "not a file",
        )];
        for (name, second, want) in &cases {
            let data = signed(k, Hash::Sha256, &sig_entry, second);
            let err = index(&data, &[ring(k)], "x86_64").unwrap_err();
            assert!(format!("{err:#}").contains(want), "{name}: {err:#}");
        }
        let mut h = tar::Header::new_gnu();
        h.set_path("APKINDEX").unwrap();
        h.set_size(INDEX_CAP);
        h.set_cksum();
        let header_only = gz(h.as_bytes());
        let data = signed(k, Hash::Sha256, &sig_entry, &header_only);
        let err = index(&data, &[ring(k)], "x86_64").unwrap_err();
        assert!(format!("{err:#}").contains("APKINDEX of"), "{err:#}");
        let raw = [tar_of(&[("APKINDEX", reg, b"")]), vec![0; 1024]].concat();
        let padded = gz(&[&raw[..], &[0u8; 64]].concat());
        let cap = raw.len() as u64 + 10;
        let err = apkindex(&padded, cap).unwrap_err();
        assert!(format!("{err:#}").contains("inflates past"), "{err:#}");
        assert!(apkindex(&padded, cap + 100).is_ok());
    }

    #[test]
    fn first_member_offsets() {
        let (a, b, c) = (
            member(&[("a", b"1")]),
            member(&[("b", b"22")]),
            member(&[("c", b"")]),
        );
        let all = [a.clone(), b.clone(), c.clone()].concat();
        assert_eq!(first_member(&all, 1 << 20).unwrap(), a.len());
        assert_eq!(first_member(&all[a.len()..], 1 << 20).unwrap(), b.len());
        assert_eq!(
            first_member(&all[a.len() + b.len()..], 1 << 20).unwrap(),
            c.len()
        );
        assert_eq!(
            first_member(&[&a[..], b"trailing"].concat(), 1 << 20).unwrap(),
            a.len()
        );
        assert!(
            first_member(&a[..a.len() - 3], 1 << 20).is_err(),
            "truncated"
        );
        assert!(first_member(b"plain", 1 << 20).is_err(), "not gzip");
        assert!(first_member(&[], 1 << 20).is_err(), "empty");
        let bomb = gz(&vec![0u8; 1 << 20]);
        assert!(first_member(&bomb, 1000).is_err(), "inflates past the cap");
    }

    #[test]
    fn parse_table() {
        let ok = |t: &str| parse(t.as_bytes());
        let q = "C:Q1pcfTfDNEbNKQc2s1tia7da05M8Q=\n";
        let one = |body: &str| format!("{q}P:a\nV:1-r0\nA:x86_64\nS:5\n{body}");
        let p = ok(&one("")).unwrap();
        assert_eq!(
            (
                p[0].name.as_str(),
                p[0].version.as_str(),
                p[0].arch.as_str(),
                p[0].size
            ),
            ("a", "1-r0", "x86_64", 5)
        );
        assert_eq!(hex(&p[0].q1), "a5c7d37c33446cd290736b35b626bb75ad3933c4");
        assert_eq!(ok("").unwrap(), []);
        assert_eq!(ok("\n\n\n").unwrap(), []);
        assert_eq!(
            ok(&format!("{}\n\n\n{}", one(""), one(""))).unwrap().len(),
            2
        );
        assert_eq!(
            ok(&one("X:ignored\nT:text: with colon\n")).unwrap().len(),
            1
        );
        let bad = [
            ("missing C", "P:a\nV:1\nA:x86_64\nS:5\n".to_string()),
            ("missing S", format!("{q}P:a\nV:1\nA:x86_64\n")),
            ("zero size", format!("{q}P:a\nV:1\nA:x86_64\nS:0\n")),
            (
                "size not a number",
                format!("{q}P:a\nV:1\nA:x86_64\nS:-3\n"),
            ),
            ("twice", one("P:b\n")),
            ("Q2", "C:Q2abc=\nP:a\nV:1\nA:x\nS:5\n".to_string()),
            ("short Q1", "C:Q1AAAA\nP:a\nV:1\nA:x\nS:5\n".to_string()),
            ("no colon", one("garbage\n")),
            ("slash in name", format!("{q}P:../a\nV:1\nA:x86_64\nS:5\n")),
            (
                "space in version",
                format!("{q}P:a\nV:1 2\nA:x86_64\nS:5\n"),
            ),
            ("bad arch", format!("{q}P:a\nV:1\nA:../x\nS:5\n")),
            ("not utf-8", String::new()),
        ];
        for (name, t) in bad {
            let r = if name == "not utf-8" {
                parse(&[0xff, 0xfe])
            } else {
                ok(&t)
            };
            assert!(r.is_err(), "{name}");
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]
        #[test]
        fn parse_never_panics(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..400)) {
            let _ = parse(&bytes);
        }

        #[test]
        fn parse_never_panics_on_index_shaped_text(t in "([A-Z]:[A-Za-z0-9=+/ .-]{0,12}\n|\n){0,40}") {
            let _ = parse(t.as_bytes());
        }
    }

    struct Apk {
        bytes: Vec<u8>,
        q1: [u8; 20],
    }

    fn apk(pkginfo: &[(&str, &[u8])], data: &[u8], datahash: Option<&str>) -> Apk {
        let sig = member(&[(&entry(Hash::Sha1), b"sig")]);
        let data_member = gz(&tar_of(&[("usr/bin/x", tar::EntryType::Regular, data)]));
        let hash = hex(&Sha256::digest(&data_member));
        let info = match datahash {
            Some(h) => format!("pkgname = x\ndatahash = {h}\n"),
            None => format!("pkgname = x\ndatahash = {hash}\n"),
        };
        let mut entries: Vec<(&str, &[u8])> = vec![(".PKGINFO", info.as_bytes())];
        entries.extend_from_slice(pkginfo);
        let control = member(&entries);
        let q1: [u8; 20] = Sha1::try_digest(&control)
            .hash()
            .as_slice()
            .try_into()
            .unwrap();
        Apk {
            bytes: [sig, control, data_member].concat(),
            q1,
        }
    }

    fn check(bytes: &[u8], q1: &[u8; 20]) -> Result<()> {
        check_apk(Cursor::new(bytes), q1)
    }

    #[test]
    fn check_apk_accepts_a_good_package() {
        let a = apk(&[(".post-install", b"#!/bin/sh\n")], b"payload", None);
        check(&a.bytes, &a.q1).unwrap();
        let again = apk(&[], &vec![7u8; 300_000], None);
        check(&again.bytes, &again.q1).unwrap();
    }

    #[test]
    fn check_apk_refuses_bad_packages() {
        let a = apk(&[], b"payload", None);
        let q1 = &a.q1;
        let mut other = *q1;
        other[0] ^= 1;
        assert!(check(&a.bytes, &other).is_err(), "wrong Q1");

        let mut data_flip = a.bytes.clone();
        let n = data_flip.len();
        data_flip[n - 12] ^= 1;
        assert!(check(&data_flip, q1).is_err(), "data member changed");

        let appended = [a.bytes.clone(), gz(b"more")].concat();
        assert!(check(&appended, q1).is_err(), "appended member");

        let mut control_flip = a.bytes.clone();
        let at = first_member(&a.bytes, 1 << 20).unwrap() + 12;
        control_flip[at] ^= 1;
        assert!(check(&control_flip, q1).is_err(), "control member changed");

        let wrong_hash = apk(&[], b"payload", Some(&"0".repeat(64)));
        assert!(
            check(&wrong_hash.bytes, &wrong_hash.q1).is_err(),
            "datahash differs"
        );

        let cut = &a.bytes[..first_member(&a.bytes, 1 << 20).unwrap() + 5];
        assert!(check(cut, q1).is_err(), "truncated control");
        assert!(check(b"plain text", q1).is_err(), "not gzip");
        assert!(check(b"", q1).is_err(), "empty");

        let sig_only = member(&[(&entry(Hash::Sha1), b"sig")]);
        assert!(check(&sig_only, q1).is_err(), "signature member alone");

        let no_data = a.bytes[..a.bytes.len()
            - gz(&tar_of(&[(
                "usr/bin/x",
                tar::EntryType::Regular,
                b"payload",
            )]))
            .len()]
            .to_vec();
        assert!(check(&no_data, q1).is_err(), "no data member");

        let two = apk(&[(".PKGINFO", b"datahash = 00\n")], b"payload", None);
        assert!(check(&two.bytes, &two.q1).is_err(), "two .PKGINFO");

        let big = vec![b'a'; 1_100_000];
        let huge = apk(&[("x.txt", &big)], b"payload", None);
        check(&huge.bytes, &huge.q1).unwrap();
        let sig = member(&[(&entry(Hash::Sha1), b"sig")]);
        let control = member(&[(".PKGINFO", &big)]);
        let mut with_big_info = [sig, control.clone()].concat();
        with_big_info.extend_from_slice(&gz(b"data"));
        let q: [u8; 20] = Sha1::try_digest(&control)
            .hash()
            .as_slice()
            .try_into()
            .unwrap();
        assert!(check(&with_big_info, &q).is_err(), ".PKGINFO over 1 MiB");

        let no_info = member(&[("other", b"x")]);
        let bytes = [
            member(&[(&entry(Hash::Sha1), b"s")]),
            no_info.clone(),
            gz(b"d"),
        ]
        .concat();
        let q: [u8; 20] = Sha1::try_digest(&no_info)
            .hash()
            .as_slice()
            .try_into()
            .unwrap();
        assert!(check(&bytes, &q).is_err(), "no .PKGINFO");

        let no_hash = member(&[(".PKGINFO", b"pkgname = x\n")]);
        let bytes = [
            member(&[(&entry(Hash::Sha1), b"s")]),
            no_hash.clone(),
            gz(b"d"),
        ]
        .concat();
        let q: [u8; 20] = Sha1::try_digest(&no_hash)
            .hash()
            .as_slice()
            .try_into()
            .unwrap();
        assert!(check(&bytes, &q).is_err(), "no datahash");
    }
}
