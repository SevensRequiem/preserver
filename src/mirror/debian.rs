//! Debian `Release` model: what a signed Release says about a suite, which of its index files
//! to read, and the pool files the indexes name. Nothing here touches the disk or the network.

use super::deb822::{self, Stanza};
use super::generation::{Walked, clear_way, remove_any, url_of, valid_path};
use super::{Anchor, Capped, Check, Ctx, Entry, Meta, rel_path};
use crate::catalog::Source;
use crate::keys;
use crate::platform;
use crate::public::versioned::{link_or_copy, read_meta};
use crate::resolve::{hex, unhex};
use crate::verify::pgp;
use crate::verify::{XZ_MEM_KIB, XZ_RATIO};
use anyhow::{Context, Result, bail, ensure};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufReader, Read};
use std::path::Path;

const RELEASE_CAP: u64 = 16 << 20;

/// A suite's Release, reduced to what a mirror acts on. File paths are relative to the
/// suite's `dists/<suite>/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Release {
    pub date: i64,
    pub by_hash: bool,
    pub components: Vec<String>,
    pub files: Vec<Entry>,
}

/// Seconds since the epoch of a Release `Date` or `Valid-Until`: `Sat, 15 Nov 2025 10:00:00 UTC`.
fn stamp(text: &str, what: &str) -> Result<i64> {
    let t = text.trim();
    let t = t
        .strip_suffix(" UTC")
        .map_or(t.to_owned(), |h| format!("{h} +0000"));
    Ok(jiff::fmt::rfc2822::parse(&t)
        .with_context(|| format!("{what} {text:?} is not a date"))?
        .timestamp()
        .as_second())
}

fn single(text: &str) -> Result<Stanza> {
    // A clearsigned text may carry CRLF line ends, which are part of the signed form.
    let text = text.replace("\r\n", "\n");
    let mut stanzas = deb822::parse(text.as_bytes());
    let first = stanzas.next().context("an empty Release")??;
    ensure!(
        stanzas.next().is_none(),
        "a Release of more than one stanza"
    );
    Ok(first)
}

/// The `Date` of a Release, for the one the live tree holds.
pub(crate) fn release_date(text: &str) -> Result<i64> {
    stamp(single(text)?.get("Date").context("no Date")?, "Date")
}

/// Reads the signed text of a Release for `suite`. The suite is matched by `Codename`, and by
/// `Suite` only when there is no `Codename`. `Date` must be strictly newer than `live` (the
/// live Release's `Date`), so an old or replayed Release is refused, and `Valid-Until` must
/// still be ahead of `now`.
pub(crate) fn parse_release(
    text: &str,
    suite: &str,
    now: i64,
    live: Option<i64>,
) -> Result<Release> {
    let s = single(text)?;
    let named = s.get("Codename").or_else(|| s.get("Suite"));
    ensure!(
        named == Some(suite),
        "the Release is for {:?}, not {suite}",
        named.unwrap_or("no suite")
    );
    let date = stamp(s.get("Date").context("no Date")?, "Date")?;
    if let Some(live) = live {
        ensure!(date > live, "the Release is not newer than the live one");
    }
    if let Some(v) = s.get("Valid-Until") {
        ensure!(stamp(v, "Valid-Until")? > now, "the Release has expired");
    }
    let mut files: Vec<Entry> = Vec::new();
    let mut seen = HashSet::new();
    for line in s.get("SHA256").context("no SHA256 list")?.lines() {
        let mut f = line.split_whitespace();
        let (Some(sum), Some(size), Some(path), None) = (f.next(), f.next(), f.next(), f.next())
        else {
            bail!("bad SHA256 line {line:?}");
        };
        ensure!(valid_path(path), "bad path {path:?}");
        ensure!(seen.insert(path), "{path} is listed twice");
        files.push(Entry {
            path: path.to_owned(),
            size: size.parse().with_context(|| format!("size of {path}"))?,
            check: Check::Sha256(unhex(sum).with_context(|| path.to_owned())?),
        });
    }
    Ok(Release {
        date,
        by_hash: s.get("Acquire-By-Hash") == Some("yes"),
        components: s
            .get("Components")
            .map(|c| c.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default(),
        files,
    })
}

/// The index files to read: per component the binary indexes of each arch and of `all`, the
/// sources and the English translations, one file for each (a repeated arch, `all` or component is read once). An index listed in several
/// compressions is taken as `.xz` or else plain, never both, so a file is not read twice. A
/// group the Release does not list is left out.
pub(crate) fn pick(rel: &Release, src: &Source) -> Result<Vec<Entry>> {
    let listed: HashMap<&str, &Entry> = rel.files.iter().map(|e| (e.path.as_str(), e)).collect();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for c in &src.components {
        ensure!(
            rel.components.is_empty() || rel.components.contains(c),
            "component {c} is not in the Release"
        );
        let arches = src.arches.iter().map(String::as_str).chain(["all"]);
        let groups = arches.map(|a| format!("{c}/binary-{a}/Packages")).chain([
            format!("{c}/source/Sources"),
            format!("{c}/i18n/Translation-en"),
        ]);
        for g in groups {
            if let Some(e) = listed
                .get(format!("{g}.xz").as_str())
                .or_else(|| listed.get(g.as_str()))
                && seen.insert(e.path.as_str())
            {
                out.push((*e).clone());
            }
        }
    }
    ensure!(
        !out.is_empty(),
        "the Release lists none of the wanted indexes"
    );
    Ok(out)
}

fn pool_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"._+~/-".contains(&b)
}

fn add(pool: &mut BTreeMap<String, Entry>, e: Entry) -> Result<()> {
    ensure!(
        e.path.starts_with("pool/") && valid_path(&e.path) && e.path.bytes().all(pool_char),
        "bad pool path {:?}",
        e.path
    );
    match pool.get(&e.path) {
        Some(old) if *old != e => bail!("{} is named with two different hashes or sizes", e.path),
        Some(_) => Ok(()),
        None => {
            pool.insert(e.path.clone(), e);
            Ok(())
        }
    }
}

/// Adds the files one `Packages` stanza (`Filename`, `Size`, `SHA256`) or one `Sources`
/// stanza (`Directory` and the `Checksums-Sha256` lines) names. The same path under two
/// different hashes fails.
pub(crate) fn pool_files(pool: &mut BTreeMap<String, Entry>, s: &Stanza) -> Result<()> {
    let entry = |path: String, size: &str, sum: &str| -> Result<Entry> {
        Ok(Entry {
            size: size.parse().with_context(|| format!("size of {path}"))?,
            check: Check::Sha256(unhex(sum).with_context(|| path.clone())?),
            path,
        })
    };
    if let Some(dir) = s.get("Directory") {
        let sums = s
            .get("Checksums-Sha256")
            .context("a source with no Checksums-Sha256")?;
        ensure!(!sums.trim().is_empty(), "a source with no files");
        for line in sums.lines() {
            let mut f = line.split_whitespace();
            let (Some(sum), Some(size), Some(name), None) =
                (f.next(), f.next(), f.next(), f.next())
            else {
                bail!("bad Checksums-Sha256 line {line:?}");
            };
            ensure!(!name.contains('/'), "bad source file name {name:?}");
            add(pool, entry(format!("{dir}/{name}"), size, sum)?)?;
        }
        return Ok(());
    }
    let path = s.get("Filename").context("a package with no Filename")?;
    let size = s.get("Size").context("a package with no Size")?;
    let sum = s.get("SHA256").context("a package with no SHA256")?;
    add(pool, entry(path.to_owned(), size, sum)?)
}

fn release_path(suite: &str) -> String {
    format!("dists/{suite}/InRelease")
}

/// The `Date` of the live tree's `InRelease` for `suite`, if it has one. It is read through the
/// keyring like a fresh one, so a live file that was changed since, or signed by a key the ring
/// no longer trusts (revoked), does not set the bar: the fresh Release still has to pass the
/// pinned-signer and validity checks.
fn live_release(
    tree: Option<&Path>,
    ring: &[::pgp::composed::SignedPublicKey],
    suite: &str,
) -> Result<Option<(Vec<u8>, i64)>> {
    let Some(path) = tree.map(|t| rel_path(t, &release_path(suite))) else {
        return Ok(None);
    };
    if std::fs::symlink_metadata(&path).is_err() {
        return Ok(None);
    }
    let bytes = read_meta(&path).with_context(|| format!("live {suite} InRelease"))?;
    let text = match pgp::release(ring, &bytes) {
        Ok((_, text)) => text,
        Err(e) => {
            tracing::warn!("live {suite} InRelease no longer verifies, no rollback bar: {e:#}");
            return Ok(None);
        }
    };
    Ok(Some((bytes, release_date(&text)?)))
}

/// Pins a generation to the signed `InRelease` of each suite. A signer must be one the source
/// pins, and the Release must be newer than the live one and unexpired (`parse_release`). Each
/// suite's `dists/<suite>` is a swap path, and its chosen indexes are the metadata, fetched by
/// hash when the Release says it keeps them.
pub(crate) fn anchor(ctx: &Ctx<'_>, src: &Source) -> Result<Anchor> {
    let ring = pgp::keyring(
        keys::find(ctx.keys, &src.keyring)
            .with_context(|| format!("no keyring {:?}", src.keyring))?,
    );
    let now = jiff::Timestamp::now().as_second();
    let mut a = Anchor::default();
    for suite in &src.suites {
        let path = release_path(suite);
        let bytes = ctx.dl.get(&url_of(&src.url, &path), RELEASE_CAP)?;
        let (signers, text) =
            pgp::release(&ring, &bytes).with_context(|| format!("{suite} InRelease"))?;
        ensure!(
            signers.iter().any(|s| s.pinned(&src.signers).is_ok()),
            "{suite} InRelease is signed by no pinned key"
        );
        // The same Release again is no rollback: the run only completes or repairs it.
        let live = live_release(ctx.tree, &ring, suite)?
            .filter(|(b, _)| *b != bytes)
            .map(|(_, d)| d);
        let rel =
            parse_release(&text, suite, now, live).with_context(|| format!("{suite} InRelease"))?;
        for e in pick(&rel, src).with_context(|| suite.clone())? {
            let Check::Sha256(h) = e.check else {
                bail!("{}: a Release names SHA-256 hashes", e.path);
            };
            let from = rel.by_hash.then(|| match e.path.rsplit_once('/') {
                Some((dir, _)) => format!("dists/{suite}/{dir}/by-hash/SHA256/{}", hex(&h)),
                None => format!("dists/{suite}/by-hash/SHA256/{}", hex(&h)),
            });
            a.meta.push(Meta {
                entry: Entry {
                    path: format!("dists/{suite}/{}", e.path),
                    ..e
                },
                from,
            });
        }
        a.docs.push((path, bytes));
        a.swaps.push(format!("dists/{suite}"));
    }
    Ok(a)
}

fn is_listing(path: &str) -> bool {
    matches!(
        path.rsplit('/').next(),
        Some("Packages.xz" | "Packages" | "Sources.xz" | "Sources")
    )
}

/// The Packages and Sources listings, which are all `walk` reads.
pub(crate) fn walk_meta(a: &Anchor) -> Vec<&Entry> {
    a.meta
        .iter()
        .map(|m| &m.entry)
        .filter(|e| is_listing(&e.path))
        .collect()
}

/// Every pool file the staged listings name, and a link at each by-hash path of the metadata
/// (declared to the commit, which accepts it only as a copy of verified metadata). A listing
/// that is not on the disk is a dry run's, which fetched only the listings.
pub(crate) fn walk(a: &Anchor, meta: &Path, emit: &mut dyn FnMut(Walked)) -> Result<()> {
    let mut pool = BTreeMap::new();
    for e in walk_meta(a) {
        let file = platform::open_regular(&rel_path(meta, &e.path))
            .with_context(|| format!("staged {}", e.path))?;
        let r: Box<dyn Read> = if e.path.strip_suffix(".xz").is_some() {
            Box::new(Capped {
                r: lzma_rust2::XzReader::new_mem_limit(BufReader::new(file), true, XZ_MEM_KIB),
                left: e.size.saturating_mul(XZ_RATIO),
            })
        } else {
            Box::new(file)
        };
        for s in deb822::parse(BufReader::new(r)) {
            pool_files(&mut pool, &s.with_context(|| e.path.clone())?)
                .with_context(|| e.path.clone())?;
        }
    }
    for m in &a.meta {
        let Some(from) = &m.from else { continue };
        let src = rel_path(meta, &m.entry.path);
        if std::fs::symlink_metadata(&src).is_err() {
            continue;
        }
        let dst = rel_path(meta, from);
        let (dir, _) = from
            .rsplit_once('/')
            .context("a by-hash path at the root")?;
        clear_way(meta, dir)?;
        remove_any(&dst)?;
        ensure!(link_or_copy(&src, &dst), "could not link {from}");
        emit(Walked::Link(from.clone()));
    }
    for e in pool.into_values() {
        emit(Walked::File(e));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write;

    const H1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const H2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const NOW: i64 = 1_763_200_000;

    fn release(head: &str, files: &[(&str, u64, &str)]) -> String {
        let mut t = format!("{head}\nSHA256:\n");
        for (p, n, h) in files {
            let _ = writeln!(t, " {h} {n} {p}");
        }
        t
    }

    fn src(components: &[&str], arches: &[&str]) -> Source {
        Source {
            components: components.iter().map(|s| (*s).to_owned()).collect(),
            arches: arches.iter().map(|s| (*s).to_owned()).collect(),
            ..Source::default()
        }
    }

    const DATE: &str = "Date: Sat, 15 Nov 2025 10:00:00 UTC";

    #[test]
    fn dates_and_validity() {
        let ok = format!(
            "Codename: trixie\n{DATE}\nValid-Until: Sat, 22 Nov 2025 10:00:00 UTC\nAcquire-By-Hash: yes\nComponents: main contrib"
        );
        let r = parse_release(
            &release(&ok, &[("main/binary-amd64/Packages.xz", 7, H1)]),
            "trixie",
            NOW,
            None,
        )
        .unwrap();
        assert_eq!(r.date, 1_763_200_800);
        assert!(r.by_hash);
        assert_eq!(r.components, ["main", "contrib"]);
        assert_eq!(r.files.len(), 1);
        let date = r.date;
        let text = release(&ok, &[]);
        for (case, live, now, good) in [
            ("older live", Some(date - 1), NOW, true),
            ("equal live", Some(date), NOW, false),
            ("newer live", Some(date + 1), NOW, false),
            ("expired", None, 1_763_900_000, false),
        ] {
            assert_eq!(
                parse_release(&text, "trixie", now, live).is_ok(),
                good,
                "{case}"
            );
        }
        assert_eq!(release_date(&text).unwrap(), date);
        for bad in ["Date: yesterday", "Date: Sun, 15 Nov 2025 10:00:00 UTC"] {
            let t = release(&format!("Codename: trixie\n{bad}"), &[]);
            assert!(parse_release(&t, "trixie", NOW, None).is_err(), "{bad}");
        }
        assert!(parse_release(&release("Codename: trixie", &[]), "trixie", NOW, None).is_err());
    }

    #[test]
    fn suite_matches_codename_first() {
        for (case, head, good) in [
            ("codename", "Codename: trixie\nSuite: stable", true),
            ("suite alone", "Suite: trixie", true),
            (
                "codename wins over suite",
                "Codename: bookworm\nSuite: trixie",
                false,
            ),
            ("other codename", "Codename: bookworm", false),
            ("neither", "Origin: Debian", false),
        ] {
            let t = release(&format!("{head}\n{DATE}"), &[]);
            assert_eq!(
                parse_release(&t, "trixie", NOW, None).is_ok(),
                good,
                "{case}"
            );
        }
    }

    #[test]
    fn release_lists_are_strict() {
        let head = format!("Codename: trixie\n{DATE}");
        for (case, files) in [
            ("twice", vec![("main/a", 1, H1), ("main/a", 1, H1)]),
            ("dotdot", vec![("main/../a", 1, H1)]),
            ("short hash", vec![("main/a", 1, "abcd")]),
            ("size", vec![("main/a", u64::MAX, H1)]),
        ] {
            let mut t = release(&head, &files);
            if case == "size" {
                t = t.replace(&u64::MAX.to_string(), "99999999999999999999999");
            }
            assert!(parse_release(&t, "trixie", NOW, None).is_err(), "{case}");
        }
        let two = format!("{head}\nSHA256:\n {H1} 1 a\n\nCodename: x\n");
        assert!(parse_release(&two, "trixie", NOW, None).is_err());
    }

    #[test]
    fn pick_takes_one_variant_per_group() {
        let files = [
            ("main/binary-amd64/Packages", 1, H1),
            ("main/binary-amd64/Packages.gz", 2, H1),
            ("main/binary-amd64/Packages.xz", 3, H1),
            ("main/binary-all/Packages", 4, H1),
            ("main/binary-arm64/Packages.xz", 5, H1),
            ("main/source/Sources.xz", 6, H1),
            ("main/i18n/Translation-en.xz", 7, H1),
            ("main/i18n/Translation-de.xz", 8, H1),
            ("contrib/binary-amd64/Packages.xz", 9, H1),
        ];
        let t = release(
            &format!("Codename: trixie\n{DATE}\nComponents: main contrib"),
            &files,
        );
        let r = parse_release(&t, "trixie", NOW, None).unwrap();
        let got: Vec<_> = pick(&r, &src(&["main"], &["amd64"]))
            .unwrap()
            .into_iter()
            .map(|e| (e.path, e.size))
            .collect();
        assert_eq!(
            got,
            [
                ("main/binary-amd64/Packages.xz".to_owned(), 3),
                ("main/binary-all/Packages".to_owned(), 4),
                ("main/source/Sources.xz".to_owned(), 6),
                ("main/i18n/Translation-en.xz".to_owned(), 7),
            ]
        );
        assert!(
            pick(&r, &src(&["non-free"], &["amd64"])).is_err(),
            "component not in the Release"
        );
        assert!(pick(&r, &src(&["main"], &["riscv64"])).is_ok());
        assert_eq!(
            pick(&r, &src(&["main", "main"], &["amd64", "all", "amd64"]))
                .unwrap()
                .len(),
            4,
            "repeats are read once"
        );
        let t = release(
            &format!("Codename: trixie\n{DATE}"),
            &[("main/binary-amd64/Packages.gz", 1, H1)],
        );
        let r = parse_release(&t, "trixie", NOW, None).unwrap();
        assert!(
            pick(&r, &src(&["main"], &["amd64"])).is_err(),
            "gz alone is not usable"
        );
    }

    fn stanza(fields: &[(&str, &str)]) -> Stanza {
        Stanza(
            fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        )
    }

    fn package(path: &str, hash: &str) -> Stanza {
        stanza(&[
            ("Package", "p"),
            ("Filename", path),
            ("Size", "10"),
            ("SHA256", hash),
        ])
    }

    #[test]
    fn pool_files_collects_and_refuses() {
        let mut pool = BTreeMap::new();
        pool_files(
            &mut pool,
            &package("pool/main/g/gcc/gcc_1.0+b1~rc1_amd64.deb", H1),
        )
        .unwrap();
        pool_files(
            &mut pool,
            &package("pool/main/g/gcc/gcc_1.0+b1~rc1_amd64.deb", H1),
        )
        .unwrap();
        let src = stanza(&[
            ("Package", "gcc"),
            ("Directory", "pool/main/g/gcc"),
            (
                "Checksums-Sha256",
                &format!("{H2} 5 gcc_1.0.dsc\n{H2} 6 gcc_1.0.tar.xz"),
            ),
        ]);
        pool_files(&mut pool, &src).unwrap();
        assert_eq!(pool.len(), 3);
        assert_eq!(pool["pool/main/g/gcc/gcc_1.0.tar.xz"].size, 6);
        for (case, s) in [
            (
                "two hashes",
                package("pool/main/g/gcc/gcc_1.0+b1~rc1_amd64.deb", H2),
            ),
            ("not under pool", package("dists/x/y.deb", H1)),
            ("dotdot", package("pool/../../x", H1)),
            ("odd character", package("pool/main/a b.deb", H1)),
            ("colon", package("pool/main/a:b.deb", H1)),
            ("backslash", package("pool/main/a\\b.deb", H1)),
            ("hidden", package("pool/.x", H1)),
            ("source with no sums", stanza(&[("Directory", "pool/a")])),
            (
                "source with empty sums",
                stanza(&[("Directory", "pool/a"), ("Checksums-Sha256", "")]),
            ),
            ("no size", stanza(&[("Filename", "pool/a"), ("SHA256", H1)])),
            ("bad hash", package("pool/a", "zz")),
            (
                "source name with a slash",
                stanza(&[
                    ("Directory", "pool/a"),
                    ("Checksums-Sha256", &format!("{H1} 1 ../x")),
                ]),
            ),
        ] {
            assert!(pool_files(&mut pool, &s).is_err(), "{case}");
        }
    }
}
