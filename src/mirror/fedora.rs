//! Fedora repodata: the metalink that anchors a tree over TLS, the repomd it vouches for and
//! the primary listing of packages. The parsers read nothing from disk or the network.

use super::generation::valid_path;
use super::{Check, Entry};
use anyhow::{Context, Result, bail};
use quick_xml::events::Event;
use quick_xml::{Reader, XmlVersion};
use sha2::{Digest, Sha256, Sha512};
use std::io::BufRead;

const MAX_DEPTH: usize = 32;
/// Longer text is cut: a field this parser reads is a number, a hash or a name, and a cut one
/// no longer parses.
const MAX_TEXT: usize = 64 * 1024;

enum Ev<'a> {
    Open {
        path: &'a str,
        attrs: &'a [(String, String)],
    },
    Close {
        path: &'a str,
        text: &'a str,
    },
}

fn attr<'a>(attrs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

/// Streams the elements of `src` with their `/`-joined local-name path. DOCTYPEs are refused
/// and entity references in text turn into `&`, so a value that held one stops parsing.
fn scan<R: BufRead>(src: R, mut f: impl FnMut(Ev<'_>) -> Result<()>) -> Result<()> {
    let mut rd = Reader::from_reader(src);
    rd.config_mut().expand_empty_elements = true;
    let (mut buf, mut path, mut text) = (Vec::new(), String::new(), String::new());
    let (mut marks, mut attrs) = (Vec::<usize>::new(), Vec::<(String, String)>::new());
    loop {
        buf.clear();
        match rd.read_event_into(&mut buf).context("bad xml")? {
            Event::Start(e) => {
                if marks.len() >= MAX_DEPTH {
                    bail!("xml nested too deep");
                }
                marks.push(path.len());
                path.push('/');
                path.push_str(e.local_name().as_ref());
                attrs.clear();
                for a in e.attributes() {
                    let a = a.context("bad xml attribute")?;
                    let key: &str = a.key.as_ref();
                    let val = a
                        .normalized_value(XmlVersion::Implicit1_0)
                        .context("bad xml attribute")?;
                    attrs.push((key.to_owned(), val.into_owned()));
                }
                text.clear();
                f(Ev::Open {
                    path: &path,
                    attrs: &attrs,
                })?;
            }
            Event::End(_) => {
                f(Ev::Close {
                    path: &path,
                    text: &text,
                })?;
                path.truncate(marks.pop().context("bad xml")?);
                text.clear();
            }
            Event::Text(t) if text.len() < MAX_TEXT => text.push_str(&t),
            Event::CData(c) if text.len() < MAX_TEXT => text.push_str(&c),
            Event::GeneralRef(_) => text.push('&'),
            Event::DocType(_) => bail!("xml with a DOCTYPE"),
            Event::Eof if marks.is_empty() => return Ok(()),
            Event::Eof => bail!("xml ends inside an element"),
            _ => {}
        }
    }
}

fn once<T>(slot: &mut Option<T>, v: T, what: &str) -> Result<()> {
    if slot.replace(v).is_some() {
        bail!("{what} twice");
    }
    Ok(())
}

fn num(text: &str, what: &str) -> Result<u64> {
    text.trim()
        .parse()
        .with_context(|| format!("{what} is not a number"))
}

fn unhex<const N: usize>(text: &str) -> Result<[u8; N]> {
    let b = text.trim().as_bytes();
    if b.len() != N * 2 {
        bail!("hash of {} characters, wanted {}", b.len(), N * 2);
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => bail!("not hex"),
    };
    let mut out = [0u8; N];
    for (o, pair) in out.iter_mut().zip(b.as_chunks::<2>().0) {
        *o = (nib(pair[0])? << 4) | nib(pair[1])?;
    }
    Ok(out)
}

/// One version of the repomd as the metalink states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Doc {
    pub size: u64,
    pub sha256: [u8; 32],
    pub sha512: [u8; 64],
}

impl Doc {
    fn matches(&self, bytes: &[u8]) -> bool {
        self.size == bytes.len() as u64
            && self.sha256 == <[u8; 32]>::from(Sha256::digest(bytes))
            && self.sha512 == <[u8; 64]>::from(Sha512::digest(bytes))
    }
}

#[derive(Default)]
struct DocBuilder {
    size: Option<u64>,
    sha256: Option<[u8; 32]>,
    sha512: Option<[u8; 64]>,
}

impl DocBuilder {
    fn hash(&mut self, kind: &str, text: &str) -> Result<()> {
        match kind {
            "sha256" => once(&mut self.sha256, unhex(text)?, "sha256"),
            "sha512" => once(&mut self.sha512, unhex(text)?, "sha512"),
            _ => Ok(()),
        }
    }

    fn done(self) -> Result<Doc> {
        Ok(Doc {
            size: self.size.context("a metalink file without a size")?,
            sha256: self.sha256.context("a metalink file without a sha256")?,
            sha512: self.sha512.context("a metalink file without a sha512")?,
        })
    }
}

/// The metalink of one tree: `ts` is its `mm0:timestamp`, `docs[0]` the current repomd and the
/// rest the alternates (older repomds that mirrors may still hold).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Metalink {
    pub ts: u64,
    pub docs: Vec<Doc>,
}

pub(crate) fn parse_metalink(xml: &[u8]) -> Result<Metalink> {
    const FILE: &str = "/metalink/files/file";
    let (mut files, mut ts, mut hash_kind) = (0, None, String::new());
    let (mut top, mut alt, mut alts) = (DocBuilder::default(), DocBuilder::default(), Vec::new());
    let mut docs = Vec::new();
    scan(xml, |ev| {
        match ev {
            Ev::Open { path, attrs } => match path.strip_prefix(FILE) {
                Some("") => {
                    files += 1;
                    if files > 1 || attr(attrs, "name") != Some("repomd.xml") {
                        bail!("a metalink that is not for one repomd.xml");
                    }
                }
                Some("/verification/hash" | "/alternates/alternate/verification/hash") => {
                    attr(attrs, "type")
                        .unwrap_or_default()
                        .clone_into(&mut hash_kind);
                }
                Some("/alternates/alternate") => alt = DocBuilder::default(),
                _ => {}
            },
            Ev::Close { path, text } => match path.strip_prefix(FILE) {
                Some("/timestamp") => once(&mut ts, num(text, "timestamp")?, "timestamp")?,
                Some("/size") => once(&mut top.size, num(text, "size")?, "size")?,
                Some("/verification/hash") => top.hash(&hash_kind, text)?,
                Some("/alternates/alternate/size") => {
                    once(&mut alt.size, num(text, "size")?, "size")?;
                }
                Some("/alternates/alternate/verification/hash") => alt.hash(&hash_kind, text)?,
                Some("/alternates/alternate") => alts.push(std::mem::take(&mut alt).done()?),
                Some("") => {
                    docs.push(std::mem::take(&mut top).done()?);
                    docs.append(&mut alts);
                }
                _ => {}
            },
        }
        Ok(())
    })?;
    if docs.is_empty() {
        bail!("a metalink without a file");
    }
    Ok(Metalink {
        ts: ts.context("a metalink without a timestamp")?,
        docs,
    })
}

/// One `<data>` of a repomd. `path` is under `repodata/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Data {
    pub kind: String,
    pub path: String,
    pub check: Check,
    pub size: u64,
    pub open_size: Option<u64>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Repomd {
    pub revision: u64,
    pub data: Vec<Data>,
}

impl Repomd {
    /// The one primary listing and its open size, which caps its decoding. It has to be zstd:
    /// any other compression fails closed.
    pub(crate) fn primary(&self) -> Result<(&Data, u64)> {
        let mut it = self.data.iter().filter(|d| d.kind == "primary");
        let d = it.next().context("a repomd without a primary")?;
        if it.next().is_some() {
            bail!("a repomd with two primaries");
        }
        if !d.path.ends_with(".xml.zst") {
            bail!("primary is not .xml.zst: {}", d.path);
        }
        let open = d.open_size.context("primary without an open-size")?;
        Ok((d, open))
    }
}

#[derive(Default)]
struct DataBuilder {
    kind: String,
    path: Option<String>,
    check: Option<Check>,
    size: Option<u64>,
    open_size: Option<u64>,
}

pub(crate) fn parse_repomd(xml: &[u8]) -> Result<Repomd> {
    let (mut revision, mut cur, mut data) = (None, DataBuilder::default(), Vec::new());
    let mut sum_kind_ok = false;
    scan(xml, |ev| {
        match ev {
            Ev::Open { path, attrs } => match path {
                "/repomd/data" => {
                    cur = DataBuilder {
                        kind: attr(attrs, "type").unwrap_or_default().to_owned(),
                        ..DataBuilder::default()
                    };
                }
                "/repomd/data/checksum" => sum_kind_ok = attr(attrs, "type") == Some("sha256"),
                "/repomd/data/location" => {
                    let href = attr(attrs, "href").context("a location without an href")?;
                    if !valid_path(href) || !href.starts_with("repodata/") {
                        bail!("repomd names {href:?}");
                    }
                    if attr(attrs, "xml:base").is_some() {
                        bail!("repomd location with an xml:base");
                    }
                    once(&mut cur.path, href.to_owned(), "location")?;
                }
                _ => {}
            },
            Ev::Close { path, text } => match path {
                "/repomd/revision" => once(&mut revision, num(text, "revision")?, "revision")?,
                "/repomd/data/checksum" => {
                    if !sum_kind_ok {
                        bail!("repomd checksum that is not sha256");
                    }
                    once(&mut cur.check, Check::Sha256(unhex(text)?), "checksum")?;
                }
                "/repomd/data/size" => once(&mut cur.size, num(text, "size")?, "size")?,
                "/repomd/data/open-size" => {
                    once(&mut cur.open_size, num(text, "open-size")?, "open-size")?;
                }
                "/repomd/data" => {
                    let d = std::mem::take(&mut cur);
                    data.push(Data {
                        path: d.path.context("data without a location")?,
                        check: d.check.context("data without a checksum")?,
                        size: d.size.context("data without a size")?,
                        open_size: d.open_size,
                        kind: d.kind,
                    });
                }
                _ => {}
            },
        }
        Ok(())
    })?;
    Ok(Repomd {
        revision: revision.context("a repomd without a revision")?,
        data,
    })
}

#[derive(Default)]
struct Package {
    sum: Option<Check>,
    size: Option<u64>,
    path: Option<String>,
}

/// Calls `f` for every package of a primary listing, as the `Packages/` file it names.
/// Anything the tree could not hold as is (a path outside `Packages/`, a base override, a
/// checksum other than sha256) is an error.
pub(crate) fn parse_primary<R: BufRead>(
    src: R,
    f: &mut dyn FnMut(Entry) -> Result<()>,
) -> Result<()> {
    let (mut cur, mut sum_kind_ok) = (Package::default(), false);
    scan(src, |ev| {
        match ev {
            Ev::Open { path, attrs } => match path {
                "/metadata/package" => cur = Package::default(),
                "/metadata/package/checksum" => {
                    sum_kind_ok = attr(attrs, "type") == Some("sha256");
                }
                "/metadata/package/size" => {
                    let n = attr(attrs, "package").context("a size without a package size")?;
                    once(&mut cur.size, num(n, "package size")?, "size")?;
                }
                "/metadata/package/location" => {
                    let href = attr(attrs, "href").context("a location without an href")?;
                    if !valid_path(href) || !href.starts_with("Packages/") {
                        bail!("primary names {href:?}");
                    }
                    if attr(attrs, "xml:base").is_some() {
                        bail!("primary location with an xml:base: {href}");
                    }
                    once(&mut cur.path, href.to_owned(), "location")?;
                }
                _ => {}
            },
            Ev::Close { path, text } => match path {
                "/metadata/package/checksum" => {
                    if !sum_kind_ok {
                        bail!("primary checksum that is not sha256");
                    }
                    once(&mut cur.sum, Check::Sha256(unhex(text)?), "checksum")?;
                }
                "/metadata/package" => {
                    let p = std::mem::take(&mut cur);
                    f(Entry {
                        path: p.path.context("a package without a location")?,
                        size: p.size.context("a package without a size")?,
                        check: p.sum.context("a package without a checksum")?,
                    })?;
                }
                _ => {}
            },
        }
        Ok(())
    })
}

/// Decides whether `repomd` (as fetched from a mirror) may replace the live tree's.
/// - It must be one of the metalink's documents (the current one or an alternate) on size,
///   sha256 and sha512.
/// - The metalink must not be older than `last_ts`, the one recorded at the last commit.
/// - Its revision must be greater than `live`'s, whether or not `live` matches anything in
///   today's metalink. The caller has already checked `live` against the hash it recorded.
pub(crate) fn accept(
    ml: &Metalink,
    repomd: &[u8],
    live: Option<&Repomd>,
    last_ts: Option<u64>,
) -> Result<Repomd> {
    if last_ts.is_some_and(|t| ml.ts < t) {
        bail!("the metalink is older than the last one accepted");
    }
    if !ml.docs.iter().any(|d| d.matches(repomd)) {
        bail!("repomd.xml matches nothing the metalink lists");
    }
    let new = parse_repomd(repomd)?;
    if let Some(live) = live
        && new.revision <= live.revision
    {
        bail!(
            "repomd revision {} is not newer than the live {}",
            new.revision,
            live.revision
        );
    }
    Ok(new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;
    use std::io::Cursor;

    const METALINK: &[u8] = include_bytes!("testdata/fedora/metalink.xml");
    const REPOMD: &[u8] = include_bytes!("testdata/fedora/repomd.xml");
    const PRIMARY: &[u8] = include_bytes!("testdata/fedora/primary.xml");

    type Case<'a> = (&'a str, &'a Metalink, Option<&'a Repomd>, Option<u64>, bool);

    fn text(b: &[u8]) -> &str {
        std::str::from_utf8(b).unwrap()
    }

    fn doc_of(b: &[u8]) -> Doc {
        Doc {
            size: b.len() as u64,
            sha256: Sha256::digest(b).into(),
            sha512: Sha512::digest(b).into(),
        }
    }

    fn primary(src: &[u8]) -> Result<Vec<Entry>> {
        let mut v = Vec::new();
        parse_primary(src, &mut |e| {
            v.push(e);
            Ok(())
        })?;
        Ok(v)
    }

    #[test]
    fn metalink_fixture() {
        let m = parse_metalink(METALINK).unwrap();
        assert_eq!(m.ts, 1_763_460_000);
        assert_eq!(m.docs.len(), 2);
        assert_eq!((m.docs[0].size, m.docs[0].sha256), (4321, [0x11; 32]));
        assert_eq!(m.docs[0].sha512, [0x22; 64]);
        assert_eq!((m.docs[1].size, m.docs[1].sha256), (4300, [0x33; 32]));
    }

    #[test]
    fn metalink_refusals() {
        let good = text(METALINK);
        let sha256 = "1".repeat(64);
        let cases = [
            ("not xml", "<metalink><files>".to_owned()),
            ("empty", String::new()),
            ("doctype", format!("<!DOCTYPE a [<!ENTITY x \"y\">]>{good}")),
            (
                "other file",
                good.replace("name=\"repomd.xml\"", "name=\"x.xml\""),
            ),
            (
                "two files",
                good.replace("</files>", "<file name=\"repomd.xml\"/></files>"),
            ),
            ("short hash", good.replace(&sha256, &"1".repeat(63))),
            ("non hex", good.replace(&sha256, &"g".repeat(64))),
            (
                "hash twice",
                good.replacen(
                    "<hash type=\"md5\"",
                    &format!("<hash type=\"sha256\">{sha256}</hash><hash type=\"md5\""),
                    1,
                ),
            ),
            (
                "no timestamp",
                good.replace("mm0:timestamp>1763460000", "mm0:other>1"),
            ),
            (
                "size text",
                good.replace("<size>4321</size>", "<size>big</size>"),
            ),
            ("no size", good.replace("<size>4321</size>", "")),
            (
                "no sha512",
                good.replace("type=\"sha512\">2", "type=\"sha1\">2"),
            ),
            ("entity in a number", good.replace("4321", "43&#50;1")),
        ];
        for (name, xml) in cases {
            assert!(parse_metalink(xml.as_bytes()).is_err(), "{name}");
        }
    }

    #[test]
    fn repomd_fixture() {
        let r = parse_repomd(REPOMD).unwrap();
        assert_eq!(r.revision, 1_763_459_000);
        assert_eq!(r.data.len(), 2);
        let (d, open) = r.primary().unwrap();
        assert_eq!(d.path, "repodata/aaaaaaaa-primary.xml.zst");
        assert_eq!(
            (d.size, open, d.check),
            (1000, 9000, Check::Sha256([0xaa; 32]))
        );
        assert_eq!(r.data[1].kind, "filelists");
        assert_eq!(r.data[1].open_size, Some(20000));
    }

    #[test]
    fn repomd_refusals() {
        let good = text(REPOMD);
        let loc = "href=\"repodata/aaaaaaaa";
        let cases = [
            ("outside repodata", good.replace(loc, "href=\"Packages/a")),
            ("dotdot", good.replace(loc, "href=\"repodata/../a")),
            ("hidden", good.replace(loc, "href=\"repodata/.a")),
            ("absolute", good.replace(loc, "href=\"/repodata/a")),
            (
                "xml:base",
                good.replace("<location href", "<location xml:base=\"http://x/\" href"),
            ),
            (
                "sha512 type",
                good.replacen("checksum type=\"sha256\"", "checksum type=\"sha512\"", 1),
            ),
            (
                "no revision",
                good.replace("<revision>1763459000</revision>", ""),
            ),
            (
                "revision text",
                good.replace("1763459000</revision>", "x</revision>"),
            ),
            ("no size", good.replacen("<size>1000</size>", "", 1)),
            (
                "no location",
                good.replacen(
                    "<location href=\"repodata/aaaaaaaa-primary.xml.zst\"/>",
                    "",
                    1,
                ),
            ),
            ("truncated", good[..good.len() / 2].to_owned()),
        ];
        for (name, xml) in cases {
            assert!(parse_repomd(xml.as_bytes()).is_err(), "{name}");
        }
    }

    #[test]
    fn primary_must_be_one_zstd_listing() {
        let good = text(REPOMD);
        let cases = [
            ("gz", good.replace("primary.xml.zst", "primary.xml.gz")),
            ("xz", good.replace("primary.xml.zst", "primary.xml.xz")),
            ("plain", good.replace("primary.xml.zst", "primary.xml")),
            ("none", good.replace("type=\"primary\"", "type=\"other\"")),
            (
                "two",
                good.replace("type=\"filelists\"", "type=\"primary\""),
            ),
            (
                "no open-size",
                good.replace("<open-size>9000</open-size>", ""),
            ),
        ];
        for (name, xml) in cases {
            let r = parse_repomd(xml.as_bytes()).unwrap();
            assert!(r.primary().is_err(), "{name}");
        }
    }

    #[test]
    fn primary_fixture() {
        let v = primary(PRIMARY).unwrap();
        assert_eq!(
            v,
            [
                Entry {
                    path: "Packages/b/bash-5.3-1.fc45.x86_64.rpm".into(),
                    size: 1_800_000,
                    check: Check::Sha256([0xdd; 32]),
                },
                Entry {
                    path: "Packages/z/zsh-5.9-1.fc45.x86_64.rpm".into(),
                    size: 3_300_000,
                    check: Check::Sha256([0xee; 32]),
                },
            ]
        );
    }

    #[test]
    fn primary_refusals() {
        let good = text(PRIMARY);
        let loc = "href=\"Packages/b";
        let cases = [
            ("outside Packages", good.replace(loc, "href=\"repodata/b")),
            ("dotdot", good.replace(loc, "href=\"Packages/../b")),
            (
                "xml:base",
                good.replace("<location href", "<location xml:base=\"http://x/\" href"),
            ),
            ("sha1", good.replacen("type=\"sha256\"", "type=\"sha1\"", 1)),
            ("short sum", good.replacen("dddddddd", "", 1)),
            (
                "no size",
                good.replacen("<size package=\"1800000\"", "<size", 1),
            ),
            (
                "size text",
                good.replace("package=\"1800000\"", "package=\"many\""),
            ),
            (
                "no location",
                good.replacen(
                    "<location href=\"Packages/b/bash-5.3-1.fc45.x86_64.rpm\"/>",
                    "",
                    1,
                ),
            ),
            ("truncated", good[..good.len() - 40].to_owned()),
            ("mismatched", good.replace("</name>", "</nome>")),
        ];
        for (name, xml) in cases {
            assert!(primary(xml.as_bytes()).is_err(), "{name}");
        }
    }

    #[test]
    fn primary_reads_the_same_through_a_one_byte_reader() {
        let slow = std::io::BufReader::with_capacity(1, Cursor::new(PRIMARY));
        let mut v = Vec::new();
        parse_primary(slow, &mut |e| {
            v.push(e);
            Ok(())
        })
        .unwrap();
        assert_eq!(v, primary(PRIMARY).unwrap());
    }

    #[test]
    fn accept_table() {
        let new = REPOMD;
        let at = |rev: &str| {
            let t = text(new).replace("1763459000</revision>", &format!("{rev}</revision>"));
            parse_repomd(t.as_bytes()).unwrap()
        };
        let (live_old, live_same, live_newer) =
            (at("1763400000"), at("1763459000"), at("1763500000"));
        let ml = |docs: Vec<Doc>, ts| Metalink { ts, docs };
        let stranger = Doc {
            size: 1,
            sha256: [0; 32],
            sha512: [0; 64],
        };

        let head = ml(vec![doc_of(new), stranger.clone()], 100);
        let lagging = ml(vec![stranger.clone(), doc_of(new)], 100);
        let none = ml(vec![stranger], 100);
        let mut wrong_size = doc_of(new);
        wrong_size.size += 1;
        let off_by_size = ml(vec![wrong_size], 100);
        let mut wrong_512 = doc_of(new);
        wrong_512.sha512[0] ^= 1;
        let off_by_512 = ml(vec![wrong_512], 100);

        let cases: [Case; 11] = [
            ("fresh", &head, None, None, true),
            (
                "lagging alternate",
                &lagging,
                Some(&live_old),
                Some(100),
                true,
            ),
            ("newer than live", &head, Some(&live_old), Some(50), true),
            ("matches nothing", &none, None, None, false),
            ("size differs", &off_by_size, None, None, false),
            ("sha512 differs", &off_by_512, None, None, false),
            ("equal revision", &head, Some(&live_same), None, false),
            ("lower revision", &head, Some(&live_newer), None, false),
            ("older metalink", &head, None, Some(101), false),
            ("same timestamp", &head, None, Some(100), true),
            (
                "older metalink, newer repomd",
                &head,
                Some(&live_old),
                Some(101),
                false,
            ),
        ];
        for (name, ml, live, ts, ok) in cases {
            let got = accept(ml, new, live, ts);
            assert_eq!(got.is_ok(), ok, "{name}: {got:?}");
        }
    }

    #[test]
    fn accept_refuses_a_matching_but_unparseable_repomd() {
        let junk = b"<repomd><revision>1</revision><data type=\"primary\"></repomd>";
        let ml = Metalink {
            ts: 1,
            docs: vec![doc_of(junk)],
        };
        assert!(accept(&ml, junk, None, None).is_err());
    }

    proptest::proptest! {
           #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

           #[test]
           fn primary_round_trips(
               rows in proptest::collection::vec(
                   (
                       "[a-z][a-z0-9]{0,8}(/[a-z0-9_+-][a-z0-9_.+-]{0,9}){0,2}",
                       0..u64::MAX,
                       proptest::array::uniform32(0u8..),
                   ),
                   0..8,
               )
           ) {
               let mut xml = String::from("<metadata>");
               for (name, size, sum) in &rows {
                   write!(
    xml,
                       "<package type=\"rpm\"><checksum type=\"sha256\" pkgid=\"YES\">{}</checksum><size package=\"{size}\"/><location href=\"Packages/{name}.rpm\"/></package>",
                       crate::resolve::hex(sum)
                   ).unwrap();
               }
               xml += "</metadata>";
               let want: Vec<Entry> = rows
                   .into_iter()
                   .map(|(n, size, sum)| Entry {
                       path: format!("Packages/{n}.rpm"),
                       size,
                       check: Check::Sha256(sum),
                   })
                   .collect();
               proptest::prop_assert_eq!(primary(xml.as_bytes()).unwrap(), want);
           }

           #[test]
           fn repomd_round_trips(
               rev in 0..u64::MAX,
               rows in proptest::collection::vec(
                   (0..u64::MAX, proptest::option::of(0..u64::MAX), proptest::array::uniform32(0u8..)),
                   0..6,
               ),
           ) {
               let mut xml = format!("<repomd><revision>{rev}</revision>");
               for (i, (size, open, sum)) in rows.iter().enumerate() {
                   let open = open.map(|o| format!("<open-size>{o}</open-size>")).unwrap_or_default();
                   write!(
    xml,
                       "<data type=\"t{i}\"><checksum type=\"sha256\">{}</checksum><location href=\"repodata/f{i}\"/><size>{size}</size>{open}</data>",
                       crate::resolve::hex(sum)
                   ).unwrap();
               }
               xml += "</repomd>";
               let r = parse_repomd(xml.as_bytes()).unwrap();
               proptest::prop_assert_eq!(r.revision, rev);
               let got: Vec<_> = r.data.iter().map(|d| (d.size, d.open_size, d.check)).collect();
               let want: Vec<_> = rows.iter().map(|(s, o, c)| (*s, *o, Check::Sha256(*c))).collect();
               proptest::prop_assert_eq!(got, want);
           }

           #[test]
           fn metalink_round_trips(
               ts in 0..u64::MAX,
               docs in proptest::collection::vec(
                   (
                       0..u64::MAX,
                       proptest::array::uniform32(0u8..),
                       proptest::collection::vec(0u8.., 64),
                       0usize..4,
                   ),
                   1..5,
               ),
           ) {
               let hashes = |(_, s256, s512, rot): &(u64, [u8; 32], Vec<u8>, usize)| {
                   let mut h = [
                       "<hash type=\"md5\">0123456789abcdef0123456789abcdef</hash>".to_owned(),
                       "<hash type=\"sha1\">0123456789abcdef0123456789abcdef01234567</hash>".to_owned(),
                       format!("<hash type=\"sha256\">{}</hash>", crate::resolve::hex(s256)),
                       format!("<hash type=\"sha512\">{}</hash>", crate::resolve::hex(s512)),
                   ];
                   h.rotate_left(*rot);
                   h.concat()
               };
               let mut xml = format!(
                   "<metalink><files><file name=\"repomd.xml\"><mm0:timestamp>{ts}</mm0:timestamp><size>{}</size><verification>{}</verification><mm0:alternates>",
                   docs[0].0,
                   hashes(&docs[0])
               );
               for d in &docs[1..] {
                   write!(
                       xml,
                       "<mm0:alternate><mm0:timestamp>1</mm0:timestamp><size>{}</size><verification>{}</verification></mm0:alternate>",
                       d.0,
                       hashes(d)
                   ).unwrap();
               }
               xml += "</mm0:alternates></file></files></metalink>";
               let want: Vec<Doc> = docs
                   .iter()
                   .map(|(size, s256, s512, _)| Doc {
                       size: *size,
                       sha256: *s256,
                       sha512: s512.as_slice().try_into().unwrap(),
                   })
                   .collect();
               let m = parse_metalink(xml.as_bytes()).unwrap();
               proptest::prop_assert_eq!(m, Metalink { ts, docs: want });
           }

           #[test]
           fn parsers_never_panic(
               bytes in proptest::collection::vec(0u8.., 0..512),
               cut in 0usize..2048,
               at in 0usize..2048,
           ) {
               let _ = parse_metalink(&bytes);
               let _ = parse_repomd(&bytes);
               let _ = primary(&bytes);
               for fixture in [METALINK, REPOMD, PRIMARY] {
                   let mut mutated = fixture.to_vec();
                   let at = at % mutated.len();
                   mutated[at] = bytes.first().copied().unwrap_or(b'<');
                   mutated.truncate(mutated.len() - cut % (mutated.len() - at));
                   let _ = parse_metalink(&mutated);
                   let _ = parse_repomd(&mutated);
                   let _ = primary(&mutated);
               }
           }
       }
}
