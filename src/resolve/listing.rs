use super::{DOC_LIMIT, Item, Resolver, glob, url_base};
use crate::catalog::Source;
use anyhow::{Context, Result, bail};
use regex::Regex;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

#[expect(clippy::expect_used, reason = "a constant pattern")]
static HREF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"href=["']([^"'#?]+)["']"#).expect("constant regex"));

/// Runs of digits and of everything else.
fn chunks(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let b = s.as_bytes();
    for i in 1..=b.len() {
        if i == b.len() || b[i].is_ascii_digit() != b[i - 1].is_ascii_digit() {
            out.push(&s[start..i]);
            start = i;
        }
    }
    out
}

/// Compares versions chunk by chunk, numbers numerically.
pub(super) fn ver_less(a: &str, b: &str) -> bool {
    let (left, right) = (chunks(a), chunks(b));
    match left.iter().zip(&right).find(|(p, q)| p != q) {
        Some((ours, theirs)) => match (ours.parse::<u64>(), theirs.parse::<u64>()) {
            (Ok(n), Ok(m)) => n < m,
            _ => ours < theirs,
        },
        None => left.len() < right.len(),
    }
}

/// Removes `.` and `..` segments from an absolute path.
fn normalize(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let segs: Vec<&str> = path.split('/').collect();
    for (i, seg) in segs.iter().enumerate() {
        let last = i == segs.len() - 1;
        match *seg {
            "." | ".." => {
                if *seg == ".." && out.len() > 1 {
                    out.pop();
                }
                if last {
                    out.push("");
                }
            }
            s => out.push(s),
        }
    }
    out.join("/")
}

/// Resolves a listing's href or a redirect's Location against the URL it came from (RFC 3986
/// section 5.2). The base's query is dropped; a relative reference's own query is treated as
/// part of its path (listing hrefs have none; an absolute one is returned untouched).
pub(crate) fn join(base: &str, href: &str) -> Option<String> {
    let scheme_end = base.find("://")?;
    let has_scheme = href.split_once(':').is_some_and(|(s, _)| {
        s.starts_with(|c: char| c.is_ascii_alphabetic())
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+.-".contains(&b))
    });
    if has_scheme {
        return Some(href.to_string());
    }
    if let Some(rest) = href.strip_prefix("//") {
        return Some(format!("{}://{rest}", &base[..scheme_end]));
    }
    let base = base.split(['?', '#']).next()?;
    let path_at = base[scheme_end + 3..]
        .find('/')
        .map_or(base.len(), |i| scheme_end + 3 + i);
    let (origin, path) = base.split_at(path_at);
    let path = if href.starts_with('/') {
        normalize(href)
    } else {
        let dir = &path[..path.rfind('/').map_or(0, |i| i + 1)];
        normalize(&format!("/{}{href}", dir.trim_start_matches('/')))
    };
    Some(format!("{origin}{path}"))
}

/// `%XX` escapes decoded; `None` when the result isn't UTF-8.
fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = (b[i] == b'%')
            .then(|| s.get(i + 1..i + 3))
            .flatten()
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        if let Some(byte) = hex {
            out.push(byte);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

struct Candidate {
    family: String,
    ver: String,
    item: Item,
}

/// The `href`s of a directory index, `./` stripped, in page order.
fn hrefs(body: &str) -> Vec<&str> {
    HREF.captures_iter(body)
        .filter_map(|m| m.get(1))
        .map(|x| x.as_str().strip_prefix("./").unwrap_or(x.as_str()))
        .collect()
}

/// Keeps the newest `top` versions of each family.
fn pick(cands: Vec<Candidate>, top: usize) -> Vec<Item> {
    let mut vers: HashMap<&str, Vec<&str>> = HashMap::new();
    for c in &cands {
        let v = vers.entry(&c.family).or_default();
        if !v.contains(&c.ver.as_str()) {
            v.push(&c.ver);
        }
    }
    let mut keep = HashSet::new();
    for (fam, vs) in &mut vers {
        vs.sort_by(|a, b| newest_first(a, b));
        for v in vs.iter().take(top.max(1)) {
            keep.insert(((*fam).to_string(), (*v).to_string()));
        }
    }
    cands
        .into_iter()
        .filter(|c| keep.contains(&(c.family.clone(), c.ver.clone())))
        .map(|c| c.item)
        .collect()
}

/// Under `prefix` as a string and as a path: a `.` or `..` segment (possibly percent-encoded)
/// would let the server resolve the URL outside it.
fn confined(url: &str, prefix: &str) -> bool {
    url.strip_prefix(prefix).is_some_and(|rest| {
        let path = rest.split(['?', '#']).next().unwrap_or_default();
        percent_decode(path).is_some_and(|d| d.split('/').all(|seg| seg != "." && seg != ".."))
    })
}

fn newest_first(a: &str, b: &str) -> Ordering {
    if ver_less(b, a) {
        Ordering::Less
    } else if ver_less(a, b) {
        Ordering::Greater
    } else {
        Ordering::Equal
    }
}

impl Resolver<'_> {
    /// Picks the highest versions out of an HTML directory index. One capture group is the
    /// version; two or more mean (family, ..., version), so each family gets its own newest.
    pub(super) fn listing(&self, s: &Source) -> Result<Vec<Item>> {
        if !s.dirs.is_empty() {
            return self.two_level(s);
        }
        let re = Regex::new(&s.pattern)?;
        let items = self.one_dir(s, &s.url, &re, "", None)?;
        if items.is_empty() {
            bail!("{}: no entry matches {}", s.url, s.pattern);
        }
        Ok(items)
    }

    /// Descends into the newest `dir_top` directories (all when 0) whose names match `dirs`,
    /// and picks files from each. A link that leaves `s.url`, or a name that decodes to a
    /// path, is not followed: parent links are normal on an index page.
    fn two_level(&self, s: &Source) -> Result<Vec<Item>> {
        let prefix = if s.url.ends_with('/') {
            s.url.clone()
        } else {
            format!("{}/", s.url)
        };
        let dirs_re = Regex::new(&s.dirs)?;
        let exclude = (!s.exclude.is_empty())
            .then(|| Regex::new(&s.exclude))
            .transpose()?;
        let body = self.get(&s.url, DOC_LIMIT)?;
        let body = String::from_utf8_lossy(&body);
        let mut seen = HashSet::new();
        let mut dirs: Vec<(String, String, String)> = Vec::new();
        for href in hrefs(&body) {
            let Some(g) = dirs_re.captures(href) else {
                continue;
            };
            let Some(url) = join(&s.url, href).filter(|u| u.starts_with(&prefix)) else {
                continue;
            };
            let Some(name) = percent_decode(href.trim_end_matches('/')) else {
                continue;
            };
            if name.is_empty()
                || name.starts_with('.')
                || name.contains('/')
                || exclude.as_ref().is_some_and(|e| e.is_match(href))
                || !seen.insert(href)
            {
                continue;
            }
            let ver = g.get(1).map_or(name.as_str(), |m| m.as_str()).to_string();
            dirs.push((url, name, ver));
        }
        dirs.sort_by(|a, b| newest_first(&a.2, &b.2));
        if s.dir_top > 0 {
            dirs.truncate(s.dir_top);
        }
        let mut out = Vec::new();
        for (url, name, ver) in &dirs {
            let re = Regex::new(&s.pattern.replace("{dir}", &regex::escape(name)))?;
            out.extend(self.one_dir(s, url, &re, ver, Some(url))?);
        }
        if out.is_empty() {
            bail!("{}: no entry matches {}", s.url, s.pattern);
        }
        Ok(out)
    }

    /// One directory index: the newest matching entries. `inside` confines every entry to
    /// that URL prefix.
    fn one_dir(
        &self,
        s: &Source,
        url: &str,
        re: &Regex,
        dir_ver: &str,
        inside: Option<&str>,
    ) -> Result<Vec<Item>> {
        let body = self.get(url, DOC_LIMIT)?;
        let body = String::from_utf8_lossy(&body);
        let all = hrefs(&body);
        let mut cands: Vec<Candidate> = Vec::new();
        let mut seen = HashSet::new();
        for href in &all {
            let Some(g) = re.captures(href) else { continue };
            if !seen.insert(*href) {
                continue;
            }
            let Some(item_url) = join(url, href) else {
                continue;
            };
            if inside.is_some_and(|p| !confined(&item_url, p)) {
                continue;
            }
            let Some(name) = percent_decode(url_base(&item_url)) else {
                continue;
            };
            let group = |i: usize| g.get(i).map_or("", |m| m.as_str()).to_string();
            let (family, ver) = match g.len() {
                1 => (String::new(), dir_ver.to_string()),
                2 => (String::new(), group(1)),
                n => (group(1), group(n - 1)),
            };
            cands.push(Candidate {
                family,
                item: Item {
                    name,
                    url: item_url,
                    version: ver.clone(),
                    ..Item::default()
                },
                ver,
            });
        }
        if cands.is_empty() {
            return Ok(cands.into_iter().map(|c| c.item).collect());
        }
        let sums_url = if s.sums.contains('*') {
            let h = all
                .iter()
                .find(|h| glob(&s.sums, url_base(h)))
                .with_context(|| format!("{url}: no entry matches {}", s.sums))?;
            join(url, h).filter(|u| inside.is_none_or(|p| confined(u, p)))
        } else {
            None
        };
        let mut items = pick(cands, s.top);
        if sums_url.is_some() {
            for it in &mut items {
                it.sums_url.clone_from(&sums_url);
            }
        }
        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{downloader, resolver, serve};
    use super::*;
    use crate::catalog::{Kind, Resolve};

    #[test]
    fn version_order() {
        let cases = [
            ("1.9", "1.10", true),
            ("1.10", "1.9", false),
            ("6.12.9", "6.12.10", true),
            ("b999", "b4100", true),
            ("1.2", "1.2.1", true),
            ("1.2.1", "1.2", false),
            ("2025-01", "2025-02", true),
            ("a", "a", false),
            ("1.0-rc1", "1.0-rc2", true),
        ];
        for (a, b, want) in cases {
            assert_eq!(ver_less(a, b), want, "{a} < {b}");
        }
    }

    #[test]
    fn href_resolution() {
        let base = "https://h.example/pub/dir/index.html?x=1";
        let cases = [
            ("f.tar.gz", "https://h.example/pub/dir/f.tar.gz"),
            ("sub/f", "https://h.example/pub/dir/sub/f"),
            ("../f", "https://h.example/pub/f"),
            ("../../../f", "https://h.example/f"),
            ("/abs/f", "https://h.example/abs/f"),
            ("/abs/../f", "https://h.example/f"),
            ("//other.example/f", "https://other.example/f"),
            ("https://cdn.example/f", "https://cdn.example/f"),
            ("http://cdn.example/f", "http://cdn.example/f"),
            ("dir/", "https://h.example/pub/dir/dir/"),
        ];
        for (href, want) in cases {
            assert_eq!(join(base, href).as_deref(), Some(want), "{href}");
        }
        assert_eq!(
            join("https://h.example", "f").as_deref(),
            Some("https://h.example/f")
        );
        assert_eq!(percent_decode("a%2Bb%20c").as_deref(), Some("a+b c"));
        assert_eq!(percent_decode("100%").as_deref(), Some("100%"));
        assert_eq!(percent_decode("%ff"), None);
    }

    fn source(url: String, pattern: &str) -> Source {
        Source {
            name: "s".into(),
            kind: Some(Kind::Http),
            resolve: Some(Resolve::Listing),
            url,
            pattern: pattern.into(),
            ..Source::default()
        }
    }

    #[test]
    fn picks_the_newest_per_family() {
        let page = br#"<a href="../">up</a>
            <a href="./pkg-1.9.tar.gz">a</a> <a href='pkg-1.10.tar.gz'>b</a>
            <a href="pkg-1.10.tar.gz">again</a> <a href="pkg-1.2.tar.gz">c</a>
            <a href="lib-3.0.tar.gz">d</a> <a href="lib-2.5.tar.gz">e</a>
            <a href="notes.txt">f</a> <a href="X-CHECKSUM">sums</a>"#;
        let srv = serve(&[("d/", page)]);
        let dl = downloader();
        let r = resolver(&dl, "");

        let mut one = source(srv.url("d/"), r"^pkg-([\d.]+)\.tar\.gz$");
        one.top = 2;
        one.sums = "*-CHECKSUM".into();
        let items = r.resolve(&one).unwrap();
        let names: Vec<_> = items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["pkg-1.9.tar.gz", "pkg-1.10.tar.gz"]);
        assert_eq!(items[1].version, "1.10");
        assert_eq!(items[1].url, srv.url("d/pkg-1.10.tar.gz"));
        assert_eq!(
            items[0].sums_url.as_deref(),
            Some(srv.url("d/X-CHECKSUM").as_str())
        );

        let fam = source(srv.url("d/"), r"^(pkg|lib)-([\d.]+)\.tar\.gz$");
        let items = r.resolve(&fam).unwrap();
        let names: Vec<_> = items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["pkg-1.10.tar.gz", "lib-3.0.tar.gz"]);

        assert!(r.resolve(&source(srv.url("d/"), r"^nothing$")).is_err());
        let mut nosums = source(srv.url("d/"), r"^pkg-([\d.]+)\.tar\.gz$");
        nosums.sums = "*.sha512".into();
        assert!(r.resolve(&nosums).is_err());
    }

    #[test]
    fn rejects_names_that_leave_the_directory() {
        let page = br#"<a href="..%2F..%2Fevil-1.0">x</a> <a href="%2e%2e-1.0">y</a>"#;
        let srv = serve(&[("d/", page)]);
        let dl = downloader();
        let r = resolver(&dl, "");
        let err = r
            .resolve(&source(srv.url("d/"), r"-([\d.]+)$"))
            .unwrap_err();
        assert!(format!("{err:#}").contains("bad or duplicate"), "{err:#}");
    }

    fn two(srv: &crate::net::testserver::Server, dirs: &str, pattern: &str) -> Source {
        let mut s = source(srv.url("p/"), pattern);
        s.dirs = dirs.into();
        s
    }

    fn names(items: &[Item]) -> Vec<&str> {
        items.iter().map(|i| i.name.as_str()).collect()
    }

    #[test]
    fn two_level_series() {
        let srv = serve(&[
            (
                "p/",
                br#"<a href="../">up</a> <a href="gcc-13.3.0/">a</a> <a href="gcc-14.2.0/">b</a>
                <a href="gcc-14.1.0/">c</a> <a href="gcc-9.5.0/">d</a> <a href="other/">e</a>"#,
            ),
            (
                "p/gcc-14.2.0/",
                br#"<a href="gcc-14.2.0.tar.xz">x</a> <a href="gcc-14.2.0.tar.xz.sig">s</a>"#,
            ),
            ("p/gcc-14.1.0/", br#"<a href="gcc-14.1.0.tar.xz">x</a>"#),
        ]);
        let dl = downloader();
        let r = resolver(&dl, "");
        let mut s = two(&srv, r"^gcc-(\d+\.\d+\.\d+)/$", r"^{dir}\.tar\.xz$");
        s.dir_top = 2;
        let items = r.resolve(&s).unwrap();
        assert_eq!(names(&items), ["gcc-14.2.0.tar.xz", "gcc-14.1.0.tar.xz"]);
        assert_eq!(items[0].url, srv.url("p/gcc-14.2.0/gcc-14.2.0.tar.xz"));
    }

    #[test]
    fn two_level_every_dir() {
        let srv = serve(&[
            ("p/", br#"<a href="a/">a</a> <a href="b/">b</a> <a href="skip/">c</a> <a href="empty/">e</a>"#),
            ("p/a/", br#"<a href="a-1.0.tgz">x</a> <a href="a-2.0.tgz">y</a>"#),
            ("p/b/", br#"<a href="b-3.tgz">x</a>"#),
            ("p/empty/", br"nothing"),
        ]);
        let dl = downloader();
        let r = resolver(&dl, "");
        let mut s = two(&srv, r"^[a-z]+/$", r"^[a-z]-([\d.]+)\.tgz$");
        s.exclude = "^skip/$".into();
        let items = r.resolve(&s).unwrap();
        let mut got = names(&items);
        got.sort_unstable();
        assert_eq!(got, ["a-2.0.tgz", "b-3.tgz"]);
        assert!(srv.hits().iter().all(|h| !h.path.contains("skip")));
    }

    #[test]
    fn two_level_version_from_dir() {
        let srv = serve(&[
            ("p/", br#"<a href="v1.9/">a</a> <a href="v1.10/">b</a>"#),
            ("p/v1.9/", br#"<a href="tool.tgz">x</a>"#),
            ("p/v1.10/", br#"<a href="tool.tgz">x</a>"#),
        ]);
        let dl = downloader();
        let r = resolver(&dl, "");
        let mut s = two(&srv, r"^v([\d.]+)/$", r"^tool\.tgz$");
        s.dir_top = 1;
        let items = r.resolve(&s).unwrap();
        assert_eq!(items[0].version, "1.10");
        assert_eq!(items[0].url, srv.url("p/v1.10/tool.tgz"));
    }

    #[test]
    fn two_level_refuses_escape() {
        let srv = serve(&[
            (
                "p/",
                br#"<a href="..%2F/">a</a> <a href="https://other/x/">b</a> <a href="//other/x/">c</a>
                <a href="../">d</a> <a href="ok/">e</a>"#,
            ),
            ("p/ok/", br#"<a href="f.tgz">x</a> <a href="https://other/f.tgz">y</a> <a href="../f.tgz">z</a>
                <a href="https://HOST/p/ok/../../evil/f.tgz">u</a> <a href="%2e%2e/%2e%2e/evil/f.tgz">v</a>"#),
        ]);
        let dl = downloader();
        let r = resolver(&dl, "");
        let items = r.resolve(&two(&srv, r"^.*/$", r"f\.tgz$")).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].url, srv.url("p/ok/f.tgz"));
        let paths: Vec<_> = srv.hits().into_iter().map(|h| h.path).collect();
        assert!(paths.iter().all(|p| p.starts_with("p/")), "{paths:?}");
        assert_eq!(paths.len(), 2, "{paths:?}");
    }
}
