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

/// Resolves a listing's href against the page it came from (RFC 3986 section 5.2, without
/// queries and fragments, which the href pattern never captures).
fn join(base: &str, href: &str) -> Option<String> {
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

impl Resolver<'_> {
    /// Picks the highest versions out of an HTML directory index. One capture group is the
    /// version; two or more mean (family, ..., version), so each family gets its own newest.
    pub(super) fn listing(&self, s: &Source) -> Result<Vec<Item>> {
        let body = self.get(&s.url, DOC_LIMIT)?;
        let body = String::from_utf8_lossy(&body);
        let re = Regex::new(&s.pattern)?;
        let mut cands: Vec<Candidate> = Vec::new();
        let mut all = Vec::new();
        let mut seen = HashSet::new();
        for m in HREF.captures_iter(&body) {
            let Some(href) = m.get(1).map(|x| x.as_str()) else {
                continue;
            };
            let href = href.strip_prefix("./").unwrap_or(href);
            all.push(href);
            let Some(g) = re.captures(href) else { continue };
            if !seen.insert(href) {
                continue;
            }
            let Some(url) = join(&s.url, href) else {
                continue;
            };
            let Some(name) = percent_decode(url_base(&url)) else {
                continue;
            };
            let group = |i: usize| g.get(i).map_or("", |m| m.as_str()).to_string();
            let (family, ver) = match g.len() {
                1 => (String::new(), String::new()),
                2 => (String::new(), group(1)),
                n => (group(1), group(n - 1)),
            };
            cands.push(Candidate {
                family,
                item: Item {
                    name,
                    url,
                    version: ver.clone(),
                    ..Item::default()
                },
                ver,
            });
        }
        let sums_url = if s.sums.contains('*') {
            let h = all
                .iter()
                .find(|h| glob(&s.sums, url_base(h)))
                .with_context(|| format!("{}: no entry matches {}", s.url, s.sums))?;
            join(&s.url, h)
        } else {
            None
        };
        if cands.is_empty() {
            bail!("{}: no entry matches {}", s.url, s.pattern);
        }
        let mut vers: HashMap<&str, Vec<&str>> = HashMap::new();
        for c in &cands {
            let v = vers.entry(&c.family).or_default();
            if !v.contains(&c.ver.as_str()) {
                v.push(&c.ver);
            }
        }
        let mut keep = HashSet::new();
        for (fam, vs) in &mut vers {
            vs.sort_by(|a, b| {
                if ver_less(b, a) {
                    Ordering::Less
                } else if ver_less(a, b) {
                    Ordering::Greater
                } else {
                    Ordering::Equal
                }
            });
            for v in vs.iter().take(s.top.max(1)) {
                keep.insert(((*fam).to_string(), (*v).to_string()));
            }
        }
        Ok(cands
            .into_iter()
            .filter(|c| keep.contains(&(c.family.clone(), c.ver.clone())))
            .map(|mut c| {
                if sums_url.is_some() {
                    c.item.sums_url.clone_from(&sums_url);
                }
                c.item
            })
            .collect())
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
}
