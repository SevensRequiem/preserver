//! Turns a catalog source into the files to fetch: names, URLs, versions and whatever hashes
//! the upstream index publishes. Everything read here is untrusted until `verify` has run.

mod json;
pub(crate) mod listing;

use crate::catalog::{Kind, Resolve, SigOver, Source};
use crate::net::download::Downloader;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const DOC_LIMIT: u64 = 32 << 20;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Item {
    pub name: String,
    pub url: String,
    pub version: String,
    /// Hex as published, empty when the index has none.
    pub sha256: String,
    pub sha512: String,
    pub size: Option<u64>,
    pub sig_url: Option<String>,
    pub sums_url: Option<String>,
    pub sums_sig_url: Option<String>,
}

pub(crate) struct Resolver<'a> {
    pub dl: &'a Downloader,
    /// `https://api.github.com/repos/`
    pub gh_api: &'a str,
    /// `https://huggingface.co/`
    pub hf_base: &'a str,
    /// Tests only: the loopback server speaks plain http.
    pub plain_http: bool,
}

pub(crate) const GH_API: &str = "https://api.github.com/repos/";
pub(crate) const HF_BASE: &str = "https://huggingface.co/";

/// A file name that is safe inside the staging directory.
pub(crate) fn valid_file_name(s: &str) -> bool {
    s.starts_with(|c: char| c.is_ascii_alphanumeric())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+@~=,-".contains(&b))
}

fn size(n: u64) -> Option<u64> {
    (n > 0).then_some(n)
}

/// The URL up to and including its last slash.
fn dir_url(u: &str) -> &str {
    &u[..u.rfind('/').map_or(0, |i| i + 1)]
}

/// The last path segment, without query or trailing slash.
pub(crate) fn url_base(u: &str) -> &str {
    let u = u.split(['?', '#']).next().unwrap_or_default();
    let u = u.trim_end_matches('/');
    &u[u.rfind('/').map_or(0, |i| i + 1)..]
}

/// `*` and `?` within one path segment: all the catalog's globs use.
fn glob(pat: &str, name: &str) -> bool {
    let (p, n) = (pat.as_bytes(), name.as_bytes());
    let (mut i, mut j) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while j < n.len() {
        if i < p.len() && p[i] == b'*' {
            star = Some((i, j));
            i += 1;
        } else if i < p.len() && (p[i] == n[j] || p[i] == b'?' && n[j] != b'/') {
            i += 1;
            j += 1;
        } else if let Some((si, sj)) = star.filter(|(_, sj)| n[*sj] != b'/') {
            star = Some((si, sj + 1));
            i = si + 1;
            j = sj + 1;
        } else {
            return false;
        }
    }
    p[i..].iter().all(|b| *b == b'*')
}

#[derive(Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
    digest: Option<String>,
    #[serde(default)]
    size: u64,
}

#[derive(Deserialize, Default)]
struct GhRelease {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    assets: Vec<GhAsset>,
}

#[derive(Deserialize)]
struct HfLfs {
    oid: String,
    size: u64,
}

#[derive(Deserialize)]
struct HfEntry {
    #[serde(rename = "type")]
    kind: String,
    path: String,
    #[serde(default)]
    size: u64,
    lfs: Option<HfLfs>,
}

impl Resolver<'_> {
    fn check_url(&self, u: &str) -> Result<()> {
        let rest = u
            .strip_prefix("https://")
            .or_else(|| u.strip_prefix("http://").filter(|_| self.plain_http));
        let host = rest.map(|r| r.split(['/', '?', '#']).next().unwrap_or_default());
        if host.is_none_or(str::is_empty) || u.bytes().any(|b| b <= b' ' || b == 0x7f) {
            bail!("refusing non-https url {u:?}");
        }
        Ok(())
    }

    fn get(&self, url: &str, limit: u64) -> Result<Vec<u8>> {
        self.check_url(url)?;
        self.dl.get(url, limit)
    }

    /// The content length of `url`, for the dry run; `None` when the server won't say.
    pub(crate) fn head_size(&self, url: &str) -> Option<u64> {
        let h = self.dl.head(url).ok()?;
        size(h.get("content-length")?.to_str().ok()?.parse().ok()?)
    }

    pub(crate) fn resolve(&self, s: &Source) -> Result<Vec<Item>> {
        let mut items = match (s.kind(), s.resolve) {
            (Kind::Hf, _) => self.hf_tree(s)?,
            (_, Some(Resolve::Static)) => self.fixed(s)?,
            (_, Some(Resolve::Listing)) => self.listing(s)?,
            (_, Some(Resolve::GhLatest)) => self.github(s, false)?,
            (_, Some(Resolve::GhTags)) => self.github(s, true)?,
            (_, Some(Resolve::Json)) => self.json_index(s)?,
            (_, Some(Resolve::YamlLite)) => self.yaml_lite(s)?,
            (_, None) => bail!("no resolver"),
        };
        if items.is_empty() {
            bail!("resolved to nothing");
        }
        let names: HashSet<String> = items.iter().map(|it| it.name.clone()).collect();
        let mut seen = HashSet::new();
        for it in &mut items {
            if !valid_file_name(&it.name) || !seen.insert(it.name.clone()) {
                bail!("bad or duplicate file name {:?}", it.name);
            }
            self.check_url(&it.url)?;
            if !s.sig.is_empty() && it.sig_url.is_none() {
                // kernel.org signs the uncompressed tar: X.tar.xz is verified with X.tar.sign.
                let base = match s.sig_over {
                    Some(SigOver::Xz) => it.url.strip_suffix(".xz").unwrap_or(&it.url),
                    None => &it.url,
                };
                it.sig_url = Some(format!("{base}{}", s.sig));
            }
            if !s.sums.is_empty() && it.sums_url.is_none() {
                let name = s.sums.replace("{file}", &it.name);
                it.sums_url = Some(format!("{}{name}", dir_url(&it.url)));
            }
            if let Some(sums) = &it.sums_url
                && it.sums_sig_url.is_none()
                && !s.sums_sig.is_empty()
                && s.sums_sig != "clear"
            {
                it.sums_sig_url = Some(format!("{sums}{}", s.sums_sig));
            }
            for side in [&it.sig_url, &it.sums_url, &it.sums_sig_url]
                .into_iter()
                .flatten()
            {
                self.check_url(side)?;
                let base = url_base(side);
                if !valid_file_name(base) || names.contains(base) {
                    bail!(
                        "signature or sums file name {base:?} is unsafe or collides with a download"
                    );
                }
            }
        }
        Ok(items)
    }

    fn fixed(&self, s: &Source) -> Result<Vec<Item>> {
        let one = [s.url.clone()];
        let urls = if s.urls.is_empty() { &one[..] } else { &s.urls };
        let mut items = Vec::new();
        for (i, u) in urls.iter().enumerate() {
            let name = if s.assets.len() == urls.len() {
                s.assets[i].clone()
            } else {
                url_base(u).to_string()
            };
            let mut it = Item {
                name,
                url: u.clone(),
                version: "static".into(),
                ..Item::default()
            };
            self.check_url(u)?;
            if !s.stored.is_empty() {
                // A key file's version is its content, so a changed key makes a new set version.
                let sum = Sha256::digest(self.get(u, 8 << 20)?);
                it.version = hex(&sum[..8]);
            } else if let Ok(h) = self.dl.head(u) {
                let get = |k: &str| h.get(k).and_then(|v| v.to_str().ok()).unwrap_or_default();
                it.size = get("content-length").parse().ok().and_then(size);
                let etag = get("etag");
                let etag = etag.strip_prefix("W/").unwrap_or(etag).trim_matches('"');
                if !etag.is_empty() {
                    it.version = etag.to_string();
                } else if !get("last-modified").is_empty() {
                    it.version = get("last-modified").to_string();
                }
            }
            items.push(it);
        }
        Ok(items)
    }

    /// The latest release, or with `tags` the newest release whose tag matches the pattern:
    /// `/releases/latest` is a trap for repos whose latest points at a non-build tag.
    fn github(&self, s: &Source, tags: bool) -> Result<Vec<Item>> {
        let rel: GhRelease = if tags {
            let url = format!("{}{}/releases?per_page=30", self.gh_api, s.repo);
            let all: Vec<GhRelease> = serde_json::from_slice(&self.get(&url, DOC_LIMIT)?)?;
            let re = regex::Regex::new(&s.pattern)?;
            all.into_iter()
                .filter(|c| !c.draft && re.is_match(&c.tag_name))
                .reduce(|best, c| {
                    if listing::ver_less(&best.tag_name, &c.tag_name) {
                        c
                    } else {
                        best
                    }
                })
                .with_context(|| format!("{}: no release tag matches {}", s.repo, s.pattern))?
        } else {
            let url = format!("{}{}/releases/latest", self.gh_api, s.repo);
            serde_json::from_slice(&self.get(&url, DOC_LIMIT)?)?
        };
        let mut items: Vec<Item> = Vec::new();
        for g in &s.assets {
            let mut hit = false;
            for a in &rel.assets {
                if !glob(g, &a.name) || items.iter().any(|i| i.name == a.name) {
                    continue;
                }
                hit = true;
                items.push(Item {
                    name: a.name.clone(),
                    url: a.browser_download_url.clone(),
                    version: rel.tag_name.clone(),
                    sha256: a
                        .digest
                        .as_deref()
                        .and_then(|d| d.strip_prefix("sha256:"))
                        .unwrap_or_default()
                        .to_string(),
                    size: size(a.size),
                    ..Item::default()
                });
            }
            if !hit {
                bail!("{} {}: no asset matches {g}", s.repo, rel.tag_name);
            }
        }
        if !s.sums.is_empty() {
            let sums = rel
                .assets
                .iter()
                .find(|a| glob(&s.sums, &a.name))
                .with_context(|| {
                    format!("{} {}: no asset matches {}", s.repo, rel.tag_name, s.sums)
                })?;
            for it in &mut items {
                it.sums_url = Some(sums.browser_download_url.clone());
            }
        }
        Ok(items)
    }

    fn hf_tree(&self, s: &Source) -> Result<Vec<Item>> {
        let url = format!(
            "{}api/models/{}/tree/main?recursive=true",
            self.hf_base, s.repo
        );
        let tree: Vec<HfEntry> = serde_json::from_slice(&self.get(&url, DOC_LIMIT)?)?;
        let mut items: Vec<Item> = Vec::new();
        for g in &s.assets {
            let mut hit = false;
            for f in &tree {
                let base = url_base(&f.path);
                if f.kind != "file"
                    || !(glob(g, &f.path) || glob(g, base))
                    || items.iter().any(|i| i.name == base)
                {
                    continue;
                }
                hit = true;
                let mut it = Item {
                    name: base.to_string(),
                    url: format!("{}{}/resolve/main/{}", self.hf_base, s.repo, f.path),
                    version: "main".into(),
                    size: size(f.size),
                    ..Item::default()
                };
                // An LFS object id is the file's sha256.
                if let Some(lfs) = &f.lfs {
                    it.sha256.clone_from(&lfs.oid);
                    it.size = size(lfs.size);
                    it.version = lfs.oid.chars().take(12).collect();
                }
                items.push(it);
            }
            if !hit {
                bail!("{}: no file matches {g}", s.repo);
            }
        }
        Ok(items)
    }

    /// Alpine's latest-releases.yaml: a list of flat `key: value` entries, no nesting.
    fn yaml_lite(&self, s: &Source) -> Result<Vec<Item>> {
        let body = self.get(&s.url, DOC_LIMIT)?;
        let text = String::from_utf8_lossy(&body);
        let mut entries: Vec<Vec<(&str, &str)>> = Vec::new();
        for line in text.lines().map(str::trim) {
            if line == "-" {
                entries.push(Vec::new());
            } else if let (Some(e), Some((k, v))) = (entries.last_mut(), line.split_once(':'))
                && !line.starts_with('#')
            {
                e.push((k.trim(), v.trim()));
            }
        }
        let mut items = Vec::new();
        for e in &entries {
            let get = |k: &str| {
                e.iter()
                    .rev()
                    .find(|(n, _)| *n == k)
                    .map_or("", |(_, v)| *v)
            };
            if !s.assets.iter().any(|a| a == get("flavor")) || get("iso").is_empty() {
                continue;
            }
            items.push(Item {
                name: get("iso").to_string(),
                url: format!("{}{}", dir_url(&s.url), get("iso")),
                version: get("version").to_string(),
                sha256: get("sha256").to_string(),
                sha512: get("sha512").to_string(),
                size: get("size").parse().ok().and_then(size),
                ..Item::default()
            });
        }
        Ok(items)
    }
}

pub(crate) fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::net::client::loopback_agent;
    use crate::net::testserver::{Behaviour, Server};
    use crate::net::throttle::Throttle;
    use std::sync::Arc;
    use ureq::tls::RootCerts;

    pub(crate) fn downloader() -> Downloader {
        Downloader::new(
            loopback_agent(RootCerts::new_with_certs(&[])),
            Arc::new(Throttle::new(0)),
            1 << 20,
        )
    }

    pub(crate) fn serve(routes: &[(&str, &[u8])]) -> Server {
        let mut b = Behaviour::new(Vec::new());
        b.routes = Some(
            routes
                .iter()
                .map(|(p, d)| ((*p).to_string(), d.to_vec()))
                .collect(),
        );
        Server::start("127.0.0.1", b)
    }

    pub(crate) fn resolver<'a>(dl: &'a Downloader, base: &'a str) -> Resolver<'a> {
        Resolver {
            dl,
            gh_api: base,
            hf_base: base,
            plain_http: true,
        }
    }

    fn http(resolve: Resolve) -> Source {
        Source {
            name: "s".into(),
            kind: Some(Kind::Http),
            resolve: Some(resolve),
            ..Source::default()
        }
    }

    #[test]
    fn globs() {
        let cases = [
            ("*.tar.xz", "a.tar.xz", true),
            ("*.tar.xz", "a.tar.gz", false),
            (
                "llama-*-bin-ubuntu-x64.zip",
                "llama-b1-bin-ubuntu-x64.zip",
                true,
            ),
            (
                "go-pmtiles_*_Linux_x86_64.tar.gz",
                "go-pmtiles_1.2_Linux_arm64.tar.gz",
                false,
            ),
            ("*", "dir/file", false),
            ("dir/*", "dir/file", true),
            ("a?c", "abc", true),
            ("a?c", "ac", false),
            ("*-CHECKSUM", "Fedora-45-CHECKSUM", true),
            ("exact", "exact", true),
            ("exact", "exact1", false),
            ("*a*b", "xxaxxb", true),
        ];
        for (pat, name, want) in cases {
            assert_eq!(glob(pat, name), want, "{pat} on {name}");
        }
    }

    #[test]
    fn url_checks() {
        let dl = downloader();
        let mut r = resolver(&dl, "");
        r.plain_http = false;
        for bad in [
            "http://example.org/x",
            "ftp://example.org/x",
            "https:///x",
            "https://exa mple.org/x",
            "example.org/x",
            "",
        ] {
            assert!(r.check_url(bad).is_err(), "{bad}");
        }
        r.check_url("https://example.org/x?y=1").unwrap();
        assert_eq!(url_base("https://h/a/b.txt?x=1"), "b.txt");
        assert_eq!(url_base("https://h/a/dir/"), "dir");
        assert_eq!(dir_url("https://h/a/b.txt"), "https://h/a/");
    }

    #[test]
    fn github_tags_skip_non_build_releases() {
        let api = br#"[
            {"tag_name":"gguf-v0.9","draft":false,"assets":[]},
            {"tag_name":"b4100","draft":false,"assets":[
                {"name":"llama-b4100-bin-ubuntu-x64.zip","browser_download_url":"https://github.com/o/r/releases/download/b4100/llama-b4100-bin-ubuntu-x64.zip","digest":"sha256:ab","size":7},
                {"name":"sums.txt","browser_download_url":"https://github.com/o/r/releases/download/b4100/sums.txt","digest":null,"size":1}]},
            {"tag_name":"b4200","draft":true,"assets":[]},
            {"tag_name":"b999","draft":false,"assets":[]}
        ]"#;
        let srv = serve(&[("o/r/releases?per_page=30", api)]);
        let dl = downloader();
        let base = srv.url("");
        let r = resolver(&dl, &base);
        let mut s = http(Resolve::GhTags);
        s.repo = "o/r".into();
        s.pattern = r"^b\d+$".into();
        s.assets = vec!["llama-*-bin-ubuntu-x64.zip".into()];
        s.sums = "sums.txt".into();
        let items = r.resolve(&s).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].version, "b4100");
        assert_eq!(items[0].sha256, "ab");
        assert_eq!(items[0].size, Some(7));
        assert!(items[0].sums_url.as_deref().unwrap().ends_with("/sums.txt"));

        s.assets = vec!["nothing-*".into()];
        assert!(r.resolve(&s).is_err());
    }

    #[test]
    fn hf_tree_uses_the_lfs_oid() {
        let oid = "aa".repeat(32);
        let tree = format!(
            r#"[{{"type":"directory","path":"sub","size":0}},
                {{"type":"file","path":"sub/model.gguf","size":134,"lfs":{{"oid":"{oid}","size":5000}}}},
                {{"type":"file","path":"README.md","size":10}}]"#
        );
        let srv = serve(&[("api/models/o/m/tree/main?recursive=true", tree.as_bytes())]);
        let dl = downloader();
        let base = srv.url("");
        let r = resolver(&dl, &base);
        let s = Source {
            name: "m".into(),
            kind: Some(Kind::Hf),
            repo: "o/m".into(),
            assets: vec!["*.gguf".into(), "README.md".into()],
            ..Source::default()
        };
        let items = r.resolve(&s).unwrap();
        assert_eq!(items[0].name, "model.gguf");
        assert_eq!(items[0].sha256, oid);
        assert_eq!(items[0].size, Some(5000));
        assert_eq!(items[0].version, &oid[..12]);
        assert!(items[0].url.ends_with("o/m/resolve/main/sub/model.gguf"));
        assert_eq!(items[1].version, "main");
        assert_eq!(items[1].sha256, "");
    }

    #[test]
    fn yaml_lite_reads_flat_entries() {
        let yaml = b"---\n-\n  flavor: alpine-standard\n  iso: alpine-standard-3.24.0-x86_64.iso\n  version: 3.24.0\n  sha256: abc\n  sha512: def\n  size: 12345\n-\n  flavor: alpine-virt\n  iso: alpine-virt-3.24.0-x86_64.iso\n  version: 3.24.0\n";
        let srv = serve(&[("rel/latest-releases.yaml", yaml)]);
        let dl = downloader();
        let r = resolver(&dl, "");
        let mut s = http(Resolve::YamlLite);
        s.url = srv.url("rel/latest-releases.yaml");
        s.assets = vec!["alpine-standard".into()];
        s.sig = ".asc".into();
        let items = r.resolve(&s).unwrap();
        assert_eq!(items.len(), 1);
        let it = &items[0];
        assert_eq!(it.url, srv.url("rel/alpine-standard-3.24.0-x86_64.iso"));
        assert_eq!((it.sha256.as_str(), it.sha512.as_str()), ("abc", "def"));
        assert_eq!(it.size, Some(12345));
        assert_eq!(
            it.sig_url.as_deref(),
            Some(
                srv.url("rel/alpine-standard-3.24.0-x86_64.iso.asc")
                    .as_str()
            )
        );
    }

    #[test]
    fn a_signature_over_the_tar_drops_the_compression_suffix() {
        let srv = serve(&[("fw/linux-firmware-20261019.tar.xz", b"x")]);
        let dl = downloader();
        let r = resolver(&dl, "");
        let mut s = http(Resolve::Static);
        s.urls = vec![srv.url("fw/linux-firmware-20261019.tar.xz")];
        s.sig = ".sign".into();
        s.sig_over = Some(SigOver::Xz);
        let it = r.resolve(&s).unwrap().remove(0);
        assert_eq!(
            it.sig_url.as_deref(),
            Some(srv.url("fw/linux-firmware-20261019.tar.sign").as_str())
        );
    }

    #[test]
    fn static_names_versions_and_side_files() {
        let srv = serve(&[("a/file.bin", b"x"), ("pks/lookup?op=get", b"key")]);
        let dl = downloader();
        let r = resolver(&dl, "");
        let mut s = http(Resolve::Static);
        s.urls = vec![srv.url("a/file.bin")];
        s.sums = "{file}.sha256".into();
        s.sums_sig = ".sig".into();
        let it = r.resolve(&s).unwrap().remove(0);
        assert_eq!(it.name, "file.bin");
        assert!(
            it.version.len() == 16 && it.version.bytes().all(|b| b.is_ascii_hexdigit()),
            "the ETag without its quotes: {}",
            it.version
        );
        assert_eq!(it.size, Some(1));
        assert_eq!(
            it.sums_url.as_deref(),
            Some(srv.url("a/file.bin.sha256").as_str())
        );
        assert_eq!(
            it.sums_sig_url.as_deref(),
            Some(srv.url("a/file.bin.sha256.sig").as_str())
        );

        // A key file is named by `assets` and versioned by its content.
        let mut keyfile = http(Resolve::Static);
        keyfile.urls = vec![srv.url("pks/lookup?op=get")];
        keyfile.assets = vec!["key.asc".into()];
        keyfile.stored = "musl".into();
        let it = r.resolve(&keyfile).unwrap().remove(0);
        assert_eq!(it.name, "key.asc");
        assert_eq!(it.version, hex(&Sha256::digest(b"key")[..8]));

        // A sums file may not take the name of a download.
        let mut clash = http(Resolve::Static);
        clash.urls = vec![srv.url("a/file.bin"), srv.url("a/SUMS")];
        clash.sums = "SUMS".into();
        let err = r.resolve(&clash).unwrap_err();
        assert!(format!("{err:#}").contains("collides"), "{err:#}");

        // Names that would leave the staging directory are refused.
        let mut t = http(Resolve::Static);
        t.urls = vec![srv.url("a/file.bin")];
        t.assets = vec!["../evil".into()];
        assert!(r.resolve(&t).is_err());
    }
}
