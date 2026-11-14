//! Extractors for the release indexes that are JSON (or, for Rust, TOML) documents.

use super::listing::ver_less;
use super::{DOC_LIMIT, Item, Resolver, dir_url, size, url_base};
use crate::catalog::{Extract, Source};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Deserialize)]
struct KernelIndex {
    releases: Vec<KernelRelease>,
}

#[derive(Deserialize)]
struct KernelRelease {
    #[serde(default)]
    moniker: String,
    #[serde(default)]
    version: String,
    source: Option<String>,
    pgp: Option<String>,
}

fn kernel(body: &[u8], s: &Source) -> Result<Vec<Item>> {
    let d: KernelIndex = serde_json::from_slice(body)?;
    Ok(d.releases
        .into_iter()
        .filter(|r| r.moniker == s.filter)
        .filter_map(|r| {
            let source = r.source.filter(|x| !x.is_empty())?;
            // The signature covers the uncompressed tar.
            let sig = r.pgp.filter(|p| !p.is_empty()).unwrap_or_else(|| {
                format!("{}.sign", source.strip_suffix(".xz").unwrap_or(&source))
            });
            Some(Item {
                name: url_base(&source).to_string(),
                url: source,
                version: r.version,
                sig_url: Some(sig),
                ..Item::default()
            })
        })
        .take(s.top.max(1))
        .collect())
}

#[derive(Deserialize)]
struct GoRelease {
    version: String,
    #[serde(default)]
    stable: bool,
    #[serde(default)]
    files: Vec<GoFile>,
}

#[derive(Deserialize)]
struct GoFile {
    filename: String,
    #[serde(default)]
    os: String,
    #[serde(default)]
    arch: String,
    #[serde(default)]
    sha256: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    size: u64,
}

fn golang(body: &[u8], s: &Source) -> Result<Vec<Item>> {
    let d: Vec<GoRelease> = serde_json::from_slice(body)?;
    let rel = d
        .into_iter()
        .find(|r| r.stable)
        .context("no stable go release")?;
    Ok(rel
        .files
        .into_iter()
        .filter(|f| {
            f.kind == "source"
                || f.kind == "archive" && f.os == "linux" && s.assets.contains(&f.arch)
        })
        .map(|f| Item {
            url: format!("https://go.dev/dl/{}", f.filename),
            name: f.filename,
            version: rel.version.clone(),
            sha256: f.sha256,
            size: size(f.size),
            ..Item::default()
        })
        .collect())
}

/// The stable channel manifest. Assets are target triples, plus `src` for the rustc source.
fn rust(body: &[u8], s: &Source) -> Result<Vec<Item>> {
    let m: toml::Table = toml::from_str(std::str::from_utf8(body)?)?;
    let pkg = m.get("pkg").and_then(|p| p.get("rust"));
    let full = pkg
        .and_then(|p| p.get("version"))
        .and_then(toml::Value::as_str)
        .unwrap_or_default();
    let v = full.split(' ').next().unwrap_or_default();
    if v.is_empty() {
        bail!("rust manifest has no version");
    }
    let mut items = Vec::new();
    for t in &s.assets {
        if t == "src" {
            let name = format!("rustc-{v}-src.tar.xz");
            items.push(Item {
                url: format!("https://static.rust-lang.org/dist/{name}"),
                name,
                version: v.to_string(),
                ..Item::default()
            });
            continue;
        }
        let target = pkg.and_then(|p| p.get("target")).and_then(|x| x.get(t));
        let field = |k: &str| {
            target
                .and_then(|x| x.get(k))
                .and_then(toml::Value::as_str)
                .filter(|x| !x.is_empty())
        };
        let (Some(url), Some(hash)) = (field("xz_url"), field("xz_hash")) else {
            bail!("rust manifest has no xz tarball for {t}");
        };
        items.push(Item {
            name: url_base(url).to_string(),
            url: url.to_string(),
            version: v.to_string(),
            sha256: hash.to_string(),
            ..Item::default()
        });
    }
    Ok(items)
}

#[derive(Deserialize)]
struct NodeRelease {
    version: String,
    #[serde(default)]
    lts: Value,
}

/// The newest LTS; `{v}` in an asset is the version with its leading v.
fn node(body: &[u8], s: &Source) -> Result<Vec<Item>> {
    let d: Vec<NodeRelease> = serde_json::from_slice(body)?;
    let rel = d
        .into_iter()
        .find(|r| !matches!(r.lts, Value::Null | Value::Bool(false)))
        .context("no LTS node release")?;
    Ok(s.assets
        .iter()
        .map(|a| {
            let name = a.replace("{v}", &rel.version);
            Item {
                url: format!("{}{}/{name}", dir_url(&s.url), rel.version),
                name,
                version: rel.version.clone(),
                ..Item::default()
            }
        })
        .collect())
}

fn zig(body: &[u8], s: &Source) -> Result<Vec<Item>> {
    let d: HashMap<String, HashMap<String, Value>> = serde_json::from_slice(body)?;
    let best = d
        .keys()
        .filter(|v| *v != "master")
        .reduce(|best, v| if ver_less(best, v) { v } else { best })
        .context("no zig release")?;
    let mut items = Vec::new();
    for a in &s.assets {
        let field = |k: &str| {
            d[best]
                .get(a)
                .and_then(|t| t.get(k))
                .and_then(Value::as_str)
                .unwrap_or_default()
        };
        let url = field("tarball");
        if url.is_empty() {
            bail!("zig {best} has no {a}");
        }
        items.push(Item {
            name: url_base(url).to_string(),
            url: url.to_string(),
            version: best.clone(),
            sha256: field("shasum").to_string(),
            ..Item::default()
        });
    }
    Ok(items)
}

impl Resolver<'_> {
    pub(super) fn json_index(&self, s: &Source) -> Result<Vec<Item>> {
        let body = self.get(&s.url, DOC_LIMIT)?;
        match s.extract {
            Some(Extract::Kernel) => kernel(&body, s),
            Some(Extract::Go) => golang(&body, s),
            Some(Extract::Rust) => rust(&body, s),
            Some(Extract::Node) => node(&body, s),
            Some(Extract::Zig) => zig(&body, s),
            None => bail!("no extractor"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(assets: &[&str]) -> Source {
        Source {
            assets: assets.iter().map(ToString::to_string).collect(),
            ..Source::default()
        }
    }

    #[test]
    fn kernel_releases() {
        let body = br#"{"releases":[
            {"moniker":"mainline","version":"6.13-rc1","source":"https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.13-rc1.tar.gz","pgp":null},
            {"moniker":"stable","version":"6.12.4","source":"https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.4.tar.xz","pgp":"https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.4.tar.sign"},
            {"moniker":"longterm","version":"6.6.64","source":"https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.64.tar.xz","pgp":null},
            {"moniker":"longterm","version":"6.1.119","source":"https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.1.119.tar.xz","pgp":""},
            {"moniker":"longterm","version":"5.15.173","source":"https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.15.173.tar.xz"},
            {"moniker":"linux-next","version":"next-20241206","source":null,"pgp":null}]}"#;
        let mut s = src(&[]);
        s.filter = "longterm".into();
        s.top = 2;
        let items = kernel(body, &s).unwrap();
        let v: Vec<_> = items.iter().map(|i| i.version.as_str()).collect();
        assert_eq!(v, ["6.6.64", "6.1.119"]);
        assert_eq!(items[0].name, "linux-6.6.64.tar.xz");
        assert_eq!(
            items[0].sig_url.as_deref(),
            Some("https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.64.tar.sign")
        );
        s.filter = "stable".into();
        s.top = 0;
        let items = kernel(body, &s).unwrap();
        assert_eq!(items.len(), 1);
        assert!(
            items[0]
                .sig_url
                .as_deref()
                .unwrap()
                .ends_with("6.12.4.tar.sign")
        );
    }

    #[test]
    fn go_releases() {
        let body = br#"[
            {"version":"go1.24rc1","stable":false,"files":[]},
            {"version":"go1.23.4","stable":true,"files":[
              {"filename":"go1.23.4.src.tar.gz","os":"","arch":"","sha256":"aa","size":10,"kind":"source"},
              {"filename":"go1.23.4.linux-amd64.tar.gz","os":"linux","arch":"amd64","sha256":"bb","size":20,"kind":"archive"},
              {"filename":"go1.23.4.linux-386.tar.gz","os":"linux","arch":"386","sha256":"cc","size":30,"kind":"archive"},
              {"filename":"go1.23.4.windows-amd64.msi","os":"windows","arch":"amd64","sha256":"dd","size":40,"kind":"installer"}]},
            {"version":"go1.22.10","stable":true,"files":[]}]"#;
        let items = golang(body, &src(&["amd64", "arm64"])).unwrap();
        let names: Vec<_> = items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(
            names,
            ["go1.23.4.src.tar.gz", "go1.23.4.linux-amd64.tar.gz"]
        );
        assert_eq!(
            items[1].url,
            "https://go.dev/dl/go1.23.4.linux-amd64.tar.gz"
        );
        assert_eq!((items[1].sha256.as_str(), items[1].size), ("bb", Some(20)));
        assert!(golang(b"[]", &src(&[])).is_err());
    }

    #[test]
    fn rust_manifest() {
        let body = br#"
manifest-version = "2"
[pkg.rust]
version = "1.83.0 (90b35a623 2024-11-26)"
[pkg.rust.target.x86_64-unknown-linux-gnu]
available = true
xz_url = "https://static.rust-lang.org/dist/2024-11-28/rust-1.83.0-x86_64-unknown-linux-gnu.tar.xz"
xz_hash = "ee"
[pkg.rust.target.riscv]
available = false
"#;
        let items = rust(body, &src(&["x86_64-unknown-linux-gnu", "src"])).unwrap();
        assert_eq!(items[0].name, "rust-1.83.0-x86_64-unknown-linux-gnu.tar.xz");
        assert_eq!(items[0].sha256, "ee");
        assert_eq!(items[1].name, "rustc-1.83.0-src.tar.xz");
        assert_eq!(items[1].version, "1.83.0");
        assert!(rust(body, &src(&["riscv"])).is_err());
        assert!(rust(b"x = 1", &src(&["src"])).is_err());
    }

    #[test]
    fn node_lts() {
        let body = br#"[{"version":"v23.3.0","lts":false},{"version":"v22.12.0","lts":"Jod"},{"version":"v20.18.1","lts":"Iron"}]"#;
        let mut s = src(&["node-{v}.tar.xz"]);
        s.url = "https://nodejs.org/dist/index.json".into();
        let items = node(body, &s).unwrap();
        assert_eq!(items[0].name, "node-v22.12.0.tar.xz");
        assert_eq!(
            items[0].url,
            "https://nodejs.org/dist/v22.12.0/node-v22.12.0.tar.xz"
        );
        assert!(node(br#"[{"version":"v1","lts":false}]"#, &s).is_err());
    }

    #[test]
    fn zig_newest() {
        let body = br#"{"master":{"version":"0.14.0-dev","src":{"tarball":"https://ziglang.org/builds/zig-dev.tar.xz","shasum":"00"}},
            "0.9.1":{"date":"2022-02-14","src":{"tarball":"https://ziglang.org/download/0.9.1/zig-0.9.1.tar.xz","shasum":"11"}},
            "0.13.0":{"date":"2024-06-07","src":{"tarball":"https://ziglang.org/download/0.13.0/zig-0.13.0.tar.xz","shasum":"22","size":"1"},
                      "x86_64-linux":{"tarball":"https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz","shasum":"33"}}}"#;
        let items = zig(body, &src(&["src", "x86_64-linux"])).unwrap();
        assert_eq!(items[0].name, "zig-0.13.0.tar.xz");
        assert_eq!(items[0].version, "0.13.0");
        assert_eq!(items[1].sha256, "33");
        assert!(zig(body, &src(&["aarch64-linux"])).is_err());
    }
}
