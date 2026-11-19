use super::gb;
use super::versioned::{plain_dirs, read_meta, read_set_file, version_dirs};
use crate::catalog::Catalog;
use crate::platform;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::Path;

const HEAD: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Code archive</title>
<style>
:root{color-scheme:light dark;--bg:#fbfaf7;--fg:#1d1b22;--dim:#6b6676;--line:#d9d5df;--acc:#6a3fd0}
@media(prefers-color-scheme:dark){:root{--bg:#0e0d12;--fg:#e6e3ee;--dim:#928da0;--line:#2a2733;--acc:#b48cff}}
body{margin:0 auto;max-width:60rem;padding:1.5rem 1rem;background:var(--bg);color:var(--fg);font:16px/1.5 ui-monospace,monospace}
h1,h2{font-weight:600}h2{margin-top:2rem;border-bottom:1px solid var(--line)}
code{color:var(--acc)}table{border-collapse:collapse;width:100%}
td,th{text-align:left;padding:.2rem .6rem .2rem 0;border-bottom:1px solid var(--line)}
.dim{color:var(--dim)}
</style>
</head>
<body>
<h1>Code archive</h1>
<p class="dim">Everything under <code>public/</code> is plaintext. Each version directory holds <code>SET.toml</code> (sources, versions, signer, license) and <code>SHA256SUMS</code>. Check a copy with <code>cd public/SET/VERSION &amp;&amp; sha256sum -c SHA256SUMS</code>. Upstream signatures sit next to their files.</p>
"#;

/// One row of `MIRRORS.toml`, which git and repo mirrors keep next to their set.
#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct Mirror {
    pub name: String,
    pub kind: String,
    pub url: String,
    pub updated: String,
    pub bytes: u64,
    pub files: Option<u64>,
    #[serde(rename = "gen")]
    pub generation: Option<String>,
    pub license: String,
}

#[derive(Default, Deserialize, Serialize)]
#[serde(default)]
pub(crate) struct Mirrors {
    pub mirror: Vec<Mirror>,
}

pub(super) fn read_mirrors(dir: &Path) -> Mirrors {
    read_meta(&dir.join("MIRRORS.toml"))
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|t| toml::from_str(&t).ok())
        .unwrap_or_default()
}

/// Replaces (or adds) the row of `m.name` in `<set_dir>/MIRRORS.toml` and drops the rows of
/// sources that are not in `sources`. The only writer of the file.
pub(crate) fn record_mirror(set_dir: &Path, sources: &[&str], m: Mirror) -> Result<()> {
    let path = set_dir.join("MIRRORS.toml");
    let mut all: Mirrors = match read_meta(&path) {
        Ok(b) => toml::from_str(&String::from_utf8(b)?)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Mirrors::default(),
        Err(e) => return Err(e).with_context(|| path.display().to_string()),
    };
    all.mirror
        .retain(|x| x.name != m.name && sources.contains(&x.name.as_str()));
    all.mirror.push(m);
    let tmp = set_dir.join(".MIRRORS.toml.tmp");
    let mut f = std::fs::File::create(&tmp).with_context(|| tmp.display().to_string())?;
    f.write_all(toml::to_string(&all)?.as_bytes())?;
    f.sync_all()?;
    let dest = set_dir.join("MIRRORS.toml");
    std::fs::rename(&tmp, &dest).with_context(|| dest.display().to_string())?;
    platform::sync_dir(set_dir).with_context(|| set_dir.display().to_string())
}

/// Text from the drive and the catalog, made safe for element content and attribute values.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn render(cat: &Catalog, public: &Path) -> String {
    let mut out = HEAD.to_string();
    for set in &cat.sets {
        let dir = public.join(&set.name);
        if plain_dirs(&[&dir]).is_err() {
            continue;
        }
        let mut licenses: Vec<String> = Vec::new();
        let mut license = |l: &str| {
            if !l.is_empty() && !licenses.iter().any(|x| x == l) {
                licenses.push(l.to_string());
            }
        };
        let mut versions = String::new();
        for v in version_dirs(&dir) {
            let sf = read_set_file(&dir.join(&v).join("SET.toml"));
            let mut how = BTreeSet::new();
            for src in &sf.sources {
                license(&src.license);
                how.insert(src.verify.clone());
            }
            let how: Vec<String> = how.into_iter().collect();
            let _ = writeln!(
                versions,
                "<tr><td><a href=\"public/{n}/{v}/\">{v}</a></td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&sf.fetched),
                gb(sf.bytes),
                esc(&how.join(", ")),
                n = esc(&set.name),
                v = esc(&v),
            );
        }
        let mut rows = String::new();
        for m in &read_mirrors(&dir).mirror {
            // Rows of sources that left the catalog are dropped, and only a current source
            // name becomes a link; the url is text, never a link.
            if !set.sources.iter().any(|s| s.name == m.name) {
                continue;
            }
            license(&m.license);
            let name = esc(&m.name);
            let shown = if m.kind == "git" {
                format!("public/{}/git/{name}.git/", esc(&set.name))
            } else {
                format!("public/{}/{name}/", esc(&set.name))
            };
            let _ = writeln!(
                rows,
                "<tr><td><a href=\"{shown}\">{name}</a></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&m.kind),
                esc(&m.url),
                gb(m.bytes),
                esc(&m.updated)
            );
        }
        if versions.is_empty() && rows.is_empty() {
            continue;
        }
        let name = esc(&set.name);
        let _ = writeln!(out, "<h2 id=\"{name}\">{name}</h2>");
        let _ = write!(out, "<p>{}", esc(&set.title));
        if !licenses.is_empty() {
            let _ = write!(
                out,
                " <span class=\"dim\">({})</span>",
                esc(&licenses.join(" · "))
            );
        }
        out.push_str("</p>\n");
        if !set.usage.is_empty() {
            let _ = writeln!(out, "<p>{}</p>", esc(&set.usage));
        }
        if !versions.is_empty() {
            out.push_str("<table>\n<tr><th>Version</th><th>Fetched</th><th>Size</th><th>Checked by</th></tr>\n");
            out.push_str(&versions);
            out.push_str("</table>\n");
        }
        if !rows.is_empty() {
            out.push_str(
                "<table>\n<tr><th>Mirror</th><th>Kind</th><th>Source</th><th>Size</th><th>Updated</th></tr>\n",
            );
            out.push_str(&rows);
            out.push_str("</table>\n");
        }
    }
    out.push_str("</body>\n</html>\n");
    out
}

/// Rewrites `INDEX.html` at the top of the archive from what is on the drive.
pub(crate) fn write(cat: &Catalog, archive: &Path) -> Result<()> {
    let html = render(cat, &archive.join("public"));
    std::fs::create_dir_all(archive)?;
    let tmp = archive.join(".INDEX.html.tmp");
    std::fs::write(&tmp, html).with_context(|| tmp.display().to_string())?;
    let dest = archive.join("INDEX.html");
    std::fs::rename(&tmp, &dest).with_context(|| dest.display().to_string())
}
