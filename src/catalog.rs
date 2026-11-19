use crate::keys;
use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashSet;

const EMBEDDED: &str = include_str!("../catalog.toml");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Catalog {
    #[serde(rename = "set")]
    pub sets: Vec<Set>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Set {
    pub name: String,
    pub title: String,
    #[serde(default, rename = "use")]
    pub usage: String,
    pub priority: u32,
    /// GB, checked against the drive's free space before the set runs.
    pub estimate: f64,
    /// Visible versions; absent means 2.
    #[serde(default)]
    pub keep: usize,
    #[serde(default, rename = "source")]
    pub sources: Vec<Source>,
    /// Subsets `preserver copy` falls back to on a small target; see `Set::variants`.
    #[serde(default, rename = "variant")]
    pub variants: Vec<Variant>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Variant {
    pub name: String,
    pub sources: Vec<String>,
}

/// `preserver copy --sets` takes these besides the catalog sets.
pub(crate) const RESERVED: [&str; 2] = ["personal", "kit"];

impl Set {
    /// The listed variants plus an implicit "full" with every source, unless one is named so.
    pub(crate) fn variants(&self) -> Vec<Variant> {
        let mut v = self.variants.clone();
        if !v.iter().any(|x| x.name == "full") {
            v.push(Variant {
                name: "full".into(),
                sources: self.sources.iter().map(|s| s.name.clone()).collect(),
            });
        }
        v
    }

    /// GB: the sources' estimates, or the set's own for a variant with every source.
    pub(crate) fn estimate_of(&self, v: &Variant) -> f64 {
        if v.sources.len() == self.sources.len() {
            return self.estimate;
        }
        self.sources
            .iter()
            .filter(|s| v.sources.contains(&s.name))
            .map(|s| s.est)
            .sum()
    }

    fn validate_variants(&self) -> Result<()> {
        let mut names = HashSet::new();
        for v in &self.variants {
            if !valid_name(&v.name) || !names.insert(&v.name) {
                bail!("bad or duplicate variant {:?}", v.name);
            }
            if v.sources.is_empty() {
                bail!("variant {} names no sources", v.name);
            }
            if let Some(s) = v
                .sources
                .iter()
                .find(|s| !self.sources.iter().any(|x| x.name == **s))
            {
                bail!(
                    "variant {} names {s:?}, which is no source of the set",
                    v.name
                );
            }
        }
        Ok(())
    }
}

/// `Http` and `Hf` produce versioned files. `Git` and `Repo` update a mirror in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Kind {
    Http,
    Hf,
    Git,
    Repo,
}

impl Kind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Hf => "hf",
            Self::Git => "git",
            Self::Repo => "repo",
        }
    }

    pub(crate) fn in_place(self) -> bool {
        matches!(self, Self::Git | Self::Repo)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Resolve {
    Static,
    Listing,
    GhLatest,
    GhTags,
    Json,
    YamlLite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Extract {
    Kernel,
    Go,
    Rust,
    Node,
    Zig,
}

/// The layout of a `repo` source, which picks its walker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RepoFormat {
    Fedora,
    Debian,
    Alpine,
}

/// One tree of a Fedora source: its path under the mirror and the metalink that names it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Tree {
    pub path: String,
    pub metalink: String,
}

/// What a detached signature covers when it isn't the file as downloaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SigOver {
    Xz,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Source {
    pub name: String,
    pub kind: Option<Kind>,
    pub url: String,
    pub enabled: Option<bool>,
    pub todo: String,
    pub license: String,
    pub est: f64,

    pub resolve: Option<Resolve>,
    pub urls: Vec<String>,
    pub repo: String,
    pub pattern: String,
    pub assets: Vec<String>,
    pub extract: Option<Extract>,
    pub filter: String,
    pub top: usize,

    /// Suffix of the detached signature next to each file.
    pub sig: String,
    pub sig_over: Option<SigOver>,
    /// The sums file: a name with `{file}`, a glob for listings and releases, or a plain name.
    pub sums: String,
    /// `clear` for a clearsigned sums file, else the suffix of its detached signature.
    pub sums_sig: String,
    pub keyring: String,
    pub signers: Vec<String>,
    pub minisign: String,
    /// The embedded keyring a downloaded key file must still match.
    pub stored: String,

    /// Repo sources only.
    pub format: Option<RepoFormat>,
    pub suites: Vec<String>,
    pub components: Vec<String>,
    pub arches: Vec<String>,
    pub trees: Vec<Tree>,
    /// Listing sources: a regex (`^…/$`) over the directories to descend into, how many of
    /// the newest to take, and a regex for the ones to leave out.
    pub dirs: String,
    pub dir_top: usize,
    pub exclude: String,
}

impl Source {
    pub(crate) fn on(&self) -> bool {
        self.enabled != Some(false)
    }

    /// Set for every source: `validate` refuses a catalog without it.
    pub(crate) fn kind(&self) -> Kind {
        self.kind.unwrap_or(Kind::Http)
    }

    fn validate(&self) -> Result<()> {
        if !valid_name(&self.name) {
            bail!("bad name");
        }
        let Some(kind) = self.kind else {
            bail!("no kind");
        };
        if !self.on() {
            if self.todo.is_empty() {
                bail!("disabled without a todo");
            }
            return Ok(());
        }
        if !self.todo.is_empty() {
            bail!("enabled with a todo: disable it or finish it");
        }
        if let Some(u) = std::iter::once(&self.url)
            .chain(&self.urls)
            .find(|u| !u.is_empty() && !u.starts_with("https://"))
        {
            bail!("{u:?} is not an https url");
        }
        match kind {
            Kind::Git | Kind::Repo if self.url.is_empty() => bail!("needs url"),
            Kind::Hf if self.repo.is_empty() || self.assets.is_empty() => {
                bail!("hf needs repo and assets")
            }
            Kind::Http => match self.resolve {
                None => bail!("needs resolve"),
                Some(Resolve::Json) if self.extract.is_none() => bail!("json needs extract"),
                Some(_) => {}
            },
            _ => {}
        }
        if kind.in_place() {
            let version_dir = Regex::new(r"^\d{4}-\d{2}-\d{2}(-\d+)?$")?;
            if self.name == "git" || version_dir.is_match(&self.name) {
                bail!("reserved name for an in-place source");
            }
        }
        self.validate_format(kind)?;
        self.validate_listing()?;
        if !self.pattern.is_empty() {
            Regex::new(&self.pattern.replace("{dir}", "x"))?;
        }
        if self.pattern.contains("{dir}") && self.dirs.is_empty() {
            bail!("{{dir}} in pattern needs dirs");
        }
        if let Some(f) = self.signers.iter().find(|f| !valid_fingerprint(f)) {
            bail!("bad signer fingerprint {f:?}");
        }
        if !self.minisign.is_empty() && !valid_minisign_key(&self.minisign) {
            bail!("bad minisign key");
        }
        // Fail closed here as well as at verification: a signature nothing can check is a bug.
        let signed = !self.sig.is_empty() || !self.sums_sig.is_empty() || self.sig_over.is_some();
        if signed && self.minisign.is_empty() && self.keyring.is_empty() {
            bail!("has a signature but no keyring");
        }
        for ring in [&self.keyring, &self.stored] {
            if !ring.is_empty() && keys::embedded(ring).is_none() {
                bail!("keyring {ring:?} is not in keys/ (fetch and pin it, see keys/fetch.sh)");
            }
        }
        Ok(())
    }
}

impl Source {
    fn validate_format(&self, kind: Kind) -> Result<()> {
        let Some(format) = self.format else {
            if kind == Kind::Repo {
                bail!("repo needs format");
            }
            if !(self.suites.is_empty()
                && self.components.is_empty()
                && self.arches.is_empty()
                && self.trees.is_empty())
            {
                bail!("suites, components, arches and trees are for repo sources");
            }
            return Ok(());
        };
        if kind != Kind::Repo {
            bail!("format is for repo sources");
        }
        let names = |what: &str, v: &[String]| {
            if v.is_empty() || v.iter().any(|n| !valid_name(n)) {
                bail!("{format:?} needs {what}, each a plain name");
            }
            Ok(())
        };
        match format {
            RepoFormat::Fedora => {
                if !(self.suites.is_empty() && self.components.is_empty() && self.arches.is_empty())
                {
                    bail!("fedora takes trees only");
                }
                if self.trees.is_empty() {
                    bail!("fedora needs trees");
                }
                for t in &self.trees {
                    if t.path.is_empty() || t.path.split('/').any(|seg| !valid_name(seg)) {
                        bail!("bad tree path {:?}", t.path);
                    }
                    if t.metalink.is_empty()
                        || !t
                            .metalink
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"=&_.-".contains(&b))
                    {
                        bail!("bad metalink {:?}", t.metalink);
                    }
                }
            }
            RepoFormat::Debian | RepoFormat::Alpine => {
                if !self.trees.is_empty() {
                    bail!("trees are for fedora");
                }
                names("suites", &self.suites)?;
                names("components", &self.components)?;
                names("arches", &self.arches)?;
                if format == RepoFormat::Debian
                    && (self.keyring.is_empty() || self.signers.is_empty())
                {
                    bail!("debian needs keyring and signers");
                }
            }
        }
        Ok(())
    }

    fn validate_listing(&self) -> Result<()> {
        if self.dirs.is_empty() && self.dir_top == 0 && self.exclude.is_empty() {
            return Ok(());
        }
        if self.resolve != Some(Resolve::Listing) {
            bail!("dirs, dir_top and exclude need resolve = \"listing\"");
        }
        if !self.dirs.is_empty() {
            if !(self.dirs.starts_with('^') && self.dirs.ends_with("/$")) {
                bail!("dirs must look like ^...../$");
            }
            Regex::new(&self.dirs)?;
        }
        if !self.exclude.is_empty() {
            Regex::new(&self.exclude)?;
        }
        Ok(())
    }
}

/// Safe as one path component: and no leading dot.
pub(crate) fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('.')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn valid_fingerprint(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
}

fn valid_minisign_key(s: &str) -> bool {
    let body = s.trim_end_matches('=');
    s.len() - body.len() <= 2
        && (40..=80).contains(&body.len())
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'))
}

impl Catalog {
    pub(crate) fn embedded() -> Result<Self> {
        Self::parse(EMBEDDED)
    }

    pub(crate) fn parse(text: &str) -> Result<Self> {
        let mut c: Self = toml::from_str(text).context("catalog")?;
        let mut seen = HashSet::new();
        for set in &mut c.sets {
            if !valid_name(&set.name)
                || RESERVED.contains(&set.name.as_str())
                || !seen.insert(set.name.clone())
            {
                bail!("catalog: bad, reserved or duplicate set {:?}", set.name);
            }
            if set.keep == 0 {
                set.keep = 2;
            }
            let mut names = HashSet::new();
            for src in &set.sources {
                src.validate()
                    .with_context(|| format!("catalog: {}/{}", set.name, src.name))?;
                if !names.insert(&src.name) {
                    bail!("catalog: duplicate source {}/{}", set.name, src.name);
                }
            }
            set.validate_variants()
                .with_context(|| format!("catalog: {}", set.name))?;
        }
        Ok(c)
    }

    /// The named sets in the order given, or all of them. Catalog order is the first-pass order;
    /// otherwise sets run by priority, catalog order within one.
    pub(crate) fn select(&self, names: &[String], first_pass: bool) -> Result<Vec<&Set>> {
        let mut sets: Vec<&Set> = if names.is_empty() {
            self.sets.iter().collect()
        } else {
            names
                .iter()
                .map(|n| {
                    self.sets
                        .iter()
                        .find(|s| s.name == *n)
                        .with_context(|| format!("no set {n:?} in the catalog"))
                })
                .collect::<Result<_>>()?
        };
        if !first_pass {
            sets.sort_by_key(|s| s.priority);
        }
        Ok(sets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_catalog_loads() {
        let c = Catalog::embedded().unwrap();
        assert!(c.sets.len() > 20, "{} sets", c.sets.len());
        assert_eq!(c.sets[0].name, "keys");
        for set in &c.sets {
            for src in &set.sources {
                assert!(
                    src.kind() != Kind::Repo || !src.on(),
                    "{}/{}: repo mirrors arrive in phase 3",
                    set.name,
                    src.name
                );
            }
        }
        let est = |set: &str, src: &str| {
            let s = c.sets.iter().find(|s| s.name == set).unwrap();
            s.sources.iter().find(|x| x.name == src).unwrap().est
        };
        assert!((est("repo-fedora", "fedora-release") - 259.0).abs() < f64::EPSILON);
        assert!((est("repo-fedora", "fedora-updates") - 52.0).abs() < f64::EPSILON);
        assert!((est("repo-alpine", "alpine") - 133.0).abs() < f64::EPSILON);
    }

    #[test]
    fn fedora_isos_are_pinned_to_the_current_release() {
        let c = Catalog::embedded().unwrap();
        let isos: Vec<&Source> = c
            .sets
            .iter()
            .flat_map(|s| &s.sources)
            .filter(|s| s.keyring == "fedora")
            .collect();
        assert_eq!(isos.len(), 4);
        for src in isos {
            assert_eq!(
                src.signers,
                ["4F50A6114CD5C6976A7F1179655A4B02F577861E"],
                "{}",
                src.name
            );
            let re = Regex::new(&src.pattern).unwrap();
            let base = src.name.strip_prefix("fedora-").unwrap();
            let (kind, tail) = match base {
                "workstation" => ("Workstation-Live", ""),
                "kde" => ("KDE-Desktop-Live", ""),
                "server-dvd" => ("Server-dvd", "x86_64-"),
                _ => ("Everything-netinst", "x86_64-"),
            };
            assert!(re.is_match(&format!("Fedora-{kind}-{tail}45-1.1.iso")));
            assert!(!re.is_match(&format!("Fedora-{kind}-{tail}43-1.6.iso")));
        }
    }

    fn one(source: &str) -> String {
        format!(
            "[[set]]\nname = \"s\"\ntitle = \"t\"\npriority = 0\nestimate = 1\n[[set.source]]\n{source}\n"
        )
    }

    #[test]
    fn validation() {
        let cases = [
            ("no kind", "name = \"a\"", "no kind"),
            ("unknown kind", "name = \"a\"\nkind = \"ftp\"", "catalog"),
            (
                "bad name",
                "name = \"../a\"\nkind = \"git\"\nurl = \"https://x\"",
                "bad name",
            ),
            (
                "hidden name",
                "name = \".a\"\nkind = \"git\"\nurl = \"https://x\"",
                "bad name",
            ),
            (
                "disabled without todo",
                "name = \"a\"\nkind = \"git\"\nenabled = false",
                "disabled without a todo",
            ),
            (
                "git without url",
                "name = \"a\"\nkind = \"git\"",
                "needs url",
            ),
            (
                "hf without assets",
                "name = \"a\"\nkind = \"hf\"\nrepo = \"o/r\"",
                "hf needs",
            ),
            (
                "http without resolve",
                "name = \"a\"\nkind = \"http\"",
                "needs resolve",
            ),
            (
                "unknown resolve",
                "name = \"a\"\nkind = \"http\"\nresolve = \"magic\"",
                "catalog",
            ),
            (
                "bad pattern",
                "name = \"a\"\nkind = \"http\"\nresolve = \"listing\"\npattern = \"(\"",
                "s/a",
            ),
            (
                "lower-case signer",
                "name = \"a\"\nkind = \"http\"\nresolve = \"static\"\nsigners = [\"abaf11c65a2970b130abe3c479be3e4300411886\"]",
                "bad signer",
            ),
            (
                "signature without keyring",
                "name = \"a\"\nkind = \"http\"\nresolve = \"static\"\nsig = \".asc\"",
                "no keyring",
            ),
            (
                "unknown keyring",
                "name = \"a\"\nkind = \"http\"\nresolve = \"static\"\nsig = \".asc\"\nkeyring = \"nope\"",
                "not in keys/",
            ),
            (
                "bad minisign key",
                "name = \"a\"\nkind = \"http\"\nresolve = \"static\"\nsig = \".minisig\"\nminisign = \"short\"",
                "bad minisign key",
            ),
            (
                "unknown field",
                "name = \"a\"\nkind = \"git\"\nurl = \"https://x\"\nurll = \"x\"",
                "catalog",
            ),
        ];
        for (name, source, want) in cases {
            let err = format!("{:#}", Catalog::parse(&one(source)).unwrap_err());
            assert!(err.contains(want), "{name}: {err}");
        }
        let ok = Catalog::parse(&one(
            "name = \"a\"\nkind = \"git\"\nenabled = false\ntodo = \"later\"",
        ))
        .unwrap();
        assert_eq!(ok.sets[0].keep, 2);
        let dup = format!(
            "{}{}",
            one("name = \"a\"\nkind = \"git\"\nurl = \"https://x\""),
            one("")
        );
        assert!(Catalog::parse(&dup).is_err(), "duplicate set");
    }

    #[test]
    fn mirror_source_validation() {
        let cases = [
            (
                "git over http",
                "name = \"a\"\nkind = \"git\"\nurl = \"http://x\"",
                "not an https url",
            ),
            (
                "static url over ftp",
                "name = \"a\"\nkind = \"http\"\nresolve = \"static\"\nurls = [\"https://x\", \"ftp://y\"]",
                "not an https url",
            ),
            (
                "enabled with a todo",
                "name = \"a\"\nkind = \"git\"\nurl = \"https://x\"\ntodo = \"later\"",
                "enabled with a todo",
            ),
            (
                "reserved name git",
                "name = \"git\"\nkind = \"git\"\nurl = \"https://x\"",
                "reserved name",
            ),
            (
                "version-like name",
                "name = \"2026-11-18-2\"\nkind = \"git\"\nurl = \"https://x\"",
                "reserved name",
            ),
            (
                "repo without format",
                "name = \"a\"\nkind = \"repo\"\nurl = \"https://x\"",
                "needs format",
            ),
            (
                "format on a git source",
                "name = \"a\"\nkind = \"git\"\nurl = \"https://x\"\nformat = \"alpine\"",
                "format is for repo",
            ),
            (
                "fedora without trees",
                "name = \"a\"\nkind = \"repo\"\nurl = \"https://x\"\nformat = \"fedora\"",
                "fedora needs trees",
            ),
            (
                "fedora tree path escapes",
                "name = \"a\"\nkind = \"repo\"\nurl = \"https://x\"\nformat = \"fedora\"\ntrees = [{ path = \"../x\", metalink = \"repo=f45\" }]",
                "bad tree path",
            ),
            (
                "fedora metalink with a slash",
                "name = \"a\"\nkind = \"repo\"\nurl = \"https://x\"\nformat = \"fedora\"\ntrees = [{ path = \"a/b\", metalink = \"x/y\" }]",
                "bad metalink",
            ),
            (
                "debian without signers",
                "name = \"a\"\nkind = \"repo\"\nurl = \"https://x\"\nformat = \"debian\"\nsuites = [\"trixie\"]\ncomponents = [\"main\"]\narches = [\"amd64\"]\nkeyring = \"fedora\"",
                "keyring and signers",
            ),
            (
                "alpine without arches",
                "name = \"a\"\nkind = \"repo\"\nurl = \"https://x\"\nformat = \"alpine\"\nsuites = [\"v3.24\"]\ncomponents = [\"main\"]",
                "needs arches",
            ),
            (
                "dirs without listing",
                "name = \"a\"\nkind = \"http\"\nresolve = \"static\"\ndirs = \"^a/$\"",
                "need resolve",
            ),
            (
                "bad dirs shape",
                "name = \"a\"\nkind = \"http\"\nresolve = \"listing\"\ndirs = \"a\"",
                "dirs must look like",
            ),
            (
                "dir in pattern without dirs",
                "name = \"a\"\nkind = \"http\"\nresolve = \"listing\"\npattern = \"{dir}x\"",
                "needs dirs",
            ),
        ];
        for (name, source, want) in cases {
            let err = format!("{:#}", Catalog::parse(&one(source)).unwrap_err());
            assert!(err.contains(want), "{name}: {err}");
        }
        for good in [
            "name = \"a\"\nkind = \"repo\"\nurl = \"https://x\"\nformat = \"fedora\"\ntrees = [{ path = \"releases/45/Everything\", metalink = \"repo=fedora-45&arch=x86_64\" }]",
            "name = \"a\"\nkind = \"repo\"\nurl = \"https://x\"\nformat = \"alpine\"\nsuites = [\"v3.24\"]\ncomponents = [\"main\"]\narches = [\"x86_64\"]",
            "name = \"a\"\nkind = \"http\"\nresolve = \"listing\"\ndirs = \"^gcc-\\\\d+/$\"\npattern = \"{dir}x\"",
        ] {
            Catalog::parse(&one(good)).unwrap_or_else(|e| panic!("{good}: {e:#}"));
        }
    }

    fn one_set(name: &str, prio: u32) -> String {
        format!("[[set]]\nname = \"{name}\"\ntitle = \"t\"\npriority = {prio}\nestimate = 1\n")
    }

    #[test]
    fn select_order() {
        let mut text = String::new();
        for (name, prio) in [("c", 2), ("a", 0), ("b", 0)] {
            text.push_str(&one_set(name, prio));
        }
        let c = Catalog::parse(&text).unwrap();
        let names = |sets: Vec<&Set>| sets.iter().map(|s| s.name.clone()).collect::<Vec<_>>();
        assert_eq!(names(c.select(&[], true).unwrap()), ["c", "a", "b"]);
        assert_eq!(names(c.select(&[], false).unwrap()), ["a", "b", "c"]);
        let pick = ["c".to_string(), "b".to_string()];
        assert_eq!(names(c.select(&pick, true).unwrap()), ["c", "b"]);
        assert_eq!(names(c.select(&pick, false).unwrap()), ["b", "c"]);
        assert!(c.select(&["nope".to_string()], false).is_err());
    }

    #[test]
    fn variants() {
        let base = "[[set]]\nname = \"s\"\ntitle = \"t\"\npriority = 0\nestimate = 9\n\
            [[set.source]]\nname = \"a\"\nkind = \"git\"\nurl = \"https://x\"\nest = 1\n\
            [[set.source]]\nname = \"b\"\nkind = \"git\"\nurl = \"https://x\"\nest = 2\n";
        let with = |v: &str| format!("{base}{v}");
        let c = Catalog::parse(&with(
            "[[set.variant]]\nname = \"small\"\nsources = [\"a\"]\n",
        ))
        .unwrap();
        let v = c.sets[0].variants();
        let names: Vec<_> = v.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(names, ["small", "full"]);
        assert_eq!(v[1].sources, ["a", "b"]);
        assert!((c.sets[0].estimate_of(&v[0]) - 1.0).abs() < f64::EPSILON);
        assert!((c.sets[0].estimate_of(&v[1]) - 9.0).abs() < f64::EPSILON);

        let explicit = Catalog::parse(&with(
            "[[set.variant]]\nname = \"full\"\nsources = [\"b\"]\n",
        ))
        .unwrap();
        let v = explicit.sets[0].variants();
        assert_eq!(v.len(), 1, "an explicit full replaces the implicit one");
        assert_eq!(v[0].sources, ["b"]);

        let cases = [
            (
                "unknown field",
                "[[set.variant]]\nname = \"x\"\nsources = [\"a\"]\nsize = 1\n",
                "catalog",
            ),
            (
                "unknown source",
                "[[set.variant]]\nname = \"x\"\nsources = [\"zz\"]\n",
                "no source of the set",
            ),
            (
                "no sources",
                "[[set.variant]]\nname = \"x\"\nsources = []\n",
                "names no sources",
            ),
            (
                "duplicate",
                "[[set.variant]]\nname = \"x\"\nsources = [\"a\"]\n[[set.variant]]\nname = \"x\"\nsources = [\"b\"]\n",
                "duplicate variant",
            ),
            (
                "bad name",
                "[[set.variant]]\nname = \"../x\"\nsources = [\"a\"]\n",
                "bad or duplicate variant",
            ),
        ];
        for (name, v, want) in cases {
            let err = format!("{:#}", Catalog::parse(&with(v)).unwrap_err());
            assert!(err.contains(want), "{name}: {err}");
        }
        for reserved in RESERVED {
            let err = Catalog::parse(&one_set(reserved, 0)).unwrap_err();
            assert!(err.to_string().contains("reserved"), "{reserved}: {err}");
        }
    }

    #[test]
    fn embedded_priorities_are_a_total_order_and_variants_resolve() {
        let c = Catalog::embedded().unwrap();
        let mut prios: Vec<u32> = c.sets.iter().map(|s| s.priority).collect();
        prios.sort_unstable();
        prios.dedup();
        assert_eq!(prios.len(), c.sets.len(), "every set has its own priority");
        let order: Vec<&str> = c
            .select(&[], false)
            .unwrap()
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        assert_eq!(&order[..4], ["keys", "specs", "kernel", "toolchains"]);
        assert_eq!(order.last(), Some(&"extras"));
        let kiwix = c.sets.iter().find(|s| s.name == "kiwix").unwrap();
        let names: Vec<String> = kiwix.variants().into_iter().map(|v| v.name).collect();
        assert_eq!(names, ["mini", "no-se", "full"]);
        let large = c.sets.iter().find(|s| s.name == "kiwix-large").unwrap();
        let full = large
            .variants()
            .into_iter()
            .find(|v| v.name == "full")
            .unwrap();
        assert_eq!(
            full.sources,
            ["wikipedia-maxi", "stackoverflow"],
            "no maxi and nopic together"
        );
    }
}
