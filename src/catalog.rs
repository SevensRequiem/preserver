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
        if !self.pattern.is_empty() {
            Regex::new(&self.pattern)?;
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

/// Safe as one path component: the Go tool's `nameRe`, and no leading dot.
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
            if !valid_name(&set.name) || !seen.insert(set.name.clone()) {
                bail!("catalog: bad or duplicate set {:?}", set.name);
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
                "name = \"../a\"\nkind = \"git\"\nurl = \"u\"",
                "bad name",
            ),
            (
                "hidden name",
                "name = \".a\"\nkind = \"git\"\nurl = \"u\"",
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
                "name = \"a\"\nkind = \"git\"\nurl = \"u\"\nurll = \"x\"",
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
            one("name = \"a\"\nkind = \"git\"\nurl = \"u\""),
            one("")
        );
        assert!(Catalog::parse(&dup).is_err(), "duplicate set");
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
}
