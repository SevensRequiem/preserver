use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    #[default]
    Ssh,
    Https,
}

/// A filesystem id as udisks reports it: hex digits and dashes (ext4 UUID, FAT `XXXX-XXXX`, NTFS serial).
/// The spelling from the config is kept, because it names the mount point and the drives.d file.
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct DriveId(String);

impl DriveId {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// Compares without dashes and case, so one id matches however the OS spells it.
    pub(crate) fn matches(&self, other: &str) -> bool {
        let norm = |s: &str| {
            s.chars()
                .filter(|c| *c != '-')
                .map(|c| c.to_ascii_uppercase())
                .collect::<String>()
        };
        norm(&self.0) == norm(other)
    }
}

impl std::str::FromStr for DriveId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let hex = s.chars().filter(char::is_ascii_hexdigit).count();
        let dashes = s.chars().filter(|c| *c == '-').count();
        if !(4..=40).contains(&s.len()) || hex < 4 || hex + dashes != s.len() || s.starts_with('-')
        {
            bail!("bad drive id {s:?}");
        }
        Ok(Self(s.to_string()))
    }
}

impl TryFrom<String> for DriveId {
    type Error = anyhow::Error;

    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl std::fmt::Display for DriveId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct LocalFolder {
    pub name: String,
    pub path: PathBuf,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Config {
    pub owners: Vec<String>,
    pub primary_uuid: DriveId,
    #[serde(default)]
    pub transport: Transport,
    #[serde(default = "default_bandwidth")]
    #[expect(dead_code, reason = "read by the public sync in phase 2")]
    pub bandwidth_mbit: u32,
    #[serde(default = "default_reserve")]
    pub reserve_percent: u8,
    #[serde(default)]
    pub local: Vec<LocalFolder>,
}

fn default_bandwidth() -> u32 {
    80
}

fn default_reserve() -> u8 {
    10
}

/// GitHub's rule for user and org names; the leading alphanumeric also keeps a name from reading as an option.
fn valid_owner(s: &str) -> bool {
    s.len() <= 39
        && s.starts_with(|c: char| c.is_ascii_alphanumeric())
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn valid_folder_name(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

impl Config {
    pub(crate) fn load(dir: &Path) -> Result<Self> {
        let file = dir.join("config.toml");
        let text = std::fs::read_to_string(&file).with_context(|| {
            format!(
                "read {} (owners and primary_uuid are required, see docs/config.example.toml)",
                file.display()
            )
        })?;
        Self::parse(&text).with_context(|| file.display().to_string())
    }

    pub(crate) fn parse(text: &str) -> Result<Self> {
        let c: Self = toml::from_str(text)?;
        if c.reserve_percent > 90 {
            bail!("reserve_percent must be 0 to 90");
        }
        if let Some(o) = c.owners.iter().find(|o| !valid_owner(o)) {
            bail!("bad owner {o:?}");
        }
        let mut seen = HashSet::new();
        for f in &c.local {
            if !valid_folder_name(&f.name) || !seen.insert(&f.name) {
                bail!("bad or duplicate local folder name {:?}", f.name);
            }
            if !f.path.is_absolute() {
                bail!("local folder {:?} needs an absolute path", f.name);
            }
        }
        Ok(c)
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct Drive {
    #[serde(skip)]
    pub id: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub label: String,
}

/// Reads the registry of extra drives, one `drives.d/<id>.toml` each.
pub(crate) fn load_drives(dir: &Path) -> Result<Vec<Drive>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).context(dir.display().to_string()),
    };
    let mut out = Vec::new();
    for entry in entries {
        let path = entry?.path();
        let Some(id) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".toml"))
            .filter(|id| id.parse::<DriveId>().is_ok())
        else {
            continue;
        };
        let text = std::fs::read_to_string(&path)?;
        let mut d: Drive = toml::from_str(&text).with_context(|| path.display().to_string())?;
        d.id = id.to_string();
        out.push(d);
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    const UUID: &str = "primary_uuid = \"0123abcd-2d54\"\n";

    #[test]
    fn accepts_a_full_config() {
        let c = Config::parse(
            "owners = [\"a-b\", \"X9\"]\nprimary_uuid = \"0123ABCD-0000-4000-8000-0123456789ab\"\n\
             transport = \"https\"\nbandwidth_mbit = 0\nreserve_percent = 90\n\
             [[local]]\nname = \"docs.v2_x-1\"\npath = \"/x\"\n",
        )
        .unwrap();
        assert_eq!(c.owners, ["a-b", "X9"]);
        assert_eq!(c.transport, Transport::Https);
        assert_eq!(c.reserve_percent, 90);
        assert_eq!(c.local[0].name, "docs.v2_x-1");
    }

    #[test]
    fn defaults_cover_only_the_optional_keys() {
        let c = Config::parse(&format!("owners = [\"a\"]\n{UUID}")).unwrap();
        assert_eq!(c.transport, Transport::Ssh);
        assert_eq!(c.reserve_percent, 10);
        assert!(c.local.is_empty());
    }

    #[test]
    fn rejects_bad_configs() {
        let long_owner = format!("owners = [\"{}\"]\n{UUID}", "a".repeat(40));
        let cases = [
            ("no owners key", UUID.to_string()),
            ("no uuid", "owners = [\"a\"]\n".to_string()),
            (
                "owner reads as a flag",
                format!("owners = [\"--flag\"]\n{UUID}"),
            ),
            ("owner with a slash", format!("owners = [\"a/b\"]\n{UUID}")),
            (
                "owner with a traversal",
                format!("owners = [\"../x\"]\n{UUID}"),
            ),
            ("empty owner", format!("owners = [\"\"]\n{UUID}")),
            ("owner over 39 chars", long_owner),
            (
                "uuid with a path",
                "owners = []\nprimary_uuid = \"../../etc\"\n".to_string(),
            ),
            (
                "uuid too short",
                "owners = []\nprimary_uuid = \"abc\"\n".to_string(),
            ),
            (
                "uuid not hex",
                "owners = []\nprimary_uuid = \"wxyz-wxyz\"\n".to_string(),
            ),
            (
                "uuid only dashes",
                "owners = []\nprimary_uuid = \"-----\"\n".to_string(),
            ),
            (
                "uuid over 40 chars",
                format!("owners = []\nprimary_uuid = \"{}\"\n", "a".repeat(41)),
            ),
            (
                "unknown transport",
                format!("owners = []\ntransport = \"ftp\"\n{UUID}"),
            ),
            (
                "negative bandwidth",
                format!("owners = []\nbandwidth_mbit = -1\n{UUID}"),
            ),
            (
                "reserve over 90",
                format!("owners = []\nreserve_percent = 91\n{UUID}"),
            ),
            (
                "folder traversal",
                format!("owners = []\n{UUID}[[local]]\nname = \"../x\"\npath = \"/x\"\n"),
            ),
            (
                "folder dot-dot",
                format!("owners = []\n{UUID}[[local]]\nname = \"..\"\npath = \"/x\"\n"),
            ),
            (
                "folder empty name",
                format!("owners = []\n{UUID}[[local]]\nname = \"\"\npath = \"/x\"\n"),
            ),
            (
                "folder relative path",
                format!("owners = []\n{UUID}[[local]]\nname = \"x\"\npath = \"rel\"\n"),
            ),
            (
                "folder duplicate",
                format!(
                    "owners = []\n{UUID}[[local]]\nname = \"x\"\npath = \"/a\"\n[[local]]\nname = \"x\"\npath = \"/b\"\n"
                ),
            ),
        ];
        for (name, text) in cases {
            assert!(Config::parse(&text).is_err(), "{name}");
        }
    }

    #[test]
    fn owner_length_limit() {
        assert!(valid_owner(&"a".repeat(39)));
        assert!(!valid_owner(&"a".repeat(40)));
    }

    #[test]
    fn drive_id_matches_any_spelling() {
        let id: DriveId = "0123abcd-0000-4000-8000-0123456789ab".parse().unwrap();
        assert!(id.matches("0123ABCD0000400080000123456789AB"));
        assert!(id.matches("0123abcd-0000-4000-8000-0123456789ab"));
        assert!(!id.matches("0123abcd-0000-4000-8000-0123456789ac"));
        assert!(!id.matches(""));
        assert_eq!(id.as_str(), "0123abcd-0000-4000-8000-0123456789ab");
    }

    #[test]
    fn drives_registry() {
        let tmp = TempDir::new();
        assert!(load_drives(&tmp.path().join("absent")).unwrap().is_empty());
        std::fs::write(
            tmp.path().join("ABCD-1234.toml"),
            "role = \"replica\"\nlabel = \"stick\"\n",
        )
        .unwrap();
        std::fs::write(tmp.path().join("notes.txt"), "x").unwrap();
        std::fs::write(tmp.path().join("not a uuid.toml"), "role = \"x\"\n").unwrap();
        let drives = load_drives(tmp.path()).unwrap();
        assert_eq!(drives.len(), 1);
        assert_eq!(
            (
                drives[0].id.as_str(),
                drives[0].role.as_str(),
                drives[0].label.as_str()
            ),
            ("ABCD-1234", "replica", "stick")
        );
    }
}
