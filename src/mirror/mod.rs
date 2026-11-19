//! In-place repository mirrors: a tree on the drive that a package manager reads, kept whole
//! by swapping its metadata in only after every file it names has landed and verified.

pub(crate) mod generation;

use crate::keys::Keyring;
use crate::net::download::Downloader;
use crate::resolve::hex;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// How a file is known to be the right one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(crate) enum Check {
    Sha256([u8; 32]),
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Check::Sha256(h) => write!(f, "sha256:{}", hex(h)),
        }
    }
}

impl FromStr for Check {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let h = s
            .strip_prefix("sha256:")
            .ok_or_else(|| format!("unknown check {s:?}"))?;
        let b = h.as_bytes();
        if b.len() != 64 {
            return Err(format!("sha256 of {} characters", b.len()));
        }
        let nib = |c: u8| match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            _ => Err(format!("not lowercase hex: {h:?}")),
        };
        let mut out = [0u8; 32];
        for (o, pair) in out.iter_mut().zip(b.as_chunks::<2>().0) {
            *o = (nib(pair[0])? << 4) | nib(pair[1])?;
        }
        Ok(Check::Sha256(out))
    }
}

impl TryFrom<String> for Check {
    type Error = String;

    fn try_from(s: String) -> Result<Self, String> {
        s.parse()
    }
}

impl From<Check> for String {
    fn from(c: Check) -> Self {
        c.to_string()
    }
}

/// A file of the tree, by its path relative to the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub path: String,
    pub size: u64,
    pub check: Check,
}

/// A metadata file the walk reads. `from` is where to fetch it, relative to the base URL, when
/// that is not `entry.path` (a by-hash path).
#[derive(Debug, Clone)]
pub(crate) struct Meta {
    pub entry: Entry,
    pub from: Option<String>,
}

/// What a generation is pinned by: the signed or TLS-anchored documents with their exact
/// bytes, the metadata they vouch for, and the paths swapped in as a whole at commit.
#[derive(Debug, Default)]
pub(crate) struct Anchor {
    pub docs: Vec<(String, Vec<u8>)>,
    pub meta: Vec<Meta>,
    pub swaps: Vec<String>,
}

/// What a walker may use to fetch and verify its anchor.
pub(crate) struct Ctx<'a> {
    pub dl: &'a Downloader,
    pub keys: &'a [Keyring<'a>],
    /// The metalink service; production passes the Fedora constant, tests a loopback server.
    pub metalink: &'a str,
    pub plain_http: bool,
    /// The live tree when the drive is mounted, for rollback checks against it.
    pub tree: Option<&'a Path>,
}

/// `base` joined with a `/`-separated path that `generation::valid_path` accepted.
pub(crate) fn rel_path(base: &Path, rel: &str) -> PathBuf {
    let mut p = base.to_path_buf();
    p.extend(rel.split('/'));
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_round_trips_and_refuses_junk() {
        let c = Check::Sha256([0xab; 32]);
        let s = c.to_string();
        assert_eq!(s, format!("sha256:{}", "ab".repeat(32)));
        assert_eq!(s.parse::<Check>().unwrap(), c);
        for bad in [
            "sha256:ab",
            &format!("sha256:{}", "AB".repeat(32)),
            &format!("sha512:{}", "ab".repeat(32)),
            &format!("sha256:{}g", "a".repeat(63)),
            "",
        ] {
            assert!(bad.parse::<Check>().is_err(), "{bad:?}");
        }
    }
}
