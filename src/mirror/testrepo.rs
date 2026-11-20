//! A Debian repository served from loopback, signed by a throwaway key, and the walker's
//! end-to-end tests against it.

use super::debian::{anchor, walk};
use super::generation::{self, Next, begin, read_tsv};
use super::{Anchor, Ctx, Walked};
use crate::catalog::{Kind, RepoFormat, Source};
use crate::net::download::Downloader;
use crate::net::testserver::{Behaviour, Server};
use crate::resolve::hex;
use crate::resolve::tests::downloader;
use crate::testutil::TempDir;
use crate::verify::testkey::TestKey;
use anyhow::{Result, bail};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, LazyLock};

fn sha(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

fn xz(b: &[u8]) -> Vec<u8> {
    let mut w =
        lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(0)).unwrap();
    w.write_all(b).unwrap();
    w.finish().unwrap()
}

/// A day before the first call, so every test in the process shares one origin.
static START: LazyLock<i64> = LazyLock::new(|| jiff::Timestamp::now().as_second() - 86_400);

fn date(n: i64) -> String {
    jiff::Timestamp::from_second(*START + n * 60)
        .unwrap()
        .strftime("%a, %d %b %Y %H:%M:%S UTC")
        .to_string()
}

pub(crate) struct Site {
    pub(crate) srv: Server,
    pub(crate) routes: HashMap<String, Vec<u8>>,
    pub(crate) src: Source,
    pub(crate) key: TestKey,
    tmp: TempDir,
}

impl Site {
    pub(crate) fn new(suites: &[&str]) -> Self {
        let srv = Server::start("127.0.0.1", Behaviour::new(Vec::new()));
        let key = TestKey::new();
        let src = Source {
            name: "d".into(),
            kind: Some(Kind::Repo),
            format: Some(RepoFormat::Debian),
            url: srv.url("deb"),
            keyring: "test".into(),
            signers: vec![key.fingerprint()],
            suites: suites.iter().map(|s| (*s).to_owned()).collect(),
            components: vec!["main".into()],
            arches: vec!["amd64".into()],
            ..Source::default()
        };
        Self {
            srv,
            routes: HashMap::new(),
            src,
            key,
            tmp: TempDir::new(),
        }
    }

    fn tree(&self) -> PathBuf {
        self.tmp.path().join("tree")
    }

    /// Publishes `suite` at `when` (minutes after a fixed start) with these pool files. The
    /// indexes are served by hash only. A name under `pool/` is the path as given.
    pub(crate) fn publish(&mut self, suite: &str, when: i64, pkgs: &[(&str, &[u8])]) -> Vec<u8> {
        let mut packages = String::new();
        for (name, body) in pkgs {
            let path = if name.starts_with("pool/") {
                (*name).to_owned()
            } else {
                format!("pool/main/{name}")
            };
            let _ = write!(
                packages,
                "Package: {name}\nFilename: {path}\nSize: {}\nSHA256: {}\n\n",
                body.len(),
                sha(body)
            );
            self.routes.insert(format!("deb/{path}"), body.to_vec());
        }
        let pk = xz(packages.as_bytes());
        let tr = format!("Translation {suite} {when}").into_bytes();
        let mut text = format!(
            "Codename: {suite}\nDate: {}\nValid-Until: {}\nAcquire-By-Hash: yes\nComponents: main\nSHA256:\n",
            date(when),
            date(when + 7 * 24 * 60),
        );
        for (p, b) in [
            ("main/binary-amd64/Packages.xz", &pk),
            ("main/i18n/Translation-en", &tr),
        ] {
            let _ = writeln!(text, " {} {} {p}", sha(b), b.len());
            let dir = p.rsplit_once('/').unwrap().0;
            self.routes.insert(
                format!("deb/dists/{suite}/{dir}/by-hash/SHA256/{}", sha(b)),
                b.clone(),
            );
        }
        let doc = self.key.clearsign(&text).into_bytes();
        self.routes
            .insert(format!("deb/dists/{suite}/InRelease"), doc.clone());
        let routes = self.routes.clone();
        self.srv.set(|b| b.routes = Some(routes));
        doc
    }

    fn ctx<'a>(dl: &'a Downloader, ring: &'a [(&'a str, &'a [u8])], tree: &'a Path) -> Ctx<'a> {
        Ctx {
            dl,
            keys: ring,
            rsa: &[],
            metalink: "",
            plain_http: true,
            tree: tree.is_dir().then_some(tree),
        }
    }

    fn anchor(&self) -> Result<Anchor> {
        let dl = downloader();
        let (public, tree) = (self.key.public(), self.tree());
        anchor(&Self::ctx(&dl, &[("test", &public)], &tree), &self.src)
    }

    fn anchor_err(&self) -> String {
        format!("{:#}", self.anchor().unwrap_err())
    }

    /// One whole run: anchor, stage, fetch, commit.
    fn run(&self) -> Result<()> {
        self.run_planting(|_| {})
    }

    /// `run`, with `plant` given the stage's metadata directory once it exists.
    fn run_planting(&self, plant: impl FnOnce(&Path)) -> Result<()> {
        let dl = downloader();
        let tree = self.tree();
        let mut g = begin(&tree, &self.src.url, self.anchor()?)?;
        plant(
            &tree
                .join(".preserver/staging")
                .join(&g.generation()[..16])
                .join("meta"),
        );
        let (stop, done) = (AtomicBool::new(false), Arc::new(AtomicU64::new(0)));
        let mut ok = Vec::new();
        loop {
            let mut w = |a: &Anchor, m: &Path, e: &mut dyn FnMut(Walked)| walk(a, m, e);
            match g.next(&ok, &mut w, u64::MAX, "ext4")? {
                Next::Batch(p) => {
                    ok.clear();
                    for (i, f) in p.fetches.iter().enumerate() {
                        if dl.fetch(f, &stop, &done).is_ok() {
                            ok.push(i);
                        }
                    }
                    if ok.len() < p.fetches.len() {
                        g.land(&ok)?;
                        bail!("a download failed");
                    }
                }
                Next::Ready => return g.commit(),
                Next::OverBudget { .. } => bail!("over budget"),
            }
        }
    }

    fn hits(&self) -> Vec<String> {
        let h = self.srv.hits().into_iter().map(|h| h.path).collect();
        self.srv.clear_log();
        h
    }

    fn live(&self) -> generation::Tsv {
        read_tsv(&generation::live_path(&self.tree())).unwrap()
    }

    fn pool(&self) -> Vec<String> {
        self.live().entries.into_iter().map(|e| e.path).collect()
    }
}

const AB: [(&str, &[u8]); 2] = [("a.deb", b"aaa"), ("b.deb", b"bbbb")];

#[test]
fn first_sync_links_the_indexes_by_hash() {
    let mut s = Site::new(&["trixie"]);
    let doc = s.publish("trixie", 1, &AB);
    s.run().unwrap();
    let tree = s.tree();
    let dists = tree.join("dists/trixie");
    assert_eq!(std::fs::read(dists.join("InRelease")).unwrap(), doc);
    assert_eq!(
        std::fs::read(tree.join("pool/main/b.deb")).unwrap(),
        b"bbbb"
    );
    let packages = std::fs::read(dists.join("main/binary-amd64/Packages.xz")).unwrap();
    let by_hash = dists.join(format!(
        "main/binary-amd64/by-hash/SHA256/{}",
        sha(&packages)
    ));
    assert_eq!(std::fs::read(by_hash).unwrap(), packages);
    let tr = std::fs::read(dists.join("main/i18n/Translation-en")).unwrap();
    assert_eq!(
        std::fs::read(dists.join(format!("main/i18n/by-hash/SHA256/{}", sha(&tr)))).unwrap(),
        tr
    );
    assert_eq!(s.pool(), ["pool/main/a.deb", "pool/main/b.deb"]);
}

#[test]
fn unchanged_makes_only_release_requests() {
    let mut s = Site::new(&["trixie"]);
    s.publish("trixie", 1, &AB);
    s.run().unwrap();
    s.hits();
    s.run().unwrap();
    assert_eq!(s.hits(), ["deb/dists/trixie/InRelease"]);
}

#[test]
fn a_tampered_index_means_no_pool_request() {
    let mut s = Site::new(&["trixie"]);
    s.publish("trixie", 1, &AB);
    let key = s
        .routes
        .keys()
        .find(|k| k.contains("by-hash") && k.contains("binary-amd64"))
        .unwrap()
        .clone();
    s.routes.insert(key, b"evil".to_vec());
    let routes = s.routes.clone();
    s.srv.set(|b| b.routes = Some(routes));
    assert!(s.run().is_err());
    assert!(!s.hits().iter().any(|h| h.contains("/pool/")));
    assert!(!s.tree().join("dists/trixie/InRelease").exists());
}

#[test]
fn a_signer_that_is_not_pinned_is_refused() {
    let mut s = Site::new(&["trixie"]);
    s.publish("trixie", 1, &AB);
    s.src.signers = vec![TestKey::new().fingerprint()];
    let e = s.anchor_err();
    assert!(e.contains("no pinned key"), "{e}");
}

#[test]
fn an_equal_date_with_other_bytes_is_refused() {
    let mut s = Site::new(&["trixie"]);
    s.publish("trixie", 5, &AB);
    s.run().unwrap();
    s.publish("trixie", 5, &[("c.deb", b"c")]);
    let e = s.anchor_err();
    assert!(e.contains("not newer"), "{e}");
}

#[test]
fn an_older_date_is_refused() {
    let mut s = Site::new(&["trixie"]);
    s.publish("trixie", 5, &AB);
    s.run().unwrap();
    s.publish("trixie", 4, &AB);
    let e = s.anchor_err();
    assert!(e.contains("not newer"), "{e}");
}

#[test]
fn a_dropped_package_is_pruned_and_a_shared_one_kept() {
    let mut s = Site::new(&["trixie", "trixie-updates"]);
    s.publish("trixie", 1, &[("a.deb", b"aaa"), ("shared.deb", b"sh")]);
    s.publish(
        "trixie-updates",
        1,
        &[("b.deb", b"bbb"), ("shared.deb", b"sh")],
    );
    s.run().unwrap();
    assert_eq!(s.live().entries.len(), 3);
    s.publish("trixie", 2, &[("c.deb", b"c")]);
    s.run().unwrap();
    let tree = s.tree();
    assert!(!tree.join("pool/main/a.deb").exists());
    assert!(tree.join("pool/main/shared.deb").exists());
    assert_eq!(
        s.pool(),
        ["pool/main/b.deb", "pool/main/c.deb", "pool/main/shared.deb"]
    );
}

#[test]
fn a_pool_path_that_climbs_out_is_refused() {
    let mut s = Site::new(&["trixie"]);
    s.publish("trixie", 1, &[("pool/../../x", b"x")]);
    let e = format!("{:#}", s.run().unwrap_err());
    assert!(e.contains("pool"), "{e}");
    assert!(!s.hits().iter().any(|h| h.contains("pool/")));
}

#[cfg(unix)]
#[test]
fn a_planted_by_hash_link_in_the_stage_is_cleared() {
    let mut s = Site::new(&["trixie"]);
    s.publish("trixie", 1, &AB);
    let outside = s.tmp.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    s.run_planting(|meta| {
        let dir = meta.join("dists/trixie/main/binary-amd64");
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("by-hash")).unwrap();
    })
    .unwrap();
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    let by_hash = s
        .tree()
        .join("dists/trixie/main/binary-amd64/by-hash/SHA256");
    assert_eq!(std::fs::read_dir(by_hash).unwrap().count(), 1);
}

#[test]
fn a_live_release_from_a_dropped_key_sets_no_bar() {
    let mut s = Site::new(&["trixie"]);
    s.publish("trixie", 1, &AB);
    s.run().unwrap();
    s.key = TestKey::new();
    s.src.signers = vec![s.key.fingerprint()];
    s.publish("trixie", 2, &AB);
    s.run().unwrap();
}
