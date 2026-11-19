use super::versioned::{read_set_file, version_dirs};
use super::*;
use crate::catalog::{Kind, Resolve};
use crate::keys::RsaKey;
use crate::mirror::Anchor;
use crate::net::testserver::Server;
use crate::platform::DriveAt;
use crate::resolve::hex;
use crate::resolve::tests::{downloader, serve};
use crate::testutil::{TempDir, paths};
use crate::verify::testkey::TestKey;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::path::PathBuf;

pub(super) struct Env {
    _tmp: TempDir,
    pub(super) paths: Paths,
    srv: Server,
    pub(super) dl: Downloader,
    pub(super) store: Store,
    key: TestKey,
    notes: Mutex<Vec<String>>,
    walkers: Walkers,
    /// Replaces the test key's public half as the ring named `test`.
    pub(super) ring: Option<Vec<u8>>,
    /// An Alpine key's name and PEM.
    pub(super) rsa: Option<(String, String)>,
    pub(super) metalink: String,
}

pub(super) const GB: u64 = 1_000_000_000;

impl Env {
    pub(super) fn new() -> Self {
        let tmp = TempDir::new();
        let paths = paths(tmp.path());
        Self {
            store: Store::new(paths.queue.clone()),
            paths,
            _tmp: tmp,
            srv: serve(&[]),
            dl: downloader(),
            key: TestKey::new(),
            notes: Mutex::new(Vec::new()),
            walkers: WALKERS,
            ring: None,
            rsa: None,
            metalink: String::new(),
        }
    }

    fn routes(&self, routes: &[(&str, &[u8])]) {
        let map = routes
            .iter()
            .map(|(p, d)| ((*p).to_string(), d.to_vec()))
            .collect();
        self.srv.set(|b| b.routes = Some(map));
    }

    pub(super) fn with<R>(
        &self,
        cat: &Catalog,
        free: (u64, u64),
        f: impl FnOnce(&Public) -> R,
    ) -> R {
        let ring = self.ring.clone().unwrap_or_else(|| self.key.public());
        let rsa: Vec<RsaKey<'_>> = self
            .rsa
            .iter()
            .map(|(name, pem)| RsaKey {
                name,
                arches: &["x86_64"],
                pem,
            })
            .collect();
        let note = |_: bool, title: &str, body: &str| {
            self.notes.lock().unwrap().push(format!("{title}: {body}"));
        };
        let free = move |_: &Path| Ok(free);
        f(&Public {
            cat,
            paths: &self.paths,
            resolver: Resolver {
                dl: &self.dl,
                gh_api: "",
                hf_base: "",
                plain_http: true,
            },
            verifier: Verifier {
                keys: &[("test", &ring)],
                rsa: &rsa,
                tofu: &self.paths.tofu,
                note: &note,
            },
            reserve_percent: 10,
            free: &free,
            staged: Mutex::new(HashMap::new()),
            resolved: Mutex::new(HashMap::new()),
            gens: Mutex::new(HashMap::new()),
            walkers: self.walkers,
            metalink: &self.metalink,
        })
    }

    fn work_queue(&self, cat: &Catalog) {
        self.with(cat, (900 * GB, 1000 * GB), |p| {
            Worker {
                store: &self.store,
                dl: &self.dl,
                plan: &|job, root, ok| p.plan(job, root, ok),
                settle: &|job, root, ok| p.settle(job, root, ok),
                drive: &|_| DriveAt::Mounted(self.paths.mnt.clone()),
            }
            .run(Pass::FRESH)
            .unwrap();
        });
    }

    /// One `public` run of the catalog's first set: enqueue, work the queue, return the job.
    fn sync_with(&self, cat: &Catalog, free: (u64, u64)) -> Job {
        let drive: DriveId = "0123-ABCD".parse().unwrap();
        let ids = enqueue_all(&self.store, &[&cat.sets[0]], &drive, true, &|_| false).unwrap();
        self.with(cat, free, |p| {
            Worker {
                store: &self.store,
                dl: &self.dl,
                plan: &|job, root, ok| p.plan(job, root, ok),
                settle: &|job, root, ok| p.settle(job, root, ok),
                drive: &|_| DriveAt::Mounted(self.paths.mnt.clone()),
            }
            .run(Pass::FRESH)
            .unwrap();
        });
        self.store.job(&ids[0].1).unwrap()
    }

    pub(super) fn sync(&self, cat: &Catalog) -> Job {
        self.sync_with(cat, (900 * GB, 1000 * GB))
    }

    pub(super) fn set_dir(&self) -> PathBuf {
        self.paths.mnt.join("preserver/public/demo")
    }

    /// The set's line in status/public.json.
    fn status(&self) -> serde_json::Value {
        let st = status::Status::read(&self.paths.status_file("public"));
        let sets: Vec<_> = st.sets.iter().filter(|s| s["name"] == "demo").collect();
        assert_eq!(sets.len(), 1, "{:?}", st.sets);
        sets[0].clone()
    }

    fn fixed(&self, name: &str, path: &str) -> Source {
        Source {
            name: name.into(),
            kind: Some(Kind::Http),
            resolve: Some(Resolve::Static),
            urls: vec![self.srv.url(path)],
            license: "MIT".into(),
            ..Source::default()
        }
    }

    fn signed(&self, name: &str, path: &str) -> Source {
        Source {
            sig: ".sig".into(),
            keyring: "test".into(),
            signers: vec![self.key.fingerprint()],
            ..self.fixed(name, path)
        }
    }
}

pub(super) fn catalog(keep: usize, sources: Vec<Source>) -> Catalog {
    Catalog {
        sets: vec![Set {
            name: "demo".into(),
            title: "Demo <set>".into(),
            usage: "For tests.".into(),
            priority: 0,
            estimate: 0.001,
            keep,
            variants: Vec::new(),
            sources,
        }],
    }
}

fn files(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            if e.file_type().unwrap().is_dir() {
                stack.push(e.path());
            } else {
                let rel = e.path().strip_prefix(dir).unwrap().to_path_buf();
                out.push(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn full_sync_publishes_only_verified_files() {
    let env = Env::new();
    let data = crate::net::testserver::body(100 << 10, 7);
    let sig = env.key.sign(&data);
    env.routes(&[("d/a.bin", &data), ("d/a.bin.sig", &sig)]);
    let cat = catalog(2, vec![env.signed("src", "d/a.bin")]);

    let job = env.sync(&cat);
    assert_eq!(job.state, JobState::Done, "{:?}", job.error);
    let versions = version_dirs(&env.set_dir());
    assert_eq!(versions.len(), 1);
    let dir = env.set_dir().join(&versions[0]);
    assert_eq!(
        files(&dir),
        ["SET.toml", "SHA256SUMS", "src/a.bin", "src/a.bin.sig"]
    );
    assert_eq!(std::fs::read(dir.join("src/a.bin")).unwrap(), data);
    assert_eq!(files(&env.set_dir().join(".staging")), Vec::<String>::new());

    let sf = read_set_file(&dir.join("SET.toml"));
    let signer = format!("gpg:{}", env.key.fingerprint());
    assert_eq!(
        (sf.set.as_str(), sf.version.as_str()),
        ("demo", versions[0].as_str())
    );
    assert_eq!(sf.bytes, (data.len() + sig.len()) as u64);
    assert_eq!(sf.entries.len(), 1);
    assert_eq!(sf.entries[0].verify, signer);
    assert_eq!(sf.entries[0].url, env.srv.url("d/a.bin"));
    assert_eq!(
        (sf.sources[0].kind.as_str(), sf.sources[0].license.as_str()),
        ("http", "MIT")
    );
    assert_eq!(sf.sources[0].verify, signer);
    assert_eq!(sf.plan.len(), 64);

    // SHA256SUMS covers every file, SET.toml included, and each line is true.
    let sums = std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap();
    let listed: Vec<&str> = sums
        .lines()
        .map(|l| l.split_once("  ").unwrap().1)
        .collect();
    assert_eq!(listed, ["src/a.bin", "src/a.bin.sig", "SET.toml"]);
    for l in sums.lines() {
        let (h, rel) = l.split_once("  ").unwrap();
        assert_eq!(
            h,
            hex(&Sha256::digest(std::fs::read(dir.join(rel)).unwrap())),
            "{rel}"
        );
    }

    let st = env.status();
    assert_eq!(
        (st["name"].as_str(), st["state"].as_str()),
        (Some("demo"), Some("ok"))
    );
    assert_eq!(st["version"].as_str(), Some(versions[0].as_str()));
    assert!(st.get("detail").is_none());
    let index = std::fs::read_to_string(env.paths.mnt.join("preserver/INDEX.html")).unwrap();
    assert!(index.contains("<h2 id=\"demo\">demo</h2>"), "{index}");
    assert!(
        index.contains("Demo &lt;set&gt; <span class=\"dim\">(MIT)</span>"),
        "{index}"
    );
    assert!(index.contains(&format!("public/demo/{0}/\">{0}</a>", versions[0])));
    assert!(index.contains(&signer));
    assert!(
        !env.paths.tofu.exists(),
        "a signed file needs no trust on first use"
    );

    // The same plan again: nothing is downloaded and no version is added.
    let served = env.srv.served();
    let job = env.sync(&cat);
    assert_eq!(job.state, JobState::Done);
    assert_eq!(env.srv.served(), served);
    assert_eq!(version_dirs(&env.set_dir()), versions);
    assert_eq!(env.status()["state"].as_str(), Some("unchanged"));
    assert!(env.notes.lock().unwrap().is_empty());
}

#[test]
fn tampered_file_fails_and_stays_invisible() {
    let env = Env::new();
    let data = b"the real release\n".to_vec();
    let sig = env.key.sign(&data);
    let good = b"the readme\n".to_vec();
    let good_sig = env.key.sign(&good);
    env.routes(&[
        ("d/a.bin", b"the real release, tampered\n"),
        ("d/a.bin.sig", &sig),
        ("d/readme", &good),
        ("d/readme.sig", &good_sig),
    ]);
    let cat = catalog(
        2,
        vec![env.signed("src", "d/a.bin"), env.signed("doc", "d/readme")],
    );

    let job = env.sync(&cat);
    assert_eq!(job.state, JobState::Failed);
    let err = job.error.unwrap();
    assert!(
        err.contains("src/a.bin") && err.contains("bad signature"),
        "{err}"
    );
    assert!(
        version_dirs(&env.set_dir()).is_empty(),
        "nothing became visible"
    );
    // The bad file and its signature are gone; the file that verified waits in staging.
    let staged = files(&env.set_dir().join(".staging"));
    assert_eq!(staged.len(), 2, "{staged:?}");
    assert!(
        staged.iter().all(|f| f.contains("/doc/readme")),
        "{staged:?}"
    );
    let st = env.status();
    assert_eq!(st["state"].as_str(), Some("failed"));
    assert!(st["detail"].as_str().unwrap().contains("bad signature"));
    let index = std::fs::read_to_string(env.paths.mnt.join("preserver/INDEX.html")).unwrap();
    assert!(
        !index.contains("demo"),
        "the index lists only visible versions"
    );

    // A good signature by a key outside the keyring fails the same way.
    let stranger = TestKey::new();
    env.routes(&[
        ("d/a.bin", &data),
        ("d/a.bin.sig", &stranger.sign(&data)),
        ("d/readme", &good),
        ("d/readme.sig", &good_sig),
    ]);
    let job = env.sync(&cat);
    assert_eq!(job.state, JobState::Failed, "{:?}", job.error);
    assert_eq!(version_dirs(&env.set_dir()), Vec::<String>::new());

    // Once upstream serves the real thing, the same job publishes.
    env.routes(&[
        ("d/a.bin", &data),
        ("d/a.bin.sig", &sig),
        ("d/readme", &good),
        ("d/readme.sig", &good_sig),
    ]);
    let retried = env.sync(&cat);
    assert_eq!(retried.id, job.id, "the failed job is retried, not doubled");
    assert_eq!(retried.state, JobState::Done, "{:?}", retried.error);
    let versions = version_dirs(&env.set_dir());
    assert_eq!(versions.len(), 1);
    let dir = env.set_dir().join(&versions[0]);
    assert_eq!(std::fs::read(dir.join("src/a.bin")).unwrap(), data);
    assert_eq!(env.status()["state"].as_str(), Some("ok"));
}

#[test]
fn budget_refusal_skips_the_set() {
    let env = Env::new();
    env.routes(&[("d/a.bin", b"x")]);
    let mut cat = catalog(2, vec![env.fixed("src", "d/a.bin")]);
    let cases = [
        (
            "free space is inside the reserve",
            0.001,
            (50 * GB, 1000 * GB),
        ),
        (
            "the estimate does not fit above the reserve",
            850.0,
            (900 * GB, 1000 * GB),
        ),
    ];
    for (name, estimate, free) in cases {
        cat.sets[0].sources[0].est = estimate;
        let job = env.sync_with(&cat, free);
        assert_eq!(job.state, JobState::Done, "{name}");
        let st = env.status();
        assert_eq!(st["state"].as_str(), Some("skipped"), "{name}");
        let detail = st["detail"].as_str().unwrap();
        assert!(
            detail.starts_with("budget: needs about"),
            "{name}: {detail}"
        );
        assert!(
            detail.ends_with("free above the 10% reserve"),
            "{name}: {detail}"
        );
    }
    assert!(env.srv.hits().is_empty(), "a refused set fetches nothing");
    assert!(!env.set_dir().exists());

    cat.sets[0].sources[0].est = 799.0;
    assert_eq!(env.sync(&cat).state, JobState::Done);
    assert_eq!(env.status()["state"].as_str(), Some("ok"));
}

#[test]
fn keep_prunes_and_unchanged_files_are_hard_links() {
    let env = Env::new();
    let cat = catalog(
        2,
        vec![env.fixed("same", "d/a.bin"), env.fixed("moving", "d/b.bin")],
    );
    let a = crate::net::testserver::body(64 << 10, 3);
    let mut served_a = 0;
    for round in 1..=3u8 {
        env.routes(&[("d/a.bin", &a), ("d/b.bin", &[round; 100])]);
        // An unsigned file that changed is only taken once the user accepted it.
        let _ = std::fs::remove_file(&env.paths.tofu);
        let before = env.srv.served();
        let job = env.sync(&cat);
        assert_eq!(job.state, JobState::Done, "round {round}: {:?}", job.error);
        if env.srv.served() - before >= a.len() as u64 {
            served_a += 1;
        }
    }
    assert_eq!(served_a, 1, "the unchanged file is downloaded once");
    let versions = version_dirs(&env.set_dir());
    assert_eq!(versions.len(), 2, "{versions:?}");
    assert!(
        versions[0].ends_with("-3") && versions[1].ends_with("-2"),
        "{versions:?}"
    );
    let (new, old) = (
        env.set_dir().join(&versions[0]),
        env.set_dir().join(&versions[1]),
    );
    assert_eq!(std::fs::read(new.join("moving/b.bin")).unwrap(), [3u8; 100]);
    assert_eq!(std::fs::read(old.join("moving/b.bin")).unwrap(), [2u8; 100]);
    assert_eq!(std::fs::read(new.join("same/a.bin")).unwrap(), a);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let ino = |d: &Path, f: &str| std::fs::metadata(d.join(f)).unwrap().ino();
        assert_eq!(ino(&new, "same/a.bin"), ino(&old, "same/a.bin"));
        assert_ne!(ino(&new, "moving/b.bin"), ino(&old, "moving/b.bin"));
    }
    // The linked file keeps its verdict and its hash line.
    let sf = read_set_file(&new.join("SET.toml"));
    assert_eq!(sf.entries.len(), 2);
    assert!(
        sf.entries.iter().all(|e| e.verify == "tofu"),
        "{:?}",
        sf.entries
    );
    let sums = std::fs::read_to_string(new.join("SHA256SUMS")).unwrap();
    assert!(sums.contains(&format!("{}  same/a.bin\n", hex(&Sha256::digest(&a)))));
    assert_eq!(files(&env.set_dir().join(".staging")), Vec::<String>::new());
    assert!(env.notes.lock().unwrap().is_empty());
}

#[test]
fn unsigned_file_that_changes_under_the_same_version_is_refused() {
    let env = Env::new();
    // A listing takes the version from the name, so new bytes under an old name are a change.
    let page = br#"<a href="pkg-1.0.tar">pkg</a>"#;
    let mut src = env.fixed("src", "d/");
    src.resolve = Some(Resolve::Listing);
    src.url = env.srv.url("d/");
    src.urls.clear();
    src.pattern = r"^pkg-([\d.]+)\.tar$".into();
    let mut cat = catalog(1, vec![src]);
    env.routes(&[("d/", page), ("d/pkg-1.0.tar", b"first")]);
    assert_eq!(env.sync(&cat).state, JobState::Done);
    let versions = version_dirs(&env.set_dir());
    assert!(env.paths.tofu.exists());

    // The plan is the same, so the visible version is left alone: add a file to force a look.
    env.routes(&[
        ("d/", page),
        ("d/pkg-1.0.tar", b"second"),
        ("d/extra", b"e"),
    ]);
    assert_eq!(env.status()["state"].as_str(), Some("ok"));
    cat.sets[0].sources.push(env.fixed("extra", "d/extra"));
    std::fs::remove_dir_all(env.set_dir().join(&versions[0])).unwrap();
    let job = env.sync(&cat);
    assert_eq!(job.state, JobState::Failed);
    assert!(job.error.unwrap().contains("tofu: "));
    assert_eq!(version_dirs(&env.set_dir()), Vec::<String>::new());
    let notes = env.notes.lock().unwrap().clone();
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert!(
        notes[0].starts_with("Unsigned download changed: "),
        "{}",
        notes[0]
    );
}

#[test]
fn sets_without_work_are_skipped() {
    let env = Env::new();
    let off = Source {
        enabled: Some(false),
        todo: "later".into(),
        ..env.fixed("off", "d/a.bin")
    };
    let git = Source {
        name: "repo".into(),
        kind: Some(Kind::Repo),
        url: "https://example.invalid/r.git".into(),
        ..Source::default()
    };
    let job = env.sync(&catalog(2, vec![off.clone()]));
    assert_eq!(job.state, JobState::Done);
    let st = env.status();
    assert_eq!(st["state"].as_str(), Some("skipped"));
    assert_eq!(st["detail"].as_str(), Some("no enabled sources"));

    env.sync(&catalog(2, vec![off, git]));
    let st = status::Status::read(&env.paths.status_file("public"));
    let row = st.sets.iter().find(|s| s["name"] == "demo/repo").unwrap();
    assert_eq!(row["state"].as_str(), Some("failed"));
    assert!(
        row["detail"].as_str().unwrap().contains("needs a format"),
        "{row}"
    );
    assert!(env.srv.hits().is_empty());
}

#[test]
fn resolve_failure_fails_the_job() {
    let env = Env::new();
    let mut src = env.fixed("src", "d/");
    src.resolve = Some(Resolve::Listing);
    src.url = env.srv.url("missing/");
    src.pattern = "x".into();
    let job = env.sync(&catalog(2, vec![src]));
    assert_eq!(job.state, JobState::Failed);
    assert!(job.error.unwrap().contains("src: resolve: "));
    assert_eq!(env.status()["state"].as_str(), Some("failed"));
}

#[test]
fn enqueue_reuses_waiting_jobs_and_drops_finished_ones() {
    let env = Env::new();
    let cat = catalog(2, Vec::new());
    let drive: DriveId = "0123-ABCD".parse().unwrap();
    let sets = [&cat.sets[0]];
    let first = enqueue_all(&env.store, &sets, &drive, false, &|_| false).unwrap();
    assert_eq!(
        enqueue_all(&env.store, &sets, &drive, false, &|_| false).unwrap(),
        first
    );
    let mut job = env.store.job(&first[0].1).unwrap();
    job.state = JobState::Done;
    env.store.save(&mut job).unwrap();
    // Without the worker lock a finished job is left for the worker to tidy.
    let second = enqueue_all(&env.store, &sets, &drive, false, &|_| false).unwrap();
    assert_ne!(second, first);
    assert_eq!(env.store.jobs().unwrap().len(), 2);
    assert_eq!(
        enqueue_all(&env.store, &sets, &drive, true, &|_| false).unwrap(),
        second
    );
    assert_eq!(env.store.jobs().unwrap().len(), 1);
}

#[test]
fn enqueue_while_the_daemon_works_retries_a_stopped_job_through_its_control() {
    let env = Env::new();
    let cat = catalog(2, Vec::new());
    let drive: DriveId = "0123-ABCD".parse().unwrap();
    let sets = [&cat.sets[0]];
    let ids = enqueue_all(&env.store, &sets, &drive, false, &|_| false).unwrap();
    let retries = || env.store.control(Some(&ids[0].1)).retry;
    assert_eq!(
        enqueue_all(&env.store, &sets, &drive, false, &|_| false).unwrap(),
        ids
    );
    assert_eq!(retries(), 0, "a queued job needs no retry");
    for (n, state) in [
        JobState::Failed,
        JobState::Blocked(crate::queue::BlockReason::DriveAbsent),
    ]
    .into_iter()
    .enumerate()
    {
        // The worker applied every earlier retry before the job stopped again.
        let mut job = env.store.job(&ids[0].1).unwrap();
        job.state = state;
        job.retry_seen = retries();
        env.store.save(&mut job).unwrap();
        assert_eq!(
            enqueue_all(&env.store, &sets, &drive, false, &|_| false).unwrap(),
            ids
        );
        assert_eq!(retries(), u32::try_from(n).unwrap() + 1, "{state:?}");
        enqueue_all(&env.store, &sets, &drive, false, &|_| false).unwrap();
        assert_eq!(
            retries(),
            u32::try_from(n).unwrap() + 1,
            "a pending retry is not asked again"
        );
    }
    assert_eq!(env.store.jobs().unwrap().len(), 1, "no new job was made");
}

#[test]
fn a_daemon_pass_skips_an_idle_queue_without_touching_the_status() {
    let env = Env::new();
    daemon_pass(&env.paths, Pass::FRESH).unwrap();
    assert!(!env.paths.status_file("public").exists());
    // A CLI run holds the queue: the pass leaves it alone, even with work waiting.
    let cat = catalog(2, Vec::new());
    let drive: DriveId = "0123-ABCD".parse().unwrap();
    enqueue_all(&env.store, &[&cat.sets[0]], &drive, false, &|_| false).unwrap();
    let _held = status::try_lock(&env.paths.lock_file("queue"))
        .unwrap()
        .unwrap();
    daemon_pass(&env.paths, Pass::FRESH).unwrap();
    assert!(!env.paths.status_file("public").exists());
}

#[test]
fn dry_run_lists_what_would_be_fetched() {
    let env = Env::new();
    env.routes(&[("d/a.bin", &[0u8; 2500])]);
    let off = Source {
        enabled: Some(false),
        todo: "needs a key".into(),
        ..env.fixed("off", "d/b.bin")
    };
    let gone = env.fixed("gone", "d/");
    let gone = Source {
        resolve: Some(Resolve::Listing),
        url: env.srv.url("missing/"),
        pattern: "x".into(),
        ..gone
    };
    let mut src = env.fixed("src", "d/a.bin");
    src.est = 100.0;
    let cat = catalog(2, vec![src, off, gone]);
    let mut out = Vec::new();
    env.with(&cat, (50 * GB, 1000 * GB), |p| {
        p.dry_run(&cat.sets[0], Some(&env.paths.mnt), &mut out)
            .unwrap();
    });
    let out = String::from_utf8(out).unwrap();
    assert!(
        out.starts_with("== demo (estimate 0.0 GB)\n   would skip: budget: "),
        "{out}"
    );
    assert!(
        out.contains(&format!("   0.00 GB  {}\n", env.srv.url("d/a.bin"))),
        "{out}"
    );
    assert!(
        out.contains("off                    disabled: needs a key\n"),
        "{out}"
    );
    assert!(out.contains("gone                   FAILED: "), "{out}");
    assert!(out.ends_with("   measured total 0.00 GB\n"), "{out}");
    assert!(
        !env.set_dir().exists(),
        "a dry run writes nothing to the drive"
    );
    assert!(env.store.jobs().unwrap().is_empty());
}

#[test]
fn a_changed_file_is_checked_against_the_current_sums_file() {
    let env = Env::new();
    let a = b"unchanged\n".to_vec();
    let sums = |b: &[u8]| {
        format!(
            "{}  a.bin\n{}  b.bin\n",
            hex(&Sha256::digest(&a)),
            hex(&Sha256::digest(b))
        )
    };
    // The unchanged file comes first, so its link of the old SUMS would be in place first.
    let src = Source {
        sums: "SUMS".into(),
        urls: vec![env.srv.url("d/a.bin"), env.srv.url("d/b.bin")],
        ..env.fixed("s", "d/a.bin")
    };
    let cat = catalog(2, vec![src]);
    for round in 1..=2u8 {
        let b = vec![round; 100];
        env.routes(&[
            ("d/a.bin", &a),
            ("d/b.bin", &b),
            ("d/SUMS", sums(&b).as_bytes()),
        ]);
        let job = env.sync(&cat);
        assert_eq!(job.state, JobState::Done, "round {round}: {:?}", job.error);
    }
    let versions = version_dirs(&env.set_dir());
    assert_eq!(versions.len(), 2, "{versions:?}");
    let new = env.set_dir().join(&versions[0]);
    assert_eq!(
        std::fs::read_to_string(new.join("s/SUMS")).unwrap(),
        sums(&[2; 100])
    );
    let sf = read_set_file(&new.join("SET.toml"));
    assert!(sf.entries.iter().all(|e| e.verify == "sums"), "{sf:?}");
}

#[test]
fn a_resumed_stage_counts_toward_the_budget_and_leftovers_stay_private() {
    let env = Env::new();
    let big = crate::net::testserver::body(100 << 10, 9);
    let data = b"the real release\n".to_vec();
    let sig = env.key.sign(&data);
    // A bad signature fails the job but leaves the plan (and so the stage) as it is.
    env.routes(&[
        ("d/x.bin", &big),
        ("d/r.bin", &data),
        ("d/r.bin.sig", &env.key.sign(b"other")),
    ]);
    let mut cat = catalog(
        2,
        vec![env.fixed("big", "d/x.bin"), env.signed("bad", "d/r.bin")],
    );
    assert_eq!(env.sync(&cat).state, JobState::Failed);

    // What a crash leaves behind: bookkeeping and an earlier attempt's set files.
    let staging = env.set_dir().join(".staging");
    let stage = std::fs::read_dir(&staging)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(stage.join("big/x.bin").is_file());
    for stray in [
        "SET.toml",
        "SHA256SUMS",
        "big/x.bin.part.json",
        "big/x.bin.part.json.tmp",
    ] {
        std::fs::write(stage.join(stray), b"stale").unwrap();
    }

    // 100 GB free above the reserve and an estimate 50 kB over it: the 100 KiB already
    // staged makes it fit.
    env.routes(&[("d/x.bin", &big), ("d/r.bin", &data), ("d/r.bin.sig", &sig)]);
    #[expect(clippy::cast_precision_loss, reason = "test arithmetic")]
    let estimate = (100 * GB + 50_000) as f64 / 1e9;
    cat.sets[0].estimate = estimate;
    let served = env.srv.served();
    let job = env.sync_with(&cat, (200 * GB, 1000 * GB));
    assert_eq!(job.state, JobState::Done, "{:?}", job.error);
    assert_eq!(env.status()["state"].as_str(), Some("ok"));
    assert!(
        env.srv.served() - served < big.len() as u64,
        "the staged file is not fetched again"
    );

    let versions = version_dirs(&env.set_dir());
    let dir = env.set_dir().join(&versions[0]);
    assert_eq!(
        files(&dir),
        [
            "SET.toml",
            "SHA256SUMS",
            "bad/r.bin",
            "bad/r.bin.sig",
            "big/x.bin"
        ]
    );
    let sums = std::fs::read_to_string(dir.join("SHA256SUMS")).unwrap();
    assert_eq!(sums.lines().count(), 4, "{sums}");
    for l in sums.lines() {
        let (h, rel) = l.split_once("  ").unwrap();
        assert_eq!(
            h,
            hex(&Sha256::digest(std::fs::read(dir.join(rel)).unwrap())),
            "{rel}"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_symlink_on_the_drive_is_refused_and_nothing_behind_it_is_touched() {
    let env = Env::new();
    env.routes(&[("d/x.bin", b"payload")]);
    let cat = catalog(1, vec![env.fixed("src", "d/x.bin")]);
    let victim = env.paths.mnt.join("victim");
    std::fs::create_dir_all(victim.join("keep")).unwrap();
    std::fs::write(victim.join("keep/file"), b"mine").unwrap();
    std::fs::create_dir_all(env.set_dir()).unwrap();
    for link in [
        env.set_dir().join(".staging"),
        env.set_dir().parent().unwrap().join("other"),
    ] {
        std::os::unix::fs::symlink(&victim, &link).unwrap();
    }
    let job = env.sync(&cat);
    assert_eq!(job.state, JobState::Failed);
    assert!(job.error.unwrap().contains("not a plain directory"));
    assert_eq!(files(&victim), ["keep/file"]);

    // A link that replaces the set directory itself is refused the same way.
    std::fs::remove_file(env.set_dir().join(".staging")).unwrap();
    std::fs::remove_dir(env.set_dir()).unwrap();
    std::os::unix::fs::symlink(&victim, env.set_dir()).unwrap();
    assert_eq!(env.sync(&cat).state, JobState::Failed);
    assert_eq!(files(&victim), ["keep/file"]);
}

#[test]
fn list_measures_the_newest_version_per_variant() {
    let tmp = TempDir::new();
    let cat = Catalog::embedded().unwrap();
    let text = list_text(&cat, None, &status::Status::default()).unwrap();
    assert!(
        text.find("keys").unwrap() < text.find("extras").unwrap(),
        "{text}"
    );
    assert!(
        text.contains("netinst") && text.contains("measured -"),
        "{text}"
    );

    let v = Public::public_dir(tmp.path()).join("isos/2026-11-01");
    std::fs::create_dir_all(&v).unwrap();
    std::fs::write(v.join("SET.toml"), "").unwrap();
    let text = list_text(&cat, Some(tmp.path()), &status::Status::default()).unwrap();
    let isos = text
        .lines()
        .skip_while(|l| !l.starts_with("isos"))
        .collect::<Vec<_>>();
    assert!(isos[0].contains("newest 2026-11-01"), "{text}");
    assert!(isos[1].contains("measured 0"), "{text}");
}

pub(super) fn mirror(name: &str, kind: Kind, est: f64) -> Source {
    Source {
        name: name.into(),
        kind: Some(kind),
        url: "https://example.invalid/m".into(),
        est,
        ..Source::default()
    }
}

#[test]
fn enqueue_all_makes_a_set_job_and_a_mirror_job_per_in_place_source() {
    let env = Env::new();
    let drive: DriveId = "0123-ABCD".parse().unwrap();
    let mut cat = catalog(
        2,
        vec![
            env.fixed("src", "d/a.bin"),
            mirror("g", Kind::Git, 1.0),
            mirror("r", Kind::Repo, 1.0),
            Source {
                enabled: Some(false),
                todo: "later".into(),
                ..mirror("off", Kind::Git, 1.0)
            },
        ],
    );
    let queue = |cat: &Catalog, skip: &dyn Fn(&JobKind) -> bool| {
        let sets: Vec<&Set> = cat.sets.iter().collect();
        enqueue_all(&env.store, &sets, &drive, false, skip).unwrap()
    };
    let first = queue(&cat, &|_| false);
    let names: Vec<&str> = first.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["demo", "demo/g", "demo/r"]);
    assert_eq!(queue(&cat, &|_| false), first, "waiting jobs are reused");
    assert_eq!(env.store.jobs().unwrap().len(), 3);

    let paused = JobKind::Mirror {
        set: "demo".into(),
        source: "g".into(),
    };
    let rest = queue(&cat, &|k| *k == paused);
    assert_eq!(rest.len(), 2, "a paused mirror is skipped: {rest:?}");

    cat.sets[0].sources.remove(0);
    let names: Vec<String> = queue(&cat, &|_| false)
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert_eq!(
        names,
        ["demo/g", "demo/r"],
        "repo-only sets get mirror jobs only"
    );
}

#[test]
fn the_set_budget_leaves_out_in_place_estimates() {
    let env = Env::new();
    env.routes(&[("d/a.bin", b"x")]);
    let mut cat = catalog(
        2,
        vec![env.fixed("src", "d/a.bin"), mirror("g", Kind::Git, 800.0)],
    );
    cat.sets[0].sources[0].est = 100.0;
    let job = env.sync_with(&cat, (900 * GB, 1000 * GB));
    assert_eq!(job.state, JobState::Done);
    assert_eq!(env.status()["state"].as_str(), Some("ok"));
    cat.sets[0].sources.remove(1);
    cat.sets[0].sources[0].est = 950.0;
    env.sync_with(&cat, (900 * GB, 1000 * GB));
    assert_eq!(env.status()["state"].as_str(), Some("skipped"));
}

#[test]
fn an_orphan_mirror_job_is_canceled() {
    let env = Env::new();
    let drive: DriveId = "0123-ABCD".parse().unwrap();
    let cat = catalog(2, vec![mirror("g", Kind::Repo, 1.0)]);
    let ids = enqueue_all(&env.store, &[&cat.sets[0]], &drive, true, &|_| false).unwrap();
    env.work_queue(&catalog(2, Vec::new()));
    assert_eq!(env.store.job(&ids[0].1).unwrap().state, JobState::Canceled);
    let st = status::Status::read(&env.paths.status_file("public"));
    assert_eq!(
        st.sets[0]["detail"].as_str(),
        Some("source no longer in the catalog")
    );
}

#[test]
fn record_mirror_drops_stale_rows_and_the_index_never_links_a_url() {
    let env = Env::new();
    let dir = env.paths.mnt.join("preserver/public/demo");
    std::fs::create_dir_all(&dir).unwrap();
    let row = |name: &str, url: &str| index::Mirror {
        name: name.into(),
        kind: "git".into(),
        url: url.into(),
        bytes: 5,
        files: Some(2),
        generation: Some("g1".into()),
        ..index::Mirror::default()
    };
    index::record_mirror(&dir, &["old", "g"], row("old", "https://a")).unwrap();
    index::record_mirror(&dir, &["g"], row("g", "javascript:alert(1)<b>")).unwrap();
    let text = std::fs::read_to_string(dir.join("MIRRORS.toml")).unwrap();
    assert!(!text.contains("old"), "{text}");
    assert!(text.contains("gen = \"g1\""), "{text}");
    index::record_mirror(&dir, &["g"], row("g", "https://b")).unwrap();
    let text = std::fs::read_to_string(dir.join("MIRRORS.toml")).unwrap();
    assert_eq!(text.matches("[[mirror]]").count(), 1, "{text}");

    index::record_mirror(&dir, &["g"], row("g", "javascript:alert(1)<b>")).unwrap();
    let cat = catalog(2, vec![mirror("g", Kind::Git, 1.0)]);
    index::write(&cat, &env.paths.mnt.join("preserver")).unwrap();
    let html = std::fs::read_to_string(env.paths.mnt.join("preserver/INDEX.html")).unwrap();
    assert!(html.contains("javascript:alert(1)&lt;b&gt;"), "{html}");
    assert!(!html.contains("href=\"javascript"), "{html}");
    assert!(html.contains("href=\"public/demo/git/g.git/\""), "{html}");
    index::write(&catalog(2, Vec::new()), &env.paths.mnt.join("preserver")).unwrap();
    let html = std::fs::read_to_string(env.paths.mnt.join("preserver/INDEX.html")).unwrap();
    assert!(
        !html.contains("javascript"),
        "a source that left the catalog has no row"
    );
}

#[test]
fn the_fat_decision_table() {
    for (fstype, est, refused) in [
        ("vfat", 4_000_000_000, true),
        ("vfat", 3_999_999_999, false),
        ("msdos", 100 * GB, true),
        ("exfat", 100 * GB, false),
        ("ext4", 100 * GB, false),
        ("", 100 * GB, false),
    ] {
        assert_eq!(fat_refuses(fstype, est), refused, "{fstype} {est}");
    }
}

#[test]
fn a_dry_run_probes_a_git_url() {
    let env = Env::new();
    let probe = "info/refs?service=git-upload-pack";
    let smart = (
        200,
        "Content-Type: application/x-git-upload-pack-advertisement\r\n".to_string(),
    );
    env.srv.set(|b| {
        b.replies.insert(format!("smart/{probe}"), smart);
        b.redirects.insert(
            format!("moved/{probe}"),
            "https://elsewhere.example/r.git/info/refs?service=x".into(),
        );
        b.routes = Some(HashMap::from([(format!("dumb/{probe}"), b"x".to_vec())]));
    });
    let mut cat = catalog(2, Vec::new());
    cat.sets[0].sources = ["smart", "moved", "dumb", "missing"]
        .map(|n| Source {
            url: env.srv.url(n),
            ..mirror(n, Kind::Git, 0.1)
        })
        .into();
    let mut out = Vec::new();
    env.with(&cat, (50 * GB, 1000 * GB), |p| {
        p.dry_run(&cat.sets[0], None, &mut out).unwrap();
    });
    let out = String::from_utf8(out).unwrap();
    for (name, said) in [
        ("smart", "ok"),
        ("moved", "redirect to elsewhere.example"),
        ("dumb", "not smart http"),
        ("missing", "HTTP 404"),
    ] {
        let line = out
            .lines()
            .find(|l| l.contains(&format!(" {name} ")))
            .unwrap();
        assert!(line.ends_with(&format!("GB): {said}")), "{line}");
    }
}

#[cfg(unix)]
#[test]
fn a_mirror_job_publishes_a_git_repo() {
    use crate::git::testcgi::{self, Cgi};
    use crate::net::throttle::Throttle;
    use crate::testutil::git;

    let mut env = Env::new();
    env.dl = Downloader::new(testcgi::agent(), Arc::new(Throttle::new(0)), CHECKPOINT);
    let remote = TempDir::new();
    let src = remote.path().join("src");
    std::fs::create_dir(&src).unwrap();
    git(&src, &["init", "-q", "-b", "main"]);
    std::fs::write(src.join("a"), "one").unwrap();
    git(&src, &["add", "a"]);
    git(&src, &["commit", "-q", "-m", "one"]);
    let want = git(&src, &["rev-parse", "HEAD"]);
    let cgi = Cgi::start(remote.path(), None);
    let g = Source {
        url: cgi.url("src"),
        license: "MIT".into(),
        ..mirror("g", Kind::Git, 0.001)
    };
    let cat = catalog(2, vec![g]);

    let job = env.sync(&cat);
    assert_eq!(job.state, JobState::Done, "{:?}", job.error);
    let repo = env.set_dir().join("git/g.git");
    assert_eq!(
        git(&repo, &["rev-parse", "refs/heads/main"]).trim(),
        want.trim()
    );
    let st = status::Status::read(&env.paths.status_file("public"));
    let row = st.sets.iter().find(|s| s["name"] == "demo/g").unwrap();
    assert_eq!(row["state"].as_str(), Some("ok"));
    assert_eq!(row["version"].as_str(), Some(&want.trim()[..7]));
    let rows = std::fs::read_to_string(env.set_dir().join("MIRRORS.toml")).unwrap();
    assert!(
        rows.contains("name = \"g\"") && rows.contains(&cgi.url("src")),
        "{rows}"
    );
    assert!(env.paths.mnt.join("preserver/INDEX.html").is_file());

    let job = env.sync(&catalog(
        2,
        vec![Source {
            url: cgi.url("nowhere"),
            ..mirror("g", Kind::Git, 0.001)
        }],
    ));
    assert_eq!(job.state, JobState::Failed);
    let st = status::Status::read(&env.paths.status_file("public"));
    let row = st.sets.iter().find(|s| s["name"] == "demo/g").unwrap();
    assert_eq!(row["state"].as_str(), Some("failed"));
}

const REL: &str = "dists/s/Release";
const LIST: &str = "dists/s/list";
const EXTRA: &str = "dists/s/extra";

/// A synthetic upstream. The Release is the anchor and names `list` and `extra` by hash and
/// size; `list` names the payload; the walk reads `list` only.
fn synth_anchor(ctx: &Ctx<'_>, src: &Source) -> Result<Anchor> {
    use crate::mirror::{Check, Entry, Meta};
    let doc = ctx
        .dl
        .get(&mirror::generation::url_of(&src.url, REL), 4096)?;
    let mut meta = Vec::new();
    for l in std::str::from_utf8(&doc)?.lines() {
        let f: Vec<&str> = l.split(' ').collect();
        let [name, h, size] = f[..] else {
            bail!("bad release line")
        };
        let check: Check = format!("sha256:{h}").parse().map_err(anyhow::Error::msg)?;
        meta.push(Meta {
            entry: Entry {
                path: format!("dists/s/{name}"),
                size: size.parse()?,
                check,
            },
            from: None,
        });
    }
    Ok(Anchor {
        docs: vec![(REL.into(), doc)],
        meta,
        swaps: vec!["dists/s".into()],
        ts: Vec::new(),
    })
}

fn synth_walk(
    _: &Source,
    _: &Anchor,
    meta: &Path,
    emit: &mut dyn FnMut(mirror::generation::Walked),
) -> Result<()> {
    use crate::mirror::{Entry, rel_path};
    for l in std::fs::read_to_string(rel_path(meta, LIST))?.lines() {
        let f: Vec<&str> = l.split(' ').collect();
        let [h, size, path] = f[..] else {
            bail!("bad list line")
        };
        emit(mirror::generation::Walked::File(Entry {
            path: path.into(),
            size: size.parse()?,
            check: format!("sha256:{h}").parse().map_err(anyhow::Error::msg)?,
        }));
    }
    Ok(())
}

fn synth_walk_meta<'a>(_: &Source, a: &'a Anchor) -> Vec<&'a mirror::Entry> {
    a.meta
        .iter()
        .map(|m| &m.entry)
        .filter(|e| e.path == LIST)
        .collect()
}

const SYNTH: Walkers = Walkers {
    anchor: synth_anchor,
    walk: synth_walk,
    walk_meta: synth_walk_meta,
};

fn sha_hex(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

/// Serves a repo under `repo/` with the given payload, and returns its source.
fn publish_repo(env: &Env, payload: &[(&str, &[u8])]) -> Source {
    let mut list = String::new();
    for (p, b) in payload {
        let _ = writeln!(list, "{} {} {p}", sha_hex(b), b.len());
    }
    let extra = b"not read by the walk".to_vec();
    let release = format!(
        "list {} {}\nextra {} {}\n",
        sha_hex(list.as_bytes()),
        list.len(),
        sha_hex(&extra),
        extra.len()
    );
    let mut routes = vec![
        (format!("repo/{REL}"), release.into_bytes()),
        (format!("repo/{LIST}"), list.into_bytes()),
        (format!("repo/{EXTRA}"), extra),
    ];
    routes.extend(
        payload
            .iter()
            .map(|(p, b)| (format!("repo/{p}"), b.to_vec())),
    );
    env.srv
        .set(|b| b.routes = Some(routes.into_iter().collect()));
    Source {
        name: "r".into(),
        kind: Some(Kind::Repo),
        format: Some(crate::catalog::RepoFormat::Alpine),
        url: env.srv.url("repo"),
        license: "MIT".into(),
        est: 0.001,
        ..Source::default()
    }
}

fn paths_hit(env: &Env) -> Vec<String> {
    env.srv.hits().into_iter().map(|h| h.path).collect()
}

fn mirror_row(env: &Env, name: &str) -> Option<serde_json::Value> {
    let st = status::Status::read(&env.paths.status_file("public"));
    st.sets.into_iter().find(|s| s["name"] == name)
}

#[test]
fn a_synthetic_repo_mirror_runs_end_to_end() {
    let mut env = Env::new();
    env.walkers = SYNTH;
    let src = publish_repo(&env, &[("pool/a", b"aaa"), ("pool/b/c", b"bc")]);
    let cat = catalog(2, vec![src]);

    let job = env.sync(&cat);
    assert_eq!(job.state, JobState::Done, "{:?}", job.error);
    let tree = env.set_dir().join("r");
    assert_eq!(std::fs::read(tree.join("pool/b/c")).unwrap(), b"bc");
    assert!(tree.join(REL).is_file() && tree.join(LIST).is_file() && tree.join(EXTRA).is_file());
    let head = read_header(&live_path(&tree)).unwrap().unwrap();
    assert_eq!((head.files, head.bytes), (2, 5));
    let row = mirror_row(&env, "demo/r").unwrap();
    assert_eq!(row["state"].as_str(), Some("ok"));
    assert_eq!(row["version"].as_str(), Some(&head.generation[..16]));
    let rows = std::fs::read_to_string(env.set_dir().join("MIRRORS.toml")).unwrap();
    assert!(
        rows.contains("kind = \"repo\"") && rows.contains("files = 2"),
        "{rows}"
    );
    let html = std::fs::read_to_string(env.paths.mnt.join("preserver/INDEX.html")).unwrap();
    assert!(html.contains("href=\"public/demo/r/\""), "{html}");

    env.srv.clear_log();
    let job = env.sync(&cat);
    assert_eq!(job.state, JobState::Done, "{:?}", job.error);
    assert_eq!(paths_hit(&env), ["repo/dists/s/Release"]);
}

#[test]
fn a_failed_repo_mirror_is_recorded_and_drops_its_generation() {
    let mut env = Env::new();
    env.walkers = SYNTH;
    let src = publish_repo(&env, &[("pool/a", b"aaa")]);
    env.srv.set(|b| {
        b.routes
            .as_mut()
            .unwrap()
            .insert("repo/pool/a".into(), b"evil".to_vec());
    });
    let cat = catalog(2, vec![src]);
    let job = env.sync(&cat);
    assert_eq!(job.state, JobState::Failed);
    assert_eq!(
        mirror_row(&env, "demo/r").unwrap()["state"].as_str(),
        Some("failed")
    );
    assert!(!env.set_dir().join("r").join(REL).exists());
    env.with(&cat, (GB, GB), |p| assert!(p.gens().is_empty()));
}

#[test]
fn the_dry_run_fetches_only_what_the_walk_reads() {
    let mut env = Env::new();
    env.walkers = SYNTH;
    let src = publish_repo(&env, &[("pool/a", b"aaa"), ("pool/b/c", b"bc")]);
    let cat = catalog(2, vec![src]);
    std::fs::create_dir_all(&env.paths.mnt).unwrap();
    let mut out = Vec::new();
    env.with(&cat, (900 * GB, 1000 * GB), |p| {
        p.dry_run(&cat.sets[0], Some(&env.paths.mnt), &mut out)
            .unwrap();
    });
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("2 files, 5 bytes"), "{text}");
    assert_eq!(
        paths_hit(&env),
        ["repo/dists/s/Release", "repo/dists/s/list"]
    );
    assert_eq!(files(&env.paths.mnt), Vec::<String>::new());
    assert_eq!(
        files(&env.paths.mirrors.with_file_name("repo-meta")),
        Vec::<String>::new()
    );
}

fn row_of(text: &str, n: &str) -> String {
    text.lines()
        .find(|l| l.trim_start().starts_with(n))
        .unwrap()
        .to_string()
}

#[test]
fn list_shows_repo_and_git_rows() {
    use crate::mirror::generation::{Header, write_tsv};
    let tmp = TempDir::new();
    let cat = catalog(
        2,
        vec![mirror("r", Kind::Repo, 1.0), mirror("g", Kind::Git, 1.0)],
    );
    let dir = Public::public_dir(tmp.path()).join("demo");
    let tree = dir.join("r");
    std::fs::create_dir_all(live_path(&tree).parent().unwrap()).unwrap();
    write_tsv(
        &live_path(&tree),
        Some(&Header {
            generation: "ab".repeat(32),
            files: 3,
            bytes: 3_000_000_000,
            at: Timestamp::now(),
            anchor_ts: Vec::new(),
        }),
        &[],
    )
    .unwrap();
    index::record_mirror(
        &dir,
        &["r", "g"],
        index::Mirror {
            name: "g".into(),
            kind: "git".into(),
            bytes: 2_000_000_000,
            ..index::Mirror::default()
        },
    )
    .unwrap();
    let mut st = status::Status::default();
    st.sets
        .push(serde_json::json!({"name": "demo/r", "state": "ok", "version": "abababababababab"}));
    st.sets
        .push(serde_json::json!({"name": "demo/g", "state": "ok", "version": "1234567"}));
    let text = list_text(&cat, Some(tmp.path()), &st).unwrap();
    assert!(
        row_of(&text, "r ").contains("mirror ok  gen abababababababab  3.00 GB"),
        "{text}"
    );
    assert!(
        row_of(&text, "g ").contains("mirror ok  gen 1234567  2.00 GB"),
        "{text}"
    );
    let text = list_text(&cat, None, &status::Status::default()).unwrap();
    assert!(row_of(&text, "r ").contains("mirror -  gen -  -"), "{text}");
}

#[test]
fn resolve_cached_across_replans() {
    let env = Env::new();
    env.routes(&[
        ("d/", br#"<a href="v1/">v1</a>"#),
        ("d/v1/", br#"<a href="f-1.tar.gz">f</a>"#),
    ]);
    let mut src = env.fixed("src", "d/");
    src.resolve = Some(Resolve::Listing);
    src.urls = Vec::new();
    src.url = env.srv.url("d/");
    src.dirs = r"^v\d+/$".into();
    src.pattern = r"^f-([\d.]+)\.tar\.gz$".into();
    let cat = catalog(2, vec![src]);
    env.with(&cat, (900 * GB, 1000 * GB), |p| {
        let first = p.resolve_set("job", &cat.sets[0]).unwrap();
        let listings = env.srv.hits().len();
        assert_eq!(listings, 2);
        let again = p.resolve_set("job", &cat.sets[0]).unwrap();
        assert_eq!(env.srv.hits().len(), listings, "a re-plan lists nothing");
        assert_eq!(first[0].1, again[0].1);
        p.resolve_set("other", &cat.sets[0]).unwrap();
        assert_eq!(env.srv.hits().len(), 2 * listings, "the cache is per job");
    });
}

#[test]
fn resolve_cache_survives_a_stop_and_ends_with_the_job() {
    let env = Env::new();
    env.routes(&[
        ("d/", br#"<a href="v1/">v1</a>"#),
        ("d/v1/", br#"<a href="f-1.tar.gz">f</a>"#),
    ]);
    let mut src = env.fixed("src", "d/");
    src.resolve = Some(Resolve::Listing);
    src.urls = Vec::new();
    src.url = env.srv.url("d/");
    src.dirs = r"^v\d+/$".into();
    src.pattern = r"^f-([\d.]+)\.tar\.gz$".into();
    let cat = catalog(2, vec![src]);
    let drive: DriveId = "0123-ABCD".parse().unwrap();
    let ids = enqueue_all(&env.store, &[&cat.sets[0]], &drive, true, &|_| false).unwrap();
    let mut job = env.store.job(&ids[0].1).unwrap();
    env.with(&cat, (900 * GB, 1000 * GB), |p| {
        p.resolve_set(&job.id, &cat.sets[0]).unwrap();
        let listings = env.srv.hits().len();
        for state in [
            JobState::Paused,
            JobState::Queued,
            JobState::Blocked(crate::queue::BlockReason::DriveAbsent),
        ] {
            job.state = state;
            p.settle(&mut job, &env.paths.mnt, &[]);
            p.resolve_set(&job.id, &cat.sets[0]).unwrap();
            assert_eq!(
                env.srv.hits().len(),
                listings,
                "{state:?} keeps the listing"
            );
        }
        job.state = JobState::Canceled;
        p.settle(&mut job, &env.paths.mnt, &[]);
        p.resolve_set(&job.id, &cat.sets[0]).unwrap();
        assert_eq!(
            env.srv.hits().len(),
            2 * listings,
            "a finished job starts over"
        );
    });
}
