use super::versioned::{read_set_file, version_dirs};
use super::*;
use crate::catalog::{Kind, Resolve};
use crate::net::testserver::Server;
use crate::resolve::hex;
use crate::resolve::tests::{downloader, serve};
use crate::testutil::{TempDir, paths};
use crate::verify::testkey::TestKey;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

struct Env {
    _tmp: TempDir,
    paths: Paths,
    srv: Server,
    dl: Downloader,
    store: Store,
    key: TestKey,
    notes: Mutex<Vec<String>>,
}

const GB: u64 = 1_000_000_000;

impl Env {
    fn new() -> Self {
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
        }
    }

    fn routes(&self, routes: &[(&str, &[u8])]) {
        let map = routes
            .iter()
            .map(|(p, d)| ((*p).to_string(), d.to_vec()))
            .collect();
        self.srv.set(|b| b.routes = Some(map));
    }

    fn with<R>(&self, cat: &Catalog, free: (u64, u64), f: impl FnOnce(&Public) -> R) -> R {
        let ring = self.key.public();
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
                tofu: &self.paths.tofu,
                note: &note,
            },
            reserve_percent: 10,
            free: &free,
            staged: Mutex::new(HashMap::new()),
        })
    }

    /// One `public` run of the catalog's first set: enqueue, work the queue, return the job.
    fn sync_with(&self, cat: &Catalog, free: (u64, u64)) -> Job {
        let drive: DriveId = "0123-ABCD".parse().unwrap();
        let ids = enqueue(&self.store, &[&cat.sets[0]], &drive, true).unwrap();
        self.with(cat, free, |p| {
            Worker {
                store: &self.store,
                dl: &self.dl,
                plan: &|job, root| p.plan(job, root),
                settle: &|job, root| p.settle(job, root),
                drive: &|_| Some(self.paths.mnt.clone()),
            }
            .run(Pass::FRESH)
            .unwrap();
        });
        self.store.job(&ids[0]).unwrap()
    }

    fn sync(&self, cat: &Catalog) -> Job {
        self.sync_with(cat, (900 * GB, 1000 * GB))
    }

    fn set_dir(&self) -> PathBuf {
        self.paths.mnt.join("preserver/public/demo")
    }

    /// The set's line in status/public.json.
    fn status(&self) -> serde_json::Value {
        let st = status::Status::read(&self.paths.status_file("public"));
        assert_eq!(st.sets.len(), 1, "{:?}", st.sets);
        st.sets[0].clone()
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

fn catalog(keep: usize, sources: Vec<Source>) -> Catalog {
    Catalog {
        sets: vec![Set {
            name: "demo".into(),
            title: "Demo <set>".into(),
            usage: "For tests.".into(),
            priority: 0,
            estimate: 0.001,
            keep,
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
        cat.sets[0].estimate = estimate;
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

    cat.sets[0].estimate = 799.0;
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
        kind: Some(Kind::Git),
        url: "https://example.invalid/r.git".into(),
        ..Source::default()
    };
    for (sources, want) in [
        (vec![off.clone()], "no enabled sources"),
        (vec![off, git], "git and repo mirrors arrive in phase 3"),
    ] {
        let job = env.sync(&catalog(2, sources));
        assert_eq!(job.state, JobState::Done);
        let st = env.status();
        assert_eq!(st["state"].as_str(), Some("skipped"));
        assert_eq!(st["detail"].as_str(), Some(want));
    }
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
    let first = enqueue(&env.store, &sets, &drive, false).unwrap();
    assert_eq!(enqueue(&env.store, &sets, &drive, false).unwrap(), first);
    let mut job = env.store.job(&first[0]).unwrap();
    job.state = JobState::Done;
    env.store.save(&mut job).unwrap();
    // Without the worker lock a finished job is left for the worker to tidy.
    let second = enqueue(&env.store, &sets, &drive, false).unwrap();
    assert_ne!(second, first);
    assert_eq!(env.store.jobs().unwrap().len(), 2);
    assert_eq!(enqueue(&env.store, &sets, &drive, true).unwrap(), second);
    assert_eq!(env.store.jobs().unwrap().len(), 1);
}

#[test]
fn enqueue_while_the_daemon_works_retries_a_stopped_job_through_its_control() {
    let env = Env::new();
    let cat = catalog(2, Vec::new());
    let drive: DriveId = "0123-ABCD".parse().unwrap();
    let sets = [&cat.sets[0]];
    let ids = enqueue(&env.store, &sets, &drive, false).unwrap();
    let retries = || env.store.control(Some(&ids[0])).retry;
    assert_eq!(enqueue(&env.store, &sets, &drive, false).unwrap(), ids);
    assert_eq!(retries(), 0, "a queued job needs no retry");
    for (n, state) in [
        JobState::Failed,
        JobState::Blocked(crate::queue::BlockReason::DriveAbsent),
    ]
    .into_iter()
    .enumerate()
    {
        let mut job = env.store.job(&ids[0]).unwrap();
        job.state = state;
        env.store.save(&mut job).unwrap();
        assert_eq!(enqueue(&env.store, &sets, &drive, false).unwrap(), ids);
        assert_eq!(retries(), u32::try_from(n).unwrap() + 1, "{state:?}");
        // Holding the lock means the caller runs a fresh pass itself: no bump.
        assert_eq!(enqueue(&env.store, &sets, &drive, true).unwrap(), ids);
        assert_eq!(retries(), u32::try_from(n).unwrap() + 1, "{state:?}");
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
    enqueue(&env.store, &[&cat.sets[0]], &drive, false).unwrap();
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
    let cat = catalog(2, vec![env.fixed("src", "d/a.bin"), off, gone]);
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
