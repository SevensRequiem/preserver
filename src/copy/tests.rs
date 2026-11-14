#![cfg(unix)]

use super::*;
use crate::public::versioned::SetFile;
use crate::resolve::hex;
use crate::testutil::TempDir;
use std::fmt::Write as _;
use std::os::unix::fs::MetadataExt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize};

const PRIMARY: &str = "0123-ABCD";
const OTHER: &str = "4567-EF01";

/// A fake primary at `tmp/primary` and an empty target at `tmp/target`; the other drive
/// "mounts" at `tmp/target` while `plugged` is set.
struct Fake {
    tmp: TempDir,
    store: Store,
    plugged: AtomicBool,
    fstype: Mutex<String>,
    said: Mutex<String>,
}

impl Fake {
    fn new() -> Self {
        let tmp = TempDir::new();
        let src = tmp.path().join("primary/preserver");
        for (rel, data) in [
            ("github-repos-personal/o/r.bundle.age", "bundle"),
            ("local-personal/docs/2026-11/L0.tar.zst.age", "level 0"),
            ("kit/README", "read me"),
            ("kit/bin/tool", "#!/bin/sh\n"),
        ] {
            write(&src.join(rel), data.as_bytes());
        }
        std::os::unix::fs::symlink("README", src.join("kit/LINK")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", src.join("kit/out")).unwrap();
        std::fs::create_dir_all(tmp.path().join("target")).unwrap();
        std::fs::create_dir_all(tmp.path().join("queue")).unwrap();
        let f = Self {
            store: Store::new(tmp.path().join("queue")),
            tmp,
            plugged: AtomicBool::new(true),
            fstype: Mutex::new("ext4".into()),
            said: Mutex::new(String::new()),
        };
        f.version(
            "keys",
            "2026-11-01",
            &[
                ("gnu-keyring/a.gpg", b"key a"),
                ("fedora-keys/b.gpg", b"key b"),
            ],
        );
        f.version("specs", "2026-11-01", &[("intel-sdm/sdm.pdf", b"manual")]);
        f
    }

    fn primary(&self) -> PathBuf {
        self.tmp.path().join("primary")
    }

    fn target(&self) -> PathBuf {
        self.tmp.path().join("target")
    }

    fn dst(&self) -> PathBuf {
        self.target().join("preserver")
    }

    /// A set version on the primary as `public` leaves it: files, SET.toml, SHA256SUMS.
    fn version(&self, set: &str, version: &str, files: &[(&str, &[u8])]) {
        let dir = self
            .primary()
            .join("preserver/public")
            .join(set)
            .join(version);
        let mut sums = String::new();
        for (rel, data) in files {
            write(&dir.join(rel), data);
            writeln!(sums, "{}  {rel}", hex(&Sha256::digest(data))).unwrap();
        }
        let sf = SetFile {
            set: set.into(),
            version: version.into(),
            ..SetFile::default()
        };
        let toml = toml::to_string(&sf).unwrap();
        write(&dir.join("SET.toml"), toml.as_bytes());
        writeln!(sums, "{}  SET.toml", hex(&Sha256::digest(toml.as_bytes()))).unwrap();
        write(&dir.join("SHA256SUMS"), sums.as_bytes());
    }

    fn with_env<T>(&self, f: impl FnOnce(&Env) -> T) -> T {
        let mount = |id: &DriveId| {
            if id.matches(PRIMARY) {
                Some(self.primary())
            } else if id.matches(OTHER) && self.plugged.load(Ordering::Relaxed) {
                Some(self.target())
            } else {
                None
            }
        };
        let fstype = |_: &Target, _: &Path| self.fstype.lock().unwrap().clone();
        let say = |s: &str| self.said.lock().unwrap().push_str(s);
        f(&Env {
            mount: &mount,
            fstype: &fstype,
            free: &|_| Ok((1 << 40, 1 << 41)),
            cluster: &|_| 4096,
            say: &say,
        })
    }

    fn job(&self, target: Target, sets: &[&str]) -> Job {
        let cat = Catalog::embedded().unwrap();
        let tokens: Vec<String> = sets.iter().map(ToString::to_string).collect();
        let kind = JobKind::Copy {
            target,
            sets: rules::resolve_sets(&cat, &tokens).unwrap(),
            size: None,
            rule: None,
        };
        self.store
            .create(&kind, &PRIMARY.parse().unwrap(), ONE_OFF_PRIORITY)
            .unwrap()
    }

    fn dir_target(&self) -> Target {
        Target::Dir {
            path: self.target(),
        }
    }

    /// Queues a copy to the target directory and runs the lane; the job as it ended.
    fn copy(&self, sets: &[&str]) -> Job {
        let id = self.job(self.dir_target(), sets).id;
        self.with_env(|env| work(&self.store, env, Pass::FRESH))
            .unwrap();
        self.store.job(&id).unwrap()
    }
}

fn write(path: &Path, data: &[u8]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, data).unwrap();
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

fn ino(path: &Path) -> u64 {
    std::fs::metadata(path).unwrap().ino()
}

#[test]
fn copies_everything_and_a_rerun_writes_nothing() {
    let f = Fake::new();
    let job = f.copy(&["keys", "specs", "kit"]);
    assert_eq!(job.state, JobState::Done, "{:?}", job.error);
    let d = f.dst();
    assert_eq!(
        read(&d.join("public/keys/2026-11-01/gnu-keyring/a.gpg")),
        "key a"
    );
    assert_eq!(
        read(&d.join("public/specs/2026-11-01/intel-sdm/sdm.pdf")),
        "manual"
    );
    assert!(read(&d.join("public/keys/2026-11-01/SHA256SUMS")).contains("fedora-keys/b.gpg"));
    assert_eq!(
        read(&d.join("github-repos-personal/o/r.bundle.age")),
        "bundle"
    );
    assert_eq!(
        read(&d.join("local-personal/docs/2026-11/L0.tar.zst.age")),
        "level 0"
    );
    assert_eq!(
        std::fs::read_link(d.join("kit/LINK")).unwrap(),
        Path::new("README")
    );
    assert!(
        std::fs::symlink_metadata(d.join("kit/out")).is_err(),
        "a link out of the kit"
    );
    assert!(!d.join("kit.tar").exists());
    assert!(d.join("INDEX.html").is_file());
    assert!(d.join(STATE).is_file());
    assert!(job.progress.bytes_done > 0);

    let before = ino(&d.join("public/keys/2026-11-01/gnu-keyring/a.gpg"));
    let personal = ino(&d.join("github-repos-personal/o/r.bundle.age"));
    let again = f.copy(&["keys", "specs", "kit"]);
    assert_eq!(again.state, JobState::Done, "{:?}", again.error);
    assert_eq!(again.progress.bytes_done, 0);
    assert_eq!(
        ino(&d.join("public/keys/2026-11-01/gnu-keyring/a.gpg")),
        before
    );
    assert_eq!(
        ino(&d.join("github-repos-personal/o/r.bundle.age")),
        personal
    );
}

#[test]
fn kit_goes_as_a_tar_on_exfat() {
    let f = Fake::new();
    *f.fstype.lock().unwrap() = "exfat".into();
    let job = f.copy(&["kit"]);
    assert_eq!(job.state, JobState::Done, "{:?}", job.error);
    assert!(!f.dst().join("kit").exists());
    let mut tar = tar::Archive::new(std::fs::File::open(f.dst().join("kit.tar")).unwrap());
    let mut seen = Vec::new();
    for e in tar.entries().unwrap() {
        let mut e = e.unwrap();
        let path = e.path().unwrap().display().to_string();
        if path == "kit/README" {
            let mut s = String::new();
            std::io::Read::read_to_string(&mut e, &mut s).unwrap();
            assert_eq!(s, "read me");
        }
        if path == "kit/LINK" {
            assert_eq!(e.link_name().unwrap().unwrap(), Path::new("README"));
        }
        seen.push(path);
    }
    for want in ["kit/README", "kit/bin/tool", "kit/LINK"] {
        assert!(
            seen.iter().any(|p| p.trim_end_matches('/') == want),
            "{want}: {seen:?}"
        );
    }
    assert!(!seen.iter().any(|p| p.contains("out")), "{seen:?}");
    // Personal comes along by default; nothing else was asked for.
    assert!(
        f.dst()
            .join("github-repos-personal/o/r.bundle.age")
            .is_file()
    );
    assert!(!f.dst().join("public/keys").exists());
}

#[test]
fn fat32_skips_files_over_4_gib_and_says_so() {
    let f = Fake::new();
    *f.fstype.lock().unwrap() = "vfat".into();
    let vdir = f.primary().join("preserver/public/keys/2026-11-01");
    let huge = vdir.join("fedora-keys/huge.iso");
    std::fs::File::create(&huge)
        .unwrap()
        .set_len(plan::FAT_MAX + 1)
        .unwrap();
    // Never read: a FAT target never gets it.
    let mut sums = read(&vdir.join("SHA256SUMS"));
    writeln!(sums, "{}  fedora-keys/huge.iso", "ab".repeat(32)).unwrap();
    std::fs::write(vdir.join("SHA256SUMS"), sums).unwrap();

    let job = f.copy(&["keys"]);
    assert_eq!(job.state, JobState::Done, "{:?}", job.error);
    let said = f.said.lock().unwrap().clone();
    assert!(
        said.contains("huge.iso") && said.contains(plan::FAT_REASON),
        "{said}"
    );
    let t = f.dst().join("public/keys/2026-11-01");
    assert!(!t.join("fedora-keys/huge.iso").exists());
    assert_eq!(read(&t.join("fedora-keys/b.gpg")), "key b");
    assert!(!read(&t.join("SHA256SUMS")).contains("huge.iso"));
}

#[test]
fn an_interrupted_copy_leaves_the_old_version_whole() {
    let f = Fake::new();
    assert_eq!(f.copy(&["keys"]).state, JobState::Done);
    f.version(
        "keys",
        "2026-11-14",
        &[
            ("gnu-keyring/a.gpg", b"key a2"),
            ("fedora-keys/b.gpg", b"key b2"),
        ],
    );
    let job = f.job(f.dir_target(), &["keys"]);
    let calls = AtomicUsize::new(0);
    // Trips on the second chunk: one new file is staged, then the run stops.
    let stop = || calls.fetch_add(1, Ordering::Relaxed) >= 1;
    let err = f
        .with_env(|env| execute(&job, env, &stop, &Prog::default()))
        .unwrap_err();
    assert!(err.is::<Halted>(), "{err:#}");
    let keys = f.dst().join("public/keys");
    assert_eq!(version_dirs(&keys), ["2026-11-01"]);
    assert_eq!(read(&keys.join("2026-11-01/gnu-keyring/a.gpg")), "key a");
    assert_eq!(read(&keys.join("2026-11-01/fedora-keys/b.gpg")), "key b");
    assert!(keys.join(".staging").is_dir());

    let done = f.copy(&["keys"]);
    assert_eq!(done.state, JobState::Done, "{:?}", done.error);
    assert_eq!(version_dirs(&keys), ["2026-11-14"]);
    assert_eq!(read(&keys.join("2026-11-14/gnu-keyring/a.gpg")), "key a2");
    assert!(!keys.join(".staging").exists() || version_dirs(&keys.join(".staging")).is_empty());
}

#[test]
fn a_cancel_cleans_the_stage_and_a_pause_keeps_it() {
    let f = Fake::new();
    let job = f.job(f.dir_target(), &["keys"]);
    let stop = || true;
    let err = f
        .with_env(|env| execute(&job, env, &stop, &Prog::default()))
        .unwrap_err();
    assert!(err.is::<Halted>(), "{err:#}");
    f.with_env(|env| clean_up(env, &job));
    assert!(!f.dst().join("public/keys/.staging").exists());
    assert!(!f.dst().join("kit.tar.copying").exists());
}

#[test]
fn blocked_until_the_drive_is_plugged_in() {
    let f = Fake::new();
    f.plugged.store(false, Ordering::Relaxed);
    let target = Target::Drive {
        id: OTHER.parse().unwrap(),
        subdir: "backup".into(),
        label: "STICK".into(),
    };
    let id = f.job(target, &["specs"]).id;
    f.with_env(|env| work(&f.store, env, Pass::TICK)).unwrap();
    let job = f.store.job(&id).unwrap();
    assert_eq!(job.state, JobState::Blocked(BlockReason::DriveAbsent));
    assert_eq!(job.attempts, 0);

    f.plugged.store(true, Ordering::Relaxed);
    f.with_env(|env| work(&f.store, env, Pass::TICK)).unwrap();
    assert!(
        matches!(f.store.job(&id).unwrap().state, JobState::Blocked(_)),
        "a tick leaves it"
    );
    let plug = Pass {
        retry_failed: false,
        retry_blocked: true,
    };
    f.with_env(|env| work(&f.store, env, plug)).unwrap();
    let job = f.store.job(&id).unwrap();
    assert_eq!(job.state, JobState::Done, "{:?}", job.error);
    let t = f
        .target()
        .join("backup/preserver/public/specs/2026-11-01/intel-sdm/sdm.pdf");
    assert_eq!(read(&t), "manual");
}

#[test]
fn dry_run_writes_nothing() {
    let f = Fake::new();
    let cat = Catalog::embedded().unwrap();
    let sets = rules::resolve_sets(&cat, &["keys".into(), "kit".into()]).unwrap();
    let primary: DriveId = PRIMARY.parse().unwrap();
    let text = f
        .with_env(|env| dry_run(env, &primary, &f.dir_target(), &sets, None))
        .unwrap();
    assert!(text.contains("keys"), "{text}");
    assert_eq!(std::fs::read_dir(f.target()).unwrap().count(), 0);

    f.plugged.store(false, Ordering::Relaxed);
    let absent = Target::Drive {
        id: OTHER.parse().unwrap(),
        subdir: String::new(),
        label: String::new(),
    };
    let err = f
        .with_env(|env| dry_run(env, &primary, &absent, &sets, None))
        .unwrap_err();
    assert!(format!("{err:#}").contains("--size"), "{err:#}");
    let text = f
        .with_env(|env| dry_run(env, &primary, &absent, &sets, Some(16_000_000_000)))
        .unwrap();
    assert!(text.contains("not connected"), "{text}");
    assert_eq!(std::fs::read_dir(f.target()).unwrap().count(), 0);
}

#[test]
fn refuses_an_archive_it_did_not_make_and_the_primary() {
    let f = Fake::new();
    write(&f.dst().join("public/keys/x"), b"someone else's");
    let job = f.copy(&["keys"]);
    assert_eq!(job.state, JobState::Failed);
    assert!(
        job.error.as_deref().unwrap().contains("did not make"),
        "{:?}",
        job.error
    );
    assert_eq!(read(&f.dst().join("public/keys/x")), "someone else's");

    let inside = Target::Dir {
        path: f.primary().join("preserver/kit"),
    };
    let id = f.job(inside, &["keys"]).id;
    f.with_env(|env| work(&f.store, env, Pass::FRESH)).unwrap();
    let job = f.store.job(&id).unwrap();
    assert_eq!(job.state, JobState::Failed);
    assert!(
        job.error.as_deref().unwrap().contains("overlaps"),
        "{:?}",
        job.error
    );
}

#[test]
fn record_writes_status_and_forgets_finished_jobs() {
    let f = Fake::new();
    let ok = f.copy(&["specs"]);
    let file = f.tmp.path().join("status/copy.json");
    let start = Timestamp::now() - jiff::SignedDuration::from_secs(3600);
    assert_eq!(
        record(&f.store, &file, start).unwrap(),
        Vec::<String>::new()
    );
    assert!(f.store.job(&ok.id).is_err());
    let st = Status::read(&file);
    assert_eq!(st.sets.len(), 1);
    assert_eq!(st.sets[0]["state"], "ok");
    assert!(last_runs(&file).contains_key(&ok.id));
}

fn fs(id: &str, label: &str, mount: Option<&Path>, removable: bool) -> FsInfo {
    FsInfo {
        device: "/dev/sdx1".into(),
        id: id.into(),
        label: label.into(),
        fstype: "exfat".into(),
        size: 0,
        mount: mount.map(Path::to_path_buf),
        removable,
    }
}

#[test]
fn targets_resolve_from_dirs_ids_and_labels() {
    let tmp = TempDir::new();
    let stick = tmp.path().join("stick");
    let plain = tmp.path().join("plain");
    std::fs::create_dir_all(stick.join("sub")).unwrap();
    std::fs::create_dir_all(&plain).unwrap();
    let primary: DriveId = PRIMARY.parse().unwrap();
    let fss = [
        fs(PRIMARY, "BACKUP", None, false),
        fs(OTHER, "STICK", Some(&stick), true),
        fs("89AB-CDEF", "TWIN", None, true),
        fs("1111-2222", "TWIN", None, true),
    ];
    let r = |arg: &str| resolve_target(arg, &fss, &primary, None);

    match r(&stick.join("sub").display().to_string()).unwrap() {
        Target::Drive { id, subdir, label } => {
            assert!(id.matches(OTHER));
            assert_eq!((subdir.as_str(), label.as_str()), ("sub", "STICK"));
        }
        t @ Target::Dir { .. } => panic!("{t:?}"),
    }
    assert!(matches!(
        r(&plain.display().to_string()).unwrap(),
        Target::Dir { .. }
    ));
    assert!(matches!(r("STICK").unwrap(), Target::Drive { id, .. } if id.matches(OTHER)));
    assert!(matches!(r(OTHER).unwrap(), Target::Drive { .. }));
    assert!(matches!(r("ABCD-0001").unwrap(), Target::Drive { label, .. } if label.is_empty()));
    assert!(format!("{:#}", r("TWIN").unwrap_err()).contains("more than one"));
    assert!(format!("{:#}", r(PRIMARY).unwrap_err()).contains("primary"));
    assert!(format!("{:#}", r("BACKUP").unwrap_err()).contains("primary"));
    assert!(format!("{:#}", r("no-such-thing").unwrap_err()).contains("no such"));
    let err = resolve_target(
        &plain.display().to_string(),
        &fss,
        &primary,
        Some(tmp.path()),
    );
    assert!(format!("{:#}", err.unwrap_err()).contains("overlaps"));
}

#[test]
fn list_shows_rules_and_jobs() {
    let f = Fake::new();
    assert!(list_text(&[], &[], &HashMap::new()).contains("no copy rules"));
    let target = f.dir_target();
    let rule = rules::Rule {
        id: rules::rule_id(&target),
        interval: 86_400,
        sets: vec!["keys".into()],
        size: Some(32_000_000_000),
        target,
    };
    let job = f.job(f.dir_target(), &["keys"]);
    let text = list_text(
        std::slice::from_ref(&rule),
        std::slice::from_ref(&job),
        &HashMap::new(),
    );
    assert!(
        text.contains(&rule.id) && text.contains("24:00:00") && text.contains("never"),
        "{text}"
    );
    assert!(text.contains(&job.id), "{text}");
}
