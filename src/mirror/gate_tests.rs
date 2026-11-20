//! Gate fixtures: each repository format served from loopback and driven through `Public` and
//! the queue worker, the way `preserver public` runs it. A test body is written once and run
//! for Fedora, Alpine and Debian; the git gate follows.

use super::tests::{Env, GB, catalog};
use super::*;
use crate::catalog::RepoFormat;
use crate::mirror::alpine::Hash;
use crate::mirror::alpine::tests::{K2048, NAME, apk, entry, member, signed};
use crate::mirror::fedora::walk_tests::Site as Fedora;
use crate::mirror::generation::{crash, done_path, read_tsv};
use crate::mirror::rel_path;
use crate::mirror::testrepo::Site as Debian;
use crate::net::testserver::{Behaviour, Server};
use crate::platform::DriveAt;
use crate::queue::Planned;
use crate::resolve::hex;
use base64ct::{Base64, Encoding};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::path::PathBuf;

/// One upstream per format. Payload files are named `a`, `b`, ...; `path` says where the format
/// puts one in the tree, and the server serves it at `<prefix>/<path>`.
trait Upstream {
    fn start() -> Self;
    fn parts(&mut self) -> (&Server, &mut HashMap<String, Vec<u8>>);
    fn prefix(&self) -> &'static str;
    fn source(&self) -> Source;
    fn arm(&self, env: &mut Env);
    /// Serves revision `rev` of the repository with these payload files.
    fn put(&mut self, rev: u32, files: &[(&str, &[u8])]);
    fn path(&self, name: &str) -> String;
    /// A signed or TLS-anchored document, by its tree path.
    fn doc(&self) -> &'static str;

    fn route(&self, rel: &str) -> String {
        format!("{}/{rel}", self.prefix())
    }

    fn push(&mut self) {
        let (srv, routes) = self.parts();
        let routes = routes.clone();
        srv.set(|b| b.routes = Some(routes));
    }

    fn served(&mut self, rel: &str) -> Vec<u8> {
        let key = self.route(rel);
        self.parts().1[&key].clone()
    }

    /// Serves a body of the right length with its last byte flipped.
    fn corrupt(&mut self, name: &str) {
        let key = self.route(&self.path(name));
        *self.parts().1.get_mut(&key).unwrap().last_mut().unwrap() ^= 0x40;
        self.push();
    }

    fn remove(&mut self, name: &str) {
        let key = self.route(&self.path(name));
        self.parts().1.remove(&key).unwrap();
        self.push();
    }

    /// The paths requested since the last call.
    fn hits(&mut self) -> Vec<String> {
        let (srv, _) = self.parts();
        let paths = srv.hits().into_iter().map(|h| h.path).collect();
        srv.clear_log();
        paths
    }
}

fn licensed(src: &Source) -> Source {
    Source {
        license: "MIT".into(),
        est: 0.001,
        ..src.clone()
    }
}

impl Upstream for Fedora {
    fn start() -> Self {
        Fedora::new()
    }

    fn parts(&mut self) -> (&Server, &mut HashMap<String, Vec<u8>>) {
        (&self.srv, &mut self.routes)
    }

    fn prefix(&self) -> &'static str {
        "m"
    }

    fn source(&self) -> Source {
        licensed(&self.src)
    }

    fn arm(&self, env: &mut Env) {
        env.metalink = self.srv.url("meta");
    }

    fn put(&mut self, rev: u32, files: &[(&str, &[u8])]) {
        let repomd = self.repo(u64::from(rev), files);
        Fedora::publish(self, 100 + u64::from(rev), &repomd, None, &repomd);
    }

    fn path(&self, name: &str) -> String {
        format!("os/Packages/{name}")
    }

    fn doc(&self) -> &'static str {
        "os/repodata/repomd.xml"
    }
}

impl Upstream for Debian {
    fn start() -> Self {
        Debian::new(&["trixie"])
    }

    fn parts(&mut self) -> (&Server, &mut HashMap<String, Vec<u8>>) {
        (&self.srv, &mut self.routes)
    }

    fn prefix(&self) -> &'static str {
        "deb"
    }

    fn source(&self) -> Source {
        licensed(&self.src)
    }

    fn arm(&self, env: &mut Env) {
        env.ring = Some(self.key.public());
    }

    fn put(&mut self, rev: u32, files: &[(&str, &[u8])]) {
        Debian::publish(self, "trixie", i64::from(rev), files);
    }

    fn path(&self, name: &str) -> String {
        format!("pool/main/{name}")
    }

    fn doc(&self) -> &'static str {
        "dists/trixie/InRelease"
    }
}

struct Alpine {
    srv: Server,
    routes: HashMap<String, Vec<u8>>,
}

const ALPINE_DIR: &str = "v3.20/main/x86_64";

impl Upstream for Alpine {
    fn start() -> Self {
        Self {
            srv: Server::start("127.0.0.1", Behaviour::new(Vec::new())),
            routes: HashMap::new(),
        }
    }

    fn parts(&mut self) -> (&Server, &mut HashMap<String, Vec<u8>>) {
        (&self.srv, &mut self.routes)
    }

    fn prefix(&self) -> &'static str {
        "alp"
    }

    fn source(&self) -> Source {
        licensed(&Source {
            name: "a".into(),
            kind: Some(Kind::Repo),
            format: Some(RepoFormat::Alpine),
            url: self.srv.url("alp"),
            suites: vec!["v3.20".into()],
            components: vec!["main".into()],
            arches: vec!["x86_64".into()],
            ..Source::default()
        })
    }

    fn arm(&self, env: &mut Env) {
        env.rsa = Some((NAME.into(), K2048.pem.clone()));
    }

    fn put(&mut self, _rev: u32, files: &[(&str, &[u8])]) {
        let mut index = String::new();
        for (name, data) in files {
            let a = apk(&[], data, None);
            let _ = write!(
                index,
                "C:Q1{}\nP:{name}\nV:1-r0\nA:x86_64\nS:{}\n\n",
                Base64::encode_string(&a.q1),
                a.bytes.len()
            );
            let key = self.route(&self.path(name));
            self.routes.insert(key, a.bytes);
        }
        let second = member(&[("APKINDEX", index.as_bytes()), ("DESCRIPTION", b"main")]);
        let doc = signed(&K2048, Hash::Sha256, &entry(Hash::Sha256), &second);
        let key = self.route(self.doc());
        self.routes.insert(key, doc);
        self.push();
    }

    fn path(&self, name: &str) -> String {
        format!("{ALPINE_DIR}/{name}-1-r0.apk")
    }

    fn doc(&self) -> &'static str {
        "v3.20/main/x86_64/APKINDEX.tar.gz"
    }
}

type Files<'a> = &'a [(&'a str, &'a [u8])];

const FILES: Files = &[
    ("a", b"aaa"),
    ("b", b"bbb"),
    ("c", b"ccc"),
    ("d", b"ddd"),
    ("e", b"eee"),
];
/// The same names with other bytes, and one more file.
const CHANGED: Files = &[
    ("a", b"AAA"),
    ("b", b"BBB"),
    ("c", b"CCC"),
    ("d", b"DDD"),
    ("e", b"EEE"),
    ("z", b"ZZZ"),
];

type Hook<'a> = &'a (dyn Fn(&Job, &Planned) + Sync);

/// Asks for a pause (or a cancel) as soon as the first payload batch is handed out. The worker
/// checks for it whenever a file finishes, so the stop can land partway through the batch: at
/// least one file is done, and not all of them. A generation hands out two files per batch
/// under test.
fn halt(store: &Store, pause: bool) -> impl Fn(&Job, &Planned) + Sync {
    move |job, planned| {
        if planned.whole.is_some() {
            store
                .edit_control(Some(&job.id), |c| {
                    c.pause = pause;
                    c.cancel = !pause;
                })
                .unwrap();
        }
    }
}

struct Rig<U> {
    env: Env,
    up: U,
    cat: Catalog,
}

impl<U: Upstream> Rig<U> {
    fn new() -> Self {
        let mut env = Env::new();
        let up = U::start();
        up.arm(&mut env);
        let cat = catalog(2, vec![up.source()]);
        Self { env, up, cat }
    }

    fn tree(&self) -> PathBuf {
        self.env.set_dir().join(&self.cat.sets[0].sources[0].name)
    }

    /// One `public` run: enqueue the set (which resumes a paused or failed job) and work the
    /// queue. `hook` sees every batch the planner hands out.
    fn go_with(&self, hook: Hook<'_>) -> Job {
        let drive: DriveId = "0123-ABCD".parse().unwrap();
        let ids = enqueue_all(&self.env.store, &[&self.cat.sets[0]], &drive, true, &|_| {
            false
        })
        .unwrap();
        let e = &self.env;
        e.with(&self.cat, (900 * GB, 1000 * GB), |p| {
            Worker {
                store: &e.store,
                dl: &e.dl,
                plan: &|job: &Job, root: &Path, ok: &[usize]| {
                    let work = p.plan(job, root, ok)?;
                    if let Work::Fetch(planned) = &work {
                        hook(job, planned);
                    }
                    Ok(work)
                },
                settle: &|job, root, ok| p.settle(job, root, ok),
                drive: &|_| DriveAt::Mounted(e.paths.mnt.clone()),
                limit: &|| {},
            }
            .run(Pass::FRESH)
            .unwrap();
        });
        e.store.job(&ids[0].1).unwrap()
    }

    fn go(&self) -> Job {
        self.go_with(&|_, _| {})
    }

    fn done(&self) -> Vec<String> {
        read_tsv(&done_path(&self.tree()))
            .map(|t| t.entries.into_iter().map(|e| e.path).collect())
            .unwrap_or_default()
    }

    /// Every file a package manager can see, with its bytes; the bookkeeping is left out.
    fn visible(&self) -> BTreeMap<String, Vec<u8>> {
        let tree = self.tree();
        let mut out = BTreeMap::new();
        let mut todo = vec![tree.clone()];
        while let Some(d) = todo.pop() {
            for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
                let rel = e.path().strip_prefix(&tree).unwrap().to_path_buf();
                if rel.starts_with(".preserver") {
                    continue;
                }
                if e.file_type().unwrap().is_dir() {
                    todo.push(e.path());
                } else {
                    let rel = rel.to_string_lossy().replace('\\', "/");
                    out.insert(rel, std::fs::read(e.path()).unwrap());
                }
            }
        }
        out
    }

    fn generation(&self) -> String {
        read_header(&live_path(&self.tree()))
            .unwrap()
            .unwrap()
            .generation
    }

    fn payload_routes(&self, files: Files) -> Vec<String> {
        let mut v: Vec<String> = files
            .iter()
            .map(|(n, _)| self.up.route(&self.up.path(n)))
            .collect();
        v.sort();
        v
    }

    /// Every file of `files` is in the tree and is what the server serves for it.
    fn assert_tree(&mut self, files: Files) {
        let tree = self.tree();
        for (name, _) in files {
            let rel = self.up.path(name);
            let got = std::fs::read(tree.join(&rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
            assert_eq!(got, self.up.served(&rel), "{rel}");
        }
    }

    /// The first generation, paused after its first payload batch.
    fn paused(&mut self) -> Job {
        self.up.put(1, FILES);
        let job = self.go_with(&halt(&self.env.store, true));
        assert_eq!(job.state, JobState::Paused, "{:?}", job.error);
        let done = self.done();
        assert!(!done.is_empty() && done.len() < FILES.len(), "{done:?}");
        job
    }

    /// Generation one live, generation two served.
    fn two_generations(&mut self) {
        self.up.put(1, FILES);
        let job = self.go();
        assert_eq!(job.state, JobState::Done, "{:?}", job.error);
        self.up.put(2, CHANGED);
    }
}

fn a_tampered_payload_leaves_the_live_tree_byte_identical<U: Upstream>() {
    let mut r = Rig::<U>::new();
    r.up.put(1, FILES);
    assert_eq!(r.go().state, JobState::Done);
    let before = r.visible();
    r.up.put(2, CHANGED);
    // One changed file that was live and one new one, both with the right size.
    r.up.corrupt("a");
    r.up.corrupt("z");
    let job = r.go();
    assert_eq!(job.state, JobState::Failed, "{:?}", job.error);
    assert_eq!(r.visible(), before);
}

fn pause_then_resume_fetches_only_the_rest<U: Upstream>() {
    let mut r = Rig::<U>::new();
    r.paused();
    let done = r.done();
    r.up.hits();
    let job = r.go();
    assert_eq!(job.state, JobState::Done, "{:?}", job.error);
    let rest: Vec<String> = {
        let mut v: Vec<String> = FILES
            .iter()
            .map(|(n, _)| r.up.path(n))
            .filter(|p| !done.contains(p))
            .map(|p| r.up.route(&p))
            .collect();
        v.sort();
        v
    };
    let all = r.payload_routes(FILES);
    let mut got: Vec<String> =
        r.up.hits()
            .into_iter()
            .filter(|h| all.contains(h))
            .collect();
    got.sort();
    assert_eq!(got, rest);
    r.assert_tree(FILES);
}

fn a_crash_after_the_journal_is_written_is_recovered<U: Upstream>() {
    let mut r = Rig::<U>::new();
    r.two_generations();
    let old = r.generation();
    let tree = r.tree();
    crash::arm(&tree, 1);
    let job = r.go();
    assert_eq!(job.state, JobState::Failed, "{:?}", job.error);
    assert!(tree.join(".preserver/swap.json").is_file());
    r.up.hits();
    let job = r.go();
    assert_eq!(job.state, JobState::Done, "{:?}", job.error);
    assert!(!tree.join(".preserver/swap.json").exists());
    assert_ne!(r.generation(), old);
    r.assert_tree(CHANGED);
    let all = r.payload_routes(CHANGED);
    let payload: Vec<String> =
        r.up.hits()
            .into_iter()
            .filter(|h| all.contains(h))
            .collect();
    assert_eq!(payload, Vec::<String>::new());
}

fn an_unchanged_upstream_fetches_nothing<U: Upstream>() {
    let mut r = Rig::<U>::new();
    r.up.put(1, FILES);
    assert_eq!(r.go().state, JobState::Done);
    let before = r.visible();
    r.up.hits();
    let job = r.go();
    assert_eq!(job.state, JobState::Done, "{:?}", job.error);
    let hits = r.up.hits();
    // The anchor documents only: at most a metalink and a repomd.
    assert!(hits.len() <= 2, "{hits:?}");
    let all = r.payload_routes(FILES);
    assert!(hits.iter().all(|h| !all.contains(h)), "{hits:?}");
    assert_eq!(r.visible(), before);
}

fn a_cancel_keeps_the_live_tree<U: Upstream>() {
    let mut r = Rig::<U>::new();
    r.two_generations();
    r.up.put(1, FILES);
    let before = r.visible();
    let old = r.generation();
    r.up.put(2, CHANGED);
    let job = r.go_with(&halt(&r.env.store, false));
    assert_eq!(job.state, JobState::Canceled, "{:?}", job.error);
    assert_eq!(r.visible(), before);
    assert_eq!(r.generation(), old);
}

fn a_planted_stage_file_and_want_list_are_rejected<U: Upstream>() {
    let mut r = Rig::<U>::new();
    r.paused();
    let tree = r.tree();
    let staging = tree.join(".preserver/staging");
    let stage = std::fs::read_dir(&staging)
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    let planted = rel_path(&stage.path().join("meta"), r.up.doc());
    assert!(planted.is_file());
    std::fs::write(&planted, b"planted").unwrap();
    let bogus = format!("sha256:{}\t4\tevil\n", hex(&Sha256::digest(b"evil")));
    std::fs::write(tree.join(".preserver/want.tsv"), bogus).unwrap();
    r.up.hits();
    let job = r.go();
    assert_eq!(job.state, JobState::Done, "{:?}", job.error);
    assert!(!tree.join("evil").exists());
    assert!(r.up.hits().iter().all(|h| !h.contains("evil")));
    assert_eq!(
        std::fs::read(tree.join(r.up.doc())).unwrap(),
        r.up.served(r.up.doc())
    );
    r.assert_tree(FILES);
    assert!(!tree.join(".preserver/want.tsv").exists());
}

fn a_stale_file_and_a_failed_fetch_leave_no_done_line<U: Upstream>() {
    let mut r = Rig::<U>::new();
    r.up.put(1, &FILES[..3]);
    r.up.remove("b");
    let stale = r.tree().join(r.up.path("b"));
    std::fs::create_dir_all(stale.parent().unwrap()).unwrap();
    std::fs::write(&stale, b"stale and longer").unwrap();
    let job = r.go();
    assert_eq!(job.state, JobState::Failed, "{:?}", job.error);
    assert!(!stale.exists());
    assert!(!r.done().contains(&r.up.path("b")), "{:?}", r.done());
}

macro_rules! gates {
    ($($module:ident: $up:ty),*) => {$(
        mod $module {
            use super::*;

            #[test]
            fn tampered_payload() {
                a_tampered_payload_leaves_the_live_tree_byte_identical::<$up>();
            }

            #[test]
            fn pause_and_resume() {
                pause_then_resume_fetches_only_the_rest::<$up>();
            }

            #[test]
            fn crash_after_journal() {
                a_crash_after_the_journal_is_written_is_recovered::<$up>();
            }

            #[test]
            fn unchanged() {
                an_unchanged_upstream_fetches_nothing::<$up>();
            }

            #[test]
            fn cancel() {
                a_cancel_keeps_the_live_tree::<$up>();
            }

            #[test]
            fn planted_files() {
                a_planted_stage_file_and_want_list_are_rejected::<$up>();
            }

            #[test]
            fn stale_file() {
                a_stale_file_and_a_failed_fetch_leave_no_done_line::<$up>();
            }
        }
    )*};
}

gates!(fedora: Fedora, alpine: Alpine, debian: Debian);

/// A pack nobody has checked, planted in the drive's mirror and damaged, is refused by the next
/// job: its refs stay where they were and the job fails naming the pack.
#[cfg(unix)]
#[test]
fn an_unchecked_corrupt_planted_pack_is_refused() {
    use crate::git::testcgi::{self, Cgi};
    use crate::net::throttle::Throttle;
    use crate::testutil::{TempDir, git};
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let mut env = Env::new();
    env.dl = Downloader::new(testcgi::agent(), Arc::new(Throttle::new(0)), CHECKPOINT);
    let remote = TempDir::new();
    let src = remote.path().join("src");
    std::fs::create_dir(&src).unwrap();
    git(&src, &["init", "-q", "-b", "main"]);
    std::fs::write(src.join("a"), "one").unwrap();
    git(&src, &["add", "a"]);
    git(&src, &["commit", "-q", "-m", "one"]);
    let first = git(&src, &["rev-parse", "HEAD"]);
    let cgi = Cgi::start(remote.path(), None);
    let g = Source {
        url: cgi.url("src"),
        license: "MIT".into(),
        ..super::tests::mirror("g", Kind::Git, 0.001)
    };
    let cat = catalog(2, vec![g]);
    let job = env.sync(&cat);
    assert_eq!(job.state, JobState::Done, "{:?}", job.error);
    let repo = env.set_dir().join("git/g.git");

    std::fs::write(src.join("b"), "two").unwrap();
    git(&src, &["add", "b"]);
    git(&src, &["commit", "-q", "-m", "two"]);
    let revs = remote.path().join("revs");
    std::fs::write(&revs, "main\n").unwrap();
    let out = Command::new("git")
        .current_dir(&src)
        .args(["pack-objects", "--revs", "-q"])
        .arg(repo.join("objects/pack/pack"))
        .stdin(std::fs::File::open(&revs).unwrap())
        .output()
        .unwrap();
    assert!(out.status.success());
    let name = format!(
        "pack-{}.pack",
        String::from_utf8(out.stdout).unwrap().trim()
    );
    let pack = repo.join("objects/pack").join(&name);
    std::fs::set_permissions(&pack, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut bytes = std::fs::read(&pack).unwrap();
    let at = bytes.len() - 21;
    bytes[at] ^= 0x40;
    std::fs::write(&pack, bytes).unwrap();

    let job = env.sync(&cat);
    assert_eq!(job.state, JobState::Failed, "{:?}", job.error);
    let err = job.error.unwrap_or_default();
    assert!(err.contains(&format!("{name} failed the check")), "{err}");
    assert_eq!(
        git(&repo, &["rev-parse", "refs/heads/main"]).trim(),
        first.trim()
    );
}
