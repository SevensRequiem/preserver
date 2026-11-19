//! A bare mirror of a remote's branches and tags. gix fetches into `refs/staged/*`; one ref
//! transaction then publishes, prunes and drops the staged refs, so a reader sees the old refs
//! or the new ones and never refs whose objects have not been checked.

use crate::git::http;
use crate::platform;
use anyhow::{Context, Result, bail};
use gix::ObjectId;
use gix::bstr::BString;
use gix::lock::acquire::Fail;
use gix::objs::ObjectRef;
use gix::odb::pack::{self, index::traverse};
use gix::protocol::fetch::RefMap;
use gix::protocol::handshake::Ref;
use gix::protocol::transport::Protocol;
use gix::protocol::transport::client::blocking_io::{Transport, ssh};
use gix::refs::file::transaction::PackedRefs;
use gix::refs::transaction::{Change, LogChange, PreviousValue, RefEdit, RefLog};
use gix::refs::{FullName, Target};
use gix::remote::Direction;
use gix::remote::fetch::Tags;
use gix::url::Scheme;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

pub(crate) enum Via<'a> {
    /// `program` is run directly, never through a shell.
    Ssh { program: &'a Path },
    Https {
        http: http::Remote,
        token: Option<&'a str>,
    },
    #[cfg(test)]
    File,
}

/// Who wrote the packs already in the mirror: a drive anyone can write to, or this host's disk.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Trust {
    Drive,
    Host,
}

/// The whole config of every mirror: nothing a planted or phase-1 config said survives a run.
const CONFIG: &str =
    "[core]\n\trepositoryformatversion = 0\n\tbare = true\n\tlogallrefupdates = false\n";
const STAGED: &[u8] = b"refs/staged/";
/// The packs that passed the check, one file name per line. It sits on the same drive as the
/// packs and is trusted as much as they are.
const CHECKED: &str = "preserver-checked";
/// The most one object may make gix allocate, on fetch and in the check: an entry's declared
/// size is otherwise reserved and zero-filled as is. GitHub refuses files over 100 MiB.
const ALLOC_LIMIT: usize = 1 << 30;

/// Whether a token may be sent to `url`: https to exactly github.com, by the parser gix connects with.
pub(crate) fn token_for(url: &str) -> bool {
    gix::url::parse(url).is_ok_and(|u| {
        u.scheme == Scheme::Https
            && u.user().is_none()
            && u.password().is_none()
            && u.port.is_none()
            && u.host() == Some("github.com")
    })
}

/// Brings the bare repo at `dir` (created when missing) up to `url`'s branches, tags and HEAD.
/// A run with nothing new writes nothing. `stop` ends the transfer and keeps what was published.
pub(crate) fn update(
    dir: &Path,
    url: &str,
    via: Via<'_>,
    checked: Trust,
    stop: &AtomicBool,
    phase: &(dyn Fn(&str) + Sync),
) -> Result<()> {
    let parsed = gix::url::parse(url).with_context(|| format!("git URL {url:?}"))?;
    let scheme = match via {
        Via::Ssh { .. } => Scheme::Ssh,
        Via::Https { .. } => Scheme::Https,
        #[cfg(test)]
        Via::File => Scheme::File,
    };
    if parsed.scheme != scheme {
        bail!("{url}: not a {} URL", scheme.as_str());
    }
    if scheme == Scheme::Https && (parsed.user().is_some() || parsed.password().is_some()) {
        bail!("a git URL with credentials is refused");
    }
    neutralise(dir)?;
    sweep(dir)?;
    if matches!(checked, Trust::Host) {
        mark_host_packs(dir)?;
    }
    let repo = open(dir)?;
    // A staged ref whose objects are gone (a pack that failed the check, deleted by hand) would
    // make the fetch see no change and never bring them back.
    let mut gone = Vec::new();
    for r in repo.references()?.all()? {
        let r = r?;
        if r.name().as_bstr().starts_with(STAGED)
            && r.target().try_id().is_some_and(|id| !repo.has_object(id))
        {
            gone.push(edit(
                r.name().as_bstr(),
                Change::Delete {
                    expected: PreviousValue::Any,
                    log: RefLog::AndReference,
                },
            )?);
        }
    }
    if !gone.is_empty() {
        transact(&repo, gone)?;
    }
    let remote = repo
        .remote_at_without_url_rewrite(parsed.clone())?
        .with_refspecs(
            [
                "+refs/heads/*:refs/staged/heads/*",
                "+refs/tags/*:refs/staged/tags/*",
            ],
            Direction::Fetch,
        )?
        .with_fetch_tags(Tags::None);
    let transport: Box<dyn Transport + Send> = match via {
        Via::Ssh { program } => Box::new(ssh::connect(
            parsed,
            Protocol::V2,
            ssh::connect::Options {
                command: Some(program.into()),
                disallow_shell: true,
                kind: Some(ssh::ProgramKind::Ssh),
            },
            false,
        )?),
        Via::Https { http, token } => {
            let mut t = gix::protocol::transport::client::blocking_io::http::Transport::new_http(
                http,
                parsed,
                Protocol::V2,
                false,
            );
            if let Some(token) = token.filter(|_| token_for(url)) {
                gix::protocol::transport::client::TransportWithoutIO::set_identity(
                    &mut t,
                    gix::sec::identity::Account {
                        username: "x-access-token".into(),
                        password: token.into(),
                        oauth_refresh_token: None,
                    },
                )?;
            }
            Box::new(t)
        }
        #[cfg(test)]
        Via::File => Box::new(
            gix::protocol::transport::client::blocking_io::file::connect(
                parsed.path.clone(),
                Protocol::V2,
                false,
            )?,
        ),
    };
    // HEAD is listed only when asked for; it has no destination, so nothing writes it but us.
    let head =
        gix::refspec::parse("HEAD".into(), gix::refspec::parse::Operation::Fetch)?.to_owned();
    phase("listing refs");
    let prepare = remote
        .to_connection_with_transport(transport)
        // Never a prompt or a credential helper: the token, if any, is already set.
        .with_credentials(|_| {
            Err(gix::Error::from_error(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the remote asked for credentials (HTTP 401 or 403)",
            )))
        })
        .prepare_fetch(
            gix::progress::Discard,
            gix::remote::ref_map::Options {
                extra_refspecs: vec![head],
                ..Default::default()
            },
        )?;
    if edits(&repo, prepare.ref_map())?.is_empty() {
        // Nothing to publish, but a pack planted since the last run is still checked.
        return check_packs(dir, checked, repo.object_hash(), &[], stop, phase);
    }
    phase("fetching");
    let outcome = prepare
        .with_write_packed_refs_only(true)
        .receive(gix::progress::Discard, stop)?;
    let edits = edits(&repo, &outcome.ref_map)?;
    let tips: Vec<ObjectId> = edits
        .iter()
        .filter_map(|e| match &e.change {
            Change::Update {
                new: Target::Object(id),
                ..
            } => Some(*id),
            _ => None,
        })
        .collect();
    check_packs(dir, checked, repo.object_hash(), &tips, stop, phase)?;
    // Relaxed: the flag carries no data, and a stop seen one step late only publishes once more.
    if stop.load(Ordering::Relaxed) {
        bail!("stopped");
    }
    phase("publishing");
    platform::sync_fs(dir).context("sync")?;
    transact(&repo, edits)?;
    platform::sync_fs(dir).context("sync")?;
    Ok(())
}

fn transact(repo: &gix::Repository, edits: Vec<RefEdit>) -> Result<()> {
    repo.refs
        .transaction()
        .packed_refs(
            PackedRefs::DeletionsAndNonSymbolicUpdatesRemoveLooseSourceReference(Box::new(
                &repo.objects,
            )),
        )
        .prepare(edits, Fail::Immediately, Fail::Immediately)?
        .commit(None)?;
    Ok(())
}

/// `git for-each-ref --format='%(objectname) %(refname)'` without its last newline.
pub(crate) fn refs_state(dir: &Path) -> Result<Vec<u8>> {
    let repo = open(dir)?;
    let mut refs = Vec::new();
    for r in repo.references()?.all()? {
        let mut r = r?;
        let name = r.name().as_bstr().to_owned();
        if name.starts_with(b"refs/") {
            refs.push((name, r.follow_to_object()?.detach()));
        }
    }
    refs.sort();
    let mut out = Vec::new();
    for (name, id) in refs {
        if !out.is_empty() {
            out.push(b'\n');
        }
        out.extend_from_slice(id.to_hex().to_string().as_bytes());
        out.push(b' ');
        out.extend_from_slice(&name);
    }
    Ok(out)
}

fn open(dir: &Path) -> Result<gix::Repository> {
    let options = gix::open::Options::isolated()
        .config_overrides([format!("gitoxide.objects.allocLimit={ALLOC_LIMIT}")]);
    gix::open_opts(dir, options).with_context(|| format!("open {}", dir.display()))
}

/// Makes `dir` a bare repo whose behaviour comes from `CONFIG` alone: no alternates (objects
/// the drive would not hold), no commondir, whatever config was there before.
fn neutralise(dir: &Path) -> Result<()> {
    for sub in ["objects/pack", "objects/info", "refs"] {
        let path = dir.join(sub);
        std::fs::create_dir_all(&path).with_context(|| path.display().to_string())?;
    }
    if std::fs::symlink_metadata(dir.join("HEAD")).is_err() {
        replace(dir, "HEAD", b"ref: refs/heads/main\n")?;
    }
    let config = dir.join("config");
    let current = match std::fs::symlink_metadata(&config) {
        Ok(m) if m.is_file() => std::fs::read(&config).ok(),
        _ => None,
    };
    if current.as_deref() != Some(CONFIG.as_bytes()) {
        replace(dir, "config", CONFIG.as_bytes())?;
    }
    for planted in [
        "commondir",
        "objects/info/alternates",
        "objects/info/http-alternates",
    ] {
        remove(&dir.join(planted))?;
    }
    Ok(())
}

/// Replaces `dir/name` through a synced temp file, so a crash leaves the old text or the new.
fn replace(dir: &Path, name: &str, data: &[u8]) -> Result<()> {
    let tmp = dir.join(format!("{name}.preserver-tmp"));
    let path = dir.join(name);
    remove(&tmp)?;
    let mut f = File::create_new(&tmp).with_context(|| tmp.display().to_string())?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, &path).with_context(|| path.display().to_string())?;
    platform::sync_dir(dir).context("sync")?;
    Ok(())
}

fn remove(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => {
            Err(e).with_context(|| path.display().to_string())
        }
        _ => Ok(()),
    }
}

/// Removes what a killed run leaves behind: ref and config locks, which would fail every later
/// run, and half-written packs. The job lock is held, so nothing else is writing here.
fn sweep(dir: &Path) -> Result<()> {
    let lock = |n: &str| Path::new(n).extension().is_some_and(|e| e == "lock");
    sweep_dir(dir, false, &lock)?;
    sweep_dir(&dir.join("refs"), true, &lock)?;
    sweep_dir(&dir.join("objects/pack"), false, &|n| {
        n.starts_with(".tmp") || n.starts_with("tmp_")
    })
}

fn sweep_dir(dir: &Path, deep: bool, stale: &dyn Fn(&str) -> bool) -> Result<()> {
    for e in std::fs::read_dir(dir).with_context(|| dir.display().to_string())? {
        let e = e?;
        let path = e.path();
        // file_type does not follow a link, so a planted link to a directory is not entered.
        if e.file_type()?.is_dir() {
            if deep {
                sweep_dir(&path, true, stale)?;
            }
        } else if e.file_name().to_str().is_some_and(stale) {
            tracing::warn!("removing {} left by an earlier run", path.display());
            remove(&path)?;
        }
    }
    Ok(())
}

/// The pack check (D15): every pack not yet in `preserver-checked` has its pack and index
/// checksums verified and every object decoded and hashed, in delta-tree order, and every object
/// any of them names must be in a pack (or, on the host's disk, loose). Packs are recorded only
/// when all pass, so the checked packs stay closed under references and a new object's closure
/// is complete once its direct references are present. `tips` must be present as well.
fn check_packs(
    dir: &Path,
    trust: Trust,
    hash: gix::hash::Kind,
    tips: &[ObjectId],
    stop: &AtomicBool,
    phase: &(dyn Fn(&str) + Sync),
) -> Result<()> {
    let listed = read_checked(dir)?;
    let names = packs(dir)?;
    let pack_dir = dir.join("objects/pack");
    let mut indexes = Vec::with_capacity(names.len());
    for name in &names {
        let path = pack_dir.join(name).with_extension("idx");
        indexes
            .push(pack::index::File::at(&path, hash).with_context(|| path.display().to_string())?);
    }
    let present = |id: &gix::oid| {
        indexes.iter().any(|i| i.lookup(id).is_some())
            || matches!(trust, Trust::Host) && {
                let hex = id.to_hex().to_string();
                dir.join("objects")
                    .join(&hex[..2])
                    .join(&hex[2..])
                    .is_file()
            }
    };
    let unchecked: Vec<usize> = (0..names.len())
        .filter(|&i| !listed.lines().any(|l| l == names[i]))
        .collect();
    let total: u64 = unchecked
        .iter()
        .map(|&i| u64::from(indexes[i].num_objects()))
        .sum();
    let done = AtomicU64::new(0);
    for (n, &i) in unchecked.iter().enumerate() {
        let label = |k: u64| {
            format!(
                "checking pack {}/{}, objects {k}/{total}",
                n + 1,
                unchecked.len()
            )
        };
        phase(&label(done.load(Ordering::Relaxed)));
        let path = pack_dir.join(&names[i]);
        let data = pack::data::File::at(&path, hash).with_context(|| path.display().to_string())?;
        let result = watched(stop, |interrupt| {
            indexes[i].traverse(
                &data,
                &mut gix::progress::Discard,
                interrupt,
                |kind, bytes, entry, _| {
                    // Relaxed: a counter and a flag that carry no data with them.
                    if stop.load(Ordering::Relaxed) {
                        return Err(gix::Error::from_error(io::Error::other("stopped")));
                    }
                    let k = done.fetch_add(1, Ordering::Relaxed) + 1;
                    if k * 100 / total != (k - 1) * 100 / total {
                        phase(&label(k));
                    }
                    references(kind, bytes, hash, &mut |id| {
                        if present(&id) {
                            Ok(())
                        } else {
                            Err(gix::Error::from_error(io::Error::other(format!(
                                "{kind} {} names {id}, which no pack holds",
                                entry.oid
                            ))))
                        }
                    })
                },
                traverse::Options {
                    traversal: traverse::Algorithm::DeltaTreeLookup,
                    thread_limit: Some(1),
                    check: traverse::SafetyCheck::All,
                    alloc_limit_bytes: Some(ALLOC_LIMIT),
                    make_pack_lookup_cache: || pack::cache::Never,
                },
            )
        });
        if stop.load(Ordering::Relaxed) {
            bail!("stopped");
        }
        // Kept, as the plan decided; it fails every run until it is deleted.
        result.with_context(|| {
            format!(
                "pack {} failed the check (delete it and its .idx to fetch its objects again)",
                path.display()
            )
        })?;
    }
    if let Some(tip) = tips.iter().find(|t| !present(t)) {
        bail!("{tip} is to be published, but no pack holds it");
    }
    if !unchecked.is_empty() {
        let mut text = listed;
        for &i in &unchecked {
            text.push_str(&names[i]);
            text.push('\n');
        }
        replace(dir, CHECKED, text.as_bytes())?;
    }
    Ok(())
}

/// Calls `need` with every object the object in `bytes` names. A submodule's commit lives in
/// another repository and is not named here.
fn references(
    kind: gix::objs::Kind,
    bytes: &[u8],
    hash: gix::hash::Kind,
    need: &mut dyn FnMut(ObjectId) -> gix::Result<()>,
) -> gix::Result<()> {
    match ObjectRef::from_bytes(bytes, kind, hash)? {
        ObjectRef::Commit(c) => {
            need(c.tree())?;
            c.parents().try_for_each(need)
        }
        ObjectRef::Tree(t) => t
            .entries
            .iter()
            .filter(|e| !e.mode.is_commit())
            .try_for_each(|e| need(e.oid.to_owned())),
        ObjectRef::Tag(t) => need(t.target()),
        ObjectRef::Blob(_) => Ok(()),
    }
}

/// Runs `f` with an interrupt flag of its own that a watcher sets within 100 ms of `stop`. gix
/// sets the flag itself when a checksum fails, so `stop` must not be handed to it; and hashing
/// the pack and index looks at that flag only, never at the per-object callback.
fn watched<T>(stop: &AtomicBool, f: impl FnOnce(&AtomicBool) -> T) -> T {
    let interrupt = AtomicBool::new(false);
    let (done_tx, done_rx) = mpsc::channel::<()>();
    std::thread::scope(|s| {
        let flag = &interrupt;
        s.spawn(move || {
            // Relaxed: the flags carry no data with them.
            while !stop.load(Ordering::Relaxed) {
                if done_rx.recv_timeout(Duration::from_millis(100))
                    != Err(RecvTimeoutError::Timeout)
                {
                    return;
                }
            }
            flag.store(true, Ordering::Relaxed);
        });
        let result = f(&interrupt);
        drop(done_tx);
        result
    })
}

/// On the first open of a mirror on this host's disk, its packs are taken as checked as they are.
fn mark_host_packs(dir: &Path) -> Result<()> {
    if std::fs::symlink_metadata(dir.join(CHECKED)).is_ok() {
        return Ok(());
    }
    let mut text = String::new();
    for name in packs(dir)? {
        text.push_str(&name);
        text.push('\n');
    }
    replace(dir, CHECKED, text.as_bytes())
}

fn read_checked(dir: &Path) -> Result<String> {
    match std::fs::read_to_string(dir.join(CHECKED)) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e).context(CHECKED),
    }
}

/// The packs git would read: `*.pack` files with an index next to them, sorted.
fn packs(dir: &Path) -> Result<Vec<String>> {
    let pack_dir = dir.join("objects/pack");
    let mut out = Vec::new();
    for e in std::fs::read_dir(&pack_dir).with_context(|| pack_dir.display().to_string())? {
        let e = e?;
        let name = e.file_name();
        if !name.as_encoded_bytes().ends_with(b".pack") {
            continue;
        }
        let Some(name) = name.to_str().filter(|n| !n.contains('\n')) else {
            bail!(
                "a pack named {} cannot be listed as checked",
                name.display()
            );
        };
        // Followed links count: git reads a pack through one.
        if pack_dir.join(name).is_file() && pack_dir.join(name).with_extension("idx").is_file() {
            out.push(name.to_owned());
        }
    }
    out.sort();
    Ok(out)
}

fn edit(name: &[u8], change: Change) -> Result<RefEdit> {
    Ok(RefEdit {
        change,
        name: FullName::try_from(BString::from(name))?,
        deref: false,
    })
}

fn set(name: &[u8], new: Target) -> Result<RefEdit> {
    edit(
        name,
        Change::Update {
            log: LogChange::default(),
            expected: PreviousValue::Any,
            new,
        },
    )
}

/// What turns the mirror's refs into the remote's: each staged ref under its own name, every
/// other ref deleted (staged ones included), and HEAD to the remote's HEAD when that is a
/// branch being published. Empty when the mirror already matches.
fn edits(repo: &gix::Repository, map: &RefMap) -> Result<Vec<RefEdit>> {
    let mut want = BTreeMap::<BString, ObjectId>::new();
    for m in &map.mappings {
        let (Some(local), Some(id)) = (&m.local, m.remote.as_id()) else {
            continue;
        };
        if let Some(rest) = local.strip_prefix(STAGED) {
            want.insert([b"refs/", rest].concat().into(), id.to_owned());
        }
    }
    let mut have = BTreeMap::<BString, Option<ObjectId>>::new();
    for r in repo.references()?.all()? {
        let r = r?;
        let name = r.name().as_bstr();
        if name.starts_with(b"refs/") {
            have.insert(name.to_owned(), r.target().try_id().map(ToOwned::to_owned));
        }
    }
    let mut out = Vec::new();
    for (name, id) in &want {
        if have.get(name) != Some(&Some(*id)) {
            out.push(set(name, Target::Object(*id))?);
        }
    }
    for name in have.keys().filter(|n| !want.contains_key(*n)) {
        out.push(edit(
            name,
            Change::Delete {
                expected: PreviousValue::Any,
                log: RefLog::AndReference,
            },
        )?);
    }
    let head = map.remote_refs.iter().find_map(|r| match r {
        Ref::Symbolic {
            full_ref_name,
            target,
            ..
        } if full_ref_name == "HEAD" => Some(target),
        _ => None,
    });
    if let Some(target) = head.filter(|t| t.starts_with(b"refs/heads/") && want.contains_key(*t))
        && repo.head_name()?.is_none_or(|n| n.as_bstr() != target)
    {
        out.push(set(
            b"HEAD",
            Target::Symbolic(FullName::try_from(target.clone())?),
        )?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{TempDir, git};
    use std::path::PathBuf;

    struct Fixture {
        _tmp: TempDir,
        src: PathBuf,
        mirror: PathBuf,
    }

    fn commit(src: &Path, file: &str, text: &str) {
        std::fs::write(src.join(file), text).unwrap();
        git(src, &["add", file]);
        git(src, &["commit", "-q", "-m", text]);
    }

    /// A source with two branches, a lightweight and an annotated tag.
    fn fixture() -> Fixture {
        let tmp = TempDir::new();
        let root = tmp.path().to_path_buf();
        let src = root.join("src");
        std::fs::create_dir(&src).unwrap();
        git(&src, &["init", "-q", "-b", "main"]);
        commit(&src, "a", "one");
        git(&src, &["tag", "v1"]);
        git(&src, &["checkout", "-q", "-b", "dev"]);
        commit(&src, "b", "two");
        git(&src, &["tag", "-a", "-m", "release", "v2"]);
        git(&src, &["checkout", "-q", "main"]);
        commit(&src, "a", "three");
        Fixture {
            mirror: root.join("m.git"),
            _tmp: tmp,
            src,
        }
    }

    impl Fixture {
        fn url(&self) -> String {
            self.src.display().to_string()
        }

        fn run(&self) -> Result<()> {
            let stop = AtomicBool::new(false);
            update(
                &self.mirror,
                &self.url(),
                Via::File,
                Trust::Drive,
                &stop,
                &|_| {},
            )
        }

        fn src_refs(&self) -> String {
            git(
                &self.src,
                &[
                    "for-each-ref",
                    "--format=%(objectname) %(refname)",
                    "refs/heads",
                    "refs/tags",
                ],
            )
        }

        /// The mirror holds exactly the source's branches and tags, all its objects, and HEAD.
        fn assert_mirrors(&self, head: &str) {
            let refs = git(
                &self.mirror,
                &["for-each-ref", "--format=%(objectname) %(refname)"],
            );
            assert_eq!(refs, self.src_refs());
            assert_eq!(refs_state(&self.mirror).unwrap(), refs.as_bytes());
            git(&self.mirror, &["fsck", "--strict", "--no-dangling"]);
            assert_eq!(git(&self.mirror, &["symbolic-ref", "HEAD"]), head);
        }

        fn packs(&self) -> usize {
            std::fs::read_dir(self.mirror.join("objects/pack"))
                .unwrap()
                .filter(|e| {
                    e.as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .ends_with(".pack")
                })
                .count()
        }
    }

    /// Every file under `dir` with its length, mtime and bytes.
    fn snapshot(dir: &Path) -> Vec<(PathBuf, std::time::SystemTime, Vec<u8>)> {
        let mut out = Vec::new();
        let mut todo = vec![dir.to_path_buf()];
        while let Some(d) = todo.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let e = e.unwrap();
                let m = e.metadata().unwrap();
                out.push((e.path(), m.modified().unwrap(), Vec::new()));
                if m.is_dir() {
                    todo.push(e.path());
                } else {
                    out.last_mut().unwrap().2 = std::fs::read(e.path()).unwrap();
                }
            }
        }
        out.sort();
        out
    }

    #[test]
    fn a_fresh_mirror_matches_the_source() {
        let f = fixture();
        f.run().unwrap();
        f.assert_mirrors("refs/heads/main");
        assert_eq!(
            std::fs::read_to_string(f.mirror.join("config")).unwrap(),
            CONFIG
        );
    }

    #[test]
    fn a_run_with_nothing_new_writes_nothing() {
        let f = fixture();
        f.run().unwrap();
        let before = snapshot(&f.mirror);
        f.run().unwrap();
        assert_eq!(snapshot(&f.mirror), before);
    }

    #[test]
    fn deletes_and_force_pushes_are_applied() {
        let f = fixture();
        f.run().unwrap();
        git(&f.src, &["branch", "-D", "dev"]);
        git(&f.src, &["tag", "-d", "v1"]);
        git(&f.src, &["commit", "-q", "--amend", "-m", "rewritten"]);
        git(&f.src, &["checkout", "-q", "-b", "new"]);
        commit(&f.src, "c", "four");
        git(&f.src, &["checkout", "-q", "main"]);
        f.run().unwrap();
        f.assert_mirrors("refs/heads/main");
    }

    #[test]
    fn an_interrupted_run_resumes() {
        let f = fixture();
        let stop = AtomicBool::new(false);
        let err = update(&f.mirror, &f.url(), Via::File, Trust::Drive, &stop, &|p| {
            if p.starts_with("checking pack") {
                stop.store(true, Ordering::Relaxed);
            }
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "stopped");
        // Fetched and staged, nothing published.
        assert_eq!(f.packs(), 1);
        assert_ne!(git(&f.mirror, &["for-each-ref", "refs/staged"]), "");
        assert_eq!(
            git(&f.mirror, &["for-each-ref", "refs/heads", "refs/tags"]),
            ""
        );
        f.run().unwrap();
        f.assert_mirrors("refs/heads/main");
        assert_eq!(f.packs(), 1, "the second run fetched again");
    }

    #[test]
    fn a_planted_config_is_neutralised() {
        let f = fixture();
        f.run().unwrap();
        commit(&f.src, "d", "five");
        let src_objects = f.src.join(".git/objects");
        std::fs::write(
            f.mirror.join("config"),
            "[core]\n\tbare = false\n\tsshCommand = false\n\tfsmonitor = false\n\
                 [include]\n\tpath = /nonexistent\n\
                 [remote \"origin\"]\n\turl = /nonexistent\n\tfetch = +refs/*:refs/*\n",
        )
        .unwrap();
        // With these left in place the new objects would only seem to be there.
        std::fs::write(
            f.mirror.join("objects/info/alternates"),
            format!("{}\n", src_objects.display()),
        )
        .unwrap();
        std::fs::write(f.mirror.join("commondir"), "../src/.git\n").unwrap();
        f.run().unwrap();
        assert_eq!(
            std::fs::read_to_string(f.mirror.join("config")).unwrap(),
            CONFIG
        );
        assert!(!f.mirror.join("objects/info/alternates").exists());
        assert!(!f.mirror.join("commondir").exists());
        f.assert_mirrors("refs/heads/main");
    }

    #[test]
    fn a_stale_lock_is_removed() {
        let f = fixture();
        f.run().unwrap();
        commit(&f.src, "e", "six");
        std::fs::create_dir_all(f.mirror.join("refs/heads")).unwrap();
        for lock in ["packed-refs.lock", "HEAD.lock", "refs/heads/main.lock"] {
            std::fs::write(f.mirror.join(lock), "").unwrap();
        }
        std::fs::write(f.mirror.join("objects/pack/.tmpAbC123"), "partial").unwrap();
        f.run().unwrap();
        f.assert_mirrors("refs/heads/main");
        for gone in [
            "packed-refs.lock",
            "HEAD.lock",
            "refs/heads/main.lock",
            "objects/pack/.tmpAbC123",
        ] {
            assert!(!f.mirror.join(gone).exists(), "{gone}");
        }
    }

    #[test]
    fn head_follows_branches_only() {
        let f = fixture();
        f.run().unwrap();
        git(&f.src, &["symbolic-ref", "HEAD", "refs/heads/dev"]);
        f.run().unwrap();
        f.assert_mirrors("refs/heads/dev");
        let main = git(&f.src, &["rev-parse", "refs/heads/main"]);
        git(&f.src, &["update-ref", "refs/pull/1", &main]);
        git(&f.src, &["symbolic-ref", "HEAD", "refs/pull/1"]);
        f.run().unwrap();
        f.assert_mirrors("refs/heads/dev");
    }

    /// A run with every phase label kept.
    fn run_logged(f: &Fixture, trust: Trust) -> (Result<()>, Vec<String>) {
        let log = std::sync::Mutex::new(Vec::new());
        let stop = AtomicBool::new(false);
        let r = update(&f.mirror, &f.url(), Via::File, trust, &stop, &|p| {
            log.lock().unwrap().push(p.to_owned());
        });
        (r, log.into_inner().unwrap())
    }

    fn checked(f: &Fixture) -> Vec<String> {
        read_checked(&f.mirror)
            .unwrap()
            .lines()
            .map(ToOwned::to_owned)
            .collect()
    }

    fn published(f: &Fixture) -> String {
        git(
            &f.mirror,
            &[
                "for-each-ref",
                "--format=%(objectname) %(refname)",
                "refs/heads",
                "refs/tags",
            ],
        )
    }

    /// Flips the last byte before the pack's trailer.
    fn flip(f: &Fixture, name: &str) {
        let path = f.mirror.join("objects/pack").join(name);
        let mut perm = std::fs::metadata(&path).unwrap().permissions();
        #[expect(
            clippy::permissions_set_readonly_false,
            reason = "a pack in the test's own temp dir"
        )]
        perm.set_readonly(false);
        std::fs::set_permissions(&path, perm).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let at = bytes.len() - 21;
        bytes[at] ^= 0x40;
        std::fs::write(&path, bytes).unwrap();
    }

    /// Packs the objects of `revs` (rev-list arguments) less `skip` into the mirror by hand.
    fn plant(f: &Fixture, revs: &str, skip: &str) -> String {
        use std::io::Read;
        use std::process::{Command, Stdio};
        let mut list = String::new();
        for line in git(&f.src, &["rev-list", "--objects", revs]).lines() {
            if !line.starts_with(skip) || skip.is_empty() {
                list.push_str(&line[..40]);
                list.push('\n');
            }
        }
        std::fs::create_dir_all(f.mirror.join("objects/pack")).unwrap();
        let prefix = f.mirror.join("objects/pack/pack");
        let mut child = Command::new("git")
            .current_dir(&f.src)
            .args(["pack-objects", "-q"])
            .arg(&prefix)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(list.as_bytes())
            .unwrap();
        let mut out = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut out)
            .unwrap();
        assert!(child.wait().unwrap().success());
        format!("pack-{}.pack", out.trim())
    }

    /// The first run stops at the check: one pack fetched and staged, none checked.
    fn fetch_only(f: &Fixture) -> String {
        let stop = AtomicBool::new(false);
        let err = update(&f.mirror, &f.url(), Via::File, Trust::Drive, &stop, &|p| {
            if p.starts_with("checking pack") {
                stop.store(true, Ordering::Relaxed);
            }
        })
        .unwrap_err();
        assert_eq!(err.to_string(), "stopped");
        assert_eq!(checked(f), Vec::<String>::new());
        let mut names = packs(&f.mirror).unwrap();
        assert_eq!(names.len(), 1);
        names.remove(0)
    }

    #[test]
    fn a_flipped_byte_is_refused() {
        let f = fixture();
        let name = fetch_only(&f);
        flip(&f, &name);
        let err = f.run().unwrap_err();
        assert!(
            format!("{err:#}").contains(&format!("{name} failed the check")),
            "{err:#}"
        );
        assert_eq!(published(&f), "");
        assert_eq!(checked(&f), Vec::<String>::new());
        // What the error says to do: the staged refs still name the deleted objects.
        let pack = f.mirror.join("objects/pack").join(&name);
        std::fs::remove_file(pack.with_extension("idx")).unwrap();
        std::fs::remove_file(pack).unwrap();
        f.run().unwrap();
        f.assert_mirrors("refs/heads/main");
    }

    /// A stop reaches the flag gix hashes under, while `f` is still running, and does not leak
    /// into `stop`'s owner the other way: gix setting its flag leaves `stop` alone.
    #[test]
    fn a_stop_reaches_the_flag_gix_watches() {
        let stop = AtomicBool::new(false);
        let seen = watched(&stop, |interrupt| {
            interrupt.store(true, Ordering::Relaxed);
            interrupt.store(false, Ordering::Relaxed);
            stop.store(true, Ordering::Relaxed);
            let until = std::time::Instant::now() + Duration::from_secs(10);
            while !interrupt.load(Ordering::Relaxed) && std::time::Instant::now() < until {
                std::thread::sleep(Duration::from_millis(10));
            }
            interrupt.load(Ordering::Relaxed)
        });
        assert!(seen);
        let quiet = AtomicBool::new(false);
        watched(&quiet, |interrupt| interrupt.store(true, Ordering::Relaxed));
        assert!(!quiet.load(Ordering::Relaxed));
    }

    /// One blob whose header claims 8 GiB over a one-byte zlib stream, with an index to match.
    #[test]
    fn a_size_bomb_is_refused_before_it_is_allocated() {
        let f = fixture();
        f.run().unwrap();
        let repo = open(&f.mirror).unwrap();
        let config = repo.config_snapshot();
        let limit = config.integer("gitoxide.objects.allocLimit");
        assert_eq!(limit, i64::try_from(ALLOC_LIMIT).ok());
        let sha1 = |parts: &[&[u8]]| {
            let mut h = gix::hash::hasher(gix::hash::Kind::Sha1);
            for p in parts {
                h.update(p);
            }
            h.try_finalize().unwrap()
        };
        let mut pack = b"PACK\0\0\0\x02\0\0\0\x01".to_vec();
        // Blob (3), size 1 << 33: four empty 7-bit groups, then 2 << 28.
        pack.extend_from_slice(&[0xb0, 0x80, 0x80, 0x80, 0x80, 0x02]);
        pack.extend_from_slice(b"x\x9c\xab\x00\x00\x00y\x00y");
        let trailer = sha1(&[&pack]);
        pack.extend_from_slice(trailer.as_bytes());
        let mut idx = b"\xfftOc\0\0\0\x02".to_vec();
        for i in 0..=255u8 {
            idx.extend_from_slice(&u32::from(i >= 0x11).to_be_bytes());
        }
        idx.extend_from_slice(&[0x11; 20]);
        idx.extend_from_slice(&[0; 4]);
        idx.extend_from_slice(&12u32.to_be_bytes());
        idx.extend_from_slice(trailer.as_bytes());
        let sum = sha1(&[&idx]);
        idx.extend_from_slice(sum.as_bytes());
        let name = format!("pack-{trailer}.pack");
        let path = f.mirror.join("objects/pack").join(&name);
        std::fs::write(&path, pack).unwrap();
        std::fs::write(path.with_extension("idx"), idx).unwrap();
        let msg = format!("{:#}", f.run().unwrap_err());
        assert!(msg.contains(&format!("{name} failed the check")), "{msg}");
        assert!(msg.contains("Entry too large to fit in memory"), "{msg}");
        assert!(!checked(&f).contains(&name));
    }

    #[test]
    fn a_pack_missing_a_blob_is_refused() {
        let f = fixture();
        f.run().unwrap();
        let before = published(&f);
        let old = git(&f.src, &["rev-parse", "main"]);
        commit(&f.src, "n", "new blob");
        let blob = git(&f.src, &["rev-parse", "main:n"]);
        let name = plant(&f, &format!("{old}..main"), &blob);
        let new = git(&f.src, &["rev-parse", "main"]);
        git(&f.mirror, &["update-ref", "refs/staged/heads/main", &new]);
        let err = f.run().unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains(&format!("{name} failed")), "{msg}");
        assert!(
            msg.contains(&format!("names {blob}, which no pack holds")),
            "{msg}"
        );
        assert_eq!(published(&f), before);
        assert!(!checked(&f).contains(&name));
    }

    /// Pack B is intact, but what it builds on is in pack A, which is not: neither is recorded.
    #[test]
    fn a_corrupt_pack_fails_the_packs_that_need_it() {
        let f = fixture();
        git(&f.src, &["branch", "-D", "dev"]);
        git(&f.src, &["tag", "-d", "v1", "v2"]);
        git(f.src.parent().unwrap(), &["init", "-q", "--bare", "m.git"]);
        let base = git(&f.src, &["rev-parse", "main"]);
        let a = plant(&f, "main", "");
        commit(&f.src, "n", "on top");
        let b = plant(&f, &format!("{base}..main"), "");
        let new = git(&f.src, &["rev-parse", "main"]);
        git(&f.mirror, &["update-ref", "refs/staged/heads/main", &new]);
        flip(&f, &a);
        let (r, log) = run_logged(&f, Trust::Drive);
        let msg = format!("{:#}", r.unwrap_err());
        assert!(msg.contains(&format!("{a} failed the check")), "{msg}");
        assert!(
            log.iter().any(|p| p.starts_with("checking pack 1/2")),
            "{log:?}"
        );
        assert_eq!(checked(&f), Vec::<String>::new(), "{b} was recorded");
        assert_eq!(published(&f), "");
    }

    #[test]
    fn a_planted_pack_is_checked_on_the_next_run() {
        let f = fixture();
        f.run().unwrap();
        let good = plant(&f, "main", "");
        let (r, log) = run_logged(&f, Trust::Drive);
        r.unwrap();
        assert!(
            log.iter().any(|p| p.starts_with("checking pack 1/1,")),
            "{log:?}"
        );
        assert!(checked(&f).contains(&good));
        let bad = plant(&f, "dev", "");
        flip(&f, &bad);
        let err = f.run().unwrap_err();
        assert!(
            format!("{err:#}").contains(&format!("{bad} failed the check")),
            "{err:#}"
        );
        assert!(!checked(&f).contains(&bad));
        // The bad pack stays (D15: kept, not deleted); the published refs are untouched.
        assert_eq!(published(&f), f.src_refs());
    }

    /// A mirror phase 1 left on this host: `git clone --mirror`, then a fetch that wrote loose
    /// refs and loose objects. Its pack is taken as checked; only the new one is decoded.
    #[test]
    fn a_phase_1_host_mirror_is_taken_as_checked() {
        let f = fixture();
        git(
            f.src.parent().unwrap(),
            &["clone", "-q", "--mirror", "--no-local", &f.url(), "m.git"],
        );
        commit(&f.src, "f", "seven");
        git(&f.mirror, &["fetch", "-q"]);
        assert!(f.mirror.join("refs/heads/main").is_file());
        let loose = git(&f.mirror, &["count-objects"]);
        assert!(!loose.starts_with("0 objects"), "{loose}");
        let first = packs(&f.mirror).unwrap();
        commit(&f.src, "g", "eight");
        let (r, log) = run_logged(&f, Trust::Host);
        r.unwrap();
        f.assert_mirrors("refs/heads/main");
        let decoded: Vec<_> = log
            .iter()
            .filter(|p| p.starts_with("checking pack"))
            .collect();
        assert_ne!(decoded.len(), 0);
        assert!(
            decoded.iter().all(|p| p.starts_with("checking pack 1/1,")),
            "{decoded:?}"
        );
        let all = packs(&f.mirror).unwrap();
        assert_eq!(all.len(), first.len() + 1);
        let new: Vec<String> = all.into_iter().filter(|n| !first.contains(n)).collect();
        assert_eq!(checked(&f), [first, new].concat());
    }

    #[test]
    fn token_for_table() {
        for (url, ok) in [
            ("https://github.com/o/n.git", true),
            ("https://github.com/o/n", true),
            ("http://github.com/o/n.git", false),
            ("https://github.com@evil/o/n.git", false),
            ("https://github.com.evil/o/n.git", false),
            ("https://evil/github.com/o/n.git", false),
            ("https://user@github.com/o/n.git", false),
            ("https://x:y@github.com/o/n.git", false),
            ("https://github.com:8443/o/n.git", false),
            ("https://api.github.com/o/n.git", false),
            ("https://evilgithub.com/o/n.git", false),
            ("git@github.com:o/n.git", false),
            ("ssh://git@github.com/o/n.git", false),
            ("github.com/o/n.git", false),
        ] {
            assert_eq!(token_for(url), ok, "{url}");
        }
    }

    #[cfg(unix)]
    mod transports {
        use super::*;
        use crate::git::testcgi::{self, Cgi};
        use crate::net::throttle::Throttle;
        use std::sync::Arc;
        use std::sync::atomic::AtomicU64;

        #[test]
        fn a_fresh_mirror_over_https() {
            let f = fixture();
            let cgi = Cgi::start(f.src.parent().unwrap(), None);
            let stop = Arc::new(AtomicBool::new(false));
            let got = Arc::new(AtomicU64::new(0));
            let remote = http::Remote::new(
                testcgi::agent(),
                Arc::new(Throttle::new(0)),
                got.clone(),
                u64::MAX,
                stop.clone(),
            );
            let via = Via::Https {
                http: remote,
                token: None,
            };
            update(
                &f.mirror,
                &cgi.url("src"),
                via,
                Trust::Drive,
                &stop,
                &|_| {},
            )
            .unwrap();
            f.assert_mirrors("refs/heads/main");
            assert!(got.load(Ordering::Relaxed) > 0);
            assert!(cgi.hits().iter().all(|h| h.auth.is_none()));
        }

        #[test]
        fn a_401_does_not_prompt() {
            let f = fixture();
            let cgi = Cgi::start(f.src.parent().unwrap(), Some("Basic c2VjcmV0".into()));
            let stop = Arc::new(AtomicBool::new(false));
            let remote = http::Remote::new(
                testcgi::agent(),
                Arc::new(Throttle::new(0)),
                Arc::default(),
                u64::MAX,
                stop.clone(),
            );
            let via = Via::Https {
                http: remote,
                token: None,
            };
            let err = update(
                &f.mirror,
                &cgi.url("src"),
                via,
                Trust::Drive,
                &stop,
                &|_| {},
            )
            .unwrap_err();
            assert!(
                format!("{err:#}").contains("asked for credentials"),
                "{err:#}"
            );
            let hits = cgi.hits();
            assert_eq!(hits.len(), 1, "{hits:?}");
            assert_eq!(
                (hits[0].method.as_str(), hits[0].path.as_str()),
                ("GET", "/src/info/refs")
            );
            assert_eq!(git(&f.mirror, &["for-each-ref"]), "");
        }

        /// The server would accept the token, but the URL is not `https://github.com`.
        #[test]
        fn a_token_is_held_back_from_other_hosts() {
            let f = fixture();
            // base64 of "x-access-token:tok"
            let cgi = Cgi::start(
                f.src.parent().unwrap(),
                Some("Basic eC1hY2Nlc3MtdG9rZW46dG9r".into()),
            );
            let stop = Arc::new(AtomicBool::new(false));
            let remote = http::Remote::new(
                testcgi::agent(),
                Arc::new(Throttle::new(0)),
                Arc::default(),
                u64::MAX,
                stop.clone(),
            );
            let via = Via::Https {
                http: remote,
                token: Some("tok"),
            };
            let err = update(
                &f.mirror,
                &cgi.url("src"),
                via,
                Trust::Drive,
                &stop,
                &|_| {},
            )
            .unwrap_err();
            assert!(
                format!("{err:#}").contains("asked for credentials"),
                "{err:#}"
            );
            assert!(cgi.hits().iter().all(|h| h.auth.is_none()));
        }

        /// The ssh path end to end, with an "ssh" that runs the remote command locally.
        #[test]
        fn over_ssh() {
            use std::os::unix::fs::PermissionsExt;
            let f = fixture();
            let ssh = f.src.parent().unwrap().join("fake-ssh");
            std::fs::write(
                &ssh,
                "#!/bin/sh\nwhile [ \"$1\" != git@localhost ]; do shift; done\nshift\nexec sh -c \"$*\"\n",
            )
            .unwrap();
            std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o755)).unwrap();
            let url = format!("git@localhost:{}", f.src.display());
            let stop = AtomicBool::new(false);
            let via = Via::Ssh { program: &ssh };
            update(&f.mirror, &url, via, Trust::Host, &stop, &|_| {}).unwrap();
            f.assert_mirrors("refs/heads/main");
        }
    }
}
