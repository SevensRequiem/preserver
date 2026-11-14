use crate::config::{Config, Transport};
use crate::crypt;
use crate::git::Auth;
use crate::paths::Paths;
use crate::personal::{Hooks, Stopped};
use crate::platform;
use age::x25519;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::io::BufWriter;
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Debug)]
pub(crate) struct Repo {
    /// `owner/name`
    pub name: String,
    pub url: String,
    pub branch: Option<String>,
}

/// The name becomes path segments on the drive and in the cache.
fn valid_repo_name(name: &str) -> bool {
    let segment = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    };
    name.split_once('/')
        .is_some_and(|(owner, repo)| segment(owner) && segment(repo))
        && !name.contains("..")
}

fn list(owner: &str, transport: Transport) -> Result<Vec<Repo>> {
    #[derive(Deserialize)]
    struct Branch {
        name: String,
    }
    #[derive(Deserialize)]
    struct Listed {
        #[serde(rename = "nameWithOwner")]
        name: String,
        #[serde(rename = "defaultBranchRef")]
        branch: Option<Branch>,
    }

    let out = Command::new("gh")
        .args(["repo", "list", owner, "--limit", "1000", "--json"])
        .arg("nameWithOwner,defaultBranchRef")
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .context("run gh")?;
    if !out.status.success() {
        bail!("gh repo list: {}", out.status);
    }
    let listed: Vec<Listed> = serde_json::from_slice(&out.stdout).context("gh repo list output")?;
    Ok(listed
        .into_iter()
        .map(|r| Repo {
            // Built from the name, which is validated before use, not taken from the listing.
            url: match transport {
                Transport::Ssh => format!("git@github.com:{}.git", r.name),
                Transport::Https => format!("https://github.com/{}.git", r.name),
            },
            name: r.name,
            branch: r.branch.map(|b| b.name).filter(|b| !b.is_empty()),
        })
        .collect())
}

fn git(mirror: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(mirror).stdin(Stdio::null());
    cmd
}

fn run_git(cmd: &mut Command, what: &str) -> Result<Vec<u8>> {
    let out = cmd.output().context("run git")?;
    if !out.status.success() {
        bail!(
            "{what}: {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out.stdout)
}

/// A snapshot is due when the refs differ from the recorded state, or when the drive has none yet.
/// `refs` and the state file compare as bytes without trailing newlines.
fn needs_bundle(refs: &[u8], state: Option<&[u8]>, has_bundle: bool) -> bool {
    !(has_bundle && state.is_some_and(|s| trim_newlines(s) == refs))
}

fn trim_newlines(mut b: &[u8]) -> &[u8] {
    while let [rest @ .., b'\n'] = b {
        b = rest;
    }
    b
}

/// Reports whether the drive holds a bundle of this repo. On the way it removes partial bundles
/// that a killed run left behind: the job lock is held, so no one else is writing one.
fn has_bundle(dir: &Path) -> bool {
    let mut found = false;
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".bundle.age.tmp") {
            let _ = std::fs::remove_file(entry.path());
        }
        found |= name.ends_with(".bundle.age");
    }
    found
}

/// Streams `git bundle create` through age into `tmp`.
fn write_bundle(mirror: &Path, recipients: &[x25519::Recipient], tmp: &Path) -> Result<()> {
    let mut child = git(mirror)
        .args(["bundle", "create", "-q", "-", "--all"])
        .stdout(Stdio::piped())
        .spawn()
        .context("run git")?;
    let copied = (|| {
        let mut plain = child.stdout.take().context("git stdout")?;
        let mut sealed =
            crypt::encrypt(recipients, BufWriter::new(platform::private_file_new(tmp)?))?;
        std::io::copy(&mut plain, &mut sealed)?;
        sealed
            .finish()?
            .into_inner()
            .map_err(std::io::IntoInnerError::into_error)?
            .sync_all()?;
        anyhow::Ok(())
    })();
    // The pipe is closed by now, so git cannot block on it.
    let status = child.wait()?;
    copied?;
    if !status.success() {
        bail!("git bundle create: {status}");
    }
    Ok(())
}

/// Fetches one repo into its mirror and writes a new encrypted bundle when its refs changed.
/// Returns whether a bundle was written.
fn backup_repo(
    paths: &Paths,
    auth: &Auth,
    recipients: &[x25519::Recipient],
    repo: &Repo,
    today: jiff::civil::Date,
) -> Result<bool> {
    if !valid_repo_name(&repo.name) {
        bail!("unsafe repo name {:?}", repo.name);
    }
    let mirror = paths.mirrors.join(format!("{}.git", repo.name));
    if !mirror.exists() {
        run_git(
            Command::new("git")
                .args(["init", "-q", "--bare", "--"])
                .arg(&mirror)
                .stdin(Stdio::null()),
            "init",
        )?;
    }
    // Heads and tags only: a plain --mirror would also pull every refs/pull/* from GitHub.
    let mut fetch = git(&mirror);
    fetch
        .args(["fetch", "-q", "--prune", "--", &repo.url])
        .args(["+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"]);
    auth.apply(&mut fetch);
    run_git(&mut fetch, "fetch")?;
    if let Some(branch) = &repo.branch {
        run_git(
            git(&mirror).args(["symbolic-ref", "HEAD", &format!("refs/heads/{branch}")]),
            "symbolic-ref",
        )?;
    }
    let out = run_git(
        git(&mirror).args(["for-each-ref", "--format=%(objectname) %(refname)"]),
        "for-each-ref",
    )?;
    let refs = trim_newlines(&out);
    if refs.is_empty() {
        return Ok(false);
    }

    let state_file = paths.github.join(format!("{}.refs", repo.name));
    let dir = paths.gh_dest().join(&repo.name);
    let state = std::fs::read(&state_file).ok();
    if !needs_bundle(refs, state.as_deref(), has_bundle(&dir)) {
        return Ok(false);
    }

    platform::private_dir_all(&dir)?;
    let dest = dir.join(format!("{today}.bundle.age"));
    let tmp = dir.join(format!("{today}.bundle.age.tmp"));
    if let Err(e) = write_bundle(&mirror, recipients, &tmp).and_then(|()| {
        std::fs::rename(&tmp, &dest)?;
        // The state below must not outlive a rename that a power loss could still undo.
        platform::sync_dir(&dir)?;
        Ok(())
    }) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.context("bundle"));
    }
    platform::write_private(&state_file, &[refs, b"\n"].concat())?;
    Ok(true)
}

/// Backs up every repo and returns how many bundles were written. One failing repo does not
/// stop the rest; a stop does, between repos (one long fetch runs to its end).
pub(crate) fn backup_all(
    paths: &Paths,
    auth: &Auth,
    recipients: &[x25519::Recipient],
    repos: &[Repo],
    today: jiff::civil::Date,
    hooks: &Hooks,
) -> Result<usize> {
    // The mirrors are plaintext copies of private repos, and git init makes what it creates 0755.
    platform::private_dir_all(&paths.mirrors)?;
    platform::restrict_dir(&paths.mirrors)?;
    let mut wrote = 0;
    let mut failed = Vec::new();
    let mut stopped = false;
    for (n, repo) in repos.iter().enumerate() {
        if (hooks.stop)() {
            stopped = true;
            break;
        }
        (hooks.on_item)(n, repos.len(), &repo.name);
        match backup_repo(paths, auth, recipients, repo, today) {
            Ok(w) => wrote += usize::from(w),
            Err(e) => {
                tracing::error!(repo = repo.name, "repo backup: {e:#}");
                failed.push(repo.name.as_str());
            }
        }
    }
    let dest = paths.gh_dest();
    platform::private_dir_all(&dest)?;
    platform::sync_fs(&dest).context("sync")?;
    if stopped {
        return Err(Stopped.into());
    }
    if !failed.is_empty() {
        bail!(
            "{} of {} repos failed: {}",
            failed.len(),
            repos.len(),
            failed.join(" ")
        );
    }
    Ok(wrote)
}

/// The shared ssh connection lives exactly as long as this guard, on every exit path.
struct SshMaster<'a>(&'a Path);

impl<'a> SshMaster<'a> {
    fn start(
        runtime: &'a Path,
        session: &[(String, String)],
        stop: &dyn Fn() -> bool,
    ) -> Result<Self> {
        platform::ssh_master(runtime, session, stop)?;
        Ok(Self(runtime))
    }
}

impl Drop for SshMaster<'_> {
    fn drop(&mut self) {
        platform::ssh_master_stop(self.0);
    }
}

/// `paths.mnt` is the primary the caller located. `gh repo list` runs before the ssh master,
/// so a network outage is a failure and not a missing touch.
pub(crate) fn run(
    paths: &Paths,
    cfg: &Config,
    transport: Transport,
    session: Vec<(String, String)>,
    hooks: &Hooks,
) -> Result<()> {
    // The recipient comes from home, not the drive, so tampering with the drive can't redirect new backups.
    let recipients = crypt::read_recipients(&paths.personal.join("recipient.txt"))?;
    let mut repos = Vec::new();
    for owner in &cfg.owners {
        repos.extend(list(owner, transport).with_context(|| format!("list repos of {owner}"))?);
    }
    let _master = if transport == Transport::Ssh {
        platform::notify(
            false,
            "GitHub backup",
            "Enter your security key PIN if asked, then touch the key.",
        );
        Some(SshMaster::start(&paths.runtime, &session, hooks.stop)?)
    } else {
        None
    };
    let auth = Auth::new(transport, &paths.runtime)?.with_session(session);
    let today = jiff::Zoned::now().date();
    let wrote = backup_all(paths, &auth, &recipients, &repos, today, hooks)?;
    platform::notify(
        false,
        "GitHub backup done",
        &format!("{} repos checked, {wrote} new snapshots.", repos.len()),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::personal::restore::restore_bundle;
    use crate::testutil::{TempDir, git as tgit, paths};
    use jiff::civil::date;

    #[test]
    fn ref_state_compare() {
        let refs = "aaa refs/heads/main\nbbb refs/tags/v1";
        let cases = [
            ("no state file", None, true, true),
            (
                "same, with the newline the tool writes",
                Some("aaa refs/heads/main\nbbb refs/tags/v1\n"),
                true,
                false,
            ),
            (
                "same, without a trailing newline",
                Some("aaa refs/heads/main\nbbb refs/tags/v1"),
                true,
                false,
            ),
            (
                "same, several trailing newlines",
                Some("aaa refs/heads/main\nbbb refs/tags/v1\n\n"),
                true,
                false,
            ),
            (
                "same refs but no bundle on the drive yet",
                Some("aaa refs/heads/main\nbbb refs/tags/v1\n"),
                false,
                true,
            ),
            (
                "moved branch",
                Some("ccc refs/heads/main\nbbb refs/tags/v1\n"),
                true,
                true,
            ),
            ("deleted tag", Some("aaa refs/heads/main\n"), true, true),
            (
                "trailing space is a difference",
                Some("aaa refs/heads/main\nbbb refs/tags/v1 \n"),
                true,
                true,
            ),
            (
                "leading newline is a difference",
                Some("\naaa refs/heads/main\nbbb refs/tags/v1\n"),
                true,
                true,
            ),
            ("empty state", Some(""), true, true),
        ];
        for (name, state, has_bundle, want) in cases {
            assert_eq!(
                needs_bundle(refs.as_bytes(), state.map(str::as_bytes), has_bundle),
                want,
                "{name}"
            );
        }
    }

    #[test]
    fn repo_names() {
        let cases = [
            ("o/r", true),
            ("Some-Org/repo.name_1", true),
            ("o/.github", true),
            ("o", false),
            ("o/", false),
            ("/r", false),
            ("o/r/x", false),
            ("../r", false),
            ("o/..", false),
            ("o/a..b", false),
            ("o/r x", false),
            ("o/r\n", false),
            ("", false),
        ];
        for (name, want) in cases {
            assert_eq!(valid_repo_name(name), want, "{name:?}");
        }
    }

    fn bundles(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn backs_up_only_changed_repos() {
        let tmp = TempDir::new();
        let p = paths(tmp.path());
        let id = x25519::Identity::generate();
        let recipients = [id.to_public()];
        let ids: crypt::Identities = vec![Box::new(id)];

        let work = tmp.path().join("work");
        let remote = tmp.path().join("remote.git");
        std::fs::create_dir(&work).unwrap();
        tgit(&work, &["init", "-q", "-b", "main"]);
        std::fs::write(work.join("f.txt"), "one").unwrap();
        tgit(&work, &["add", "."]);
        tgit(&work, &["commit", "-q", "-m", "one"]);
        tgit(&work, &["tag", "v1"]);
        tgit(
            &work,
            &["clone", "-q", "--bare", ".", remote.to_str().unwrap()],
        );

        // A file:// remote: the ssh transport is set up for real, but git never needs it here.
        let auth = Auth::new(Transport::Ssh, &p.runtime).unwrap();
        let repos = [Repo {
            name: "o/r".into(),
            url: format!("file://{}", remote.display()),
            branch: Some("main".into()),
        }];
        let run = |day| {
            backup_all(
                &p,
                &auth,
                &recipients,
                &repos,
                date(2026, 11, day),
                &Hooks::NONE,
            )
            .unwrap()
        };
        let dir = p.gh_dest().join("o/r");
        let state_file = p.github.join("o/r.refs");

        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("2026-11-01.bundle.age.tmp"), "cut off").unwrap();
        assert_eq!(
            run(13),
            1,
            "first run, with a partial bundle from a killed one"
        );
        assert_eq!(bundles(&dir), ["2026-11-13.bundle.age"]);
        assert_eq!(run(14), 0, "unchanged repo");
        assert_eq!(bundles(&dir), ["2026-11-13.bundle.age"]);

        let refs = tgit(
            &p.mirrors.join("o/r.git"),
            &["for-each-ref", "--format=%(objectname) %(refname)"],
        );
        assert_eq!(refs.lines().count(), 2, "one head and one tag: {refs}");
        assert_eq!(
            std::fs::read_to_string(&state_file).unwrap(),
            format!("{refs}\n")
        );
        std::fs::write(&state_file, &refs).unwrap();
        assert_eq!(run(14), 0, "state without the trailing newline");

        std::fs::remove_file(dir.join("2026-11-13.bundle.age")).unwrap();
        assert_eq!(run(14), 1, "state matches but the drive has no bundle");
        assert_eq!(bundles(&dir), ["2026-11-14.bundle.age"]);

        std::fs::write(work.join("f.txt"), "two").unwrap();
        tgit(&work, &["commit", "-q", "-am", "two"]);
        tgit(&work, &["push", "-q", remote.to_str().unwrap(), "main"]);
        assert_eq!(run(15), 1, "changed repo");
        assert_eq!(
            bundles(&dir),
            ["2026-11-14.bundle.age", "2026-11-15.bundle.age"]
        );

        let restored = tmp.path().join("restored");
        restore_bundle(&ids, &dir.join("2026-11-15.bundle.age"), &restored).unwrap();
        assert_eq!(
            std::fs::read_to_string(restored.join("f.txt")).unwrap(),
            "two"
        );
        tgit(&restored, &["fsck", "--strict"]);
        assert_eq!(tgit(&restored, &["tag", "--list"]), "v1");
    }

    #[test]
    fn a_failing_repo_is_reported_and_the_rest_still_run() {
        let tmp = TempDir::new();
        let p = paths(tmp.path());
        let recipients = [x25519::Identity::generate().to_public()];
        let auth = Auth::new(Transport::Ssh, &p.runtime).unwrap();

        let work = tmp.path().join("work");
        std::fs::create_dir(&work).unwrap();
        tgit(&work, &["init", "-q", "-b", "main"]);
        std::fs::write(work.join("f.txt"), "one").unwrap();
        tgit(&work, &["add", "."]);
        tgit(&work, &["commit", "-q", "-m", "one"]);

        let repos = [
            Repo {
                name: "../escape".into(),
                url: format!("file://{}", work.display()),
                branch: None,
            },
            Repo {
                name: "o/gone".into(),
                url: format!("file://{}", tmp.path().join("absent").display()),
                branch: None,
            },
            Repo {
                name: "o/ok".into(),
                url: format!("file://{}", work.display()),
                branch: Some("main".into()),
            },
        ];
        let err = backup_all(
            &p,
            &auth,
            &recipients,
            &repos,
            date(2026, 11, 13),
            &Hooks::NONE,
        )
        .unwrap_err();
        assert_eq!(err.to_string(), "2 of 3 repos failed: ../escape o/gone");
        assert_eq!(
            bundles(&p.gh_dest().join("o/ok")),
            ["2026-11-13.bundle.age"]
        );
        assert!(!tmp.path().join("home/.cache/preserver/escape.git").exists());
        assert!(!p.gh_dest().join("o/gone").exists());
    }

    #[test]
    fn an_empty_repo_writes_nothing() {
        let tmp = TempDir::new();
        let p = paths(tmp.path());
        let recipients = [x25519::Identity::generate().to_public()];
        let auth = Auth::new(Transport::Ssh, &p.runtime).unwrap();
        let empty = tmp.path().join("empty.git");
        tgit(
            tmp.path(),
            &["init", "-q", "--bare", empty.to_str().unwrap()],
        );
        let repos = [Repo {
            name: "o/empty".into(),
            url: format!("file://{}", empty.display()),
            branch: None,
        }];
        assert_eq!(
            backup_all(
                &p,
                &auth,
                &recipients,
                &repos,
                date(2026, 11, 13),
                &Hooks::NONE
            )
            .unwrap(),
            0
        );
        assert!(!p.gh_dest().join("o/empty").exists());
    }
}
