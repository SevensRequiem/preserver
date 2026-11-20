mod fs;
mod notify;
mod tray;
mod udisks;

pub(crate) use fs::{
    block_size, disk_free, drop_cache, exchange, fs_type, is_mounted, link_self, open_nofollow,
    open_regular, open_rw_regular, private_dir_all, private_dir_new, private_file,
    private_file_new, restrict_dir, set_mode, symlink, sync_dir, sync_fs,
};
pub(crate) use notify::notify;
pub(crate) use tray::run_tray;
pub(crate) use udisks::{list_filesystems, locate, mount, mount_added, watch_drives};

use super::TouchMissing;
use anyhow::{Context, Result, bail};
use rustix::fs::inotify;
use rustix::process::{Pid, Signal, kill_process_group};
use std::ffi::OsString;
use std::io::{IsTerminal, Read};
use std::mem::MaybeUninit;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const ASKPASS: &str = "/usr/bin/ksshaskpass";

pub(crate) fn open_path(path: &Path) -> Result<()> {
    let status = Command::new("xdg-open")
        .arg(path)
        .status()
        .context("xdg-open")?;
    if !status.success() {
        bail!("xdg-open: {status}");
    }
    Ok(())
}

pub(crate) const SSH: &str = "/usr/bin/ssh";

/// ssh on the run's one multiplexed connection, so the security key is touched once. The master
/// (`master`) may open it and prompt. Any other caller, git's shim included, is a mux client; if
/// the master is gone ssh connects on its own, so that connection is given no way to
/// authenticate and fails at once instead of waiting for a touch. The options come first:
/// everything the caller appends is git's.
pub(crate) fn ssh_command(program: &Path, runtime: &Path, master: bool) -> Command {
    let mut control = OsString::from("ControlPath=");
    control.push(runtime.join("preserver-ssh-%C"));
    let mut cmd = Command::new(program);
    cmd.args([
        "-o",
        if master {
            "ControlMaster=auto"
        } else {
            "ControlMaster=no"
        },
        "-o",
    ])
    .arg(control)
    .args(["-o", "ControlPersist=60"]);
    if !master {
        cmd.args([
            "-o",
            "BatchMode=yes",
            "-o",
            "IdentityAgent=none",
            "-o",
            "IdentityFile=none",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
        ]);
    // Backups run from the tray with no terminal, so the PIN and touch prompts go to a dialog.
    } else if Path::new(ASKPASS).exists() {
        cmd.env("SSH_ASKPASS", ASKPASS)
            .env("SSH_ASKPASS_REQUIRE", "force");
    }
    cmd
}

const GITHUB: &str = "git@github.com";

/// How long a PIN or touch prompt may stay unanswered: a bound on how long a person is waited
/// for, not a tuning knob.
const TOUCH_WAIT: Duration = Duration::from_secs(120);

/// Waits for `child` until it exits, `deadline` passes or `stop` says so; on the last two it
/// ends the child (its whole process group when `grouped`). `None` when it was ended.
fn wait_bounded(
    child: &mut Child,
    deadline: Duration,
    stop: &dyn Fn() -> bool,
    grouped: bool,
) -> std::io::Result<Option<ExitStatus>> {
    let end = Instant::now() + deadline;
    loop {
        if let Some(s) = child.try_wait()? {
            return Ok(Some(s));
        }
        if Instant::now() >= end || stop() {
            if grouped {
                // An askpass dialog is the child's child: ending the group closes it too.
                let _ = kill_process_group(Pid::from_child(child), Signal::TERM);
            } else {
                let _ = child.kill();
            }
            child.wait()?;
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Waits for `ssh -fN`: `-f` exits 0 only once it authenticated, so anything else is a prompt
/// nobody answered.
fn wait_auth(
    child: &mut Child,
    deadline: Duration,
    stop: &dyn Fn() -> bool,
    grouped: bool,
) -> Result<()> {
    match wait_bounded(child, deadline, stop, grouped)? {
        Some(s) if s.success() => Ok(()),
        Some(s) => {
            if grouped {
                let _ = kill_process_group(Pid::from_child(child), Signal::TERM);
            }
            Err(TouchMissing(format!("ssh to github.com: {s}")).into())
        }
        None => Err(TouchMissing(format!("no answer within {} s", deadline.as_secs())).into()),
    }
}

/// Opens the shared connection up front, so the key is touched here and nothing outlives the run.
/// `ControlPersist` only bounds the master if `ssh_master_stop` never gets to run. `session`
/// lets a daemon reach the graphical session's askpass and agent.
pub(crate) fn ssh_master(
    program: &Path,
    runtime: &Path,
    session: &[(String, String)],
    stop: &dyn Fn() -> bool,
) -> Result<()> {
    let mut cmd = ssh_command(program, runtime, true);
    cmd.args(["-fN", GITHUB])
        .envs(session.iter().map(|(k, v)| (k, v)));
    // On a terminal ssh may read the PIN from it, which a background process group cannot.
    let grouped = !std::io::stdin().is_terminal();
    if grouped {
        cmd.process_group(0);
    }
    let mut child = cmd.spawn().context("start ssh")?;
    wait_auth(&mut child, TOUCH_WAIT, stop, grouped)
}

const SESSION_VARS: [&str; 4] = ["DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "SSH_AUTH_SOCK"];

/// The graphical session's variables from the user manager, read per job: a daemon started
/// before login still sees what the session imported since. Empty when that fails.
pub(crate) fn session_env() -> Vec<(String, String)> {
    let run = || -> Result<String> {
        let mut child = Command::new("systemctl")
            .args(["--user", "show-environment"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()?;
        let Some(mut out) = child.stdout.take() else {
            bail!("no stdout");
        };
        let reader = std::thread::spawn(move || {
            let mut s = String::new();
            out.read_to_string(&mut s).map(|_| s)
        });
        match wait_bounded(&mut child, Duration::from_secs(5), &|| false, true)? {
            Some(s) if s.success() => reader
                .join()
                .map_err(|_| anyhow::anyhow!("reader panicked"))?
                .context("read"),
            Some(s) => bail!("{s}"),
            None => bail!("timed out"),
        }
    };
    match run() {
        Ok(text) => session_vars(&text),
        Err(e) => {
            tracing::debug!("systemctl --user show-environment: {e:#}");
            Vec::new()
        }
    }
}

/// `$'…'` is systemd quoting a value with odd bytes: no display or socket path looks like that.
fn session_vars(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .filter(|(k, v)| SESSION_VARS.contains(k) && !v.starts_with("$'"))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Calls `on_change` from a thread of its own when `wake` or a `.ctl` file lands in `dir`. Job
/// files, saved every second while one runs, wake nothing. Without inotify the daemon still
/// runs on its 30 s tick.
pub(crate) fn watch_queue(dir: &Path, on_change: impl Fn() + Send + 'static) {
    let setup = || -> std::io::Result<rustix::fd::OwnedFd> {
        private_dir_all(dir)?;
        let fd = inotify::init(inotify::CreateFlags::CLOEXEC)?;
        inotify::add_watch(
            &fd,
            dir,
            inotify::WatchFlags::MOVED_TO | inotify::WatchFlags::CLOSE_WRITE,
        )?;
        Ok(fd)
    };
    let fd = match setup() {
        Ok(fd) => fd,
        Err(e) => {
            tracing::warn!("queue wake-ups unavailable, running on the 30 s tick: {e}");
            return;
        }
    };
    std::thread::spawn(move || {
        let mut buf = [MaybeUninit::uninit(); 4096];
        let mut events = inotify::Reader::new(&fd, &mut buf);
        loop {
            match events.next() {
                Ok(ev) => {
                    let name = ev
                        .file_name()
                        .map(std::ffi::CStr::to_bytes)
                        .unwrap_or_default();
                    if name == b"wake" || name.ends_with(b".ctl") {
                        on_change();
                    }
                }
                Err(rustix::io::Errno::INTR) => {}
                Err(e) => {
                    tracing::warn!("queue wake-ups stopped, running on the 30 s tick: {e}");
                    return;
                }
            }
        }
    });
}

/// Opens the master again when `ControlPersist` or a crash ended it since the last repo.
pub(crate) fn ssh_ensure_master(
    program: &Path,
    runtime: &Path,
    session: &[(String, String)],
    stop: &dyn Fn() -> bool,
) -> Result<()> {
    let alive = ssh_command(program, runtime, false)
        .args(["-O", "check", GITHUB])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if alive {
        return Ok(());
    }
    ssh_master(program, runtime, session, stop)
}

pub(crate) fn ssh_master_stop(runtime: &Path) {
    let stopped = ssh_command(Path::new(SSH), runtime, true)
        .args(["-O", "exit", GITHUB])
        .stderr(Stdio::null())
        .status();
    if !stopped.is_ok_and(|s| s.success()) {
        tracing::debug!("ssh master already gone");
    }
}

/// Replaces this process with `cmd`; it only returns when that failed.
pub(crate) fn exec(mut cmd: Command) -> std::io::Error {
    cmd.exec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use std::sync::mpsc;

    fn grouped(prog: &str, args: &[&str]) -> Child {
        Command::new(prog)
            .args(args)
            .process_group(0)
            .spawn()
            .unwrap()
    }

    #[test]
    fn wait_auth_outcomes() {
        assert!(wait_auth(&mut grouped("true", &[]), TOUCH_WAIT, &|| false, true).is_ok());
        let e = wait_auth(&mut grouped("false", &[]), TOUCH_WAIT, &|| false, true).unwrap_err();
        assert!(e.is::<TouchMissing>(), "{e:#}");

        let mut child = grouped("sleep", &["30"]);
        let pid = Pid::from_child(&child);
        let start = Instant::now();
        let e = wait_auth(&mut child, Duration::from_millis(200), &|| false, true).unwrap_err();
        assert!(e.is::<TouchMissing>(), "{e:#}");
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(
            rustix::process::test_kill_process_group(pid).is_err(),
            "the group is gone"
        );

        let e = wait_auth(&mut grouped("sleep", &["30"]), TOUCH_WAIT, &|| true, true).unwrap_err();
        assert!(e.is::<TouchMissing>(), "a stop ends the wait");
    }

    #[test]
    fn session_vars_keep_only_the_display_and_agent() {
        let text = "HOME=/home/u\nDISPLAY=:0\nWAYLAND_DISPLAY=wayland-0\nXAUTHORITY=$'\\x01'\n\
                    SSH_AUTH_SOCK=/run/user/1000/ssh-agent.socket\nPATH=/usr/bin\nnoequals\n";
        let want: Vec<(String, String)> = [
            ("DISPLAY", ":0"),
            ("WAYLAND_DISPLAY", "wayland-0"),
            ("SSH_AUTH_SOCK", "/run/user/1000/ssh-agent.socket"),
        ]
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
        assert_eq!(session_vars(text), want);
    }

    #[test]
    fn queue_wakes_on_wake_and_ctl_files_only() {
        let tmp = TempDir::new();
        let dir = tmp.path().join("queue");
        let (tx, rx) = mpsc::channel();
        watch_queue(&dir, move || {
            let _ = tx.send(());
        });
        std::fs::write(dir.join("a.json.tmp"), b"{}").unwrap();
        std::fs::rename(dir.join("a.json.tmp"), dir.join("a.json")).unwrap();
        assert!(
            rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "job saves wake nothing"
        );
        crate::platform::write_private(&dir.join("wake"), b"").unwrap();
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
        crate::platform::write_private(&dir.join("abc.ctl"), b"{}").unwrap();
        rx.recv_timeout(Duration::from_secs(2)).unwrap();
    }

    #[test]
    fn the_shims_ssh_cannot_authenticate_on_its_own() {
        let cmd = ssh_command(Path::new(SSH), Path::new("/run/user/1000"), false);
        let args: Vec<_> = cmd.get_args().map(|a| a.to_str().unwrap()).collect();
        assert!(args.contains(&"ControlMaster=no"), "{args:?}");
        for opt in [
            "BatchMode=yes",
            "IdentityAgent=none",
            "IdentityFile=none",
            "PasswordAuthentication=no",
            "KbdInteractiveAuthentication=no",
        ] {
            assert!(args.contains(&opt), "{opt}: {args:?}");
        }
        assert!(!args.contains(&"ControlMaster=auto"), "{args:?}");
    }

    #[test]
    fn ssh_options_precede_the_callers_arguments() {
        let mut cmd = ssh_command(Path::new(SSH), Path::new("/run/user/1000"), true);
        cmd.args(["-p", "22", "git@github.com", "git-upload-pack 'o/r.git'"]);
        assert_eq!(cmd.get_program(), "/usr/bin/ssh");
        let args: Vec<_> = cmd.get_args().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(
            args,
            [
                "-o",
                "ControlMaster=auto",
                "-o",
                "ControlPath=/run/user/1000/preserver-ssh-%C",
                "-o",
                "ControlPersist=60",
                "-p",
                "22",
                "git@github.com",
                "git-upload-pack 'o/r.git'",
            ]
        );
    }
}
