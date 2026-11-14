//! Drives the built binary the way git, the units and a user do.

#![cfg(unix)]
#![expect(
    clippy::unwrap_used,
    reason = "helpers outside #[test] functions panic on a failed setup too"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_preserver");

fn fresh_dir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("cli-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("run")).unwrap();
    dir
}

/// The binary with every home-relative path inside `root`.
fn preserver(root: &Path) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", root.join("home"))
        .env("XDG_RUNTIME_DIR", root.join("run"))
        .env("USER", "u")
        .stdin(Stdio::null());
    cmd
}

fn write_config(root: &Path) {
    let dir = root.join("home/.config/preserver");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("config.toml"),
        "owners = [\"o\"]\nprimary_uuid = \"0123-ABCD\"\n",
    )
    .unwrap();
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn missing_config_names_the_file() {
    let root = fresh_dir("noconfig");
    let out = preserver(&root).arg("drives").output().unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("config.toml"), "{}", stderr(&out));
}

#[test]
fn bad_config_is_rejected_before_anything_runs() {
    let root = fresh_dir("badconfig");
    let dir = root.join("home/.config/preserver");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("config.toml"),
        "owners = [\"--upload-pack=x\"]\nprimary_uuid = \"0123-ABCD\"\n",
    )
    .unwrap();
    let out = preserver(&root).arg("personal").output().unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("bad owner"), "{}", stderr(&out));
}

#[test]
fn later_phases_say_so() {
    let root = fresh_dir("phases");
    let out = preserver(&root).args(["verify"]).output().unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("phase 4"), "{}", stderr(&out));
}

#[test]
fn copy_rules_are_checked_before_any_drive_is_touched() {
    let root = fresh_dir("copy");
    write_config(&root);
    let run = |args: &[&str]| preserver(&root).arg("copy").args(args).output().unwrap();

    let out = run(&["--list"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("no copy rules"));

    let out = run(&[".", "-t", "1:60:00"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("1:60:00"), "{}", stderr(&out));

    let out = run(&[".", "--sets", "nope"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("nope"), "{}", stderr(&out));

    let out = run(&["--remove", "000000000000"]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no rule"), "{}", stderr(&out));

    let out = run(&[]);
    assert!(!out.status.success());
}

#[test]
fn public_list_without_the_drive_shows_estimates() {
    let root = fresh_dir("publist");
    write_config(&root);
    // A bus address that leads nowhere: the test never talks to the real udisks.
    let out = preserver(&root)
        .env(
            "DBUS_SYSTEM_BUS_ADDRESS",
            format!("unix:path={}", root.join("no-bus").display()),
        )
        .args(["public", "--list"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("estimates only"), "{text}");
    assert!(text.contains("priority"), "{text}");
    assert!(
        text.find("keys").unwrap() < text.find("extras").unwrap(),
        "{text}"
    );
}

#[test]
fn public_refuses_an_unknown_set_before_touching_the_drive() {
    let root = fresh_dir("public");
    write_config(&root);
    let out = preserver(&root)
        .args(["public", "no-such-set", "--dry-run"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("no set \"no-such-set\" in the catalog"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn tray_without_a_session_bus_fails_cleanly() {
    // XDG_RUNTIME_DIR is the test's own, so there is no bus socket and no real tray is touched.
    let root = fresh_dir("tray");
    let out = preserver(&root).arg("tray").output().unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("start the tray"), "{}", stderr(&out));
}

#[test]
fn a_second_daemon_waits_for_the_first() {
    use std::io::BufRead;
    let root = fresh_dir("daemon");
    // The test plays the running daemon by holding its lock.
    let lock = std::fs::File::create(root.join("run/preserver-daemon.lock")).unwrap();
    lock.try_lock().unwrap();
    let mut child = preserver(&root)
        .arg("daemon")
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stderr).lines() {
            let _ = tx.send(line.unwrap_or_default());
        }
    });
    let mut seen = Vec::new();
    let waiting = loop {
        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(line) if line.contains("waiting for the running daemon to exit") => break true,
            Ok(line) => seen.push(line),
            Err(_) => break false,
        }
    };
    let _ = child.kill();
    let _ = child.wait();
    assert!(waiting, "{seen:?}");
    assert!(
        !root
            .join("home/.local/state/preserver/status/daemon.json")
            .exists(),
        "a waiting daemon writes nothing"
    );
}

/// A config with one local folder, an age recipient, and a system bus that leads nowhere, so
/// the test never talks to the real udisks.
fn personal_setup(name: &str, local: bool) -> (PathBuf, impl Fn() -> Command) {
    let root = fresh_dir(name);
    write_config(&root);
    let cfg = root.join("home/.config/preserver");
    if local {
        let mut text = std::fs::read_to_string(cfg.join("config.toml")).unwrap();
        text.push_str("[[local]]\nname = \"docs\"\npath = \"/nonexistent\"\n");
        std::fs::write(cfg.join("config.toml"), text).unwrap();
    }
    std::fs::create_dir_all(cfg.join("personal")).unwrap();
    std::fs::write(cfg.join("personal/recipient.txt"), "age1x\n").unwrap();
    let bus = format!("unix:path={}", root.join("no-bus").display());
    let r = root.clone();
    (root, move || {
        let mut cmd = preserver(&r);
        cmd.env("DBUS_SYSTEM_BUS_ADDRESS", &bus);
        cmd
    })
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn local_only_without_folders_does_nothing() {
    let (root, cmd) = personal_setup("nolocal", false);
    let out = cmd().args(["personal", "--local-only"]).output().unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("no [[local]] folders"),
        "{}",
        stdout(&out)
    );
    assert!(!root.join("home/.local/state/preserver/queue").exists());
}

#[test]
fn without_a_daemon_a_missing_drive_blocks_the_job_here() {
    let (_root, cmd) = personal_setup("nodrive", true);
    let out = cmd().args(["personal", "--local-only"]).output().unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("no daemon running; running here"), "{text}");
    assert!(text.contains("local folders: blocked"), "{text}");
    let out = cmd().args(["queue", "list"]).output().unwrap();
    assert!(stdout(&out).contains("local folders"), "{}", stdout(&out));
}

#[test]
fn with_the_daemon_running_personal_only_queues() {
    let (root, cmd) = personal_setup("handoff", true);
    // The test plays the running daemon by holding its lock.
    let lock = std::fs::File::create(root.join("run/preserver-daemon.lock")).unwrap();
    lock.try_lock().unwrap();
    let out = cmd().arg("personal").output().unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("queued as "), "{}", stdout(&out));
    assert!(root.join("home/.local/state/preserver/queue/wake").exists());
    let out = cmd().args(["queue", "list"]).output().unwrap();
    let list = stdout(&out);
    assert!(
        list.contains("github") && list.contains("local folders"),
        "{list}"
    );
    assert!(
        !root
            .join("home/.local/state/preserver/status/local.json")
            .exists(),
        "nothing ran here"
    );
}

#[test]
fn personal_without_init_fails() {
    let root = fresh_dir("noinit");
    write_config(&root);
    let out = preserver(&root).arg("personal").output().unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("init"), "{}", stderr(&out));
}

#[test]
fn restore_refuses_a_non_empty_dir_before_asking_for_the_password() {
    let root = fresh_dir("restore");
    write_config(&root);
    let target = root.join("target");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("keep"), "mine").unwrap();
    let out = preserver(&root)
        .arg("restore")
        .arg(root.join("x.bundle.age"))
        .arg(&target)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("not empty"), "{}", stderr(&out));
}

/// git itself asks the helper, with the configuration the https transport sets on `git fetch`.
fn git_credential_fill(root: &Path, request: &str) -> Output {
    use std::io::Write;
    let helper = root.join("run/preserver-credential");
    if !helper.exists() {
        std::os::unix::fs::symlink(BIN, &helper).unwrap();
    }
    let mut child = Command::new("git")
        .args(["credential", "fill"])
        .current_dir(root)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_COUNT", "2")
        .env("GIT_CONFIG_KEY_0", "credential.helper")
        .env("GIT_CONFIG_VALUE_0", "")
        .env("GIT_CONFIG_KEY_1", "credential.helper")
        .env("GIT_CONFIG_VALUE_1", &helper)
        .env("PRESERVER_GH_TOKEN", "test-token-not-real")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn credential_helper_answers_git_for_github_only() {
    let root = fresh_dir("credential");
    let out = git_credential_fill(&root, "protocol=https\nhost=github.com\n\n");
    assert!(out.status.success(), "{}", stderr(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("username=x-access-token\n"), "{stdout}");
    assert!(
        stdout.contains("password=test-token-not-real\n"),
        "{stdout}"
    );

    for request in [
        "protocol=https\nhost=example.com\n\n",
        "protocol=http\nhost=github.com\n\n",
    ] {
        let out = git_credential_fill(&root, request);
        assert!(
            !String::from_utf8_lossy(&out.stdout).contains("test-token-not-real"),
            "token leaked for {request:?}"
        );
        assert!(
            !out.status.success(),
            "git got a credential for {request:?}"
        );
    }
}

#[test]
fn ssh_shim_becomes_ssh_with_its_options_first() {
    if !Path::new("/usr/bin/ssh").exists() {
        eprintln!("skipped: /usr/bin/ssh is not installed");
        return;
    }
    let root = fresh_dir("shim");
    let shim = root.join("run/preserver-ssh");
    std::os::unix::fs::symlink(BIN, &shim).unwrap();
    // -G prints the resolved client configuration and exits without connecting.
    let out = Command::new(&shim)
        .args(["-F", "/dev/null", "-G", "-p", "2222", "git@host.invalid"])
        .env("XDG_RUNTIME_DIR", root.join("run"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let config = String::from_utf8_lossy(&out.stdout).to_lowercase();
    assert!(config.contains("controlmaster auto"), "{config}");
    assert!(config.contains("controlpersist 60"), "{config}");
    assert!(
        config.contains(&format!(
            "controlpath {}/preserver-ssh-",
            root.join("run").display().to_string().to_lowercase()
        )),
        "{config}"
    );
    assert!(config.contains("port 2222"), "{config}");
    assert!(config.contains("hostname host.invalid"), "{config}");
}
