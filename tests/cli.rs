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
    let out = preserver(&root).args(["clone", "/x"]).output().unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("phase 4"), "{}", stderr(&out));
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

fn local_status(root: &Path) -> String {
    std::fs::read_to_string(root.join("home/.local/state/preserver/status/local.json")).unwrap()
}

#[test]
fn local_only_without_folders_succeeds_without_the_drive() {
    let root = fresh_dir("nolocal");
    write_config(&root);
    let personal = root.join("home/.config/preserver/personal");
    std::fs::create_dir_all(&personal).unwrap();
    std::fs::write(personal.join("recipient.txt"), "age1x\n").unwrap();
    let out = preserver(&root)
        .args(["personal", "--local-only"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let status = local_status(&root);
    assert!(status.contains(r#""error":"""#), "{status}");
    assert!(!status.contains(r#""last_ok":"0001"#), "{status}");
    assert!(
        !root
            .join("home/.local/state/preserver/status/github.json")
            .exists(),
        "--local-only leaves GitHub alone"
    );
}

#[test]
fn nightly_local_run_skips_quietly_when_the_drive_is_absent() {
    let root = fresh_dir("nodrive");
    write_config(&root);
    let cfg = root.join("home/.config/preserver");
    let mut text = std::fs::read_to_string(cfg.join("config.toml")).unwrap();
    text.push_str("[[local]]\nname = \"docs\"\npath = \"/nonexistent\"\n");
    std::fs::write(cfg.join("config.toml"), text).unwrap();
    std::fs::create_dir_all(cfg.join("personal")).unwrap();
    std::fs::write(cfg.join("personal/recipient.txt"), "age1x\n").unwrap();
    let out = preserver(&root)
        .args(["personal", "--local-only"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stderr(&out).contains("skipped"), "{}", stderr(&out));
    let status = local_status(&root);
    assert!(status.contains("backup drive is not connected"), "{status}");
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
