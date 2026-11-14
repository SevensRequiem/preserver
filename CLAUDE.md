# preserver

Encrypted GitHub mirror bundles (age), encrypted local-folder archives, and signed public-archive mirroring to removable drives. Design: `docs/design.md`. Example config: `docs/config.example.toml`.

## Names and personal data

preserver is its own app: `~/.config/preserver` (`config.toml`, `personal/{identity.age,recipient.txt}`), `~/.local/state/preserver`, `~/.cache/preserver`, `$XDG_RUNTIME_DIR/preserver` and `preserver-<job>.lock`, units `preserver-*`, `<drive>/preserver/{github-repos-personal,local-personal,public,kit,.state}`. Windows: `%APPDATA%\preserver`, `%LOCALAPPDATA%\preserver`. Nothing from another tool is read or migrated. An existing key comes in with `init --import <identity.age>`; old backups restore from wherever they are, since `restore` takes a file path and looks for `identity.age` next to it. Nothing host-specific or personal (drive uuid, email, owners) goes in source or docs: it comes from `~/.config/preserver/config.toml`; only `restore` runs without it.

## Layout

One package: `src/lib.rs` holds the logic, `src/main.rs` stays thin. Modules follow section 3 of `docs/design.md`. No platform trait: `src/platform/{linux,windows}/` export identical free functions under `cfg`.

## Build and gates

```
~/.claude/bin/cap ~/.claude/bin/ctrim cargo build -j N
~/.claude/bin/cap ~/.claude/bin/ctrim cargo clippy --all-targets --all-features -- -D warnings
~/.claude/bin/cap ~/.claude/bin/ctrim cargo test
cargo fmt --check
cargo deny check
```

N is 90% of cores. In the Claude sandbox set `CARGO_HOME=$TMPDIR/cargo` and `CARGO_TARGET_DIR=$TMPDIR/target`. `rustup target add` (targets in `rust-toolchain.toml`) writes `~/.rustup`, so run it outside the sandbox. Linux musl and `x86_64-pc-windows-gnu` cross builds are configured in `.cargo/config.toml`; MSVC builds come from CI.

## Rules

- Sync only (std threads, `std::sync::mpsc`), no tokio.
- Add a crate only in the phase that uses it, at an exact `=` pin. `deny.toml` bans `cc` outside ring (re-add the blake3 wrapper when a phase pulls it in).
- A file becomes visible only after it verifies. The age recipient is read from the home config only.
- GitHub token never in argv, URL, log or file.
- A catalog source with a `todo` is disabled until the todo is resolved.
- The personal flow touches real credentials and FIDO keys: run it by hand, not from an automated session.

## Phase 1a notes

- `main.rs` dispatches on argv0: `preserver-ssh` (git's `GIT_SSH`, execs ssh with the ControlMaster options first) and `preserver-credential` (git credential helper, answers only for https github.com from `PRESERVER_GH_TOKEN`). Both are symlinks to the binary in `$XDG_RUNTIME_DIR/preserver/`, created by `git::Auth`.
- Library internals are `pub(crate)`; unit tests sit next to the code and `tests/cli.rs` drives the built binary. Only `cli`, `SHIM`/`shim_main` and `HELPER`/`helper_main` are public.
- A test must not check that a job lock is free again after dropping it: a child another test thread is spawning shares the flock until it execs.
- In the Claude sandbox cargo cannot run inside the repo (it walks up to an unreadable `~/.cargo/config.toml`): rsync the tree to `$TMPDIR/pbuild` and build there; `rustfmt --edition 2024 src/lib.rs src/main.rs tests/cli.rs` works in place. The system D-Bus is blocked there too, so `drives`, `open` and mounting are only verifiable outside it.

## Phase 1b notes

- `tray_model.rs` is the whole tray logic as a pure function (status files + lock state in, icon/tooltip/menu labels out). `platform/linux/tray.rs` only maps it onto ksni and owns one loop: menu clicks and helper threads send it a `Cmd`, it refreshes hourly, on every command and when the menu opens. ksni re-registers by itself when the watcher restarts (`service.rs`, `NameOwnerChanged`).
- "Back up personal now" queues the GitHub and local jobs for the daemon when it runs (`actions::enqueue_personal`, then `queue/wake`), else runs `preserver personal --foreground` and waits for it on a thread: the exit status is the only sign of a run that died before writing its status file. At start the tray imports DISPLAY, WAYLAND_DISPLAY and XAUTHORITY into the user manager, where the daemon reads them per job for the askpass dialog.
- The transport menu edits the `transport` line of `config.toml` in place (`config::with_transport`) and re-parses the result: every other setting must be unchanged or nothing is written. No TOML writer, so comments survive.
- Notifications go over zbus (`platform/linux/notify.rs`), no `notify-send`. The overdue reminder is shown once per day per tray process, not persisted.
- Local folders (`personal/local.rs`): tar on a thread -> pipe -> ruzstd -> age -> `.tmp`, fsync, rename, fsync dir. ruzstd only has its fastest level and unwraps I/O results, hence the `Held` adapters. Format details are in `docs/design.md` section 4.
- `restore` of a `Dnn` reads the `L0.tar.zst.age` next to it; of an `L0`, just that. An archive with no manifest (not written by preserver) is refused, and the error gives the GNU tar command.
- A month whose L0 has no `.idx` in the state dir makes `personal --local-only` fail for that folder until the month directory is moved aside or the month ends.
- The sandbox blocks unix sockets: the tray is checked outside it against a private `dbus-daemon --config-file` (no service dirs, or Notify hangs on activation) with HOME and XDG_RUNTIME_DIR in a scratch dir. Never test against the session bus.

## Phase 2 notes

- `net/`: `client.rs` (ureq agent, rustls+ring, roots from the OS via rustls-platform-verifier; `embedded_roots` is the webpki-roots fallback, `RootCerts::WebPki`, used when the platform verifier cannot load an OS store; ureq's `rustls-webpki-roots` feature brings the crate and a direct `=` line pins it, and `deny.toml` allows CDLA-Permissive-2.0 for that crate only), `throttle.rs` (one token bucket with debt, shared by every stream and proxy tunnel), `download.rs` (segmented Range/If-Range GETs, `.part` + `.part.json` sidecar holding the SHA-256/512 midstate at each checkpoint), `hash.rs` (resumable SHA-2 on `sha2::compress*`), `proxy.rs` (loopback CONNECT proxy, ports 443/873/9418 only).
- `queue/`: job JSON is written by the worker only; the CLI and tray write `<id>.ctl` / `all.ctl`, which the worker reads every second. One worker, under the `preserver-queue` lock.
- A `.part` without a matching sidecar restarts from zero: nothing proves what its bytes are. A `200` to a ranged request that is longer than one segment is dropped and asked for again as a plain GET, so its timeout comes from the file size. A failed `fetch` takes its bytes back off the shared progress counter (not a stop).
- Network tests use `net/testserver.rs` (in-process loopback HTTP) and `net/testdata/` (a test CA and leaf; `gen.sh` regenerates them). The per-host test binds 127.0.0.2, which Linux routes to loopback.
- ring needs a C cross compiler for the cross clippy gates. Without mingw or MSVC headers they pass with `CFLAGS=-DRING_CORE_NOSTDLIBINC`, `CC_<target>=clang`, `AR_<target>=ar`; for `aarch64-pc-windows-msvc` also `-D__GNUC__=4` in its CFLAGS and an AR that maps lib.exe arguments onto `ar crs`. Those objects are only for checking, never ship them.
- `catalog.toml` and `keys/*.gpg` are compiled in (`catalog.rs`, `keys.rs`). `keys/FINGERPRINTS` lists every primary key and a test holds it to what rpgp parses; `keys/fetch.sh` (needs gpg and curl, run by hand) fetches a missing keyring, never replaces one, and rewrites FINGERPRINTS. A new keyring also needs its line in `keys.rs`. The catalog refuses unknown fields, and a signed source whose keyring is not compiled in.
- `resolve/`: `Item` keeps hashes as the published hex, and the plan hash is built from it. No `url` crate: `listing.rs` joins hrefs itself.
- `verify/pgp.rs` replaces gpgv. Same verdicts as gpgv's zero-exit VALIDSIG (a test runs both when `/usr/bin/gpgv` exists): every signature in the file must verify, an expired key still counts, an expired signature or one older than its key does not. Stricter in one place: a revoked key or subkey is refused. Clearsigned sums are read from the signed text only. Two gnu-keyring keys (RSA 9888 and 15424 bit) are above rpgp's size limit without its `large-rsa` feature, so their signatures fail closed.
- `public/`: one queue job per set. The worker's `plan` resolves and stages (`.staging/<plan16>/`, hard links or copies from the newest version, signature and sums files as extra downloads); its `settle` hook verifies and renames the stage into place, or fails the job. A file that fails verification is deleted with its side files; the rest of the stage waits for the next run. `git` and `repo` sources are skipped until phase 3. Bytes already staged count against the budget, so a resumed job is not refused. A carried file never brings a side file that a changed file of the same source fetches fresh. `publish` deletes anything in the stage that is not a plan file or its side file, then `syncfs` before the rename (prune follows), since copies on FAT/exFAT are not otherwise flushed.
- Tests make OpenPGP keys with rpgp (`verify/testkey.rs`). The RNG trait comes from the `rsa` dev-dependency's `rand_core` re-export; `rsa` is not a normal dependency yet.
- `deny.toml`: `Zlib` is allowed for zlib-rs (pgp's flate2 backend); RUSTSEC-2023-0071 (rsa 0.9) is ignored because nothing here holds an RSA private key.
- `$TMPDIR` is a 16 GB tmpfs with a quota: a full `target/` makes tests fail with "Disk quota exceeded". Delete `target/debug/incremental` and build with `CARGO_INCREMENTAL=0`.

## Daemon notes

- `daemon.rs`: `preserver daemon` holds `preserver-daemon.lock` for life (a second one logs "waiting for the running daemon to exit" and blocks, so an overlapping restart is no crash loop) and writes `status/daemon.json` once. Main runs the event loop (schedules, copy rules, mounting a wanted drive on plug-in), one thread per lane runs passes, the udisks and queue watchers wake main (`Wake::{Drive, Queue}`). The CLI, tray and daemon share `actions.rs`: `daemon_live` (the lock), `wake` (`queue/wake`, which the inotify watch on the queue directory turns into a pass; `.ctl` writes wake it too), best-effort `mount`, `enqueue_personal`, `retry` and the CLI `handoff`. No socket: control stays `.ctl` in, job JSON and `status/*.json` out.
- Lanes: `JobKind::lane()`. A worker resets, applies controls to and writes only its own lane's jobs, so two lanes never write the same job file. `Lane::Download` runs under `preserver-queue.lock`, `Lane::Copy` under `preserver-copy-queue.lock`, `Lane::Personal` (GitHub and local jobs, `personal/lane.rs`) under `preserver-personal-queue.lock`, then `github`/`local` (`status::job`), so the status files keep their meaning.
- `Pass { retry_failed, retry_blocked }`: `FRESH` for CLI runs, `TICK` for the 30 s tick and queue wake-ups (requeues only crashed `Running` jobs), drive events and the hourly sweep also requeue `Blocked`, except `Blocked(NeedsTouch)`: only a ctl retry or the next scheduled occurrence asks for the key again, so the daemon never prompts in a loop. `runnable()` decides whether a pass would do anything, so an idle tick loads nothing and writes no status. Coalesced passes OR their flags.
- `daemon_pass` only `try_lock`s the queue: a CLI run already holding it wins and the daemon tries again next tick. Lock order is queue, then public (`status::job`). `Store::enqueue` keeps one unfinished job per kind (any GitHub job matches, whatever its transport) and bumps `retry` and clears `pause` in a stopped one's ctl; a retry requeues `Blocked` as well as `Failed`.
- The watcher is one `MessageIterator` with one match rule (udisks signals under `/org/freedesktop/UDisks2`, turned into `DriveEvent`s by `drive_event`); it reconnects every 30 s and warns once per failure streak. Its end-to-end test runs only outside the sandbox against a private bus: `PRESERVER_DBUS_TEST=1` on the test binary with `DBUS_SESSION_BUS_ADDRESS` and `DBUS_SYSTEM_BUS_ADDRESS` unset, filter `watcher_sees_a_plug_in`.
- The tray shows the daemon and queue lines and a pause item (writes `all.ctl`), and polls every 5 s while a job runs, 60 s while one waits, hourly otherwise.
- Lanes never mount (`platform::locate`: Absent and Unmounted are `Blocked` without an attempt). Only people's actions mount, and the daemon's `mount_added` on InterfacesAdded for a wanted id (primary, copy rule or unfinished copy job targets); a drive already plugged in when the daemon starts stays "not mounted" until someone mounts it, replugs it or presses Retry. Mounting from the user service goes through polkit with `auth.no_user_interaction`; not yet checked on a real session.
- Schedules: `[schedule]` in config.toml (`personal` = the GitHub job, `local`, `public`; `H:MM:SS` every, `HH:MM` daily) go through `schedule::tick` before every pass; `copy::rules::due` uses the same `schedule::due`. `last_run` from `status/<job>.json` is the memory, so a missed occurrence runs once and a manual run counts. A Failed or `NeedsTouch` job older than the occurrence gets one ctl retry.
- The personal lane gets the session's DISPLAY, WAYLAND_DISPLAY, XAUTHORITY and SSH_AUTH_SOCK from `systemctl --user show-environment` per job (5 s bound). ssh over the FIDO key waits 120 s for the touch (`TOUCH_WAIT`), in its own process group so a timeout or a pause ends the askpass too; on a terminal (a foreground run) it keeps the terminal's group so a PIN prompt there works. No answer, or ssh with no graphical session, is `Blocked(NeedsTouch)`. Windows has no drive events yet (`watch_drives` warns), and restart-on-failure for the `\preserver\daemon` task XML is phase 5.
- The AR wrapper for the `aarch64-pc-windows-msvc` clippy gate must accept lowercase `-out:` too: cc-rs passes that form.

## Copy notes

- `copy/`: `plan.rs` is pure (inputs in, `Plan` out, unit-tested at 16G/32G/128G/2T and shrinking); `exec.rs` writes (stage, read back, rename); `rules.rs` owns `copy.toml`; `mod.rs` scans both trees, runs a job, and is the lane, the scheduler and the CLI. Design in `docs/design.md` §3.6.
- The lane's lock order is `copy-queue`, then `copy` (`status::job`). `record` writes `status/copy.json` (one `sets` entry per rule, or `once-<target id>` for one-off copies) before it removes Done and Canceled jobs: `schedule` reads the last run from there, so a rule never looks as if it never ran.
- A job runs `execute` on a scoped thread; the lane thread polls the job's ctl every second and sets `Prog::stop`, which `copy_file` checks per 1 MiB chunk. A run that finds the primary pruned under it (`Vanished`) plans once more. A missing primary or target is `Blocked` without an attempt.
- `.state/copy.json` on the target marks the tree as a copy's (and holds the personal size/mtime and kit fingerprint); without it a non-empty `preserver/` is refused. It is written before anything else so an interrupted first run resumes.
- The Env seam (`drive`, `fstype`, `free`, `cluster`, `say`) lets the end-to-end tests in `copy/tests.rs` fake both drives in a temp dir; nothing there touches udisks. The `public --list` CLI test points `DBUS_SYSTEM_BUS_ADDRESS` at a missing socket for the same reason.
- clippy's `allow-unwrap-in-tests` only recognizes a literal `#[cfg(test)]` on the module: gate a unix-only test file with `#![cfg(unix)]` inside it, not `#[cfg(all(test, unix))]`.
- Anything read from the target's metadata (`copy.json`, `SET.toml`, `SHA256SUMS`, `MIRRORS.toml`) goes through `read_meta`: no links, no FIFOs, 32 MiB cap. A personal file the target cannot hold (FAT32 size, Windows names) fails the job after the rest is copied; a skipped public file is only a warning. A file reused from the old version is hashed again before the new `SHA256SUMS` lists it; an in-place replacement deletes the old files it will not reuse before copying.
- Not done: Windows `fs_type`/`block_size` return Unsupported (the drive's udisks/volume fstype is used first, else the copy is planned as "other"); a canceled job that never ran leaves an old stage until the next copy to that target clears it; an interrupted in-place replacement (no room for both versions) leaves that set absent until the next run.

## Install and release

- `./install.sh` builds this checkout (`cargo build --release --locked`) and installs; `./install.sh DIR` installs from a downloaded release dir (`preserver-<target>` + `SHA256SUMS`), checking the host target's hash with `sha256sum -c` on the staged copy and refusing on a mismatch. Binary goes to `~/.local/bin/preserver` by atomic rename, the one it replaces is kept as `preserver.prev`. Units in `dist/systemd/` are copied (not linked) to `~/.config/systemd/user`: the tray and `preserver-daemon.service` (started at once, try-restarted on upgrade and rollback), both enabled. Job times live in `[schedule]` in config.toml, run by the daemon. The retired `preserver-{personal,local,public}.service` and `preserver-{local,public}.timer` are disabled, stopped and removed on install (with a hint to set `local` under `[schedule]` when the local timer was on), and removed by `--uninstall` too. The installer imports whichever of DISPLAY, WAYLAND_DISPLAY and XAUTHORITY it has into the user manager. The daemon unit has no `PrivateTmp` (the askpass needs `/tmp/.X11-unix`) and defaults `SSH_AUTH_SOCK` to `%t/ssh-agent.socket`. `--rollback` swaps `preserver` and `preserver.prev` (run it again to swap forward), `--uninstall` removes binary and units and never touches config, keys, state or backups.
- `install.bat` does the same on Windows (`certutil` hash check, `%LOCALAPPDATA%\preserver\bin`, `preserver.prev.exe`, `/rollback`, `/uninstall`) and registers `\preserver\{tray,daemon}` through `schtasks /XML` itself, because the binary's `install` subcommand is still a phase 5 stub, and ends and deletes the retired `\preserver\{local,public}`; `/uninstall` removes all four. It has not been run on Windows yet.
- `tests/install-sh.sh` drives `install.sh` in a scratch HOME with fake `systemctl` and `cargo`; CI runs it.
- Releases: push a `v*` tag matching the `Cargo.toml` version. `.github/workflows/release.yml` builds `preserver-<target>[.exe]` for x86_64/aarch64 linux-musl and windows-msvc, writes `SHA256SUMS` and attaches both to the GitHub release. `ci.yml` runs fmt, clippy, test, `cargo deny` and the install test on Linux, build and test on Windows x64 and ARM64. Actions are pinned by commit SHA with the version in a comment.
