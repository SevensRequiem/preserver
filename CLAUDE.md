# preserver

Rust rewrite of the Go `code-archive`: encrypted GitHub mirror bundles (age), encrypted local-folder archives, and signed public-archive mirroring to removable drives. Design: `docs/design.md`. Example config: `docs/config.example.toml`.

## Compatibility rule

Keep every code-archive path, unit name, lock name and on-disk format (`code-archive` dirs on host and drive, `code-archive-*` units and locks, bundle and status formats). Only the binary is named `preserver`. A run against Go-era state must write zero new bundles. Nothing host-specific or personal (drive uuid, email, owners) goes in source or docs: it comes from `~/.config/code-archive/config.toml`. Cut-over from the Go tool: write that file (owners, primary_uuid) first, since Go compiled these in; only `restore` runs without it.

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

- `main.rs` dispatches on argv0: `preserver-ssh` (git's `GIT_SSH`, execs ssh with the ControlMaster options first) and `preserver-credential` (git credential helper, answers only for https github.com from `PRESERVER_GH_TOKEN`). Both are symlinks to the binary in `$XDG_RUNTIME_DIR/code-archive/`, created by `git::Auth`.
- Library internals are `pub(crate)`; unit tests sit next to the code and `tests/cli.rs` drives the built binary. Only `cli`, `SHIM`/`shim_main` and `HELPER`/`helper_main` are public.
- `migrate` is kept (ported from Go) although the design table lists it as dropped.
- A test must not check that a job lock is free again after dropping it: a child another test thread is spawning shares the flock until it execs.
- In the Claude sandbox cargo cannot run inside the repo (it walks up to an unreadable `~/.cargo/config.toml`): rsync the tree to `$TMPDIR/pbuild` and build there; `rustfmt --edition 2024 src/lib.rs src/main.rs tests/cli.rs` works in place. The system D-Bus is blocked there too, so `drives`, `open` and mounting are only verifiable outside it.

## Phase 1b notes

- `tray_model.rs` is the whole tray logic as a pure function (status files + lock state in, icon/tooltip/menu labels out). `platform/linux/tray.rs` only maps it onto ksni and owns one loop: menu clicks and helper threads send it a `Cmd`, it refreshes hourly, on every command and when the menu opens. ksni re-registers by itself when the watcher restarts (`service.rs`, `NameOwnerChanged`).
- "Back up personal now" runs `systemctl --user start code-archive-personal.service` and waits for it on a thread, as Go did: the exit status is the only sign of a run that died before writing its status file.
- The transport menu edits the `transport` line of `config.toml` in place (`config::with_transport`) and re-parses the result: every other setting must be unchanged or nothing is written. No TOML writer, so comments survive.
- Notifications go over zbus (`platform/linux/notify.rs`), no `notify-send`. The overdue reminder is shown once per day per tray process, not persisted, as in Go.
- Local folders (`personal/local.rs`): tar on a thread -> pipe -> ruzstd -> age -> `.tmp`, fsync, rename, fsync dir. ruzstd only has its fastest level and unwraps I/O results, hence the `Held` adapters. Format details are in `docs/design.md` section 4.
- `restore` of a `Dnn` reads the `L0.tar.zst.age` next to it; of an `L0`, just that. Go-era `.tar.zst.age` files have no manifest and are restored with GNU tar (the error says how).
- Cut-over: a month whose L0 the Go tool wrote has no `.idx`, so `personal --local-only` fails for that folder until its month directory is moved aside or the month ends.
- The sandbox blocks unix sockets: the tray is checked outside it against a private `dbus-daemon --config-file` (no service dirs, or Notify hangs on activation) with HOME and XDG_RUNTIME_DIR in a scratch dir. Never test against the session bus.

## Phase 2 notes

- `net/`: `client.rs` (ureq agent, rustls+ring, roots from the OS via rustls-platform-verifier; `embedded_roots` is the seam for the webpki-roots fallback, which is not approved yet, so a host with no CA store fails closed), `throttle.rs` (one token bucket with debt, shared by every stream and proxy tunnel), `download.rs` (segmented Range/If-Range GETs, `.part` + `.part.json` sidecar holding the SHA-256/512 midstate at each checkpoint), `hash.rs` (resumable SHA-2 on `sha2::compress*`), `proxy.rs` (loopback CONNECT proxy, ports 443/873/9418 only).
- `queue/`: job JSON is written by the worker only; the CLI and tray write `<id>.ctl` / `all.ctl`, which the worker reads every second. One worker, under the `code-archive-queue` lock.
- A `.part` without a matching sidecar restarts from zero: nothing proves what its bytes are. A `200` to a ranged request that is longer than one segment is dropped and asked for again as a plain GET, so its timeout comes from the file size. A failed `fetch` takes its bytes back off the shared progress counter (not a stop).
- Network tests use `net/testserver.rs` (in-process loopback HTTP) and `net/testdata/` (a test CA and leaf; `gen.sh` regenerates them). The per-host test binds 127.0.0.2, which Linux routes to loopback.
- ring needs a C cross compiler for the cross clippy gates. Without mingw or MSVC headers they pass with `CFLAGS=-DRING_CORE_NOSTDLIBINC`, `CC_<target>=clang`, `AR_<target>=ar`; for `aarch64-pc-windows-msvc` also `-D__GNUC__=4` in its CFLAGS and an AR that maps lib.exe arguments onto `ar crs`. Those objects are only for checking, never ship them.
- `catalog.toml` and `keys/*.gpg` are compiled in (`catalog.rs`, `keys.rs`). `keys/FINGERPRINTS` lists every primary key and a test holds it to what rpgp parses; `keys/fetch.sh` (needs gpg and curl, run by hand) fetches a missing keyring, never replaces one, and rewrites FINGERPRINTS. A new keyring also needs its line in `keys.rs`. The catalog refuses unknown fields, and a signed source whose keyring is not compiled in.
- `resolve/` ports the Go resolvers; `Item` keeps hashes as the published hex so the plan hash equals the Go tool's and a Go-era version reads as unchanged. No `url` crate: `listing.rs` joins hrefs itself.
- `verify/pgp.rs` replaces gpgv. Same verdicts as gpgv's zero-exit VALIDSIG (a test runs both when `/usr/bin/gpgv` exists): every signature in the file must verify, an expired key still counts, an expired signature or one older than its key does not. Stricter in one place: a revoked key or subkey is refused. Clearsigned sums are read from the signed text only. Two gnu-keyring keys (RSA 9888 and 15424 bit) are above rpgp's size limit without its `large-rsa` feature, so their signatures fail closed.
- `public/`: one queue job per set. The worker's `plan` resolves and stages (`.staging/<plan16>/`, hard links or copies from the newest version, signature and sums files as extra downloads); its `settle` hook verifies and renames the stage into place, or fails the job. A file that fails verification is deleted with its side files; the rest of the stage waits for the next run. `git` and `repo` sources are skipped until phase 3. Bytes already staged count against the budget, so a resumed job is not refused. A carried file never brings a side file that a changed file of the same source fetches fresh. `publish` deletes anything in the stage that is not a plan file or its side file, then `syncfs` before the rename (prune follows), since copies on FAT/exFAT are not otherwise flushed.
- Tests make OpenPGP keys with rpgp (`verify/testkey.rs`). The RNG trait comes from the `rsa` dev-dependency's `rand_core` re-export; `rsa` is not a normal dependency yet.
- `deny.toml`: `Zlib` is allowed for zlib-rs (pgp's flate2 backend); RUSTSEC-2023-0071 (rsa 0.9) is ignored because nothing here holds an RSA private key.
- `$TMPDIR` is a 16 GB tmpfs with a quota: a full `target/` makes tests fail with "Disk quota exceeded". Delete `target/debug/incremental` and build with `CARGO_INCREMENTAL=0`.
