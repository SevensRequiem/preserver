# preserver: design

Crate versions and features were checked on crates.io. Dependency counts come from `cargo tree` on a scratch workspace with the exact versions and features listed below.

## 0. Decisions at a glance

| Question | Decision | Main reason |
|---|---|---|
| Async or sync | **Sync for the whole program**: std threads plus `std::sync::mpsc`, no tokio | At most about 8 concurrent transfers. ureq, the gix blocking client, `ksni::blocking` and `zbus::blocking` are all sync. tokio would add about 60 crates and spawn_blocking glue for file I/O and hashing |
| HTTP | `ureq` 3 + rustls + ring + platform verifier | 27 deps against reqwest's 105. reqwest 0.13 brings tokio and defaults to aws-lc |
| rustls backend | **ring** | aws-lc needs cmake, clang and perl per target. `rustls-rustcrypto` only exists as `0.1.0-pre.0` |
| age | **crate, in-process** | Windows parity without shipping age.exe. Same v1 format and same author (str4d) as the spec |
| OpenPGP | **`pgp` (rpgp)** | sequoia: 200 deps, LGPL-2.0+, nettle (C) by default, and its pure-Rust backend needs `allow-experimental-crypto` + `allow-variable-time-crypto` |
| git | `gix` for fetch and for reading or indexing packs. **Bundle creation execs `git bundle create`.** Phase 1 execs git for fetch as well | gix has no bundle support at all (crate-status: `gix-bundle` all unchecked, clone/fetch "bundles" unchecked) |
| git over ssh | gix's ssh transport already **execs `ssh`**. That stays, through a shim (§3.5) | OpenSSH owns FIDO, ksshaskpass and ControlMaster |
| git over https (public mirrors) | gix with **our own `gix_transport::client::blocking_io::http::Http` impl over ureq** | No curl (C) and no reqwest (tokio). git traffic goes through the in-process token bucket |
| Queue store | **JSON job files on the host, plus per-file sidecars next to the data on the drive** (§3.3) | Pure Rust. Several processes can control it with no IPC. The per-file state travels with the drive, so unplugging can't make state and data diverge |
| zstd | **`ruzstd`** (pure Rust, encode and decode) | Removes the last C library apart from ring. Cost: its encoder only implements roughly level 1 |
| Hash midstate | **Persist it** at 64 MiB / 60 s checkpoints | Re-hashing a 30 GB partial on a USB HDD costs minutes on every resume |
| Tray | `ksni` on Linux, raw `windows-sys` `Shell_NotifyIconW` on Windows | tray-icon is 92 deps on Linux, wraps ksni anyway, and wants an event-loop crate |
| Windows scheduling | exec `schtasks.exe /Create /XML` with a generated task XML | No `windows` COM crate. Fixed system binary, no user data in args |
| Drive events | udisks2 `InterfacesAdded` over zbus. Windows: `CM_Register_Notification` (needs no window) | Message-only windows don't get `WM_DEVICECHANGE` broadcasts |
| par2 | exec `par2` when it is on PATH (Linux: dnf `par2cmdline`; Windows: user installs par2cmdline). Absent means skip with a status warning | The par2 crates are young (all under 17k downloads) |
| Paths | **preserver's own names**, one tree per XDG base: `~/.config/preserver`, `~/.local/state/preserver`, `~/.cache/preserver`, `$XDG_RUNTIME_DIR/preserver` (shims) and `preserver-<job>.lock` locks, units `preserver-*`, and `<drive>/preserver/` on the drive. Windows uses `%APPDATA%\preserver` and `%LOCALAPPDATA%\preserver` | A new app has no state to inherit. The formats below are its own and are documented here. Backups made by other tools stay where they are and still restore (see §4) |
| Platform abstraction | **No trait.** `src/platform/{linux,windows}/` export identical free-function signatures under `cfg`, and CI type-checks both | Only one implementation is ever compiled per target. A trait would have one impl per build |

## 1. Crate list (for approval)

Common flags: exact `=` pins, `default-features = false` wherever listed. "Deps" means transitive normal+build crates for that crate alone on Linux, from `cargo tree` (Windows in parentheses where different). **Whole-program union: 444 crates on linux-musl, 420 on aarch64-windows-msvc.** Sharing sha2 0.10 and rsa 0.9 with age and pgp (below) brings that down a little. Crates unique to each heavy dependency: gix ~84, pgp ~69, age ~51, ksni+zbus ~40, ureq ~14.

| Crate | Version / features | Purpose | Maintainer | Deps | build.rs / C | License | Why std or a lighter option won't do |
|---|---|---|---|---|---|---|---|
| `age` | 0.12.1, no features | init, encrypt to X25519, decrypt scrypt identity | str4d (rage) | 140 (51 unique: i18n-embed/fluent) | no C | MIT/Apache-2.0 | Exec needs age.exe on Windows plus process plumbing. Rolling our own age format is not an option |
| `gix` | 0.90.0, `["blocking-network-client","sha1"]` (no `parallel`: a separate vetted decision), plus `"worktree-mutation"` from phase 4 (native restore) | fetch mirrors, read refs, index packs | GitoxideLabs (Byron) | 122 | no C (zlib-rs) | MIT/Apache-2.0 | git2 is C (libgit2). Exec git doesn't put git https under our bandwidth cap |
| `gix-transport` | 0.62.0, `["blocking-client","http-client"]` | the `Http` trait, so the ureq backend can plug in | GitoxideLabs | 44 (mostly shared) | no | MIT/Apache-2.0 | The only alternatives are its curl or reqwest backends |
| `pgp` | 0.21.1, no default (drops bzip2) | detached, clearsigned and sig-over-xz verify; keyring parsing; fingerprint pins | rpgp org | 148 (69 unique) | no C | MIT/Apache-2.0 | sequoia: see §0. gpgv: not on Windows |
| `ureq` | 3.5.2, `["rustls-no-provider","platform-verifier","rustls-webpki-roots"]` | every HTTP fetch | algesten | 27 | no | MIT/Apache-2.0 | std has no TLS. reqwest: see §0 |
| `rustls` | 0.23.46, `["ring","std","tls12","logging"=off]` | builds the ring `CryptoProvider` that is passed to ureq's `TlsConfig` | rustls org | (in ureq) | — | Apache-2.0/ISC/MIT | Avoids leaning on ureq's private `_ring` feature |
| `ring` | 0.17.14 (transitive) | TLS crypto | Brian Smith | — | **build.rs, C + asm via cc**. Freestanding: needs only clang for the target, no libc headers | Apache-2.0 AND ISC | aws-lc: see §0 |
| `rustls-platform-verifier` | 0.7.1 (through ureq) | OS trust store: /etc/pki on Linux, CryptoAPI with revocation on Windows | rustls org | (in ureq) | no | MIT/Apache-2.0 | webpki-roots freezes the CA set into the binary. Open question 9 |
| `webpki-roots` | 1.0.11 (through ureq, pinned by a direct line) | the fallback root store when the OS has none (a bare container, a rescue system) | rustls org | 1 (rustls-pki-types, shared) | no | CDLA-Permissive-2.0 (a deny.toml exception for this crate only) | Without it a host with no CA store cannot download at all. Used only when the platform verifier fails to load |
| `sha2` | **0.10.9** | sha256/sha512; `compress256`/`compress512` make the resumable midstate possible | RustCrypto | 9 | no | MIT/Apache-2.0 | 0.10 is the version age, pgp and rsa use, so no duplicate. 0.11 has `SerializableState`, but rsa 0.9 can't use 0.11 digests |
| `sha1-checked` | =0.10.0 (already in tree) | Alpine `Q1` control checksums, `.SIGN.RSA.`, with collision detection | RustCrypto | 0 new | no | MIT/Apache-2.0 | — |
| `base64ct` | =1.8.3 (already in tree) | Alpine `Q1` decode | RustCrypto | 0 new | no | Apache-2.0/MIT | — |
| `rsa` | =0.9.10, `std` + `pem` (direct; also in tree through pgp) | Alpine APKINDEX and apk RSA PKCS#1 v1.5 verify | RustCrypto | 0 new | no | MIT/Apache-2.0 | Alpine signatures aren't OpenPGP |
| `ruzstd` | 0.9.1 | Fedora `primary.xml.zst` decode; local-folder `.tar.zst` encode and decode | KillingSpark | 2 | no | MIT | `zstd` = libzstd in C, which needs libc headers per target |
| `lzma-rust2` | 0.25.0, `["std","xz"]` (decoder only) | `.tar.sign` over the uncompressed kernel tar; Debian `Packages.xz`/`Sources.xz`; Fedora `.xz` repodata | hasenbanck | 10 | no | Apache-2.0 | `xz2`/`liblzma` are C. `lzma-rs` was last released in 2023 |
| `flate2` | 1.1.11, `["zlib-rs"]` | APKINDEX.tar.gz member splitting, `.gz` repodata | rust-lang | 6 | no (zlib-rs, already in tree through pgp) | MIT/Apache-2.0 | std has no inflate |
| `tar` | 0.4.46, no default (no xattr) | local-folder archives and restore; apk control segment; `kit.tar` | composefs org (moved from alexcrichton; **confirm the owners on crates.io**) | 4 | no | MIT/Apache-2.0 | Writing ustar/pax by hand is error-prone |
| `quick-xml` | 0.42.0, no features (streaming reader) | Fedora metalink, repomd, primary | tafia/Mingun | 2 | no | MIT | std has no XML |
| `regex` | 1.13.1 | catalog patterns, href scan, sum-line formats | rust-lang | 5 | no | MIT/Apache-2.0 | — |
| `minisign-verify` | 0.3.0 | Zig signatures | jedisct1 | 1 | no | MIT | replaces the exec of `minisign` |
| `serde` + `serde_json` + `toml` | 1.0.229 / 1.0.154 / 1.2.1 `["parse","display","serde"]` | config, catalog, SET.toml, status/job JSON, API docs | dtolnay / toml-rs | 7 / 5 / 7 | serde has a build.rs, no C | MIT/Apache-2.0 | — |
| `clap` | 4.6.7 `["derive"]` | about 12 subcommands plus `queue` | clap-rs | 17 (21) | no | MIT/Apache-2.0 | It is the stack default |
| `anyhow`, `thiserror` | 1.0.104, 2.0.21 | errors (bin and lib) | dtolnay | 1, 6 | no | MIT/Apache-2.0 | It is the convention |
| `tracing` + `tracing-subscriber` | 0.1.44 + 0.3.23 `["fmt","std"]` | logging to the journal or console | tokio-rs | 15 | no | MIT | It is the stack default |
| `jiff` | 0.2.43 | local-date names (`YYYY-MM-DD`), parsing RFC 3339 timestamps, Windows tz | BurntSushi | 2 (5) | no | Unlicense/MIT | std has no local time zone |
| `rpassword` | 7.5.5 | passphrase prompt (init, restore) on a tty or Windows console | conradkleinespel | 3 (4) | no | Apache-2.0 | — |
| `rustix` (unix only) | 1.1.6 `["fs"]` | `statvfs` for the budget | bytecodealliance | 3 | build.rs, no C | Apache-2.0 WITH LLVM-exception/MIT | std has no statvfs. libc would need unsafe |
| `ksni` (linux only) | 0.3.7, no default, `["blocking","async-io"]` | SNI tray | iovxw | 77 | no | Unlicense | Pinned to zbus 5, so we pin zbus 5 too |
| `zbus` (linux only) | **5.19.0** `["async-io","blocking-api"]` | udisks2 GetManagedObjects/Mount/InterfacesAdded, Notifications with an action | z-galaxy | 67 (shared with ksni) | no | MIT | zbus 6.3.0 exists, but ksni needs ^5, so 6 would mean two zbus copies. `udisks2` crate rejected: three calls don't need it |
| `windows-sys` (windows only) | 0.61.2 `Win32_UI_Shell, Win32_UI_WindowsAndMessaging, Win32_Storage_FileSystem, Win32_System_Ioctl, Win32_Devices_DeviceAndDriverInstallation, Win32_System_Threading, Win32_Foundation, Win32_Graphics_Gdi` | tray, balloons, volumes and serials, CM notifications, background priority, free space | Microsoft | 2 | no (windows-link raw-dylib, no prebuilt import libs) | MIT/Apache-2.0 | The `windows` crate is only needed for COM, which schtasks makes unnecessary |
| `blake3` | 1.8.7, **added only when the Protomaps source is enabled** | PMTiles check | BLAKE3-team | 8 | build.rs, asm via cc (clang is fine) | CC0/Apache-2.0 | replaces the exec of `b3sum` |

**Rejected:** `sequoia-openpgp`, `reqwest`, `aws-lc-rs`, `rustls-rustcrypto` (pre-release only), `zstd` (C), `rusqlite` (C SQLite, needs libc headers for the cross targets), `redb` (single-process file lock, so the tray and CLI can't read while the worker runs), `tray-icon`, `windows`, `udisks2`, `notify-rust`, `url` (resolving listing hrefs is about 25 lines of tested code; `url` + idna pull in icu), `hex`, `dirs`, `fs4`/`fd-lock` (`File::try_lock` has been in std since 1.89), `crossbeam-channel` and `parking_lot` (std is enough here), and the par2 crates.

**Names checked:** every crate above was looked up on crates.io. No typosquat risk was found. The only flag is `tar`, whose repository moved to `composefs/tar-rs`: confirm the owners before approving.

**deny.toml advisory:** `rsa` 0.9 has RUSTSEC-2023-0071 (Marvin timing attack). It only affects private-key decryption and signing. We only verify signatures, so ignore it with that reason.

## 2. Cross-build plan (Fedora 45 host, Claude sandbox)

**Toolchain.** `rust-toolchain.toml` pins channel 1.99.1. Targets:

- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`
- `x86_64-pc-windows-gnu`
- `x86_64-pc-windows-msvc`
- `aarch64-pc-windows-msvc`
- `aarch64-pc-windows-gnullvm`

Set `rust-version = "1.89"`: that is the floor from `File::try_lock`, gix 1.88 and zbus 1.89.

**Sandbox facts:**
- `rustup target add` writes `~/.rustup`, which the sandbox can't write. Run it once outside the sandbox.
- `~/.cargo/config.toml` is masked (it's a character device), so in the sandbox use `CARGO_HOME=$TMPDIR/cargo` and `CARGO_TARGET_DIR=$TMPDIR/target`. This already matches error-patterns.md.
- static.rust-lang.org, crates.io and static.crates.io all worked from the sandbox.

**dnf packages:**
- Needed: `clang` (already installed), `lld`, `llvm` (for llvm-ar), `mingw64-gcc` (pulls mingw64-crt, headers and binutils), `mingw64-winpthreads-static`, `cargo-deny`.
- Runtime and tests: `par2cmdline`, `git-core` (installed), `openssh-clients` (installed), `gh`, `ksshaskpass`.
- Optional test runners: `qemu-user-static-aarch64`, `wine`.
- Fallback only: `zig` (0.16, packaged).

| Target | Local (sandbox) | Linker / CC | Ships from |
|---|---|---|---|
| x86_64-unknown-linux-musl | build + test | `linker="rust-lld"`, `CC=clang`, `AR=llvm-ar` | local or CI |
| aarch64-unknown-linux-musl | build; test with `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER=qemu-aarch64-static` | same (cc passes `--target` to clang; ring only needs freestanding headers) | local or CI |
| x86_64-pc-windows-gnu | build; optional test under wine | `x86_64-w64-mingw32-gcc` | dev only |
| aarch64-pc-windows-gnullvm | `cargo check`/`clippy` only. Linking needs llvm-mingw, which isn't in dnf (a GitHub release binary: the maintainer's call) | clang for ring | not shipped |
| x86_64/aarch64-pc-windows-msvc | `cargo check` only. cargo-xwin is rejected: it downloads the MS CRT/SDK from Microsoft hosts, which are off the allowlist, and needs the MS license accepted | — | **GitHub Actions `windows-2025` and `windows-11-arm`** with `+crt-static`. Free for a public repo |

The load-bearing parts of `.cargo/config.toml`:
```toml
[target.x86_64-unknown-linux-musl]
linker = "rust-lld"
[target.aarch64-unknown-linux-musl]
linker = "rust-lld"
[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-gcc"
[target.'cfg(all(windows, target_env = "msvc"))']
rustflags = ["-C", "target-feature=+crt-static"]
[env]
CC_x86_64_unknown_linux_musl = "clang"
CC_aarch64_unknown_linux_musl = "clang"
AR_x86_64_unknown_linux_musl = "llvm-ar"
AR_aarch64_unknown_linux_musl = "llvm-ar"
```

**Keeping C out:**
- The C in the final tree is ring (freestanding) and, later, blake3's asm.
- `rusqlite`, `zstd`, `xz2`/`liblzma`, `libgit2`, curl, `aws-lc-rs`, `bzip2-sys` and nettle are all excluded by the choices above.
- `deny.toml [bans]` denies `cc` everywhere except under `ring` and `blake3` (`wrappers`), so a new C dependency fails CI.

**CI** (the `deploy` agent writes it; actions pinned by SHA):
- `ubuntu-24.04`: fmt, clippy, test on musl x86_64 and cross-build aarch64
- `ubuntu-24.04-arm`: native aarch64 test
- `windows-2025` and `windows-11-arm`: test
- `cargo deny check` in every job

## 3. Module layout and core types

It's one package, `preserver`, with `src/lib.rs` and a thin `src/main.rs`; no workspace, because there is only one bin and one lib. `catalog.toml` and `keys/` move into the repo. Keys are embedded with one `include_bytes!` per file in `keys.rs`. **The public repo has no host defaults.** Both `primary_uuid` and the owner list are required in `~/.config/preserver/config.toml` (see `config.example.toml`).

```
src/main.rs            clap dispatch; argv0 == "preserver-ssh" -> ssh shim (§3.5)
src/paths.rs           Paths: XDG on Linux / APPDATA+LOCALAPPDATA on Windows; ghDest/localDest/publicDir
src/config.rs          Config, LocalFolder, Drive registry (drives.d/<id>.toml), validation
src/status.rs          status JSON (+ alerts[]); job locks via File::try_lock in runtime dir
src/catalog.rs         Catalog/Set/Source (+ kind "repo", format fedora|debian|alpine); catalog.toml embedded
src/keys.rs            embedded keyrings; stored-key pin check
src/crypt.rs           age: init (generate + scrypt-lock), encrypt_stream(recipient.txt), open_identity(passphrase)
src/personal/{github.rs, local.rs, restore.rs}
src/git/{mirror.rs (gix fetch, refs state), bundle.rs (exec git bundle create; native reader), http.rs (gix Http over ureq), ssh.rs (shim + mux args)}
src/net/{client.rs (ureq Agent, https-only incl. redirects, timeouts, doc size limits), throttle.rs (token bucket), download.rs (resumable Range/If-Range, sidecars), hash.rs (ResumableSha256/512 on sha2::compress*)}
src/queue/{job.rs, store.rs, sched.rs}
src/resolve/{mod.rs (Item, dispatch, name/URL checks), listing.rs, github.rs, json.rs (kernel/go/rust/node/zig), hf.rs, yaml_lite.rs, static_.rs, href.rs}
src/verify/{mod.rs (verify_item, TOFU), sums.rs (findSum port), pgp.rs, minisign.rs}
src/public/{mod.rs (enqueue, budget, record), versioned.rs (staging/hardlinks/SET.toml/SHA256SUMS/prune), index.rs (INDEX.html), dry_run.rs}
src/mirror/{generation.rs (stage -> verify -> swap -> prune, done.tsv), fedora.rs, debian.rs, deb822.rs, alpine.rs}
src/copy/{mod.rs (scan, run, lane, CLI), plan.rs (auto-fit, FAT/exFAT/NTFS limits), exec.rs (stage, read back, kit.tar), rules.rs (copy.toml, due)}
src/scrub.rs           verify [--repair], rotating quarter, par2 exec
src/tray_model.rs      platform-neutral tray state: labels, overdue (4 days), icon/status, menu items (unit-tested)
src/platform/mod.rs    cfg re-export
src/platform/linux/{udisks.rs, notify.rs, tray.rs (ksni), fs.rs}
src/platform/windows/{volumes.rs, devnotify.rs, tray.rs (Shell_NotifyIcon + balloons + TaskbarCreated re-add), tasks.rs (schtasks XML), fs.rs}
```

### 3.1 Platform API (the same signatures in both cfg modules)

| fn | Linux | Windows |
|---|---|---|
| `list_filesystems() -> Vec<FsInfo{id, label, fstype, size, mount, removable}>` | udisks2 GetManagedObjects | FindFirstVolumeW + GetVolumePathNamesForVolumeNameW + GetVolumeInformationW + FSCTL_GET_NTFS_VOLUME_DATA |
| `mount(&DriveId) -> PathBuf` | udisks `Filesystem.Mount` with `auth.no_user_interaction` (replaces the udisksctl exec). Called only for a person's action (CLI, tray) | resolve the volume path; no mount step |
| `locate(&DriveId) -> DriveAt{Absent, Unmounted, Mounted(path)}` | udisks GetManagedObjects; never mounts, any error is Absent. What the lanes use | Absent (phase 5) |
| `mount_added(object, wanted) -> Option<(DriveId, PathBuf)>` | mounts the filesystem just added at `object` only if its id is in `wanted`; the daemon's only mount | Ok(None) |
| `disk_free(&Path) -> (free, total)` | rustix statvfs | GetDiskFreeSpaceExW |
| `is_mounted(&Path)` | st_dev differs from the parent's | volume root exists |
| `watch_drives(on_event: impl Fn(DriveEvent))`, `DriveEvent{Added(object path), Changed}` | one match rule on udisks InterfacesAdded (a Filesystem interface gives Added) and Filesystem MountPoints changes (Changed), reconnecting every 30 s (Changed after a reconnect) | CM_Register_Notification on GUID_DEVINTERFACE_VOLUME |
| `watch_queue(dir, on_change)` | inotify on the queue directory, firing for `wake` and `*.ctl` only | none yet: the daemon's 30 s tick |
| `session_env()` | `systemctl --user show-environment`, filtered to DISPLAY, WAYLAND_DISPLAY, XAUTHORITY and SSH_AUTH_SOCK, read per job | empty |
| `run_tray(TrayModel, Receiver<..>)` | ksni blocking | hidden top-level window + Shell_NotifyIconW |
| `notify(Alert)` | org.freedesktop.Notifications with the "run" action | NIF_INFO balloon, where NIN_BALLOONUSERCLICK means run |
| `open_path` | xdg-open | explorer.exe |
| `ssh_program()`, `ssh_mux_args()` | `/usr/bin/ssh` + ControlMaster args, `SSH_ASKPASS=/usr/bin/ksshaskpass`, `SSH_ASKPASS_REQUIRE=force` | `%SystemRoot%\System32\OpenSSH\ssh.exe`, no mux args |
| `install_schedule()` | none: `install.sh` installs the tray and daemon units from `dist/systemd/`; job times come from `[schedule]` in config.toml | schtasks XML: `\preserver\tray` and `\preserver\daemon` at logon (install.bat for now) |
| `background_priority()` | none (the units set Nice and IOSchedulingClass=idle) | SetPriorityClass(PROCESS_MODE_BACKGROUND_BEGIN) |

**`DriveId` newtype (an invariant).** It is normalized hex without dashes, upper case. udisks reports FAT as `XXXX-XXXX` and NTFS as a 16-hex serial, which are the same values Windows returns. So the same `drives.d/<id>.toml` matches on both OSes, and the existing ext4 UUID still works on Linux.

**Notifications** are raised by the tray from status transitions: jobs append to `alerts[]` in the status JSON, and the tray tracks the last id it has shown. That gives one mechanism on both OSes. The CLI also prints alerts.

### 3.2 Core types

```rust
struct Item { name: String, url: String, version: String, expect: Expect, size: Option<u64>, sig_url: Option<String>, sums_url: Option<String>, sums_sig_url: Option<String> }
enum Expect { None, Sha256([u8; 32]), Sha512([u8; 64]), Both([u8; 32], [u8; 64]), Blake3([u8; 32]) }

struct Job { id: JobId, kind: JobKind, priority: u32, state: JobState, attempts: u32, next_try: Option<Timestamp>,
             drive: DriveId, created: Timestamp, updated: Timestamp, progress: Progress, error: Option<String> }
enum JobKind { Github { transport: Option<Transport> }, Local, Set { set: String }, Mirror { set: String, source: String },
               Copy { target: Target /* Drive { id, subdir, label } | Dir { path } */, sets: Vec<String>, size: Option<u64>, rule: Option<String> },
               Scrub { repair: bool } }
enum JobState { Queued, Blocked(BlockReason /* DriveAbsent | Unmounted | NeedsTouch */), Running { pid: u32 }, Paused, Done, Failed, Canceled }
struct Control { pause: bool, cancel: bool, priority: Option<u32> }          // <id>.ctl, written by CLI/tray only
struct Progress { phase: Phase, files_done: u64, files_total: u64, bytes_done: u64, bytes_total: u64, rate_bps: u64, current: Vec<String> }
struct Fetch { job: JobId, order: u32, host: String, url: String, dest: PathBuf, size: Option<u64>, expect: Expect }
struct PartState { v: u8, url: String, validator: Validator /* ETag | LastModified */, offset: u64, total: Option<u64>, sha256: [u32; 8], sha512: Option<[u64; 8]> }
enum RepoFormat { Fedora, Debian, Alpine }    // enum + match: three walkers in one build, but no trait needed
```

### 3.3 Queue

| Aspect | Design |
|---|---|
| Store | `~/.local/state/preserver/queue/<id>.json`, written only by the worker (tmp + rename). Control lives in `<id>.ctl`, written by the CLI and tray. New jobs are created with `O_EXCL` by anyone. The worker rescans every 1 s |
| Lanes and daemon | Each job kind belongs to a lane (`Lane::Download` for sets, `Lane::Copy`, `Lane::Personal` for GitHub and local folders); a worker resets and writes only its own lane's jobs. `preserver daemon` (user service) runs one thread per lane and takes the lane lock for one pass at a time: a 30 s tick or a queue wake-up (crashed jobs only), a drive event or the hourly sweep (also `Blocked`, except `NeedsTouch`). A `Running{pid}` job whose lock isn't held is a crash and goes back to Queued |
| Handoff | `personal`, `public` and `copy` (not their `--dry-run`, `--list` or `--remove`) queue for a live daemon (its lock is held) and write `queue/wake`, which its inotify watch turns into a pass at once. With no daemon, or with `--foreground`, they take the lane lock first, queue, run the lane here and exit non-zero on Failed or `NeedsTouch`; when another worker holds the lane they only queue. One unfinished job per kind (`Store::enqueue`): a stopped one gets a `retry` and is unpaused instead of a second job. The tray uses the same code (`actions.rs`) |
| Mounting | Lanes only `locate` the drive: Absent is `Blocked(DriveAbsent)`, plugged in but unmounted is `Blocked(Unmounted)`, both without an attempt. People's actions (CLI, tray, `queue retry`, `queue run`) mount first, best effort. The daemon mounts only a filesystem that appears while it runs and that a job wants (the primary, a copy rule's or unfinished copy job's target), so a drive already plugged in at login stays "not mounted" until someone mounts it, replugs it or presses Retry |
| Schedules | `[schedule]` in config.toml: `personal` (the GitHub job), `local` and `public`, each `H:MM:SS` (every interval since the last run) or `HH:MM` (daily, local time, DST gaps and folds resolved the compatible way). The daemon checks them before every pass (`schedule.rs`). A missed occurrence runs once when the daemon next looks (systemd `Persistent=true`), since `last_run` in `status/<job>.json` is set by every run, manual ones too. A job still waiting is left alone; a Failed or `NeedsTouch` one older than the occurrence gets one retry, so an unanswered security key is asked for once per occurrence. Copy rules use the same `due` |
| Security key | The personal lane runs ssh with the session's DISPLAY, WAYLAND_DISPLAY, XAUTHORITY and SSH_AUTH_SOCK, read from the user manager per job (the tray imports them at login). The prompt waits 120 s; no answer, or no graphical session, is `Blocked(NeedsTouch)` without an attempt. A pause or cancel during the prompt ends ssh and its askpass (their process group) |
| Per-file state | The filesystem is the state: a final file exists only after verification. A partial is `<dest>.part` + `<dest>.part.json` (PartState). Repo trees add `<tree>/.preserver/done.tsv`, appended only for fetches the pool reported verified; a present file with no line is hashed again. `want.tsv` is rebuilt every run and metadata is re-checked against the anchor every run |
| Batches | A planner returns the next fetches (`Work::Fetch`) or a `Work::Run` for a git transfer. Each batch's verified positions go back to the planner. A `Work::Run` is never yielded to a higher-priority job; pause and cancel still stop it. Git has no child process to throttle: gix runs in-process over the shared agent |
| Priority | `Job.priority` is the position in first-pass catalog order (`--first-pass`), or stable by `priority` then catalog order. Within a job, items keep plan order |
| Concurrency | `downloads = 4` threads. Per-host semaphores default to 2, overridable in config `[hosts]` (e.g. `"huggingface.co" = 4`) |
| Retry | Per item: backoff 5 s·2ⁿ with jitter, capped at 10 min, 6 tries per run. 4xx other than 408/429 is permanent. A 429/503 `Retry-After` pauses the whole host. After that the job is Failed, and the next scheduled occurrence retries it |
| Pause/resume/cancel | Applied at the next 64 KiB chunk. Pause keeps `.part` files. Cancel deletes the job's staging. `queue pause --all` writes a global ctl |
| Unplug | A write error showing the mount is gone (ENOENT/EIO/ENODEV, or `is_mounted` false) puts every job on that drive into `Blocked(DriveAbsent)` without counting attempts. The daemon's drive watcher resumes them on replug |
| Bandwidth | One global token bucket (default `bandwidth_mbit = 80`, 0 = off, burst 256 KiB). It is taken before each body read in `net` and in the gix Http backend. It counts payload bytes, so the wire is about 2–3% above; TCP backpressure keeps the link honest. Personal ssh fetches are unthrottled, as now |
| Resume | One GET per attempt for the rest of the file, with Range + If-Range (validator) and a timeout sized from the remaining bytes. Every 64 MiB of the body, or 60 s when fewer bytes arrived (the time checkpoint ends at the next 128-byte boundary), is a checkpoint: `sync_data` the part, then write the sidecar atomically. On resume: truncate the part to `offset`, restore the hashers from the midstate, continue. 200 instead of 206 means restart from 0. A part without a sidecar restarts from zero. Without Range support it is a single stream with a size-derived timeout and no resume. BLAKE3 has no public midstate, so its sources re-hash on resume |
| Midstate | **Persist it.** `ResumableSha256/512` wrap `sha2::compress256/512`. Checkpoints sit on 128-byte (SHA-512 block) boundaries, so the state is just the words plus the length, and the sidecar carries a version number |
| Visibility | Versioned sets: `<set>/.staging/<plan16>/`, hardlinks from the previous version (copy on exFAT/FAT), SET.toml + SHA256SUMS, rename into place, prune to `keep`. Repo mirrors follow §3.4 |
| Progress | The worker rewrites `<id>.json` every 1 s. The tray polls every 2 s while a worker lock is held, otherwise hourly. `queue list [--watch]` |

**Why JSON over rusqlite or redb:**
- There are only hundreds of jobs. The 100k-file item state lives on the drive next to the data, so it can't drift from the data after a crash or an unplug.
- The tray and CLI work concurrently without IPC.
- No C, and every file can be read with `cat`.
- The cost is no ad-hoc SQL. That's acceptable.

### 3.4 Mirror walkers (replace rsync)

| Format | Trust chain | Visibility |
|---|---|---|
| Fedora | **repomd.xml is not signed by Fedora.** The anchor is the metalink from `mirrors.fedoraproject.org` over TLS (sha256/sha512 + size of repomd.xml), then repomd `<data>` checksums, then the primary (`.xml.zst` only, anything else fails closed) `<checksum type=sha256>` per `<location>`. A new repomd needs a `<revision>` above the live one, and a metalink `mm0:timestamp` older than the one recorded at the last commit is refused. One walk each for `fedora-45`, `fedora-source-45`, `updates-released-f45` and the updates source repo | New `Packages/` files first (unreferenced until the swap), then the `repodata/` swap (`renameat2 RENAME_EXCHANGE` where the platform has it; otherwise rename-aside then rename, with `swap.json` as the journal on every OS), then delete unreferenced files |
| Debian | InRelease verified with a new `keys/debian-archive.gpg` (trixie archive keys pinned by fingerprint), then SHA256 of `{main,contrib,non-free,non-free-firmware}/{binary-amd64,binary-all,source,i18n}` indexes, then `Packages` Filename/Size/SHA256 and `Sources` Directory + Checksums-Sha256. The union over the configured suites gives the exact pool file set, which fixes the old "pool mixes every suite" problem. Security comes from `security.debian.org/debian-security` as its own mirror | Pool first, then `dists/<suite>` swap, then prune. Create `by-hash/SHA256/<hash>` hardlinks, because trixie's Release has `Acquire-By-Hash: yes` |
| Alpine | APKINDEX.tar.gz: the first gzip member holds `.SIGN.RSA256.` (or `.SIGN.RSA.`), RSA-verified over the raw second member with pinned `keys/alpine-*.rsa.pub` (new). Then per apk: sha1 of the control member equals `C:Q1…`, and the sha256 of the data member equals `datahash` in .PKGINFO | Packages first, then rename APKINDEX.tar.gz into place, then prune |

`dry-run` for repos fetches metadata only and reports exact byte totals.

**Catalog migrations** (a `chore` job):
- rsync kinds become `kind = "repo"`.
- `rfcs` (`rsync.rfc-editor.org::rfcs`) becomes https from `www.ietf.org/rfc/` (`catalog.toml`), txt and xml only.
- `gcc` and `gnu-latest` become https `listing` with a two-level resolver.
- Fix the 3 dry-run failures: debian-cd-key 404, musl `/releases/` 404, the geofabrik pattern.

### 3.5 GitHub personal path

| Step | Linux | Windows |
|---|---|---|
| List | exec `gh repo list --json …` (parity) | same, with gh.exe |
| Fetch | gix fetch (`git/mirror.rs`) through the shim: `ssh::connect::Options { command: Some(shim), kind: Some(ProgramKind::Ssh), disallow_shell: true }`, refspecs `+refs/heads/*` and `+refs/tags/*`. Before each repo, `ssh -O check` restarts an expired master; a failed check is `NeedsTouch` | ssh.exe direct, no shim and no master (Windows Hello handles PIN and touch) |
| Shim | `preserver-ssh` is a symlink to the binary. main sees argv0 and execs /usr/bin/ssh with `ControlPath=$XDG_RUNTIME_DIR/preserver-ssh-%C` first. The master (`ControlMaster=auto`) may open the connection and prompt. Any other caller, gix's ssh included, gets `ControlMaster=no` and no way to authenticate, so a missing master fails at once instead of waiting for a touch (`platform/linux/mod.rs`, `ssh_command`) | not needed |
| Change detection | `<oid> <refname>\n` lines sorted by refname bytes (heads and tags only, unpeeled, the same as `for-each-ref`), compared byte-for-byte with the existing `.refs` file | same |
| Bundle | exec `git -C mirror bundle create -q - --all`, stdout into the in-process age Encryptor, then `.tmp` and rename | needs Git for Windows |
| Restore | Phase 1: in-process age decrypt, then exec `git clone` + `remote remove origin` (parity). Phase 4: native. Parse the v2/v3 header, `gix_pack::Bundle::write_to_directory` (index-pack), init, write refs + HEAD, check out with gix worktree-mutation. The kit and Windows then need no git | same |

### 3.6 Copy to other drives (`preserver copy`)

| Aspect | Design |
|---|---|
| What | `<primary>/preserver/` (personal trees, `kit/`, `public/<set>/`) onto another drive (by filesystem id, wherever it mounts, plus a subdirectory) or a plain directory, into `<target>/preserver/`. Jobs run in `Lane::Copy`, so a copy never waits on downloads. An absent drive is `Blocked(DriveAbsent)` and runs on the next drive event |
| Sets | `--sets` takes catalog names plus `personal` and `kit`; `-name` leaves one out. Without a positive name everything goes; `personal` is in unless `-personal`. Rules keep the tokens and resolve them per job, so a set added to the catalog later comes along |
| Auto-fit | Re-planned on every run from the target's free space (or `--size`, counting what already sits on the target), less a 5% reserve. Personal files must fit or the copy fails. Then the kit, then sets greedily in catalog `priority` order: each takes its biggest variant (`[[set.variant]]`, a filter on sources; an implicit `full` has them all) that still fits, a set that fits none is dropped and lower ones still get their chance. When room shrinks, the lowest priorities go first. Sets on the target that the copy did not select stay and count as used. `--dry-run` prints the plan and writes nothing |
| Writing | Each set version is staged in `public/<set>/.staging/<version>~<variant>/`, hard linked from the old version where the filesystem has links, every file read back (`fadvise DONTNEED` first) and checked against the primary's SHA256SUMS, given its own SET.toml (with `variant`) and SHA256SUMS, then renamed into place; the old version goes after. An interrupted run leaves the old version whole and the next run resumes the stage. Without room for both side by side, the old version is moved aside and its files reused (in place) |
| Filesystems | FAT32: files over 4 GiB are skipped and listed. FAT, exFAT and NTFS: names Windows refuses or that differ only in case are skipped; the kit goes as one `kit.tar` (read back by hash) since links do not survive. Footprints round up to the cluster size |
| Safety | A non-empty `preserver/` without `.state/copy.json` (the primary, someone's other archive) is refused, as is a target inside the primary or the other way round. Links on the primary are never followed; kit links that leave the kit are left out. Personal files are only added and replaced, never deleted |
| Rules | `-t HH:MM:SS` keeps a rule in `~/.config/preserver/copy.toml` (id: 12 hex of the target's hash). The daemon's main loop calls `copy::schedule` every tick: a rule whose last run (`status/copy.json`) is an interval old gets a job, a failed one gets a retry an interval later |
| Tray | Each unfinished copy job gets a menu entry with Cancel and, when stopped, Retry. A failed copy turns the icon to failed |

## 4. CLI

**On the drive** (`<drive>/preserver/`):

| Path | Content |
|---|---|
| `github-repos-personal/<owner>/<repo>/` | `YYYY-MM-DD.bundle.age` snapshots and the `.refs` state; `identity.age` (locked key) and `recipient.txt` at the top |
| `local-personal/<name>/YYYY-MM/` | `L0.tar.zst.age` and `Dnn.tar.zst.age` |
| `public/<set>/` | mirrored public sets (`<version>/`, `SET.toml`, `.staging/`) |
| `kit/` | recovery kit |
| `.state/` | reserved for drive-side state |

On the host: `~/.config/preserver/{config.toml,drives.d/,personal/{identity.age,recipient.txt}}`, `~/.local/state/preserver/{status/<job>.json,github/,local/,queue/,tofu.json}` and `~/.cache/preserver/mirrors/`.


| Command | Notes |
|---|---|
| `init [--import IDENTITY_AGE]` | in-process keygen. The secret goes straight into the scrypt Encryptor (zeroized) and never touches disk unencrypted. Writes `identity.age` on the drive and at home, and `recipient.txt`. With `--import` it copies an existing passphrase-locked identity instead: the restore password must unlock it (checked before anything is written), and `recipient.txt` is derived from the keys inside. Neither form replaces an identity that is already stored |
| `personal [--local-only] [--transport T] [--foreground]` | queues the local-folder and GitHub jobs (§3.3 Handoff), refs state, alerts |
| `restore FILE DIR` | `.bundle.age` or `.tar.zst.age` (L0 then Dnn applies the manifest's deletions). FILE can be anywhere, for example a bundle of an older backup tree on a drive. The locked key is the `identity.age` found in the three directories above FILE, else the primary drive's, else the home copy |
| `public [SET…] [--dry-run] [--first-pass] [--foreground]` | enqueue, then the daemon or this process runs the worker (§3.3 Handoff) |
| `queue list [--watch] \| show ID \| pause [ID\|--all] \| resume [ID\|--all\|--drive ID] \| cancel ID \| retry ID \| prio ID N \| run` | new |
| `public --list` | the sets by priority with their variants, estimated and, with the primary connected, measured |
| `copy TARGET [-t HH:MM:SS] [--sets a,b,-c] [--size 32G] [--dry-run] [--foreground]`, `copy --list`, `copy --remove ID` | copy to a drive (id or label) or a directory, fitted to its room (§3.6); `-t` keeps a rule the daemon runs; `--remove` takes a rule id or cancels a copy job |
| `verify [--repair]` | phase 4 |
| `drives`, `open`, `tray` | list drives, open the archive folder, run the tray |
| `install` | Windows only: Task Scheduler tasks + tray at logon |
| deferred: `kit` | the existing `kit/` stays. Later, add preserver binaries for 4 targets + `cargo vendor` source |

**Local-folder format (new, because the `tar` crate can't write GNU `--listed-incremental` dumps):**
- Layout: `<name>/YYYY-MM/{L0,Dnn}.tar.zst.age`.
- The first entry is `.preserver/manifest.tsv`: a header line (`preserver-manifest`, version, this archive's id, the id of its level 0 or `-`) and one line per path present (kind, mode, size, mtime ns, ctime ns, escaped path). Dnn holds the entries whose line differs from the L0 index.
- The index is the L0's manifest, kept in `~/.local/state/preserver/local/<name>/YYYY-MM.L0.idx`. A level 0 whose index is gone gets no differentials: the month's folder has to be moved aside.
- Restore takes modes and times from the manifest, never writes through a symlink, and skips (and reports, with a non-zero exit) symlinks whose target is absolute, climbs above the target directory, or has a `..` after a plain name (a link it passes through could lead out).
- GNU tar can still extract the archives, just without applying deletions.

## 5. Phases and steps

Every phase ends with `fmt`, `clippy -D warnings`, `test`, `cargo deny`, then a commit and push.

| # | Step | Files | Agent |
|---|---|---|---|
| **0** | Repo `preserver`: Cargo.toml (lints from rust.md, profiles, `panic="abort"`), rust-toolchain.toml, deny.toml (licenses MIT/Apache-2.0/ISC/BSD-3/Unicode-3.0/Unlicense/CC0/Apache-2.0-WITH-LLVM-exception; cc wrappers; rsa advisory note), `.cargo/config.toml`, CLAUDE.md. **Proof:** a stub that links ring + age + ureq for all musl targets and `x86_64-pc-windows-gnu`, and `cargo check` passes for msvc/gnullvm | root files | `coder`; CLAUDE.md by `writer` |
| 0b | CI workflow (4 targets, pinned actions) | `.github/workflows/ci.yml` | `deploy` |
| **1a** | paths, config (no defaults), status (a null time means never), locks, crypt, github (exec git + shim), restore (exec git clone), drives + mount (udisks/zbus), `open`. Linux only; Windows `platform` stubs return `Unsupported` | `src/{paths,config,status,crypt}.rs`, `src/personal/{github,restore}.rs`, `src/git/ssh.rs`, `src/platform/linux/{udisks,fs}.rs` | `coder` |
| 1a gate | (1) `init --import` of an existing locked identity keeps the key and derives the recipient; (2) a `.bundle.age` outside `<drive>/preserver/` restores with the identity stored next to it; (3) the `age` CLI decrypts a new bundle under `env -i PATH=/nonexistent`; (4) restore of one repo matches `git fsck` | tests in `tests/personal.rs` | `test-writer`, then it is run by hand outside any sandbox (it touches real credentials and FIDO keys) |
| **1b** | tray_model + ksni tray + Linux notifications with action + reminder logic; local folders (tar + ruzstd + age, manifest, L0/Dnn) | `src/tray_model.rs`, `src/platform/linux/{tray,notify}.rs`, `src/personal/local.rs` | `coder` |
| **2** | net (client, throttle, segmented download, sidecars, resumable hash), queue (job/store/sched), resolvers, verify (sums, rpgp detached/clear/xz, pins, stored-key pin, minisign, TOFU), public (versioned, budget, index, dry-run), catalog + keys moved in | `src/net/*`, `src/queue/*`, `src/resolve/*`, `src/verify/*`, `src/public/*`, `catalog.toml`, `keys/*` | `coder` (the resumable hash, midstate and checkpoint protocol go to `novel-coder` if `coder` reports trouble) |
| 2 gate | Public tests on a rustls test server with a checked-in test cert. Kill mid-download and resume with no full re-hash (assert bytes read). Pause and cancel from a second process. Bad signature never becomes visible. TOFU change raises an alert. Budget refusal. `keep` pruning. **Differential test: rpgp vs gpgv on every enabled signed source and all 11 keyrings.** Bandwidth ≤ 80 Mbit/s with `ip -s link` | `tests/*` | `test-writer`; then `security-auditor` on net, verify and resolve |
| **3** | gix mirror + ureq `Http` impl (pipe thread for POST bodies); move personal fetch to gix; generation swap; Fedora, then Alpine, then Debian walkers; deb822 parser (proptest); catalog `kind="repo"` + the rsync replacements + the 3 dry-run fixes | `src/git/{mirror,http}.rs`, `src/mirror/*`, `catalog.toml` | `coder` for the walkers; `chore` for the catalog edits |
| 3 gate | Fixture repos (tiny Fedora/Debian/Alpine trees, signed with test keys); a tampered file is rejected; interrupted generation resumes; `dnf --repofrompath` and `apt` (podman debian container) install from the mirror; personal again writes 0 new bundles via gix | | `test-writer`, `security-auditor` |
| **4** | sync_tree for replicas, scrub + par2, native bundle restore (copy with auto-fit, the FAT 4 GiB rule and kit.tar came with the daemon work, §3.6) | `src/scrub.rs`, `src/git/bundle.rs` | `coder` |
| 4 gate | copy to a 16G FAT32 loop image in $TMPDIR; `sha256sum -c` passes on the copy; native restore equals `git clone` for every backed-up repo | | `test-writer` |
| **5** | Windows: paths, volumes/serials, CM notifications, Shell_NotifyIcon tray + balloons + TaskbarCreated, schtasks XML install, background priority, OpenSSH path; GraphQL ref pre-check (open question 1) | `src/platform/windows/*` | `coder` |
| 5 gate | CI on windows-2025 and windows-11-arm runs the full suite; a manual run on a Windows machine with a FIDO key | | `test-writer`, `reviewer` before tagging v1 |
| later | native bundle writer: gix-pack `count::objects` + `iter_from_counts(Mode::PackCopyAndBaseObjects, allow_thin_pack=false)` + v2 header, verified by native index-pack before rename, switched on only after its object set equals `git bundle` output on all repos | `src/git/bundle.rs` | `novel-coder` |

**Contents of the new CLAUDE.md:**
- purpose
- the layout table above
- the build and cross matrix, with the sandbox notes (CARGO_HOME, rustup outside it)
- the gates
- invariants: the recipient is read from home only; a file is visible only after it verifies; no host defaults in the repo
- the personal flow: run it yourself, because it touches real credentials and FIDO keys
- the catalog `todo` rule

## 6. Risks

| Risk | Status / mitigation |
|---|---|
| **Windows OpenSSH has no ControlMaster** | Confirmed: Win32-OpenSSH issue #405 is still in the backlog, and the options are accepted but silently do nothing. So there is one touch (and PIN, with verify-required) per fetched repo. Mitigation: a GraphQL pre-check (one `gh api graphql` lists every repo's head/tag oids) means only changed repos get fetched, but the first run is still N touches. FIDO on Windows goes through webauthn.dll (Windows Hello UI, no askpass). It needs OpenSSH ≥ 8.9 (I believe Windows 11 ships 9.5; check `ssh -V`) and the `id_*_sk` key handle file on that machine (or `ssh-keygen -K` for a resident key). I haven't verified this on hardware |
| **gix bundles** | No create and no read in gix 0.90 (crate-status). So: exec `git bundle create`, which means Windows personal backups need Git for Windows until the native writer lands. gix-pack's pack *output* exists but has no delta compression for loose objects; copied packed entries keep their deltas. Treat the native writer as experimental |
| **age compatibility** | `identity.age` header: `-> scrypt … 18`. The age crate decrypts scrypt stanzas, but its default max work factor is derived from the machine, so set `set_max_work_factor(22)` explicitly (2^18 means 256 MiB, fine even on an RPi). Then `IdentityFile::from_buffer` takes age-keygen's comment lines. Encrypting to `age1…` X25519 follows the same v1 spec as the age CLI. The output is **not byte-identical** (random file key and ephemeral share) but **is interoperable both ways**. Gate 1a proves both directions against real files |
| rpgp vs gpgv semantics | v3 or ancient keys in gnu-keyring.gpg, SHA-1 binding signatures, expiry and revocation handling, subkey choice by issuer fingerprint. Parse each key separately, skip and log the ones that don't parse, never fail the whole keyring. The phase-2 differential test against gpgv decides |
| ring + rust-lld for aarch64-musl | This is the usual recipe, but not yet proven on this host. Phase 0 proves it. Fallback: `zig cc` from dnf as CC and linker |
| Fedora repodata unsigned | Trust rests on the TLS metalink plus the revision and timestamp rules (weaker than Debian or Alpine). Packages carry RPM signatures that dnf checks on use. Native RPM header verification is open question 6 |
| `preserver-checked` on the drive | Packs listed there are not re-verified. The list has the same trust as the packs, so a drive that is changed while unplugged can hide a bad pack. The check runs again for every pack not in the list |
| Windows swap is path-based | Without `RENAME_EXCHANGE` the swap and prune walk use paths, not directory fds, so they are not protected from a symlink race the way the Linux walk is. The journal still covers a crash mid-swap |
| Git packs accumulate | There is no repack. A pack that fails the check is kept and fails every run until someone deletes it and its `.idx`, as the error says; the next run drops the staged refs that named its objects and fetches them again |
| Long git fetch is never yielded | A `Work::Run` job cannot be preempted, so a long fetch delays higher-priority sets until it finishes |
| No redirects | A renamed upstream fails until the catalog changes. The dry-run probe catches it first |
| By-hash entries vanish at the swap | Security's `Valid-Until` lapses about a week after the last sync |
| No exchange on exFAT, vfat and Windows | A short 404 window during the swap. Windows `sync_fs` is a stub |
| `pgp::release` departs from gpgv on purpose | The audit must confirm that |
| linux-git stays disabled | Its closure check costs minutes to hours and its memory is unknown until H7 |
| `live.tsv` on the drive is forgeable | Like `preserver-checked`, it carries the same trust as the data: anyone with write access to the drive can change it |
| Plan steps can't be interrupted | Each run re-hashes meta (Fedora about 300 MB per tree, Debian about 100 MB) and re-walks before the first batch, so pause takes about a minute on USB HDDs |
| No mirror-list fallback for Fedora | A mirrors.kernel.org that lags past the metalink alternates fails that run |
| GNU all or nothing, RFCs TOFU | GNU publishes all or nothing. RFCs are trusted on first use. A full gnu-latest resolve costs about 2 minutes per new job (cached per job) |
| Alpine format drift | apk-tools v3 index and package formats may appear. Check the real v3.24 index at phase 3. The walker refuses unknown signature names |
| Debian by-hash and apt expectations | Create by-hash links. The phase-3 apt container test catches gaps |
| ruzstd at level 1 | Measured in phase 1b on 1.2 GB of source code: 282 MB, against 185 MB for `zstd -1` and 163 MB for `zstd -3` (about 50% and 70% bigger). Its encoder also panics on I/O errors, so `local.rs` holds them back. Restore of anything made by GNU zstd works |
| Windows long paths, exFAT | std handles long paths. There are no hardlinks on exFAT/FAT, so copy instead (`keep` then costs full size) |
| Payload-only throttling | Measured overhead of about 2–3%. Lower the default to 78 if 80 on the wire is a hard limit |


## 7. Decisions (final)

Supersedes the open questions of the original report.

- **Crates:** all approved at the pins in section 1. Each phase adds only the crates it uses. Phase 1a carries age, serde, serde_json, toml, clap, anyhow, thiserror, tracing, tracing-subscriber, jiff, rpassword, rustix and zbus. The later-phase crates (gix, gix-transport, pgp, ureq, rustls, sha2, ruzstd, lzma-rust2, flate2, tar, quick-xml, regex, minisign-verify, ksni, windows-sys, blake3) are added in their phase at the pinned version. A pin that does not resolve is reported, never replaced by a guess.
- **GitHub transport** is user-configurable, and both modes work on both operating systems:
  - `ssh`: ssh with a FIDO key through the `preserver-ssh` argv0 shim (ControlMaster for one touch per run; on Linux `SSH_ASKPASS=ksshaskpass` and `SSH_ASKPASS_REQUIRE=force`).
  - `https`: a token obtained from the `gh` CLI (`gh auth token`), sent only to github.com, through the in-process gix HTTP transport. The token never appears in argv, a URL, a log or a file.
  - Selected by `transport = "ssh" | "https"` in `config.toml` and overridden per run by `--transport`. Tray selection arrives in phase 1b.
- **zstd:** `ruzstd`. **TLS roots:** the OS store with an embedded fallback (relevant from phase 2).
- **Names:** every path, unit name, lock name and on-disk format is preserver's own. Nothing from an earlier tool is read or migrated; backups it wrote still restore, because `restore` takes the file path and finds the locked key next to it (see §4).
- **No host defaults in the repo:** owners and the primary drive uuid come from `~/.config/preserver/config.toml` (example: `docs/config.example.toml`). Nothing personal (drive uuid, email) in source or docs.
- **License:** MIT OR Apache-2.0.
