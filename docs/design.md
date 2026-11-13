# preserver: design for the Rust rewrite of code-archive

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
| Hash midstate | **Persist it** at 64 MiB checkpoints | Re-hashing a 30 GB partial on a USB HDD costs minutes on every resume |
| Tray | `ksni` on Linux, raw `windows-sys` `Shell_NotifyIconW` on Windows | tray-icon is 92 deps on Linux, wraps ksni anyway, and wants an event-loop crate |
| Windows scheduling | exec `schtasks.exe /Create /XML` with a generated task XML | No `windows` COM crate. Fixed system binary, no user data in args |
| Drive events | udisks2 `InterfacesAdded` over zbus. Windows: `CM_Register_Notification` (needs no window) | Message-only windows don't get `WM_DEVICECHANGE` broadcasts |
| par2 | exec `par2` when it is on PATH (Linux: dnf `par2cmdline`; Windows: user installs par2cmdline). Absent means skip with a status warning | The par2 crates are young (all under 17k downloads) |
| Paths | **Keep every existing path and name** (`code-archive` on host and drive, `code-archive-*` units and lock names). Only the binary is renamed | No migration while no backup is running. Windows uses `%APPDATA%\code-archive` and `%LOCALAPPDATA%\code-archive` |
| Platform abstraction | **No trait.** `src/platform/{linux,windows}/` export identical free-function signatures under `cfg`, and CI type-checks both | Only one implementation is ever compiled per target. A trait would have one impl per build |

## 1. Crate list (for approval)

Common flags: exact `=` pins, `default-features = false` wherever listed. "Deps" means transitive normal+build crates for that crate alone on Linux, from `cargo tree` (Windows in parentheses where different). **Whole-program union: 444 crates on linux-musl, 420 on aarch64-windows-msvc.** Sharing sha2 0.10 and rsa 0.9 with age and pgp (below) brings that down a little. Crates unique to each heavy dependency: gix ~84, pgp ~69, age ~51, ksni+zbus ~40, ureq ~14.

| Crate | Version / features | Purpose | Maintainer | Deps | build.rs / C | License | Why std or a lighter option won't do |
|---|---|---|---|---|---|---|---|
| `age` | 0.12.1, no features | init, encrypt to X25519, decrypt scrypt identity | str4d (rage) | 140 (51 unique: i18n-embed/fluent) | no C | MIT/Apache-2.0 | Exec needs age.exe on Windows plus process plumbing. Rolling our own age format is not an option |
| `gix` | 0.90.0, `["blocking-network-client","sha1"]`, plus `"worktree-mutation"` from phase 4 (native restore) | fetch mirrors, read refs, index packs | GitoxideLabs (Byron) | 122 | no C (zlib-rs) | MIT/Apache-2.0 | git2 is C (libgit2). Exec git doesn't put git https under our bandwidth cap |
| `gix-transport` | 0.62.0, `["blocking-client","http-client"]` | the `Http` trait, so the ureq backend can plug in | GitoxideLabs | 44 (mostly shared) | no | MIT/Apache-2.0 | The only alternatives are its curl or reqwest backends |
| `pgp` | 0.21.1, no default (drops bzip2) | detached, clearsigned and sig-over-xz verify; keyring parsing; fingerprint pins | rpgp org | 148 (69 unique) | no C | MIT/Apache-2.0 | sequoia: see §0. gpgv: not on Windows |
| `ureq` | 3.5.2, `["rustls-no-provider","platform-verifier"]` | every HTTP fetch | algesten | 27 | no | MIT/Apache-2.0 | std has no TLS. reqwest: see §0 |
| `rustls` | 0.23.46, `["ring","std","tls12","logging"=off]` | builds the ring `CryptoProvider` that is passed to ureq's `TlsConfig` | rustls org | (in ureq) | — | Apache-2.0/ISC/MIT | Avoids leaning on ureq's private `_ring` feature |
| `ring` | 0.17.14 (transitive) | TLS crypto | Brian Smith | — | **build.rs, C + asm via cc**. Freestanding: needs only clang for the target, no libc headers | Apache-2.0 AND ISC | aws-lc: see §0 |
| `rustls-platform-verifier` | 0.7.1 (through ureq) | OS trust store: /etc/pki on Linux, CryptoAPI with revocation on Windows | rustls org | (in ureq) | no | MIT/Apache-2.0 | webpki-roots freezes the CA set into the binary. Open question 9 |
| `sha2` | **0.10.9** | sha256/sha512; `compress256`/`compress512` make the resumable midstate possible | RustCrypto | 9 | no | MIT/Apache-2.0 | 0.10 is the version age, pgp and rsa use, so no duplicate. 0.11 has `SerializableState`, but rsa 0.9 can't use 0.11 digests |
| `sha1` | 0.10.x (already in tree through gix) | Alpine `Q1` control checksums, `.SIGN.RSA.` | RustCrypto | 0 new | no | MIT/Apache-2.0 | — |
| `rsa` | 0.9.10 (already in tree through pgp) | Alpine APKINDEX and apk RSA PKCS#1 v1.5 verify | RustCrypto | 0 new | no | MIT/Apache-2.0 | Alpine signatures aren't OpenPGP |
| `ruzstd` | 0.9.1 | Fedora `primary.xml.zst` decode; local-folder `.tar.zst` encode and decode | KillingSpark | 2 | no | MIT | `zstd` = libzstd in C, which needs libc headers per target |
| `lzma-rust2` | 0.25.0, `["std","xz"]` (decoder only) | `.tar.sign` over the uncompressed kernel tar; Debian `Packages.xz`/`Sources.xz`; Fedora `.xz` repodata | hasenbanck | 10 | no | Apache-2.0 | `xz2`/`liblzma` are C. `lzma-rs` was last released in 2023 |
| `flate2` | 1.1.11, `["rust_backend"]` | APKINDEX.tar.gz member splitting, `.gz` repodata | rust-lang | 6 | no (miniz_oxide) | MIT/Apache-2.0 | std has no inflate |
| `tar` | 0.4.46, no default (no xattr) | local-folder archives and restore; apk control segment; `kit.tar` | composefs org (moved from alexcrichton; **confirm the owners on crates.io**) | 4 | no | MIT/Apache-2.0 | Writing ustar/pax by hand is error-prone |
| `quick-xml` | 0.42.0, no features (streaming reader) | Fedora metalink, repomd, primary | tafia/Mingun | 2 | no | MIT | std has no XML |
| `regex` | 1.13.1 | catalog patterns, href scan, sum-line formats | rust-lang | 5 | no | MIT/Apache-2.0 | — |
| `minisign-verify` | 0.3.0 | Zig signatures | jedisct1 | 1 | no | MIT | replaces the exec of `minisign` |
| `serde` + `serde_json` + `toml` | 1.0.229 / 1.0.154 / 1.2.1 `["parse","display","serde"]` | config, catalog, SET.toml, status/job JSON, API docs | dtolnay / toml-rs | 7 / 5 / 7 | serde has a build.rs, no C | MIT/Apache-2.0 | — |
| `clap` | 4.6.7 `["derive"]` | about 12 subcommands plus `queue` | clap-rs | 17 (21) | no | MIT/Apache-2.0 | It is the stack default |
| `anyhow`, `thiserror` | 1.0.104, 2.0.21 | errors (bin and lib) | dtolnay | 1, 6 | no | MIT/Apache-2.0 | It is the convention |
| `tracing` + `tracing-subscriber` | 0.1.44 + 0.3.23 `["fmt","std"]` | logging to the journal or console | tokio-rs | 15 | no | MIT | It is the stack default |
| `jiff` | 0.2.43 | local-date names (`YYYY-MM-DD`), parsing Go's RFC 3339 timestamps, Windows tz | BurntSushi | 2 (5) | no | Unlicense/MIT | std has no local time zone |
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

It's one package, `preserver`, with `src/lib.rs` and a thin `src/main.rs`; no workspace, because there is only one bin and one lib. `catalog.toml` and `keys/` move into the repo. Keys are embedded with one `include_bytes!` per file in `keys.rs`. **The public repo has no host defaults.** The Go code hard-codes `primary_uuid` and the owner list. In preserver both are required in `~/.config/code-archive/config.toml` (see `config.example.toml`).

```
src/main.rs            clap dispatch; argv0 == "preserver-ssh" -> ssh shim (§3.5)
src/paths.rs           Paths: XDG on Linux / APPDATA+LOCALAPPDATA on Windows; ghDest/localDest/publicDir
src/config.rs          Config, LocalFolder, Drive registry (drives.d/<id>.toml), validation (ports Go regexes)
src/status.rs          Go-compatible status JSON (+ alerts[]); job locks via File::try_lock in runtime dir
src/catalog.rs         Catalog/Set/Source (+ kind "repo", format fedora|debian|alpine); catalog.toml embedded
src/keys.rs            embedded keyrings; stored-key pin check
src/crypt.rs           age: init (generate + scrypt-lock), encrypt_stream(recipient.txt), open_identity(passphrase)
src/personal/{github.rs, local.rs, restore.rs}
src/git/{mirror.rs (gix fetch, refs state), bundle.rs (exec git bundle create; native reader), http.rs (gix Http over ureq), ssh.rs (shim + mux args)}
src/net/{client.rs (ureq Agent, https-only incl. redirects, timeouts, doc size limits), throttle.rs (token bucket), download.rs (segmented Range/If-Range, sidecars), hash.rs (ResumableSha256/512 on sha2::compress*)}
src/queue/{job.rs, store.rs, sched.rs}
src/resolve/{mod.rs (Item, dispatch, name/URL checks), listing.rs, github.rs, json.rs (kernel/go/rust/node/zig), hf.rs, yaml_lite.rs, static_.rs, href.rs}
src/verify/{mod.rs (verify_item, TOFU), sums.rs (findSum port), pgp.rs, minisign.rs}
src/public/{mod.rs (enqueue, budget, record), versioned.rs (staging/hardlinks/SET.toml/SHA256SUMS/prune), index.rs (INDEX.html), dry_run.rs}
src/mirror/{generation.rs (stage -> verify -> swap -> prune, done.tsv), fedora.rs, debian.rs, deb822.rs, alpine.rs}
src/clone.rs           tiers, FAT/exFAT rules, kit.tar, sync_tree (also replicas)
src/scrub.rs           verify [--repair], rotating quarter, par2 exec
src/tray_model.rs      platform-neutral tray state: labels, overdue (4 days), icon/status, menu items (unit-tested; ports tray.go logic)
src/platform/mod.rs    cfg re-export
src/platform/linux/{udisks.rs, notify.rs, tray.rs (ksni), fs.rs}
src/platform/windows/{volumes.rs, devnotify.rs, tray.rs (Shell_NotifyIcon + balloons + TaskbarCreated re-add), tasks.rs (schtasks XML), fs.rs}
```

### 3.1 Platform API (the same signatures in both cfg modules)

| fn | Linux | Windows |
|---|---|---|
| `list_filesystems() -> Vec<FsInfo{id, label, fstype, size, mount, removable}>` | udisks2 GetManagedObjects | FindFirstVolumeW + GetVolumePathNamesForVolumeNameW + GetVolumeInformationW + FSCTL_GET_NTFS_VOLUME_DATA |
| `mount(&DriveId) -> PathBuf` | udisks `Filesystem.Mount` with `auth.no_user_interaction` (replaces the udisksctl exec) | resolve the volume path; no mount step |
| `disk_free(&Path) -> (free, total)` | rustix statvfs | GetDiskFreeSpaceExW |
| `is_mounted(&Path)` | st_dev differs from the parent's | volume root exists |
| `watch_drives(Sender<DriveEvent>)` | InterfacesAdded/Removed signals | CM_Register_Notification on GUID_DEVINTERFACE_VOLUME |
| `run_tray(TrayModel, Receiver<..>)` | ksni blocking | hidden top-level window + Shell_NotifyIconW |
| `notify(Alert)` | org.freedesktop.Notifications with the "run" action | NIF_INFO balloon, where NIN_BALLOONUSERCLICK means run |
| `open_path` | xdg-open | explorer.exe |
| `ssh_program()`, `ssh_mux_args()` | `/usr/bin/ssh` + ControlMaster args, `SSH_ASKPASS=/usr/bin/ksshaskpass`, `SSH_ASKPASS_REQUIRE=force` | `%SystemRoot%\System32\OpenSSH\ssh.exe`, no mux args |
| `install_schedule()` | none: units ship in `dist/systemd/`, installed by the environment repo | schtasks XML: `\code-archive\public` 03:00 StartWhenAvailable Priority 7, `local` nightly, `verify` weekly, `tray` LogonTrigger |
| `background_priority()` | none (the units set Nice and IOSchedulingClass=idle) | SetPriorityClass(PROCESS_MODE_BACKGROUND_BEGIN) |

**`DriveId` newtype (an invariant).** It is normalized hex without dashes, upper case. udisks reports FAT as `XXXX-XXXX` and NTFS as a 16-hex serial, which are the same values Windows returns. So the same `drives.d/<id>.toml` matches on both OSes, and the existing ext4 UUID still works on Linux.

**Notifications** are raised by the tray from status transitions: jobs append to `alerts[]` in the status JSON, and the tray tracks the last id it has shown. That gives one mechanism on both OSes. The CLI also prints alerts.

### 3.2 Core types

```rust
struct Item { name: String, url: String, version: String, expect: Expect, size: Option<u64>, sig_url: Option<String>, sums_url: Option<String>, sums_sig_url: Option<String> }
enum Expect { None, Sha256([u8; 32]), Sha512([u8; 64]), Both([u8; 32], [u8; 64]), Blake3([u8; 32]) }

struct Job { id: JobId, kind: JobKind, priority: u32, state: JobState, attempts: u32, next_try: Option<Timestamp>,
             drive: DriveId, created: Timestamp, updated: Timestamp, progress: Progress, error: Option<String> }
enum JobKind { Personal { github: bool, local: bool }, Set { set: String }, Mirror { set: String, source: String },
               Clone { dest: PathBuf, tier: Option<Tier>, sets: Vec<String>, once: bool }, Scrub { repair: bool } }
enum JobState { Queued, Blocked(BlockReason /* DriveAbsent | Budget */), Running { pid: u32 }, Paused, Done, Failed, Canceled }
struct Control { pause: bool, cancel: bool, priority: Option<u32> }          // <id>.ctl, written by CLI/tray only
struct Progress { phase: Phase, files_done: u64, files_total: u64, bytes_done: u64, bytes_total: u64, rate_bps: u64, current: Vec<String> }
struct Fetch { job: JobId, order: u32, host: String, url: String, dest: PathBuf, size: Option<u64>, expect: Expect }
struct PartState { v: u8, url: String, validator: Validator /* ETag | LastModified */, offset: u64, total: Option<u64>, sha256: [u32; 8], sha512: Option<[u64; 8]> }
enum RepoFormat { Fedora, Debian, Alpine }    // enum + match: three walkers in one build, but no trait needed
```

### 3.3 Queue

| Aspect | Design |
|---|---|
| Store | `~/.local/state/code-archive/queue/<id>.json`, written only by the worker (tmp + rename). Control lives in `<id>.ctl`, written by the CLI and tray. New jobs are created with `O_EXCL` by anyone. The worker rescans every 1 s |
| Single worker | `preserver queue run` holds `code-archive-queue.lock`. `public`, `clone` and `scrub` enqueue, then run the worker if the lock is free; otherwise they print "queued; worker running". A `Running{pid}` job whose lock isn't held is a crash and goes back to Queued, as Go's `lockHeld` does |
| Per-file state | The filesystem is the state: a final file exists only after verification. A partial is `<dest>.part` + `<dest>.part.json` (PartState). Repo generations add `.staging/<gen>/done.tsv` (append-only, fsync batched) |
| Priority | `Job.priority` is the position in first-pass catalog order (`--first-pass`), or stable by `priority` then catalog order, as Go does. Within a job, items keep plan order |
| Concurrency | `downloads = 4` threads. Per-host semaphores default to 2, overridable in config `[hosts]` (e.g. `"huggingface.co" = 4`) |
| Retry | Per item: backoff 5 s·2ⁿ with jitter, capped at 10 min, 6 tries per run. 4xx other than 408/429 is permanent. A 429/503 `Retry-After` pauses the whole host. After that the job is Failed, and the next timer run retries it |
| Pause/resume/cancel | Applied at the next 64 KiB chunk. Pause keeps `.part` files. Cancel deletes the job's staging. `queue pause --all` writes a global ctl |
| Unplug | A write error showing the mount is gone (ENOENT/EIO/ENODEV, or `is_mounted` false) puts every job on that drive into `Blocked(DriveAbsent)` without counting attempts. The tray's drive watcher resumes them on replug |
| Bandwidth | One global token bucket (default `bandwidth_mbit = 80`, 0 = off, burst 256 KiB). It is taken before each body read in `net` and in the gix Http backend. It counts payload bytes, so the wire is about 2–3% above; TCP backpressure keeps the link honest. Personal ssh fetches are unthrottled, as now |
| Resume | Segmented GETs, each with Range + If-Range (validator) and `timeout_recv_body` 10 min. A segment end is a checkpoint: `sync_data` the part, then write the sidecar atomically. On resume: truncate the part to `offset`, restore the hashers from the midstate, continue. 200 instead of 206 means restart from 0. A part without a sidecar (for example a leftover from the Go era) is re-hashed once. Without Range support it is a single stream with a size-derived timeout and no resume. BLAKE3 has no public midstate, so its sources re-hash on resume |
| Midstate | **Persist it.** `ResumableSha256/512` wrap `sha2::compress256/512`. Checkpoints sit on 64 MiB boundaries, so the state is just the words plus the length, and the sidecar carries a version number |
| Visibility | Versioned sets work exactly as in Go: `<set>/.staging/<plan16>/`, hardlinks from the previous version (copy on exFAT/FAT), SET.toml + SHA256SUMS, rename into place, prune to `keep`. Repo mirrors follow §3.4 |
| Progress | The worker rewrites `<id>.json` every 1 s. The tray polls every 2 s while a worker lock is held, otherwise hourly. `queue list [--watch]` |

**Why JSON over rusqlite or redb:**
- There are only hundreds of jobs. The 100k-file item state lives on the drive next to the data, so it can't drift from the data after a crash or an unplug.
- The tray and CLI work concurrently without IPC.
- No C, and every file can be read with `cat`.
- The cost is no ad-hoc SQL. That's acceptable.

### 3.4 Mirror walkers (replace rsync)

| Format | Trust chain | Visibility |
|---|---|---|
| Fedora | **repomd.xml is not signed by Fedora.** The anchor is the metalink from `mirrors.fedoraproject.org` over TLS (sha256/sha512 + size of repomd.xml), then repomd `<data>` checksums, then primary(.zst/.xz/.gz) `<checksum type=sha256>` per `<location>`. One walk each for `fedora-45`, `fedora-source-45`, `updates-released-f45` and the updates source repo | New `Packages/` files first (unreferenced until the swap), then the `repodata/` swap (`renameat2 RENAME_EXCHANGE` on Linux; rename-aside then rename on Windows, with the window covered by a job journal), then delete unreferenced files |
| Debian | InRelease verified with a new `keys/debian-archive.gpg` (trixie archive keys pinned by fingerprint), then SHA256 of `{main,contrib,non-free,non-free-firmware}/{binary-amd64,binary-all,source,i18n}` indexes, then `Packages` Filename/Size/SHA256 and `Sources` Directory + Checksums-Sha256. The union over the configured suites gives the exact pool file set, which fixes the old "pool mixes every suite" problem. Security comes from `security.debian.org/debian-security` as its own mirror | Pool first, then `dists/<suite>` swap, then prune. Create `by-hash/SHA256/<hash>` hardlinks, because trixie's Release has `Acquire-By-Hash: yes` |
| Alpine | APKINDEX.tar.gz: the first gzip member holds `.SIGN.RSA256.` (or `.SIGN.RSA.`), RSA-verified over the raw second member with pinned `keys/alpine-*.rsa.pub` (new). Then per apk: sha1 of the control member equals `C:Q1…`, and the sha256 of the data member equals `datahash` in .PKGINFO | Packages first, then rename APKINDEX.tar.gz into place, then prune |

`dry-run` for repos fetches metadata only and reports exact byte totals.

**Catalog migrations** (a `chore` job):
- rsync kinds become `kind = "repo"`.
- `rfcs` (`rsync.rfc-editor.org::rfcs`) becomes http.
- `gcc` and `gnu-latest` become https `listing` with a two-level resolver.
- Fix the 3 dry-run failures: debian-cd-key 404, musl `/releases/` 404, the geofabrik pattern.

### 3.5 GitHub personal path

| Step | Linux | Windows |
|---|---|---|
| List | exec `gh repo list --json …` (parity) | same, with gh.exe |
| Fetch | **Phase 1:** exec `git fetch` as Go does, with `GIT_SSH=<runtime>/code-archive/preserver-ssh` (no shell, unlike Go's `GIT_SSH_COMMAND`) and `GIT_SSH_VARIANT=ssh`. **Phase 3:** gix fetch via `ssh::connect::Options { command: Some(shim), kind: Some(ProgramKind::Ssh), disallow_shell: true }`, refspecs `+refs/heads/*` and `+refs/tags/*`, prune, set HEAD | ssh.exe direct (Windows Hello handles PIN and touch) |
| Shim | `preserver-ssh` is a symlink to the binary. main sees argv0, adds `-o ControlMaster=auto -o ControlPath=$XDG_RUNTIME_DIR/code-archive-ssh-%C -o ControlPersist=60`, sets SSH_ASKPASS*, then `exec`s /usr/bin/ssh. It exists because gix's Options can't carry extra args or env, and `set_var` is unsafe in edition 2024 | not needed |
| Change detection | `<oid> <refname>\n` lines sorted by refname bytes (heads and tags only, unpeeled, the same as `for-each-ref`), compared byte-for-byte with the existing `.refs` file | same |
| Bundle | exec `git -C mirror bundle create -q - --all`, stdout into the in-process age Encryptor, then `.tmp` and rename | needs Git for Windows |
| Restore | Phase 1: in-process age decrypt, then exec `git clone` + `remote remove origin` (parity). Phase 4: native. Parse the v2/v3 header, `gix_pack::Bundle::write_to_directory` (index-pack), init, write refs + HEAD, check out with gix worktree-mutation. The kit and Windows then need no git | same |

## 4. CLI

| Command | Notes |
|---|---|
| `init` | in-process keygen. The secret goes straight into the scrypt Encryptor (zeroized) and never touches disk unencrypted. Writes `identity.age` on the drive and at home, and `recipient.txt` |
| `personal [--local-only]` | github + local jobs, refs state, alerts |
| `restore FILE DIR` | `.bundle.age` or `.tar.zst.age` (L0 then Dnn applies the manifest's deletions) |
| `public [SET…] [--dry-run] [--first-pass]` | enqueue + run the worker |
| `queue list [--watch] \| show ID \| pause [ID\|--all] \| resume [ID\|--all\|--drive ID] \| cancel ID \| retry ID \| prio ID N \| run` | new |
| `clone DEST [--tier usb64\|disk1t\|full] [--sets …] [--once]` | phase 4 |
| `verify [--repair]` | phase 4 |
| `drives`, `open`, `tray` | parity |
| `install` | Windows only: Task Scheduler tasks + tray at logon |
| dropped: `migrate` | the gh-backup migration is done, and paths are kept |
| deferred: `kit` | the existing `kit/` stays. Later, add preserver binaries for 4 targets + `cargo vendor` source |

**Local-folder format (new, because the `tar` crate can't write GNU `--listed-incremental` dumps):**
- Same names: `<name>/YYYY-MM/{L0,Dnn}.tar.zst.age`.
- The first entry is `.preserver/manifest.tsv`, listing every path present plus the base. Dnn holds the files changed against the L0 index (size, mtime, ctime on unix).
- The index lives in `~/.local/state/code-archive/local/<name>/YYYY-MM.L0.idx`.
- GNU tar can still extract the archives, just without applying deletions.

## 5. Phases and steps

Every phase ends with `fmt`, `clippy -D warnings`, `test`, `cargo deny`, then a commit and push.

| # | Step | Files | Agent |
|---|---|---|---|
| **0** | Repo `preserver`: Cargo.toml (lints from rust.md, profiles, `panic="abort"`), rust-toolchain.toml, deny.toml (licenses MIT/Apache-2.0/ISC/BSD-3/Unicode-3.0/Unlicense/CC0/Apache-2.0-WITH-LLVM-exception; cc wrappers; rsa advisory note), `.cargo/config.toml`, CLAUDE.md. **Proof:** a stub that links ring + age + ureq for all musl targets and `x86_64-pc-windows-gnu`, and `cargo check` passes for msvc/gnullvm | root files | `coder`; CLAUDE.md by `writer` |
| 0b | CI workflow (4 targets, pinned actions) | `.github/workflows/ci.yml` | `deploy` |
| **1a** | paths, config (no defaults), status (Go-compatible: year-1 zero time means none), locks, crypt, github (exec git + shim), restore (exec git clone), drives + mount (udisks/zbus), `open`. Linux only; Windows `platform` stubs return `Unsupported` | `src/{paths,config,status,crypt}.rs`, `src/personal/{github,restore}.rs`, `src/git/ssh.rs`, `src/platform/linux/{udisks,fs}.rs` | `coder` |
| 1a gate | (1) the first real run writes **zero** new bundles; (2) decrypt a Go-era `.bundle.age` with the existing `identity.age`; (3) the kit's Go `age` decrypts a new bundle under `env -i PATH=/nonexistent`; (4) restore of one repo matches `git fsck`. Point the systemd units at `preserver` | tests in `tests/personal.rs` | `test-writer`, then it is run by hand outside any sandbox (it touches real credentials and FIDO keys) |
| **1b** | tray_model + ksni tray + Linux notifications with action + reminder logic; local folders (tar + ruzstd + age, manifest, L0/Dnn) | `src/tray_model.rs`, `src/platform/linux/{tray,notify}.rs`, `src/personal/local.rs` | `coder` |
| **2** | net (client, throttle, segmented download, sidecars, resumable hash), queue (job/store/sched), resolvers (port resolve.go), verify (sums, rpgp detached/clear/xz, pins, stored-key pin, minisign, TOFU), public (versioned, budget, index, dry-run), catalog + keys moved in | `src/net/*`, `src/queue/*`, `src/resolve/*`, `src/verify/*`, `src/public/*`, `catalog.toml`, `keys/*` | `coder` (the resumable hash, midstate and checkpoint protocol go to `novel-coder` if `coder` reports trouble) |
| 2 gate | Port public_test.go (rustls test server with a checked-in test cert). Kill mid-download and resume with no full re-hash (assert bytes read). Pause and cancel from a second process. Bad signature never becomes visible. TOFU change raises an alert. Budget refusal. `keep` pruning. **Differential test: rpgp vs gpgv on every enabled signed source and all 11 keyrings.** Bandwidth ≤ 80 Mbit/s with `ip -s link` | `tests/*` | `test-writer`; then `security-auditor` on net, verify and resolve |
| **3** | gix mirror + ureq `Http` impl (pipe thread for POST bodies); move personal fetch to gix; generation swap; Fedora, then Alpine, then Debian walkers; deb822 parser (proptest); catalog `kind="repo"` + the rsync replacements + the 3 dry-run fixes | `src/git/{mirror,http}.rs`, `src/mirror/*`, `catalog.toml` | `coder` for the walkers; `chore` for the catalog edits |
| 3 gate | Fixture repos (tiny Fedora/Debian/Alpine trees, signed with test keys); a tampered file is rejected; interrupted generation resumes; `dnf --repofrompath` and `apt` (podman debian container) install from the mirror; personal again writes 0 new bundles via gix | | `test-writer`, `security-auditor` |
| **4** | clone (tiers, FAT 4 GiB rule, no symlinks, kit.tar), sync_tree for replicas + drive watcher in the tray, scrub + par2, native bundle restore | `src/{clone,scrub}.rs`, `src/git/bundle.rs` | `coder` |
| 4 gate | clone usb64 to a FAT32 loop image in $TMPDIR; `sha256sum -c` passes on the copy; native restore equals `git clone` for every backed-up repo | | `test-writer` |
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
| **age compatibility** | `identity.age` header: `-> scrypt … 18`. The age crate decrypts scrypt stanzas, but its default max work factor is derived from the machine, so set `set_max_work_factor(22)` explicitly (2^18 means 256 MiB, fine even on an RPi). Then `IdentityFile::from_buffer` takes age-keygen's comment lines. Encrypting to `age1…` X25519 follows the same v1 spec as Go age 1.3.1. The output is **not byte-identical** (random file key and ephemeral share) but **is interoperable both ways**. Gate 1a proves both directions against real files |
| rpgp vs gpgv semantics | v3 or ancient keys in gnu-keyring.gpg, SHA-1 binding signatures, expiry and revocation handling, subkey choice by issuer fingerprint. Parse each key separately, skip and log the ones that don't parse, never fail the whole keyring. The phase-2 differential test against gpgv decides |
| ring + rust-lld for aarch64-musl | This is the usual recipe, but not yet proven on this host. Phase 0 proves it. Fallback: `zig cc` from dnf as CC and linker |
| Fedora repodata unsigned | Trust rests on the TLS metalink (weaker than Debian or Alpine). Packages carry RPM signatures that dnf checks on use. Native RPM header verification is open question 6 |
| Alpine format drift | apk-tools v3 index and package formats may appear. Check the real v3.24 index at phase 3. The walker refuses unknown signature names |
| Debian by-hash and apt expectations | Create by-hash links. The phase-3 apt container test catches gaps |
| ruzstd at level 1 | Local archives come out maybe 5–10% bigger than zstd -3. Restore of anything made by GNU zstd works |
| Go status JSON | Go zero time `0001-01-01T00:00:00Z` and local offsets. Parse leniently. Writing adds fields but removes none |
| Windows long paths, exFAT | std handles long paths. There are no hardlinks on exFAT/FAT, so copy instead (`keep` then costs full size) |
| Payload-only throttling | Measured overhead of about 2–3%. Lower the default to 78 if 80 on the wire is a hard limit |


## 7. Decisions (final)

Supersedes the open questions of the original report.

- **Crates:** all approved at the pins in section 1. Each phase adds only the crates it uses. Phase 1a carries age, serde, serde_json, toml, clap, anyhow, thiserror, tracing, tracing-subscriber, jiff, rpassword, rustix and zbus. The later-phase crates (gix, gix-transport, pgp, ureq, rustls, sha2, ruzstd, lzma-rust2, flate2, tar, quick-xml, regex, minisign-verify, ksni, windows-sys, blake3) are added in their phase at the pinned version. A pin that does not resolve is reported, never replaced by a guess.
- **GitHub transport** is user-configurable, and both modes work on both operating systems:
  - `ssh`: ssh with a FIDO key through the `preserver-ssh` argv0 shim (ControlMaster for one touch per run; on Linux `SSH_ASKPASS=ksshaskpass` and `SSH_ASKPASS_REQUIRE=force`).
  - `https`: a token obtained from the `gh` CLI (`gh auth token`), handed to git through a credential helper on stdin or a GIT_ASKPASS-style mechanism. The token never appears in argv, a URL, a log or a file.
  - Selected by `transport = "ssh" | "https"` in `config.toml` and overridden per run by `--transport`. Tray selection arrives in phase 1b.
- **zstd:** `ruzstd`. **TLS roots:** the OS store with an embedded fallback (relevant from phase 2).
- **Compatibility:** every code-archive path, unit name, lock name and on-disk format is kept, so the Go-era state is picked up with zero new bundles. Only the binary is named `preserver`.
- **No host defaults in the repo:** owners and the primary drive uuid come from `~/.config/code-archive/config.toml` (example: `docs/config.example.toml`). Nothing personal (drive uuid, email) in source or docs.
- **License:** MIT OR Apache-2.0.
