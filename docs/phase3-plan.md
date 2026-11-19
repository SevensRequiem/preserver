# Preserver phase 3: revised implementation plan

This revision folds in the three critiques: completeness (C1–C23), correctness and security (R1–R18 plus the smaller points, marked Rs), and feasibility (F1–F16). The disposition table at the end gives one line per item. Nothing was built.

I re-checked these hooks for this revision:
- `JobKind` matches that end in a wildcard (`_ =>`): `daemon.rs:142`, `personal/lane.rs:55,123,132,158,302`, `tray_model.rs:388,399`.
- `outranked` is at `sched.rs:326`.
- `budget` is at `public/mod.rs:60`.
- `Downloader::get` is at `download.rs:679`.
- `Expect` is at `download.rs:29` and its verdict is at `:570-573`.
- `Worker` literals are at `public/mod.rs:323`, `sched.rs:681,788` and `public/tests.rs:79`.
- `TOUCH_WAIT`, `ssh_master` and `ssh_command` are at `platform/linux/mod.rs:61,113,42`.
- In the catalog, a todo is required only when a source is disabled (`catalog.rs:200`).
- Status readers count entries by `state` (`tray_model.rs:151`, `status.rs:73`).

## (a) Decisions

**D1. One `JobKind::Mirror { set, source }` per enabled in-place source (`git` or `repo`), in `Lane::Download`.**
- A `Set` job is queued only for sets that have a versioned source.
- `Store::enqueue` (`store.rs:103-131`) works per `(set, source)` unchanged.
- Older binaries skip job kinds they can't parse (`store.rs:43-46`).
- The step that adds the variant reviews every wildcard match listed above by hand (F11). The tray needs a Mirror arm for its label and running text.

**D2. Worker contract:**
```rust
pub(crate) struct Whole { pub files: u64, pub bytes: u64, pub files_done: u64, pub bytes_done: u64 }
#[derive(Default)] pub(crate) struct Planned { pub fetches: Vec<Fetch>, pub more: bool, pub whole: Option<Whole> }
pub(crate) enum Work<'a> {
    Fetch(Planned),
    Run(Box<dyn FnOnce(&AtomicBool, &Arc<AtomicU64>) -> Result<()> + Send + 'a>),
}
impl From<Vec<Fetch>> for Work<'_>
// Worker.plan:   &'a (dyn Fn(&Job, &Path, &[usize]) -> Result<Work<'a>> + Sync)
// Worker.settle: gains the same `ok: &[usize]` argument
// ok = indices into the previous batch's `fetches` that finished verified (R1)
```
- If `more = true` comes back with an empty `fetches`, the job fails with "planner returned an empty batch" (F9).
- `halt_requested` is re-checked between batches. `outranked` is checked only for `Work::Fetch` jobs.
- A `Work::Run` job is never yielded; pause and cancel still apply (C4). The reason: git has no resume, so a yield throws the whole transfer away.

**D3. Walkers are free functions dispatched by `match src.format`. No trait.**
- Signatures: `anchor(ctx, src) -> Result<Anchor>`, `walk(src, meta_dir, emit) -> Result<()>`, `walk_meta(src, &Anchor) -> Vec<&Entry>` (the subset that `walk` reads, used by dry runs, C19).
- There is one swap, prune and recover implementation, in `generation.rs`.

**D4. Alpine apks are verified in the Downloader, as `Expect::Apk([u8; 20])`.**
- `land()` has no apk branch (R14). There is one verification point.
- Resume: the sidecar keeps the SHA-256 midstate as it does today (harmless). The verdict re-reads the whole `.part` in `finish`, since apks are small. A resumed apk still passes `check_apk` (C23).

**D5. One done ledger per tree: `<tree>/.preserver/done.tsv`.**
- A line is appended only for fetches the pool reports Ok (the `ok` indices). Before a batch is handed out, any existing dest that classify did not mark "have" is deleted (R1).
- A crash can leave a present file with no done line. Such a file is re-hashed ("suspect").

**D6. Tree locations, with bookkeeping in `<tree>/.preserver/`.**
- Repo trees are `public/<set>/<source>/`. `.preserver/` holds `{live,done}.tsv`, `swap.json` and `staging/<gen16>/{meta,incoming,old}`.
- `want.tsv` is rebuilt on every run. It is never a resume shortcut (R2).
- Git trees are `public/<set>/git/<source>.git`.
- Reserved names (catalog validation, C15/R18): an in-place source name can't be `git`, can't start with `.`, and can't match the version-directory pattern.

**D7. Fedora: one source with `trees = [{ path, metalink }]`.**
- Splitting binary from source later is a catalog-only change: several sources with one tree each, no code (C10). Fedora question 1 is therefore dropped from the user questions.
- Images, `EFI/` and `.treeinfo` are never mirrored: the walker emits only repodata and primary's `Packages/`.
- The metalink base is `Ctx.metalink`. Production passes the constant `https://mirrors.fedoraproject.org/metalink`; only `#[cfg(test)]` code passes loopback (C7, F6, R11).
- The metalink is fetched through a new `Downloader::get_direct` that refuses any 3xx (R11).
- Acceptance (C9, R12):
  - The repomd must match the current anchor or one of the alternates on size, sha256 and sha512.
  - Its `<revision>` must be greater than the live repomd's `<revision>`. The live repomd is re-hashed against the doc hash in `live.tsv`; on a mismatch the check fails with an error.
  - When the live repomd matches nothing in today's metalink, the revision rule alone decides.
  - The metalink's `mm0:timestamp` must not be older than the one recorded at the last commit. That timestamp is stored in the `live.tsv` header field `anchor_ts`.
- The primary must be `.xml.zst`. Anything else fails closed.

**D8. `pgp::release(ring, doc)` for Debian.**
- Issuers are matched by the hashed issuer-fingerprint subpacket, falling back to the key ID.
- Signatures whose issuer is not in the ring are ignored. Every signature that claims a ring key must verify; a garbage signature claiming a ring ID fails closed.
- A subkey must carry the signing flag and is mapped to its primary for `signers`.
- At least one signer must be pinned.
- `detached` and `clearsigned` keep gpgv parity.

**D9. Catalog schema.**
- New fields: `format: Option<RepoFormat>`, `suites`, `components`, `arches`, `trees: Vec<Tree>`, `dirs`, `dir_top`, `exclude`.
- Every enabled source has https URLs only, `git` included (F16).
- Validation enforces "todo ⇒ disabled" (F13, the default; see question 1).

**D10. `MIRRORS.toml`.**
- `Mirror` and `Mirrors` (`index.rs:34,44`) become `pub(crate)` and gain `Serialize`. New fields: `url`, `files: Option<u64>`, `gen: Option<String>`.
- One writer, `record_mirror`, which lands in S2 (C22).
- Rendering (R18):
  - `url` is escaped text only, never a link.
  - The only link is to `<set>/<dir>/`, and only when `dir` is a current catalog source name of that set.
  - Rows for sources no longer in the set are dropped (C16).

**D11. Swap.**
- Directories are swapped with `platform::exchange` (`renameat2` `RENAME_EXCHANGE`). Where that is unsupported (it returns `Ok(false)`, always on Windows), the old tree is renamed aside and the new one renamed in.
- Files are swapped with a plain rename.
- `swap.json` is the journal. It holds the expected sha256 of every file under every swap path (R3).
- Prune and the swap walk use directory fds: `rustix::fs::openat(dirfd, name, O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)` and `unlinkat` (R16).
- On Windows the walk is path-based; that tree is not exposed to the symlink race the same way, and this is noted in the risks.

**D12. The copy lane leaves mirror trees out until phase 4.** Only the note text in `copy/plan.rs:345-348` changes.

**D13. Delete the phase-1 git exec plumbing.**
- Deleted:
  - `src/net/proxy.rs` and its `expect(dead_code)` (`net/mod.rs:4-11`);
  - `credential::{HELPER, TOKEN_ENV, reply, helper_main}`;
  - `pub use git::credential::{HELPER, helper_main}` (`lib.rs:31`);
  - the argv0 dispatch for `preserver-credential` (`main.rs:11`);
  - the `git_credential_fill` test (`tests/cli.rs:291-300`);
  - `git::Auth` (`git/mod.rs:11-95`);
  - `Repo.branch`;
  - the `defaultBranchRef` query.
- Kept: `credential::token`, `ssh::SHIM`/`shim_main`, `shell_safe`, and the `git bundle create` exec.

**D14. Status: Mirror results are recorded as `status/public.json` `sets` entries named `<set>/<source>` (F12).**
- `tray_model.rs:151` already counts any entry by `state`.
- `status.rs:73` copies the array as is.
- `list_text` and the GUI match on the `<set>/` prefix. No reader needs any other change.

**D15. git integrity (R6, F3, C12).**
- Every pack not listed in `preserver-checked` gets full verification before anything is published:
  - the pack and index trailer checksums;
  - every object decoded through gix's index-traverse path in delta-tree order, with no object larger than 1 GiB (`gitoxide.objects.allocLimit`, on fetch too). `DeltaTreeLookup` takes no pack cache: its memory is the resolved bases on the current delta path;
  - every object id recomputed.
- Then connectivity is checked over the union of the unchecked packs plus the already-checked ones. All packs in the set pass, or none are recorded and nothing is published.
- `preserver-checked` lives on the drive and has the same trust as the packs themselves; the docs say so.
- Progress shows as a phase label: "checking pack i/n, objects k/N".
- gix's `parallel` feature is not enabled. It would be a separate, vetted dependency decision. linux-git stays disabled until a measured run (H7).

## (b) Crates (exact pins)

| Crate | Where | Pin and features | Why |
|---|---|---|---|
| gix | deps | `=0.90.0`, no default features, `["blocking-network-client","sha1"]` | approved in design.md §1. `parallel` is off (D15) |
| gix-transport | deps | `=0.62.0`, no default features, `["blocking-client","http-client"]` | the `Http` trait. `http-client-insecure-credentials` is never enabled (F5) |
| quick-xml | deps | `=0.42.0`, no default features | Fedora XML. `deny` only warns about the gui's 0.41.0 duplicate |
| flate2 | deps | `=1.1.11`, no default features, `["zlib-rs"]` | Alpine gzip. zlib-rs is already in the tree |
| rsa | deps | `=0.9.10`, no default features, `["std","pem"]` | Alpine verify. Already in the lock |
| sha1-checked | deps | `=0.10.0` | Q1 and `.SIGN.RSA.` with collision detection. Already in the lock |
| base64ct | deps | `=1.8.3` | Q1 decode. Already in the lock |
| proptest | dev | `=1.12.0`, no default features, `["std"]` | parser and path_cmp properties |
| lzma-rust2 | dev (change) | add `"encoder"` | Debian xz fixtures |

The sha2 `oid` feature is dropped. RSA verification builds `Pkcs1v15Sign { hash_len: Some(n), prefix: <fixed DER DigestInfo prefix>.into() }` for both SHA-1 (15 bytes) and SHA-256 (19 bytes). `Pkcs1v15Sign::new_unprefixed` is forbidden (R13). If those fields are not public in 0.9.10, the fallback is sha2 `oid` with `new::<Sha256>()` and sha1-checked's `AssociatedOid`; the coder confirms which applies before writing.

Gates in every step that adds a crate:
- `cargo tree -i cc` shows ring only.
- `cargo deny check` passes.
- Starting with S3, the cross clippy gates for x86_64/aarch64 musl and windows-gnu/msvc run with the ring CFLAGS recipe from CLAUDE.md (C3).
- The RUSTSEC-2023-0071 reason in `deny.toml` becomes "verify only, public keys; private keys only in tests".

## (c) Steps

Dependency graph:
- S1 → S2 → {S3 → S4a → S4b → S5, S6} and, in parallel, {S7 → S8 → S9}.
- S9 → S10/S11 (Fedora), S12/S13 (Alpine), S14/S15a/S15b (Debian). S16 needs only S2.
- S17 needs S5, S11, S13, S15b and S16. S18 needs S17. S19 needs S18.
- Two agents may run in parallel. Split the job count between them, and only one of them runs a heavy build at a time.

**S1. Batched and closure Worker** (`coder`, ~380 lines)
- Files:
  - `src/queue/sched.rs`;
  - `src/public/mod.rs`: `plan` wrapped in `Work::from`, and the `Worker` literal at :323;
  - `src/public/tests.rs:79`;
  - the `sched.rs` test literals at :681 and :788.
- `run_job` (:384):
  - The scoped pool section moves into `fn batch(&self, job, fetches, base) -> (State, Option<Halt>, u64, Vec<usize> /*ok*/)`.
  - It loops while `more`, guards against an empty batch, and calls `stopped()` only at the end.
- `Run` runs on a scoped thread with the 1 s control loop and no `outranked` check. Outcomes map as follows:

  | Outcome | Job result |
  |---|---|
  | Ok | Done |
  | Err with the drive gone | `Blocked(DriveAbsent)`, `attempts -= 1` |
  | Cancel | Canceled |
  | Pause | Paused |
  | any other Err | Failed |

- Tests:
  - `batches_run_until_no_more`: settle is called once, totals come from `whole`, and `ok` is passed through;
  - `halt_between_batches`;
  - `empty_batch_with_more_fails`;
  - `run_work_pause_resume`;
  - `run_work_not_outranked`: a higher-priority queued job doesn't stop it;
  - `run_work_drive_gone_blocked`;
  - `run_work_error_failed`;
  - the existing tests stay green.

**S2. Mirror kind, catalog schema, budget and index plumbing** (`coder`, ~650 lines)
- Files: `src/queue/{job,mod}.rs`, `src/catalog.rs`, `catalog.toml`, `src/public/{mod,index}.rs`, `src/schedule.rs`, `src/tray_model.rs`, `src/daemon.rs`, `src/personal/lane.rs`, `src/copy/plan.rs`.
- Queue:
  - `JobKind::Mirror`; `lane()` returns Download.
  - Queue label `mirror {set}/{source}`; tray label `Public {set}/{source}`; the "public running" check covers Mirror.
  - Review each wildcard arm (`daemon.rs:142`, `lane.rs:55,123,132,158,302`, `tray_model.rs:388,399`) and add explicit Mirror arms where the label or state differs.
  - `schedule.rs:193-207`: `paused` becomes a list of `JobKind`.
- Catalog, as in D9, with the validation table:
  - https only for `url`, every entry in `urls`, and git sources;
  - `format` is required for repo sources and refused elsewhere;
  - the per-format fields (Fedora `trees`, with valid path segments and a metalink of `[A-Za-z0-9=&_.-]`; Debian `suites`, `components`, `arches`, `keyring`, non-empty `signers`; Alpine `suites`, `components`, `arches`);
  - `dirs`, `dir_top` and `exclude` need `resolve = "listing"`, and `dirs` matches `^…/$`;
  - `{dir}` in `pattern` needs `dirs`;
  - the reserved names from D6;
  - todo ⇒ disabled.
- `catalog.toml`:
  - linux-git is disabled, with the todo "closure-check cost measured (H7); clone.bundle stays a note: gix 0.90 cannot read bundles".
  - live-bootstrap's todo is dropped in S17 when its sources land; until then it is disabled.
- `public/mod.rs`:
  - Extract `fn room(&self, root) -> Result<u64>` (free space minus the reserve) from `budget` (:60-87).
  - The Set budget sums only the estimates of versioned sources (new `Source.est`-based sum) plus held bytes, so in-place estimates are not counted twice (F1).
  - `enqueue_all(…, skip: &dyn Fn(&JobKind) -> bool) -> Result<Vec<(String, String)>>` (:271); `run` iterates the result; `daemon_pass` matches `Set | Mirror`.
  - `plan` for a Mirror whose source is missing or disabled returns `Err(Halt::Cancel)` semantics: the job ends Canceled and the status gets "source no longer in the catalog" (C16).
  - Interim `plan` for an enabled Mirror records "skipped: arrives later in phase 3".
- `index.rs`: `pub(crate)` + `Serialize`, the new fields, and `pub(crate) fn record_mirror(set_dir: &Path, sources: &[&str], m: Mirror) -> Result<()>` (`read_meta`, tmp, fsync, rename, `sync_dir`; drops unknown rows). Rendering as in D10.
- Tests:
  - the job round trip with Mirror;
  - `enqueue_all`: an http+git+repo set gives 1 Set and 2 Mirror jobs; repo-only gives Mirror jobs only; enqueuing again reuses them; a paused Mirror is skipped;
  - the validation table, including reserved names, `git` over `http://`, and an enabled source with a todo;
  - the Set budget excludes in-place estimates;
  - an orphan Mirror is canceled;
  - `record_mirror` drops stale rows, and a `javascript:` url renders as escaped text.

**S3. gix `Http` over ureq** (`coder`, ~500 lines)
- Files: `Cargo.toml` (gix, gix-transport), `src/git/{http,mod}.rs`, `src/net/download.rs`, `src/net/testserver.rs`.
- `download.rs`: `agent()`, `throttle()`, and `get_direct(url, limit)` (refuses a 3xx; used by Fedora).
- `testserver.rs`: records request bodies; per-route status and headers.
- `Remote::new(agent, throttle, got: Arc<AtomicU64>, limit: u64, stop: Arc<AtomicBool>)` implements `blocking_io::http::Http`, using the `pipe` Reader and Writer.
- Errors are built with the gix_error Exn API (`gix::error::message`, `.or_raise`, `Error::from_error`) (F4).
- Rules:
  - Each request runs on its own thread. `Remote` keeps the join handles and joins them on drop.
  - Every 64 KiB chunk checks `stop`; `got` is incremented on the reader side of the pipe only (F10).
  - POST bodies are capped at 16 MiB.
  - 401 and 403 become a plain `io::Error(PermissionDenied, "<url>: 401")`. No headers pipe ceremony (F4).
  - A 3xx is an error naming the `Location` without its query; redirects are never followed.
  - URLs with userinfo are refused before any request.
  - Error text holds only the status and the URL without its query. Header lines never reach errors, panics, thread names or logs (R10).
  - `configure` is a no-op.
- Tests:
  - passthrough;
  - throttle (≥0.45 s for 512 KiB at 1 MiB/s);
  - POST body intact;
  - 302 makes exactly one request;
  - 404, 500 and over-limit;
  - dropping the reader joins the thread, and `got` doesn't move after the stop;
  - userinfo is refused;
  - `token_never_in_errors`: Authorization is set, a 500 and a forced transport error are produced, and the token bytes are absent from `Display`, `Debug` and the captured tracing.
- Gates: `cargo tree -i cc`, `cargo deny`, and the cross clippy targets.

**S4a. `git::mirror::update`: fetch and publish** (`novel-coder`, ~550 lines)
- Files: `src/git/mirror.rs`; `src/git/testcgi.rs` (`#![cfg(unix)]` inside the file; TLS with `net/testdata` and a loopback agent built from the test roots; bridges to `git http-backend`) (C3, F5); `src/git/mod.rs`.
- Interfaces:
  - `pub(crate) enum Via<'a> { Ssh { program: &'a Path }, Https { http: http::Remote, token: Option<&'a str> }, #[cfg(test)] File }`
  - `pub(crate) fn update(dir: &Path, url: &str, via: Via, checked: Trust, stop: &AtomicBool, phase: &dyn Fn(&str)) -> Result<()>`
  - `pub(crate) enum Trust { Drive, Host }`
  - `refs_state`
  - `token_for(url) -> bool`: parses the host and compares it exactly with `github.com`.
  - No `TRIES` here: a Mirror `Work::Run` error maps straight to Failed (the S1 outcome table), and retries come from the queue's own `attempts` and ctl retry, so nothing in S4a counts attempts.
- Steps:
  1. Write the fixed config text (tmp, fsync, rename) and delete `commondir` and alternates. This happens for both `Trust` values (R9).
  2. Sweep stale `*.lock` files under the root and `refs/`, plus pack temp files (R7).
  3. `open_opts(isolated)`.
  4. `remote_at_without_url_rewrite`.
  5. Refspecs into `refs/staged/*`, with `Tags::None`, packed refs only, and `with_credentials(|_| Ok(None))`.
  6. One transaction that publishes, prunes, removes `refs/staged/*` and sets `HEAD`, wrapped in `sync_fs`. `HEAD` is set only if the advertised target starts with `refs/heads/` and is published in this transaction; otherwise it stays as it is (R8).
- This step leaves the integrity check as a stub that refuses all unchecked packs except under `#[cfg(test)]` (removed in S4b).
- Tests:
  - fresh mirror: refs equal `for-each-ref`, `fsck --strict` passes, the HEAD symref is right;
  - a no-change run writes nothing;
  - deletes and force-pushes are applied;
  - an interrupted run resumes;
  - a planted config is neutralised;
  - a planted `packed-refs.lock` is removed and the run succeeds;
  - a HEAD symref to `refs/pull/1` is not written;
  - a 401 doesn't prompt;
  - the `token_for` table, including `https://github.com@evil/` and `https://github.com.evil/`.
- Escalate if HEAD isn't advertised with the extra refspec. The fallback is `prefix_from_spec_as_filter_on_remote: false`.

**S4b. Pack integrity and connectivity** (`novel-coder`, ~400 lines)
- Files: `src/git/mirror.rs`.
- D15. For `Trust::Host`, packs present on the first gix open are appended to `preserver-checked` without a check, because the host disk is trusted (C11).
- Tests:
  - a flipped byte in a pack is refused and nothing is published;
  - a pack missing a blob is refused;
  - pack B, which needs objects from pack A, is refused when A is corrupt (the union rule);
  - an unchecked pack planted by hand is verified on the next run;
  - a phase-1 host mirror with loose refs and `remote.origin` passes without decoding (checked-file count).

**S5. Public git mirrors** (`coder`, ~350 lines)
- Files: `src/public/mod.rs`.
- `plan` for a git Mirror:
  1. `plain_dirs` on `<set>/git/<source>.git/{objects/pack,refs}`.
  2. The `est` is checked against `room()`.
  3. On a vfat or msdos primary (`platform` fstype) with `est ≥ 4` GB, refuse: "needs a filesystem with files over 4 GiB" (C5).
  4. `Work::Run` → `update(… Via::Https { http: Remote::new(dl.agent().clone(), dl.throttle().clone(), got, room, stop) , token: None }, Trust::Drive, …)`, then `record_mirror`, `record("<set>/<source>", "ok", <short HEAD>, "")`, and `index::write`.
- `settle` records failures.
- Dry run: one `GET <url>/info/refs?service=git-upload-pack` through `Remote`, reporting "ok", "redirect to <host>", "not smart http" or the status (C13).
- Tests:
  - a Worker-driven Mirror job against testcgi (unix): Done, a `MIRRORS.toml` row, and the status entry `<set>/<source>`;
  - the vfat decision table;
  - dry-run probe output for 200 smart, 302 and dumb.

**S6. Personal fetch on gix; delete the exec plumbing** (`coder`, −500/+300 lines)
- Files: `src/personal/github.rs`, `src/personal/lane.rs`, `src/git/{mod,credential,ssh}.rs`, `src/platform/linux/mod.rs`, `src/lib.rs:31`, `src/main.rs:11`, `src/net/{proxy.rs (deleted), mod.rs:4-11}`, `tests/cli.rs:291-300`, `CLAUDE.md` (the Phase 1a credential line and the Phase 2 proxy line).
- `backup_repo` (:148): the block at :158-184 becomes `mirror::update(&mirror, &url, via, Trust::Host, stop, phase)` plus `refs_state`. `stop` is the personal lane's real flag (C1).
- The ssh URL is built from the validated owner and name as `git@github.com:<owner>/<name>.git`, never from an API string (R9).
- The shim adds `-o ControlMaster=no -o BatchMode=yes`, so it can only be a mux client (C1, F2).
- Before each repo, `ssh -O check` runs on the control path. When the master is gone, `ssh_master` (`linux/mod.rs:113`) restarts it with the session env and the `TOUCH_WAIT` bound. A failure still maps to `Blocked(NeedsTouch)`. That is the only place DISPLAY and the askpass are needed.
- `cfg(windows)`: `Via::Ssh { program: <ssh.exe from PATH> }`, no shim and no master check (C2).
- https: `Remote` with `client::agent(client::os_roots())`, `Throttle::new(0)` and `u64::MAX`; the identity is set only when `token_for` holds.
- Delete everything listed in D13, including the github.rs tests built on `Auth::new` and `Repo.branch` (:435, :506, :555). Rewrite them on `Via::File`.
- Tests:
  - the three existing tests through `Via::File`;
  - **parity gate**: a phase-1 mirror (loose refs, `.refs`) gives 0 new bundles and a byte-identical `.refs`;
  - https Basic auth through TLS testcgi: the right token works; the token appears in no file under the mirror or state dir and in no captured log or error;
  - the shim argv contains `ControlMaster=no`;
  - with the control socket missing, the fetch ends within 10 s as `NeedsTouch` (unix; the fake ssh is a script on PATH);
  - Windows CI compiles and the `Via::File` tests pass.

**S7. Generation core: filesystem layer** (`novel-coder`, ~900 lines)
- Files: `src/mirror/{mod,generation}.rs`, `src/lib.rs`, `src/platform/linux/fs.rs` and `src/platform/windows/mod.rs` (`exchange`), and `src/public/versioned.rs`: `link_or_copy` (:188) and `write_synced` (:379) become `pub(crate)` here (F8).
- `mirror/mod.rs`:
  - `Check { Sha256([u8;32]) }` (`Display`/`FromStr`);
  - `Entry { path, size, check }`;
  - `Meta { entry: Entry, from: Option<String> }`, where `from` is a fetch path relative to the base, such as a by-hash path (C6, F7);
  - `Anchor { docs: Vec<(String, Vec<u8>)>, meta: Vec<Meta>, swaps: Vec<String> }`;
  - `Ctx<'a> { dl, keys: &'a [Keyring], rsa: &'a [RsaKey<'a>], metalink: &'a str, plain_http, tree: Option<&'a Path> }` (C7);
  - `rel_path`.
- `generation.rs`:
  - `path_cmp` and `url_of`.
  - TSV format:
    - `live.tsv` header: `#preserver-mirror\t1\t<gen64>\t<files>\t<bytes>\t<rfc3339>\t<anchor_ts|->`.
    - Lines: `<check>\t<size>\t<path>`.
    - Read by streaming through `open_regular` with a 4096-byte line cap and a 10M-line cap. Not `read_meta` (R4).
  - One validator `valid_path` for walk output, tsv lines, journal paths and anchor paths: `safe_rel` (`copy/exec.rs:66`), no control characters, no leading-dot component.
  - `swap.json`:
    - holds `gen` (64 hex) and `steps[{path, key, files: [(rel, sha256)], replace[]}]`;
    - `key` must be under its own `path`;
    - every path is validated (R3, R4).
  - `commit_swap`, `recover(tree)` (checks every listed file's sha256 before any rename), `live_gen`.
  - fd-based `prune` (R16).
  - `fs_limits(fstype, entries)`:
    - files of 4 GiB or more on vfat/msdos;
    - case-fold collisions on vfat, exfat, ntfs and Windows;
    - Windows device names and trailing dots or spaces, through the copy lane's existing check (R15).
    - The error reports counts.
- Tests:
  - proptest `path_order_matches_tree_walk`;
  - the tsv table, including a torn last line and an over-long line;
  - `url_of_encodes`;
  - `swap_recovers_from_every_crash_point` (exchange and aside);
  - `recover_refuses_tampered_staged_file`;
  - `journal_paths_validated` (`../`, a key outside its path, a bad gen);
  - `prune_removes_only_strays` (unix; a symlink's target survives; a directory swapped for a symlink is not followed);
  - `collision_replaced_at_swap`;
  - the `fs_limits` table, including `aux`, `nul.txt` and a name ending in `x.`.

**S8. Generation state machine** (`novel-coder`, ~850 lines)
- Files: `src/mirror/generation.rs`.
- Interfaces:
  - `begin(tree, base_url, anchor) -> Result<Begin>`.
  - `Begin` validates the anchor before writing anything (R5):
    - swap paths are valid, not under `.preserver`, and pairwise disjoint;
    - every doc and meta path is under exactly one swap path;
    - every swap path has a doc, which becomes its key.
  - `Gen::{next(&mut self, ok: &[usize], walk, room, fstype) -> Result<Next>, land(&mut self, ok: &[usize]), ready, commit}`.
- Each run:
  1. Fetch the missing meta files (via `from` when set).
  2. Re-hash every meta file against `anchor.meta` (R2).
  3. Walk with decompression caps taken from the anchor's sizes.
  4. Validate, sort and dedupe, apply `fs_limits`, and refuse payload at or under a swap path.
  5. Write `want.tsv` (rebuilt every run).
  6. Classify by a 3-way merge with `live.tsv` and `done.tsv`.
  7. Delete dests that classify did not mark "have" (R1).
  8. Budget.
  9. Hand out batches of 2048 files / 4 GiB, re-hashing suspects.
  10. Before the swap, stat every want line.
  11. `commit`:
      - re-hash each doc byte-for-byte against `Anchor.docs` and each meta file against `anchor.meta`;
      - refuse any extra file under `meta/<swap>` that is not a doc, a meta file or a walker-declared derived link;
      - then `sync_fs`, the journal, the swap, `live.tsv`, prune and cleanup (R3).
- Tests:
  - `fresh_generation_end_to_end`;
  - `tampered_payload_never_visible`;
  - `tampered_metadata_rejected` (the walk is never called);
  - `planted_meta_and_want_rejected`;
  - `stale_wrong_size_plus_404_leaves_no_done_line`;
  - `interrupted_generation_resumes` (a truncated done.tsv and a re-hash mismatch);
  - `carries_landed_files`;
  - `unchanged_fetches_nothing`;
  - `budget_refuses_before_payload`;
  - `anchor_validation_table`;
  - `extra_file_in_swap_dir_refused`.

**S9. Public glue for repo mirrors** (`coder`, ~500 lines)
- Files: `src/public/mod.rs`, `src/mirror/mod.rs`, `src/gui/public.rs` (if its column layout needs a mirror row).
- `gens: Mutex<HashMap<String, Gen>>`.
- `plan_mirror`: `plain_dirs`, `recover`, `anchor`, `begin`, `clear_other_stages(staging, gen16)`, then `next(ok)`. `OverBudget` is recorded as skipped with the numbers.
- `settle_mirror`: Done and ready → `commit` + `record_mirror` + `record("<set>/<source>", "ok", gen16)` + `index::write`. Any other state → `land(ok)`, plus record failed on Failed. The `Gen` is dropped in every case.
- `mirror::dry_run`: fetches only `walk_meta` (C19) into `<cache>/repo-meta/<set>/<source>/<gen16>/`, walks, prints totals, merges against `live.tsv`/`done.tsv` when mounted, then deletes the cache.
- `list_text` (:401-445) adds one line per in-place source: the `<set>/<source>` status, the generation, and bytes from the `live.tsv` header, or from `MIRRORS.toml` for git (C21).
- Tests:
  - a synthetic repo end to end through `Public`;
  - the dry run fetches only `walk_meta` (server hit log) and the drive stays empty;
  - `list_text` shows repo and git rows.

**S10. Fedora parsers** (`coder`, ~750 lines)
- Files: `Cargo.toml` (quick-xml), `src/mirror/fedora.rs`, `src/mirror/testdata/fedora/`.
- Items: `parse_metalink` (with `mm0:timestamp`), `parse_repomd` (with `<revision>`), `parse_primary`, `accept`.
- Tests: the parser tables and proptests (no panic; round trip).

**S11. Fedora anchor and walk** (`coder`, ~650 lines)
- Files: `src/mirror/{fedora,mod}.rs`.
- The metalink is fetched with `get_direct(ctx.metalink + "?" + tree.metalink)`. Acceptance and rollback follow D7.
- `walk` decodes primary with ruzstd, capped at the anchor's open-size.
- Tests (loopback through `Ctx.metalink`):
  - fresh mirror;
  - tampered rpm;
  - lagging alternate accepted;
  - live repomd matches nothing in the metalink but has a lower revision → accepted;
  - equal or lower revision → refused;
  - older metalink timestamp → refused;
  - metalink 302 → refused;
  - all-tampered fails with nothing written;
  - unchanged makes 0 payload hits.

**S12. Alpine format and crypto** (`coder`, ~700 lines)
- Files: `Cargo.toml`, `deny.toml`, `src/keys.rs` (`RsaKey`, `ALPINE` empty until H3), `src/mirror/alpine.rs`, `src/resolve/mod.rs:44` (`valid_file_name` becomes `pub(crate)`), `src/catalog.rs`.
- Validation:
  - an enabled Alpine source needs at least one `keys::ALPINE` key for every arch;
  - every Debian `signers` entry must appear in `keys/FINGERPRINTS` under its keyring (C8).
- Crypto (R13):
  - the explicit DigestInfo prefix; keys under 2048 bits are refused at runtime; the signature length must equal the modulus size.
- Caps (R14):
  - `index()` reads `APKINDEX` only if its header size is under 256 MiB, and refuses a duplicate `APKINDEX` or `DESCRIPTION` and non-regular entries.
  - `check_apk` reads one `.PKGINFO` of at most 1 MiB and skips other entries without buffering them.
  - `datahash` hashes exactly `size - control_end` raw bytes; the data member is never inflated.
- Tests:
  - RSA and RSA256 are both accepted;
  - refused: a flipped byte, an appended member, an unknown key, another arch's key, RSA512, two signature entries, non-gzip input, `ADB` magic, a signature over the bare digest (no DigestInfo), a 1024-bit key, and a short signature;
  - the tar caps;
  - the `parse` table;
  - `first_member` offsets;
  - `check_apk` good and bad cases;
  - proptest that `parse` never panics;
  - the catalog key-coverage rules.

**S13. Alpine walker** (`coder`, ~450 lines)
- Files: `src/net/download.rs` (`Expect::Apk` at :29; the verdict at :570 calls `check_apk` on the whole `.part`), `src/mirror/{mod,alpine,generation}.rs`.
- `Check::ApkQ1`. Collisions fetch into `incoming/` with `Expect::Apk`.
- `anchor` takes keys from `ctx.rsa`.
- Tests:
  - an `Expect::Apk` mismatch is never visible;
  - an interrupted apk resumes and passes;
  - end to end with the test key through `Ctx.rsa`: fresh tree, tampered apk, a changed Q1 replaced at the swap, and a removed package pruned.

**S14. deb822 and `pgp::release`** (`coder`, ~600 lines)
- Files: `src/mirror/deb822.rs`, `src/verify/pgp.rs`, `src/verify/testkey.rs`.
- `release` follows D8.
- Tests:
  - the deb822 table and proptests (round trip, a 1-byte BufReader gives the same result, no panic);
  - `release`:
    - a signature from outside the ring is accepted;
    - a failing ring signature is refused;
    - a garbage signature claiming a ring key ID is refused;
    - a revoked key is refused;
    - a subkey without the signing flag is refused;
    - no ring signature is refused;
    - text outside the signed block is not returned;
  - `detached` and `clearsigned` stay green.

**S15a. Debian Release model** (`coder`, ~400 lines)
- Files: `src/mirror/debian.rs`, `src/verify/mod.rs` (`XZ_MEM_KIB` and `XZ_RATIO` become `pub(crate)`), `src/resolve/mod.rs` (`unhex::<N>`).
- `parse_release`:
  - matches `Codename` first and falls back to `Suite` only when no `Codename` is present;
  - `Date` must be strictly newer than the live InRelease's (Rs);
  - `Valid-Until` must be in the future.
- `pick` (one variant per index group).
- `pool_files`: the same path with two hashes fails; the character set is `[A-Za-z0-9._+~/-]`.
- Unit tests for each.

**S15b. Debian anchor and walk** (`coder`, ~500 lines)
- Files: `Cargo.toml` (dev lzma encoder), `src/mirror/{debian,mod}.rs`, `src/mirror/testrepo.rs`.
- Meta entries use `from = by-hash/SHA256/<hex>` when `Acquire-By-Hash` is set.
- The walk creates the by-hash links as declared derived links. A failed `link_or_copy` fails the walk (R16).
- Tests:
  - first sync with by-hash links;
  - unchanged makes only InRelease GETs;
  - a tampered `Packages.xz` means no pool GET;
  - a non-pinned signer is refused;
  - an equal Date with different bytes is refused;
  - an older Date is refused;
  - a dropped package is pruned while a package shared with the other suite is kept;
  - `pool/../../x` is refused.

**S16. Two-level listing** (`coder`, ~450 lines)
- Files: `src/resolve/listing.rs`, `src/public/mod.rs`.
- Split the resolver into `hrefs`, `pick` and `two_level`.
- URL containment (R17):
  - every joined directory URL stays under `s.url`;
  - every item URL stays under its directory URL;
  - absolute and `//host` hrefs are refused unless they resolve under the prefix;
  - `{dir}` is replaced through `regex::escape`.
- Resolved items are cached per job id in `Public` next to `staged`, so re-plans after a pause, yield or retry don't repeat the ~335 GETs (C17).
- Tests:
  - `two_level_series`;
  - `two_level_every_dir`;
  - `two_level_version_from_dir`;
  - `two_level_refuses_escape` (`..%2F/`, `https://other/x/`, `//other/x/`);
  - `resolve_cached_across_replans`;
  - the existing tests pass untouched.

**S17. Catalog migrations** (`chore`, then `coder` for the tests; ~350 lines)
- Files: `catalog.toml`, `keys/fetch.sh:37`, `src/catalog.rs` tests.
- Changes:
  - debian-cd-key gets the debian.org URL.
  - Enabled: unicode, rfcs (https from ietf.org, txt and xml), gcc and gnu-latest (two-level), musl (the `/releases/` fix), and geofabrik-na (the pattern fix).
  - python stays disabled.
  - repo-fedora:
    - `format`, `trees` and the https base `https://mirrors.kernel.org/fedora/` (F16);
    - enabled;
    - the `use` text says repodata is unsigned.
  - repo-alpine (https base `https://dl-cdn.alpinelinux.org/alpine/`) and repo-debian (https base `https://deb.debian.org/debian/`, pending question 4): disabled, with the todo "pin keys by hand (H3/H4)". Debian's `use` text names `check-valid-until=no` for security.
  - Add the stage0-posix and builder-hex0 git sources with the catalog design's TOML, and drop live-bootstrap's todo.
- Out of scope: stable-diffusion-cpp submodules (question 7) and alpine-distfiles (`:1193`; aports is mirrored, but the distfiles walker is not phase-3 work).
- Tests:
  - `catalog_patterns_match_real_names`;
  - `embedded_catalog_loads`: no `rsync` and no `::`; the `est` asserts are updated; the Debian signer coverage passes.

**S18. Gate fixtures** (`test-writer`, ~700 lines)
- Files: `src/mirror/gate_tests.rs`.
- For each of Fedora, Alpine and Debian, through `Public` and the Worker:
  - a tampered payload leaves the live tree byte-identical;
  - pause after N files: only the rest is fetched;
  - a crash after the journal is written is recovered;
  - unchanged fetches nothing;
  - cancel keeps the live tree;
  - a planted `meta/` file and `want.tsv` are rejected;
  - a stale wrong-size file plus a failed fetch leaves no done line.
- Git:
  - an unchecked, corrupt planted pack is refused;
  - the S6 parity gate.
- Then `security-auditor` reviews:
  - `git/{http,mirror}.rs` and the token path;
  - `generation.rs` (paths, prune, journal);
  - `alpine.rs`;
  - `pgp::release`;
  - `Expect::Apk`;
  - `fedora.rs` (`get_direct`).
- `reviewer` gets the diff.

**S19. Docs** (`writer`)
- `CLAUDE.md`, new phase 3 notes:
  - `Work`, `Planned` and `ok`; `Run` is never yielded;
  - `Mirror` jobs and the `<set>/<source>` status entries;
  - the `.preserver/` layout;
  - the gix `Http` rules;
  - testcgi is unix-only and uses TLS;
  - `pgp::release`;
  - key pinning;
  - "todo ⇒ disabled" is enforced.
- `CLAUDE.md`, edits: remove the Phase 1a credential-helper text and the Phase 2 `proxy.rs` text.
- `docs/design.md`:
  - §1: the gix features without `parallel`, flate2 zlib-rs, sha1-checked, base64ct;
  - §3.3:
    - `done.tsv` per tree, recorded only for verified fetches;
    - meta re-hashed each run;
    - batched planning;
    - no git child throttling (the proxy is gone);
  - §3.4:
    - a journal on every OS, with exchange where the filesystem supports it;
    - the Fedora primary must be `.zst`;
    - the revision and timestamp rollback rule;
    - rfcs from ietf.org;
  - §3.5: the Phase 1/Phase 3 fetch row (gix, ControlMaster=no, `ssh -O check`, Windows ssh.exe);
  - §6: the risks below.

## (d) Things the user does by hand

- **H1. Real FIDO key.** After S6, run `personal --foreground` over ssh, then over https. Also run it once after the ControlMaster has expired: it should re-prompt for a touch. Expect 0 bundles when nothing changed and 1 after a push.
- **H2. Real dry runs.** After S17, run `public --dry-run` for the repo sets, gnu-latest, gcc, rfcs, unicode and musl.
  - Also all enabled git sources, for the redirect and smart-http probe.
  - Note Alpine's signature type, and any GNU package that needs an `exclude`.
- **H3. Alpine keys.** Fetch them from aports at a pinned commit, cross-check against `alpine:3.24` `/usr/share/apk/keys`, and write `keys/alpine/SHA256SUMS`. Then `chore` adds the entries and enables repo-alpine.
- **H4. Debian keyring.** Run `keys/fetch.sh debian-archive`, cross-check against `debian:trixie` and ftp-master, and fill in `signers`. Then `chore` enables repo-debian.
- **H5. Install from the mirror (C18).** Without a full fill this can't be done from the compiled-in catalog, so there are two options:
  - Default: a scratch build whose `catalog.toml` is cut down to Debian `trixie-updates` main amd64, Alpine `main/x86_64` and Fedora `updates` source only. Then run the dnf, apt and apk commands from the earlier draft in podman. No runtime override knob is added.
  - Otherwise the gate closes only after H6.
- **H6. First full runs** of about 310, 250 and 133 GB.
- **H7. linux-git measurement.** On a non-FAT drive, a scratch build with linux-git enabled. Record the check's wall time and peak RSS. Then decide whether to enable it, or whether `parallel` needs vetting.

## (e) Open risks

1. **gix details are settled only by the fixtures.** HEAD advertisement, and a ref transaction with a `None` committer. Fallbacks: list all refs; a fixed signature.
2. **Fedora's trust rests on TLS to one host**, because repodata is unsigned. A mirrors.kernel.org that lags past the alternates fails that run. There is no mirror-list fallback.
3. **Plan steps can't be interrupted.** Each run re-hashes meta (Fedora about 300 MB per tree, Debian about 100 MB) and re-walks before the first batch. Pause responsiveness is about a minute on USB HDDs.
4. **`PER_HOST = 2`** makes first fills latency-bound: days.
5. **Upstream moves during a fill** cause 404s and failed runs. The next run re-anchors and keeps what landed.
6. **No exchange on exFAT, vfat and Windows**: a short 404 window. Windows `sync_fs` is a stub. Windows prune is path-based, so the symlink race (R16) is mitigated only on Linux.
7. **By-hash entries vanish at the swap.** Security's `Valid-Until` lapses about a week after the last sync.
8. **Git has no repack, and packs accumulate.** A pack that fails the check is kept and fails every run until someone deletes it and its `.idx`, as the error says; the next run drops the staged refs that named its objects and fetches them again. `Run` jobs are never yielded, so a long git fetch delays higher-priority sets until it finishes.
9. **No redirects:** a renamed upstream fails until the catalog changes. The dry-run probe catches it first.
10. **Copy lane and kit** don't carry mirror trees until phase 4.
11. **GNU publishes all or nothing.** RFCs are TOFU. A full gnu-latest resolve costs about 2 minutes per new job (cached per job).
12. **Format drift and key rotation fail closed** and need a code change or a hand pin.
13. **`pgp::release` departs from gpgv on purpose.** The audit must confirm that.
14. **linux-git's closure check** costs minutes to hours and its memory is unknown until H7. It stays disabled until then.
15. **`preserver-checked` and `live.tsv` on the drive are forgeable** by anyone with write access to the drive. They carry the same trust as the data, and the docs say so.

**Questions for the user**
1. "todo ⇒ disabled" is enforced, and linux-git is disabled until H7. Keep that, or relax the CLAUDE.md rule?
2. Is `public/<set>/<source>/` acceptable as the dnf, apt and apk path?
3. Debian:
   - suites: `trixie` + `trixie-updates` only, or also backports?
   - translations: only `en`, or all?
   - host: `deb.debian.org` or mirrors.kernel.org?
4. Per-host stream count: configurable now, or keep 2?
5. Git: delete a pack that fails the check and refetch, or keep it (the default)?
6. rfcs: txt and xml only? python: keep disabled, or pin a 3.13 key? gcc: the newest release of each of 2 series? geofabrik: monthly?
7. Which stable-diffusion.cpp submodules?
8. On cancel, keep landed payload until the next commit (the default)?
9. H5: a cut-down scratch catalog (the default), or wait for H6?

**Size.** About 4,900 lines of non-test code and 4,300 of tests in 21 steps. That is net of about −850 deleted (`proxy.rs`, the credential helper, `git::Auth`, `Repo.branch`).

## Critique disposition

**Completeness (C)**

| Item | Fix | Where |
|---|---|---|
| C1 | real stop flag, `ControlMaster=no`/`BatchMode`, `-O check` + master restart, timeout test | S6 |
| C2 | Windows `ssh.exe` branch | S6 |
| C3 | `#![cfg(unix)]` testcgi; cross clippy gates | S3, S4a |
| C4 | `Run` never outranked | D2, S1 |
| C5 | vfat refusal before fetch | S5 |
| C6 | `Meta.from` | S7 |
| C7 | `Ctx.metalink` and `Ctx.rsa` | S7 |
| C8 | key-coverage validation and FINGERPRINTS test | S12 |
| C9 | revision rule when nothing matches | D7, S11 |
| C10 | D7 kept; split is catalog-only; question dropped | D7 |
| C11 | `Trust::Host` marks existing packs; parity on a loose-ref mirror | S4b, S6 |
| C12 | bounded cache, phase label, H7, risk 14; prefix-only check rejected because R6 needs full verification | D15 |
| C13 | info/refs probe | S5, H2 |
| C14 | bootstrap sources added; linux-git note; alpine-distfiles out of scope | S17 |
| C15 | reserved names | S2 |
| C16 | orphan cancel, stale rows dropped, old trees left | S2 |
| C17 | per-job resolve cache, risk 11 | S16 |
| C18 | cut-down scratch catalog, no knob | H5 |
| C19 | `walk_meta` subset | D3, S9 |
| C20 | stale docs listed | S19 |
| C21 | mirror rows in `list_text` | S9 |
| C22 | `record_mirror` and `room` in S2; two parallel tracks; S4 and S15 split | S2, S4a/b, S15a/b |
| C23 | `Expect::Apk` resume rule and test | D4, S13 |

**Correctness and security (R)**

| Item | Fix | Where |
|---|---|---|
| R1 | `ok` indices; non-have dests deleted | D2, D5, S8 |
| R2 | meta re-hashed each run, always re-walk, caps from anchor sizes | S8 |
| R3 | commit re-hash, extras refused, journal hashes | D11, S7, S8 |
| R4 | one validator, streaming with caps | S7 |
| R5 | anchor validation in `begin` | S8 |
| R6 | full pack verify and union connectivity | D15, S4b |
| R7 | lock sweep, atomic config write | S4a |
| R8 | HEAD target validated | S4a |
| R9 | config rewrite for personal mirrors; ssh URL built from owner/name | S4a, S6 |
| R10 | token rules, exact-host `token_for` | S3, S4a |
| R11 | `get_direct`; test-only override | D7, S3 |
| R12 | revision and timestamp rule | D7 |
| R13 | explicit prefix, `new_unprefixed` forbidden, key and signature length checks | S12 |
| R14 | tar caps; one verification point | D4, S12 |
| R15 | Windows names in `fs_limits` | S7 |
| R16 | fd-based prune; `link_or_copy` result checked | D11, S7, S15b |
| R17 | prefix containment | S16 |
| R18 | escaped url, catalog-checked link, reserved names | D10, S2 |
| Rs | issuer/subkey handling, Codename-first, strict Date, three extra gate tests | D8, S14, S15a, S18 |

**Feasibility (F)**

| Item | Fix | Where |
|---|---|---|
| F1 | `room` in S2; per-source `est`; Set budget excludes in-place sources | S2 |
| F2 | same fix as C1 | S6 |
| F3 | delta-order traverse with cache, H7, `parallel` deferred | D15 |
| F4 | Exn API; plain 401/403; headers-pipe test dropped | S3 |
| F5 | TLS testcgi; never `insecure-credentials` | S4a |
| F6 | same fix as C7 | S7 |
| F7 | same fix as C6 | S7 |
| F8 | visibility changes listed in each step | S7, S12, S15a |
| F9 | empty-batch guard; literals named | S1 |
| F10 | joined threads, stop flag, reader-side counting | S3 |
| F11 | wildcard arms reviewed | D1, S2 |
| F12 | `<set>/<source>` entries; readers already count by state | D14 |
| F13 | todo ⇒ disabled enforced; question 1 | D9, S2 |
| F14 | removal list | S6 |
| F15 | `proxy.rs` deleted | S6 |
| F16 | https bases named; validation | S2, S17 |
## Answers (2026-11-18)

- Crates: approved as listed in (b).
- Debian: `trixie`, `trixie-updates` and security, `en` translations only, from `deb.debian.org`. No backports.
- "todo ⇒ disabled" stays enforced; linux-git stays disabled until H7.
- Per-host streams: fixed at 2.
- Everything else takes the plan's default: keep a pack that fails the check, keep landed payload on cancel until the next commit, rfcs txt and xml only, python disabled, gcc the newest release of 2 series, geofabrik monthly, stable-diffusion.cpp submodules out of scope, H5 through a cut-down scratch catalog.
