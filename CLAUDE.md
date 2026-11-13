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
