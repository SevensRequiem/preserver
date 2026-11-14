<p align="center"><img src="docs/banner.svg" alt="preserver" width="100%"></p>

preserver backs up to drives you own. It keeps encrypted backups of your GitHub repositories and local folders, and an offline archive of public material: kernel and toolchain sources, specs, distro ISOs, Kiwix wikis, maps and local AI models. A background daemon runs the work as a job queue, and you control it from the CLI, a tray icon or a small GUI.

- **Write without a password, read with one.** Backups are encrypted with [age](https://age-encryption.org) to a public key kept in your home directory. Restoring needs the passphrase-locked identity.
- **Every download is checked.** Public files are verified against upstream PGP signatures, minisign or published checksums, with signing keys pinned and embedded in the binary. A source with none of those is trusted on first use and flagged if its bytes ever change.
- **Copies fit the target.** `copy` fills another drive or directory by priority, choosing the largest variant of each set that fits. It handles FAT32 and exFAT limits.

Runs on Linux. Windows support is in progress.

## Install

Requires Rust 1.95+.

```
git clone https://github.com/SevensRequiem/preserver && cd preserver
./install.sh
```

This builds the checkout and installs `preserver` and `preserver-gui` to `~/.local/bin`. It also installs and starts the systemd user units for the tray and the daemon. To install a downloaded release instead, run `./install.sh DIR`, where `DIR` holds the binaries and `SHA256SUMS`. `./install.sh --rollback` switches back to the previous binaries, and `--uninstall` removes everything except your config and backups.

## Setup

1. Copy `docs/config.example.toml` to `~/.config/preserver/config.toml`. Set `owners` (GitHub users or orgs) and `primary_uuid` (the backup drive's filesystem id; `preserver drives` lists them).
2. Run `preserver init` in a terminal. It creates the key and asks for the restore password. To keep an existing key, run `preserver init --import identity.age` instead.

## Use

```
preserver personal                  # back up GitHub repos and local folders
preserver public --list             # catalog sets, sizes, what the drive holds
preserver public kernel specs       # mirror some sets (no args: every set)
preserver copy /mnt/usb --size 32G  # copy what fits onto another drive
preserver copy usb-label -t 24:00:00  # keep doing it daily whenever it's plugged in
preserver queue list                # jobs and their progress
preserver queue retry ID
preserver restore FILE.bundle.age DIR
preserver-gui                       # settings, progress, the same actions as the tray
```

`personal`, `public` and `copy` add a job to the daemon's queue and return. Add `--foreground` to run the job in the terminal instead. To have the daemon run jobs on a timer, add a `[schedule]` table to the config:

```toml
[schedule]
personal = "24:00:00"   # interval since the last run
local = "01:30"         # daily at a local time
public = "03:00"
```

## Layout

```
<drive>/preserver/
  github-repos-personal/<owner>/<repo>/DATE.bundle.age
  local-personal/<name>/YYYY-MM/{L0,Dnn}.tar.zst.age
  public/<set>/<version>/   SET.toml, SHA256SUMS
  INDEX.html
```

Only the personal folders are encrypted. Everything under `public/` is plain files with checksums, readable without preserver.

`catalog.toml` lists the public sets and their sources. `docs/design.md` has the design.

## License

MIT or Apache-2.0.
