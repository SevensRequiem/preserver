#!/usr/bin/env bash
# Installs preserver and its systemd user units. See CLAUDE.md, "Install and release".
set -euo pipefail

src=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
bindir=$HOME/.local/bin
unitdir=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user
bin=$bindir/preserver
prev=$bindir/preserver.prev
units=(preserver-tray.service preserver-personal.service preserver-local.service preserver-local.timer preserver-public.service preserver-public.timer)

die() { echo "install.sh: $*" >&2; exit 1; }
say() { echo "install.sh: $*"; }
have_systemd() { command -v systemctl >/dev/null 2>&1; }
ctl() { systemctl --user "$@"; }

usage() {
	cat <<'USAGE'
usage: install.sh [RELEASE_DIR]   install from a downloaded release (preserver-<target> + SHA256SUMS), or build this checkout
       install.sh --rollback      swap back to the previous binary
       install.sh --uninstall     remove the binary and the units (data and keys stay)
USAGE
}

[ "$(id -u)" -ne 0 ] || die "run as your own user, not root"

mkdir -p "$bindir"
work=$(mktemp -d "$bindir/.preserver.XXXXXX")
trap 'rm -rf "$work"' EXIT

uninstall() {
	if have_systemd; then
		ctl disable --now preserver-tray.service preserver-local.timer preserver-public.timer 2>/dev/null || true
		ctl stop preserver-personal.service preserver-local.service preserver-public.service 2>/dev/null || true
	fi
	for u in "${units[@]}"; do rm -f "$unitdir/$u"; done
	rm -f "$bin" "$prev"
	have_systemd && { ctl daemon-reload || true; }
	say "removed binary, previous binary and units; config, keys, state and backups are untouched"
}

rollback() {
	[ -f "$prev" ] || die "no previous binary at $prev"
	local d=$work
	# Hard links keep $bin present throughout: each rename is atomic.
	ln "$prev" "$d/new"
	if [ -f "$bin" ]; then
		ln "$bin" "$d/old"
	fi
	mv -f "$d/new" "$bin"
	if [ -f "$d/old" ]; then
		mv -f "$d/old" "$prev"
	else
		rm -f "$prev"
	fi
	say "rolled back: $bin is the previous binary, $prev is the one replaced"
	restart_tray
}

restart_tray() {
	have_systemd || return 0
	ctl try-restart preserver-tray.service || say "warning: could not restart the tray"
}

host_target() {
	local arch
	arch=$(uname -m)
	case $arch in
	x86_64 | aarch64) echo "$arch-unknown-linux-musl" ;;
	arm64) echo "aarch64-unknown-linux-musl" ;;
	*) die "no release binary for architecture $arch" ;;
	esac
}

install_binary() {
	local new=$1 d=$work
	install -m 0755 "$new" "$d/preserver"
	if [ -f "$bin" ] && cmp -s "$d/preserver" "$bin"; then
		say "$bin is already this binary"
		return 0
	fi
	if [ -f "$bin" ]; then
		cp -p "$bin" "$d/prev"
		mv -f "$d/prev" "$prev"
		say "kept the previous binary as $prev"
	fi
	mv -f "$d/preserver" "$bin"
	say "installed $bin"
}

install_units() {
	local u
	[ -d "$src/dist/systemd" ] || die "no dist/systemd next to this script"
	mkdir -p "$unitdir"
	for u in "${units[@]}"; do
		install -m 0644 "$src/dist/systemd/$u" "$unitdir/.$u.new"
		mv -f "$unitdir/.$u.new" "$unitdir/$u"
	done
	say "installed ${#units[@]} units into $unitdir"
}

enable_units() {
	have_systemd || { say "warning: no systemctl, units are installed but not enabled"; return 0; }
	ctl daemon-reload
	ctl enable preserver-tray.service preserver-local.timer
	ctl start preserver-local.timer
	ctl try-restart preserver-tray.service || true
	ctl start preserver-tray.service || say "warning: tray not started (no graphical session?); it starts with the next one"
	say "enabled preserver-tray.service and preserver-local.timer (nightly 01:30)"
	say "preserver-public.timer is installed but not enabled: systemctl --user enable --now preserver-public.timer"
}

case ${1-} in
-h | --help) usage; exit 0 ;;
--rollback) [ $# -eq 1 ] || die "--rollback takes no argument"; rollback; exit 0 ;;
--uninstall) [ $# -eq 1 ] || die "--uninstall takes no argument"; uninstall; exit 0 ;;
-*) usage >&2; exit 2 ;;
esac
[ $# -le 1 ] || { usage >&2; exit 2; }

if [ $# -eq 1 ]; then
	rel=$1
	t=$(host_target)
	name=preserver-$t
	[ -f "$rel/$name" ] || die "$rel/$name not found"
	[ -f "$rel/SHA256SUMS" ] || die "$rel/SHA256SUMS not found"
	command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found"
	line=$(grep -E "^[0-9a-fA-F]{64} [ *]${name}\$" "$rel/SHA256SUMS" || true)
	[ "$(printf '%s\n' "$line" | grep -c .)" -eq 1 ] || die "SHA256SUMS needs exactly one entry for $name"
	# Hash the staged copy, not the download, so what is checked is what gets installed.
	check=$work
	install -m 0755 "$rel/$name" "$check/$name"
	(cd "$check" && printf '%s\n' "$line" | sha256sum -c --status -) || die "checksum mismatch for $name, nothing installed"
	say "checksum ok for $name"
	new=$check/$name
else
	[ -f "$src/Cargo.toml" ] || die "no Cargo.toml next to this script: pass a release directory"
	command -v cargo >/dev/null 2>&1 || die "cargo not found"
	(cd "$src" && cargo build --release --locked)
	new=${CARGO_TARGET_DIR:-$src/target}/release/preserver
	[ -f "$new" ] || die "build did not produce $new"
fi

install_binary "$new"
install_units
enable_units
