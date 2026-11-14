#!/usr/bin/env bash
# Installs preserver, preserver-gui and the systemd user units. See CLAUDE.md, "Install and release".
set -euo pipefail

src=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
bindir=$HOME/.local/bin
unitdir=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user
desktop=${XDG_DATA_HOME:-$HOME/.local/share}/applications/preserver.desktop
bin=$bindir/preserver
prev=$bindir/preserver.prev
gui=$bindir/preserver-gui
gprev=$bindir/preserver-gui.prev
units=(preserver-tray.service preserver-daemon.service)
# Jobs the daemon now runs from config.toml [schedule]; removed on install and uninstall.
retired=(preserver-personal.service preserver-local.service preserver-local.timer preserver-public.service preserver-public.timer)

die() { echo "install.sh: $*" >&2; exit 1; }
say() { echo "install.sh: $*"; }
have_systemd() { command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; }
ctl() { systemctl --user "$@"; }

usage() {
	cat <<'USAGE'
usage: install.sh [RELEASE_DIR]   install from a downloaded release (preserver-<target> + SHA256SUMS), or build this checkout
       install.sh --rollback      swap back to the previous binaries
       install.sh --uninstall     remove the binaries, the desktop file and the units (data and keys stay)
USAGE
}

[ "$(id -u)" -ne 0 ] || die "run as your own user, not root"
# The desktop file's Exec quotes this path, and these characters would need escaping inside it.
case $bindir in
*[\"\`\$\\%]* | *$'\n'*) die "unsupported character in $bindir" ;;
esac

mkdir -p "$bindir"
work=$(mktemp -d "$bindir/.preserver.XXXXXX")
trap 'rm -rf "$work"' EXIT

uninstall() {
	if have_systemd; then
		ctl disable --now preserver-tray.service preserver-daemon.service 2>/dev/null || true
		stop_retired
	fi
	for u in "${units[@]}" "${retired[@]}"; do rm -f "$unitdir/$u"; done
	rm -f "$bin" "$prev" "$gui" "$gprev" "$desktop"
	have_systemd && { ctl daemon-reload || true; }
	say "removed the binaries, their previous versions, the desktop file and the units; config, keys, state and backups are untouched"
}

# swap CURRENT PREVIOUS: hard links keep CURRENT present throughout, each rename is atomic.
swap() {
	local cur=$1 old=$2 d=$work
	rm -f "$d/new" "$d/old"
	ln "$old" "$d/new"
	if [ -f "$cur" ]; then
		ln "$cur" "$d/old"
	fi
	mv -f "$d/new" "$cur"
	if [ -f "$d/old" ]; then
		mv -f "$d/old" "$old"
	else
		rm -f "$old"
	fi
	say "rolled back: $cur is the previous binary, $old is the one replaced"
}

rollback() {
	[ -f "$prev" ] || [ -f "$gprev" ] || die "no previous binary at $prev or $gprev"
	if [ -f "$prev" ]; then swap "$bin" "$prev"; fi
	if [ -f "$gprev" ]; then swap "$gui" "$gprev"; fi
	restart_services
}

restart_services() {
	have_systemd || return 0
	ctl try-restart preserver-tray.service preserver-daemon.service || say "warning: could not restart the tray and the daemon"
}

host_arch() {
	local arch
	arch=$(uname -m)
	case $arch in
	x86_64 | aarch64) echo "$arch" ;;
	arm64) echo aarch64 ;;
	*) die "no release binary for architecture $arch" ;;
	esac
}

# verify RELEASE_DIR NAME: stages NAME into $work and checks it against SHA256SUMS.
verify() {
	local rel=$1 name=$2 line
	line=$(grep -E "^[0-9a-fA-F]{64} [ *]${name}\$" "$rel/SHA256SUMS" || true)
	[ "$(printf '%s\n' "$line" | grep -c .)" -eq 1 ] || die "SHA256SUMS needs exactly one entry for $name, nothing installed"
	# Hash the staged copy, not the download, so what is checked is what gets installed.
	install -m 0755 "$rel/$name" "$work/$name"
	(cd "$work" && printf '%s\n' "$line" | sha256sum -c --status -) || die "checksum mismatch for $name, nothing installed"
	say "checksum ok for $name"
}

# install_binary NEW NAME: NEW becomes $bindir/NAME, the one it replaces $bindir/NAME.prev.
# Sets changed=1 when it replaced anything.
install_binary() {
	local new=$1 dst=$bindir/$2 d=$work
	changed=0
	install -m 0755 "$new" "$d/$2.new"
	if [ -f "$dst" ] && cmp -s "$d/$2.new" "$dst"; then
		say "$dst is already this binary"
		return 0
	fi
	changed=1
	if [ -f "$dst" ]; then
		cp -p "$dst" "$d/$2.prev"
		mv -f "$d/$2.prev" "$dst.prev"
		say "kept the previous binary as $dst.prev"
	else
		rm -f "$dst.prev"
	fi
	mv -f "$d/$2.new" "$dst"
	say "installed $dst"
}

install_desktop() {
	local line
	mkdir -p "$(dirname "$desktop")"
	while IFS= read -r line; do
		case $line in Exec=*) line="Exec=\"$gui\"" ;; esac
		printf '%s\n' "$line"
	done <"$src/dist/applications/preserver.desktop" >"$desktop.new"
	chmod 0644 "$desktop.new"
	mv -f "$desktop.new" "$desktop"
	say "installed $desktop"
}

install_units() {
	local u
	mkdir -p "$unitdir"
	for u in "${units[@]}"; do
		install -m 0644 "$src/dist/systemd/$u" "$unitdir/.$u.new"
		mv -f "$unitdir/.$u.new" "$unitdir/$u"
	done
	say "installed ${#units[@]} units into $unitdir"
}

# One unit per call: systemctl stops at a unit that no longer exists, before --now stops anything.
stop_retired() {
	local u
	for u in preserver-local.timer preserver-public.timer; do ctl disable --now "$u" 2>/dev/null || true; done
	for u in preserver-personal.service preserver-local.service preserver-public.service; do ctl stop "$u" 2>/dev/null || true; done
}

retire_units() {
	local u found=0
	for u in "${retired[@]}"; do
		if [ -e "$unitdir/$u" ]; then found=1; fi
	done
	[ "$found" -eq 1 ] || return 0
	if have_systemd; then
		if ctl is-enabled --quiet preserver-local.timer 2>/dev/null; then
			say 'nightly local backups now come from config.toml: add local = "01:30" under [schedule]'
		fi
		stop_retired
	fi
	for u in "${retired[@]}"; do rm -f "$unitdir/$u"; done
	say "removed the retired personal, local and public units; the daemon runs those jobs now"
}

enable_units() {
	have_systemd || { say "warning: no systemd user session, units are installed but not enabled; from a login session run: systemctl --user daemon-reload && systemctl --user enable --now preserver-tray.service preserver-daemon.service"; return 0; }
	ctl daemon-reload
	ctl enable preserver-tray.service preserver-daemon.service
	# The daemon asks for the security key through the session's askpass dialog; the tray
	# imports these at each login, this covers the daemon started below.
	local v vars=()
	for v in DISPLAY WAYLAND_DISPLAY XAUTHORITY; do
		if [ -n "${!v-}" ]; then vars+=("$v"); fi
	done
	if [ ${#vars[@]} -gt 0 ]; then ctl import-environment "${vars[@]}" || true; fi
	# A new binary only takes over once the long-running services restart.
	ctl try-restart preserver-tray.service preserver-daemon.service || true
	ctl start preserver-daemon.service || say "warning: daemon not started; see journalctl --user -u preserver-daemon.service"
	ctl start preserver-tray.service || say "warning: tray not started (no graphical session?); it starts with the next one"
	say "enabled preserver-tray.service and preserver-daemon.service; backups run on the times under [schedule] in config.toml"
}

case ${1-} in
-h | --help) usage; exit 0 ;;
--rollback) [ $# -eq 1 ] || die "--rollback takes no argument"; rollback; exit 0 ;;
--uninstall) [ $# -eq 1 ] || die "--uninstall takes no argument"; uninstall; exit 0 ;;
-*) usage >&2; exit 2 ;;
esac
[ $# -le 1 ] || { usage >&2; exit 2; }

newgui=
if [ $# -eq 1 ]; then
	rel=$1
	arch=$(host_arch)
	name=preserver-$arch-unknown-linux-musl
	gname=preserver-gui-$arch-unknown-linux-gnu
	[ -f "$rel/$name" ] || die "$rel/$name not found"
	[ -f "$rel/SHA256SUMS" ] || die "$rel/SHA256SUMS not found"
	command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found"
	verify "$rel" "$name"
	new=$work/$name
	if [ ! -f "$rel/$gname" ]; then
		if [ -f "$gui" ]; then say "this release has no $gname: left $gui as it is"; fi
	elif ! getconf GNU_LIBC_VERSION >/dev/null 2>&1; then
		say "skipped $gname: it needs glibc and this system has none"
	else
		verify "$rel" "$gname"
		newgui=$work/$gname
	fi
else
	[ -f "$src/Cargo.toml" ] || die "no Cargo.toml next to this script: pass a release directory"
	command -v cargo >/dev/null 2>&1 || die "cargo not found"
	(cd "$src" && cargo build --release --locked --features gui)
	new=${CARGO_TARGET_DIR:-$src/target}/release/preserver
	newgui=${CARGO_TARGET_DIR:-$src/target}/release/preserver-gui
	[ -f "$new" ] || die "build did not produce $new"
	[ -f "$newgui" ] || die "build did not produce $newgui"
fi

[ -d "$src/dist/systemd" ] || die "no dist/systemd next to this script, nothing installed"
for u in "${units[@]}"; do
	[ -f "$src/dist/systemd/$u" ] || die "dist/systemd/$u not found, nothing installed"
done
[ -z "$newgui" ] || [ -f "$src/dist/applications/preserver.desktop" ] || die "dist/applications/preserver.desktop not found, nothing installed"
install_binary "$new" preserver
bin_changed=$changed gui_changed=0
if [ -n "$newgui" ]; then
	install_binary "$newgui" preserver-gui
	gui_changed=$changed
	install_desktop
fi
# --rollback undoes the last install, so a .prev it did not write (an older install's) goes.
if [ "$bin_changed" -ne "$gui_changed" ]; then
	if [ "$bin_changed" -eq 1 ]; then rm -f "$gprev"; else rm -f "$prev"; fi
fi
retire_units
install_units
enable_units
