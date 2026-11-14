#!/usr/bin/env bash
# Runs install.sh against a scratch HOME with a fake systemctl and cargo on PATH.
# shellcheck disable=SC2015,SC2016 # fail() exits, so A && B || fail is a plain check; the fake systemctl body must stay unexpanded
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
export HOME=$t/home
unset XDG_CONFIG_HOME XDG_DATA_HOME FAKE_MUSL DISPLAY WAYLAND_DISPLAY XAUTHORITY
mkdir -p "$HOME" "$t/fakebin"
export CALLS=$t/calls
: >"$CALLS"
export UNITS=$HOME/.config/systemd/user
cat >"$t/fakebin/systemctl" <<'SYSTEMCTL'
#!/bin/sh
echo "systemctl $*" >>"$CALLS"
# Like systemd 262: disable fails on a unit file that does not exist, before --now stops anything.
[ "$2" = disable ] || exit 0
for u; do case $u in *.service | *.timer) [ -e "$UNITS/$u" ] || exit 1 ;; esac; done
SYSTEMCTL
cat >"$t/fakebin/cargo" <<'CARGO'
#!/bin/sh
echo "cargo $*" >>"$CALLS"
mkdir -p "$CARGO_TARGET_DIR/release"
case " $* " in *" --features gui "*) ;; *) echo "cargo: no --features gui" >&2; exit 1 ;; esac
printf '#!/bin/sh\necho built\n' >"$CARGO_TARGET_DIR/release/preserver"
printf '#!/bin/sh\necho built-gui\n' >"$CARGO_TARGET_DIR/release/preserver-gui"
CARGO
# FAKE_MUSL=1 plays a host without glibc.
printf '#!/bin/sh\n[ -z "$FAKE_MUSL" ] || exit 1\necho "glibc 2.41"\n' >"$t/fakebin/getconf"
chmod +x "$t/fakebin/systemctl" "$t/fakebin/cargo" "$t/fakebin/getconf"
export PATH=$t/fakebin:$PATH
export CARGO_TARGET_DIR=$t/target

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }
run() { "$repo/install.sh" "$@" >"$t/out" 2>&1 || return 1; }
bin=$HOME/.local/bin/preserver
prev=$bin.prev
gui=$HOME/.local/bin/preserver-gui
gprev=$gui.prev
desktop=$HOME/.local/share/applications/preserver.desktop
units=$HOME/.config/systemd/user

case $(uname -m) in
aarch64 | arm64) arch=aarch64 ;;
*) arch=x86_64 ;;
esac
name=preserver-$arch-unknown-linux-musl
gname=preserver-gui-$arch-unknown-linux-gnu
# mkrel DIR VERSION [gui]: a release dir, with the GUI when the third argument is given.
mkrel() {
	mkdir -p "$1"
	printf '#!/bin/sh\necho %s\n' "$2" >"$1/$name"
	if [ $# -eq 3 ]; then printf '#!/bin/sh\necho gui-%s\n' "$2" >"$1/$gname"; fi
	(cd "$1" && sha256sum preserver-* >SHA256SUMS)
}
mkrel "$t/r1" v1
mkrel "$t/r2" v2

run "$t/r1" || fail "install v1: $(cat "$t/out")"
grep -q v1 "$bin" || fail "binary is not v1"
[ ! -e "$prev" ] || fail "first install made a .prev"
for u in tray.service daemon.service; do
	[ -f "$units/preserver-$u" ] && [ ! -L "$units/preserver-$u" ] || fail "unit $u missing or a symlink"
done
grep -q "systemctl --user daemon-reload" "$CALLS" || fail "no daemon-reload"
grep -q "enable preserver-tray.service preserver-daemon.service" "$CALLS" || fail "tray and daemon not enabled"
grep -q "start preserver-daemon.service" "$CALLS" || fail "daemon not started"
grep -q "import-environment" "$CALLS" && fail "imported variables the session does not have"
ok install

run "$t/r1" || fail "re-install v1"
[ ! -e "$prev" ] || fail "re-install of the same binary made a .prev"
ok "re-install is idempotent"

retired=(personal.service local.service local.timer public.service public.timer)
for u in "${retired[@]}"; do : >"$units/preserver-$u"; done
: >"$CALLS"
WAYLAND_DISPLAY=wayland-test run "$t/r2" || fail "install v2"
for u in "${retired[@]}"; do
	[ ! -e "$units/preserver-$u" ] || fail "retired unit $u left behind"
done
for u in local.timer public.timer; do
	grep -qx "systemctl --user disable --now preserver-$u" "$CALLS" || fail "retired $u not disabled on its own"
done
grep -q "import-environment WAYLAND_DISPLAY$" "$CALLS" || fail "the session display was not imported"
grep -q "try-restart.* preserver-daemon.service" "$CALLS" || fail "upgrade did not restart the daemon"
grep -q v2 "$bin" && grep -q v1 "$prev" || fail "v2 install did not keep v1 as .prev"
ok "upgrade keeps previous"

: >"$CALLS"
run --rollback || fail "rollback"
grep -q "try-restart.* preserver-daemon.service" "$CALLS" || fail "rollback did not restart the daemon"
grep -q v1 "$bin" && grep -q v2 "$prev" || fail "rollback did not swap"
run --rollback || fail "second rollback"
grep -q v2 "$bin" && grep -q v1 "$prev" || fail "second rollback did not swap back"
ok rollback

mkrel "$t/r3" v3
printf '#!/bin/sh\necho tampered\n' >"$t/r3/$name"
if run "$t/r3"; then fail "tampered binary was installed"; fi
grep -q "checksum mismatch" "$t/out" || fail "no mismatch message"
grep -q v2 "$bin" && grep -q v1 "$prev" || fail "mismatch changed the installed binary"
rm "$t/r3/SHA256SUMS"
if run "$t/r3"; then fail "install without SHA256SUMS"; fi
ok "checksum mismatch refused"

mkrel "$t/r4" v4 gui
run "$t/r4" || fail "install with the GUI: $(cat "$t/out")"
grep -q v4 "$bin" && grep -q gui-v4 "$gui" || fail "release with the GUI did not install both"
[ ! -e "$gprev" ] || fail "first GUI install made a .prev"
grep -qx "Exec=\"$gui\"" "$desktop" || fail "desktop Exec is not the absolute GUI path: $(grep Exec "$desktop")"
grep -qx "StartupWMClass=preserver" "$desktop" || fail "desktop file has no StartupWMClass"
ok "release with the GUI installs both and the desktop file"

mkrel "$t/r5" v5 gui
printf '#!/bin/sh\necho tampered\n' >"$t/r5/$gname"
if run "$t/r5"; then fail "tampered GUI was installed"; fi
grep -q "checksum mismatch for $gname" "$t/out" || fail "no GUI mismatch message"
grep -q v4 "$bin" && grep -q gui-v4 "$gui" || fail "a tampered GUI changed what is installed"
ok "tampered GUI installs nothing"

mkrel "$t/r6" v6 gui
FAKE_MUSL=1 run "$t/r6" || fail "install on a musl host: $(cat "$t/out")"
grep -q v6 "$bin" && grep -q gui-v4 "$gui" || fail "musl host did not skip the GUI"
grep -q "skipped $gname" "$t/out" || fail "no skip message"
ok "musl host skips the GUI"

mkrel "$t/r7" v7 gui
run "$t/r7" || fail "install v7"
grep -q gui-v7 "$gui" && grep -q gui-v4 "$gprev" || fail "v7 did not keep the GUI as .prev"
run --rollback || fail "rollback with the GUI"
grep -q v6 "$bin" && grep -q v7 "$prev" || fail "rollback did not swap the binary"
grep -q gui-v4 "$gui" && grep -q gui-v7 "$gprev" || fail "rollback did not swap the GUI"
run --rollback || fail "rollback forward"
grep -q gui-v7 "$gui" && grep -q gui-v4 "$gprev" || fail "second rollback did not swap the GUI back"
ok "rollback swaps both"

run "$t/r1" || fail "install a release without the GUI"
grep -q v1 "$bin" && grep -q gui-v7 "$gui" || fail "a release without the GUI touched it"
grep -q "left $gui as it is" "$t/out" || fail "no message about the GUI left alone"
[ ! -e "$gprev" ] || fail "a GUI .prev the install did not write was kept"
run --rollback || fail "rollback after a release without the GUI"
grep -q v7 "$bin" && grep -q v1 "$prev" && grep -q gui-v7 "$gui" || fail "rollback touched the GUI the install left alone"
run --rollback || fail "rollback forward without the GUI"
grep -q v1 "$bin" || fail "second rollback did not swap back"
ok "release without the GUI leaves it alone"

mkdir -p "$HOME/.config/preserver" "$HOME/.local/state/preserver"
echo key >"$HOME/.config/preserver/identity.age"
run || fail "source-mode install: $(cat "$t/out")"
grep -q "cargo build --release --locked --features gui" "$CALLS" || fail "no cargo build with the GUI"
grep -q built "$bin" || fail "source build not installed"
grep -q built-gui "$gui" || fail "source GUI not installed"
grep -qx "Exec=\"$gui\"" "$desktop" || fail "source install wrote no desktop file"
ok "source install"

mkrel "$t/r9" built gui
run "$t/r9" || fail "install a new GUI only: $(cat "$t/out")"
grep -q built "$bin" && grep -q gui-built "$gui" && [ ! -e "$prev" ] || fail "a GUI-only install kept the stale preserver.prev"
run --rollback || fail "rollback of a GUI-only install"
grep -q built "$bin" && grep -q built-gui "$gui" && grep -q gui-built "$gprev" || fail "rollback of a GUI-only install"
ok "rollback swaps only what the last install replaced"

: >"$CALLS"
for u in "${retired[@]}"; do : >"$units/preserver-$u"; done
run --uninstall || fail "uninstall"
grep -qx "systemctl --user disable --now preserver-tray.service preserver-daemon.service" "$CALLS" || fail "uninstall stops the tray and daemon together with other units"
grep -q "disable --now.* preserver-daemon.service" "$CALLS" || fail "uninstall did not stop the daemon"
[ ! -e "$bin" ] && [ ! -e "$prev" ] && [ ! -e "$gui" ] && [ ! -e "$gprev" ] || fail "a binary left behind"
[ ! -e "$desktop" ] || fail "desktop file left behind"
ls "$units"/preserver-* >/dev/null 2>&1 && fail "units left behind"
[ -f "$HOME/.config/preserver/identity.age" ] || fail "uninstall touched data"
run --uninstall || fail "second uninstall"
ok uninstall

mkdir "$t/lone"
cp "$repo/install.sh" "$t/lone/"
"$t/lone/install.sh" "$t/r1" >"$t/out" 2>&1 && fail "install.sh without dist/systemd succeeded"
[ ! -e "$bin" ] || fail "binary installed before the units were found"
ok "missing units refused before anything is installed"

odd=$t/odd\$home
mkdir -p "$odd"
if HOME=$odd "$repo/install.sh" "$t/r4" >"$t/out" 2>&1; then fail "install into a bindir with \$ succeeded"; fi
grep -q "unsupported character" "$t/out" || fail "no unsupported-character message"
[ ! -e "$odd/.local/bin" ] || fail "odd bindir was created"
ok "bindir that the desktop file cannot quote refused"
