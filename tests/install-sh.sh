#!/usr/bin/env bash
# Runs install.sh against a scratch HOME with a fake systemctl and cargo on PATH.
# shellcheck disable=SC2015,SC2016 # fail() exits, so A && B || fail is a plain check; the fake systemctl body must stay unexpanded
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
export HOME=$t/home
unset XDG_CONFIG_HOME DISPLAY WAYLAND_DISPLAY XAUTHORITY
mkdir -p "$HOME" "$t/fakebin"
export CALLS=$t/calls
: >"$CALLS"
printf '#!/bin/sh\necho "systemctl $*" >>"$CALLS"\n' >"$t/fakebin/systemctl"
cat >"$t/fakebin/cargo" <<'CARGO'
#!/bin/sh
echo "cargo $*" >>"$CALLS"
mkdir -p "$CARGO_TARGET_DIR/release"
printf '#!/bin/sh\necho built\n' >"$CARGO_TARGET_DIR/release/preserver"
CARGO
chmod +x "$t/fakebin/systemctl" "$t/fakebin/cargo"
export PATH=$t/fakebin:$PATH
export CARGO_TARGET_DIR=$t/target

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }
run() { "$repo/install.sh" "$@" >"$t/out" 2>&1 || return 1; }
bin=$HOME/.local/bin/preserver
prev=$bin.prev
units=$HOME/.config/systemd/user

case $(uname -m) in
aarch64 | arm64) arch=aarch64 ;;
*) arch=x86_64 ;;
esac
name=preserver-$arch-unknown-linux-musl
mkrel() {
	mkdir -p "$1"
	printf '#!/bin/sh\necho %s\n' "$2" >"$1/$name"
	(cd "$1" && sha256sum "$name" >SHA256SUMS)
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
grep -q "disable --now preserver-local.timer preserver-public.timer" "$CALLS" || fail "retired timers not disabled"
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

mkdir -p "$HOME/.config/preserver" "$HOME/.local/state/preserver"
echo key >"$HOME/.config/preserver/identity.age"
run || fail "source-mode install: $(cat "$t/out")"
grep -q "cargo build --release --locked" "$CALLS" || fail "no cargo build"
grep -q built "$bin" || fail "source build not installed"
ok "source install"

for u in "${retired[@]}"; do : >"$units/preserver-$u"; done
run --uninstall || fail "uninstall"
grep -q "disable --now.* preserver-daemon.service" "$CALLS" || fail "uninstall did not stop the daemon"
[ ! -e "$bin" ] && [ ! -e "$prev" ] || fail "binary left behind"
ls "$units"/preserver-* >/dev/null 2>&1 && fail "units left behind"
[ -f "$HOME/.config/preserver/identity.age" ] || fail "uninstall touched data"
run --uninstall || fail "second uninstall"
ok uninstall

mkdir "$t/lone"
cp "$repo/install.sh" "$t/lone/"
"$t/lone/install.sh" "$t/r1" >"$t/out" 2>&1 && fail "install.sh without dist/systemd succeeded"
[ ! -e "$bin" ] || fail "binary installed before the units were found"
ok "missing units refused before anything is installed"
