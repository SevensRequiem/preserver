#!/usr/bin/env bash
# Fetch the trust anchors that keys/ is still missing and print each fingerprint to check
# against the catalog pins. An existing keyring is never overwritten: a different upstream key
# is reported and left alone. FINGERPRINTS is rewritten from the keyrings at the end; a new
# keyring also needs its line in src/keys.rs.
set -euo pipefail
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export GNUPGHOME="$work/gh"
mkdir -m700 "$GNUPGHOME"

put() {
    local name=$1 file=$2
    gpg --batch --dearmor <"$file" >"$work/$name.gpg" 2>/dev/null || cp "$file" "$work/$name.gpg"
    local fprs
    fprs=$(gpg --batch --show-keys --with-colons "$work/$name.gpg" | awk -F: '/^pub/{p=1} /^fpr/&&p{print $10; p=0}' | sort)
    if [[ -e $here/$name.gpg ]]; then
        local have
        have=$(gpg --batch --show-keys --with-colons "$here/$name.gpg" | awk -F: '/^pub/{p=1} /^fpr/&&p{print $10; p=0}' | sort)
        [[ $have == "$fprs" ]] && echo "$name: unchanged" || echo "$name: UPSTREAM KEY CHANGED, stored key kept" >&2
        return
    fi
    install -m644 "$work/$name.gpg" "$here/$name.gpg"
    echo "$name:"; sed 's/^/  /' <<<"$fprs"
}

get() { curl -fsS --max-time 60 --proto '=https' -o "$work/$2" "$1" && put "$3" "$work/$2"; }

get https://ftp.gnu.org/gnu/gnu-keyring.gpg gnu gnu-keyring
get https://fedoraproject.org/fedora.gpg fedora fedora
get https://alpinelinux.org/keys/ncopa.asc ncopa alpine-ncopa
get https://releases.llvm.org/release-keys.asc llvm llvm
get https://musl.libc.org/musl.pub musl musl
get https://www.debian.org/CD/key-DF9B9C49EAA9298432589D76DA87E80D6294BE9B.asc debcd debian-cd

gpg --batch --auto-key-locate clear,wkd,nodefault --locate-keys torvalds@kernel.org gregkh@kernel.org alx@kernel.org jwboyer@kernel.org >/dev/null 2>&1
gpg --batch --export >"$work/kernel.raw"
put kernel "$work/kernel.raw"

for f in "$here"/*.gpg; do
    gpg --batch --show-keys --with-colons "$f" 2>/dev/null |
        awk -F: -v n="$(basename "$f")" '/^pub/{p=1} /^fpr/&&p{print n, $10; p=0}'
done | LC_ALL=C sort >"$here/FINGERPRINTS"
