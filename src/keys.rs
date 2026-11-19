//! The trust anchors, compiled in. `keys/FINGERPRINTS` lists every primary key in them and a
//! test holds the two together; `keys/fetch.sh` fetches a missing one and never replaces one.

pub(crate) type Keyring<'a> = (&'a str, &'a [u8]);

pub(crate) const EMBEDDED: &[Keyring<'static>] = &[
    ("alpine-ncopa", include_bytes!("../keys/alpine-ncopa.gpg")),
    ("debian-cd", include_bytes!("../keys/debian-cd.gpg")),
    ("fedora", include_bytes!("../keys/fedora.gpg")),
    ("gnu-keyring", include_bytes!("../keys/gnu-keyring.gpg")),
    ("kernel", include_bytes!("../keys/kernel.gpg")),
    ("llvm", include_bytes!("../keys/llvm.gpg")),
    ("musl", include_bytes!("../keys/musl.gpg")),
    ("node-release", include_bytes!("../keys/node-release.gpg")),
    ("rust", include_bytes!("../keys/rust.gpg")),
];

pub(crate) fn find<'a>(rings: &[Keyring<'a>], name: &str) -> Option<&'a [u8]> {
    rings.iter().find(|(n, _)| *n == name).map(|(_, b)| *b)
}

pub(crate) fn embedded(name: &str) -> Option<&'static [u8]> {
    find(EMBEDDED, name)
}

/// An Alpine package signing key (an RSA public key, SPKI PEM) and the architectures whose
/// indexes and packages it signs. `name` is the file name apk puts in `.SIGN.RSA*.<name>`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RsaKey<'a> {
    pub name: &'a str,
    pub arches: &'a [&'a str],
    pub pem: &'a str,
}

/// Empty until the keys are pinned by hand (H3).
pub(crate) const ALPINE: &[RsaKey<'static>] = &[];

/// Whether `keys/FINGERPRINTS` lists `fingerprint` as a primary key of the keyring `ring`.
pub(crate) fn listed(ring: &str, fingerprint: &str) -> bool {
    include_str!("../keys/FINGERPRINTS")
        .lines()
        .filter_map(|l| l.split_once(' '))
        .any(|(file, fp)| file.strip_suffix(".gpg") == Some(ring) && fp == fingerprint)
}
