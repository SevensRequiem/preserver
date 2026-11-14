//! Throwaway `OpenPGP` keys made by rpgp for the tests: no gpg, no agent, no fixtures to rot.

use pgp::composed::{
    CleartextSignedMessage, DetachedSignature, KeyType, SecretKeyParamsBuilder, SignedSecretKey,
    SubkeyParamsBuilder,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::packet::{KeyFlags, SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::ser::Serialize;
use pgp::types::{Duration, KeyDetails, Password, Tag, Timestamp};
use rsa::rand_core::OsRng;

pub(crate) struct TestKey {
    pub secret: SignedSecretKey,
}

fn now() -> u32 {
    Timestamp::now().as_secs()
}

impl TestKey {
    /// A primary key that signs, created `age` seconds ago; `subkey` adds a signing subkey.
    pub(crate) fn make(age: u32, subkey: bool) -> Self {
        let created = Timestamp::from_secs(now() - age);
        let mut b = SecretKeyParamsBuilder::default();
        b.key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .can_certify(true)
            .created_at(created)
            .primary_user_id("Test Key <test@example.invalid>".into());
        if subkey {
            b.subkey(
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::Ed25519Legacy)
                    .can_sign(true)
                    .created_at(created)
                    .build()
                    .unwrap(),
            );
        }
        Self {
            secret: b.build().unwrap().generate(OsRng).unwrap(),
        }
    }

    pub(crate) fn new() -> Self {
        Self::make(3600, false)
    }

    /// The public key as a binary keyring.
    pub(crate) fn public(&self) -> Vec<u8> {
        self.secret.to_public_key().to_bytes().unwrap()
    }

    pub(crate) fn armored(&self) -> String {
        self.secret
            .to_public_key()
            .to_armored_string(pgp::composed::ArmorOptions::default())
            .unwrap()
    }

    pub(crate) fn fingerprint(&self) -> String {
        format!("{:X}", self.secret.primary_key.fingerprint())
    }

    pub(crate) fn subkey_fingerprint(&self) -> String {
        format!("{:X}", self.secret.secret_subkeys[0].key.fingerprint())
    }

    /// A binary detached signature by the primary key.
    pub(crate) fn sign(&self, data: &[u8]) -> Vec<u8> {
        DetachedSignature::sign_binary_data(
            OsRng,
            &self.secret.primary_key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            data,
        )
        .unwrap()
        .to_bytes()
        .unwrap()
    }

    pub(crate) fn sign_armored(&self, data: &[u8]) -> String {
        DetachedSignature::sign_binary_data(
            OsRng,
            &self.secret.primary_key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            data,
        )
        .unwrap()
        .to_armored_string(pgp::composed::ArmorOptions::default())
        .unwrap()
    }

    pub(crate) fn sign_with_subkey(&self, data: &[u8]) -> Vec<u8> {
        DetachedSignature::sign_binary_data(
            OsRng,
            &self.secret.secret_subkeys[0].key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            data,
        )
        .unwrap()
        .to_bytes()
        .unwrap()
    }

    pub(crate) fn clearsign(&self, text: &str) -> String {
        CleartextSignedMessage::sign(OsRng, text, &self.secret.primary_key, &Password::empty())
            .unwrap()
            .to_armored_string(pgp::composed::ArmorOptions::default())
            .unwrap()
    }

    fn subpackets(&self, created: Timestamp) -> (Vec<Subpacket>, Vec<Subpacket>) {
        let key = &self.secret.primary_key;
        (
            vec![
                Subpacket::regular(SubpacketData::SignatureCreationTime(created)).unwrap(),
                Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint())).unwrap(),
            ],
            vec![Subpacket::regular(SubpacketData::IssuerKeyId(key.legacy_key_id())).unwrap()],
        )
    }

    /// Replaces the user id's self-signature with one that ends the key's life `life` seconds
    /// after its creation.
    pub(crate) fn expire_after(&mut self, life: u32) {
        let key = &self.secret.primary_key;
        let mut cfg = SignatureConfig::from_key(OsRng, key, SignatureType::CertPositive).unwrap();
        let (mut hashed, unhashed) = self.subpackets(key.created_at());
        let mut flags = KeyFlags::default();
        flags.set_sign(true);
        flags.set_certify(true);
        hashed.push(Subpacket::regular(SubpacketData::KeyFlags(flags)).unwrap());
        hashed.push(
            Subpacket::regular(SubpacketData::KeyExpirationTime(Duration::from_secs(life)))
                .unwrap(),
        );
        cfg.hashed_subpackets = hashed;
        cfg.unhashed_subpackets = unhashed;
        let sig = cfg
            .sign_certification(
                key,
                key.public_key(),
                &Password::empty(),
                Tag::UserId,
                &self.secret.details.users[0].id,
            )
            .unwrap();
        self.secret.details.users[0].signatures = vec![sig];
    }

    /// Adds the owner's revocation of the whole key.
    pub(crate) fn revoke(&mut self) {
        let key = &self.secret.primary_key;
        let mut cfg = SignatureConfig::from_key(OsRng, key, SignatureType::KeyRevocation).unwrap();
        (cfg.hashed_subpackets, cfg.unhashed_subpackets) = self.subpackets(Timestamp::now());
        let sig = cfg
            .sign_key(key, &Password::empty(), key.public_key())
            .unwrap();
        self.secret.details.revocation_signatures.push(sig);
    }

    /// A detached signature with the given creation time and, when `life` is set, an expiry
    /// that many seconds later.
    pub(crate) fn sign_at(&self, data: &[u8], created: u32, life: Option<u32>) -> Vec<u8> {
        let key = &self.secret.primary_key;
        let (mut hashed, unhashed) = self.subpackets(Timestamp::from_secs(created));
        if let Some(l) = life {
            hashed.push(
                Subpacket::regular(SubpacketData::SignatureExpirationTime(Duration::from_secs(
                    l,
                )))
                .unwrap(),
            );
        }
        DetachedSignature::sign_binary_data_with_subpackets(
            OsRng,
            key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            data,
            pgp::composed::SubpacketConfig::UserDefined { hashed, unhashed },
        )
        .unwrap()
        .to_bytes()
        .unwrap()
    }
}
