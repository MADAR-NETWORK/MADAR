//! Encrypted local backup of user keys — the Security/Recovery phase (§9).
//!
//! Per D30 of the design document.
//! **This crate has nothing to do with node/validator
//! keys** — those stay in the standard, unmodified `sc-keystore`
//! (the IDN-2 separation decided in the Identity phase). This crate only serves local recovery
//! of the user's key (no social/guardian recovery — D30).
//!
//! Mechanism: Argon2id derives an encryption key from the user's passphrase + a random salt,
//! then ChaCha20-Poly1305 (AEAD) encrypts and authenticates the raw secret together. Every
//! temporary buffer of the raw secret is wrapped in `zeroize::Zeroizing`.

//!
//! **File format (version 2):** `[2][m_kib u32][t u32][lanes u32][salt 16][nonce 12][ciphertext+tag]` — the Argon2id
//! parameters are **stored explicitly** in the file, so recoverability does not change if the defaults of the `argon2` library change later. Version 1
//! (without parameters) is read as it is with the default parameters it was written with (`m=19456,t=2,p=1`). Parameter limits are checked on read
//! (a malicious file cannot request unreasonable memory/time).
//!
//! **Writing files:** [`create_new_secret_file`] creates exclusively (no overwrite and no symlink following) with `0600` permissions on
//! Unix; [`create_key_files`] writes both files together (`.enc` then `.pub`), rolls back the first if the second fails, and verifies by reading back.

#![deny(unsafe_code)]

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

/// Salt length in bytes — enough to prevent rainbow tables.
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
/// Poly1305 tag length (16 bytes) — the smallest possible ciphertext (an empty secret) is the tag alone.
pub const TAG_LEN: usize = 16;
pub const DERIVED_KEY_LEN: usize = 32;

/// The current version (2: explicit KDF parameters). Version 1 is read-only.
const FORMAT_VERSION: u8 = 2;
const LEGACY_FORMAT_VERSION: u8 = 1;
const V2_HEADER: usize = 1 + 12 + SALT_LEN + NONCE_LEN;

/// Argon2id parameters. The default = what version 1 wrote (`Argon2::default()`): 19 MiB, two passes, one lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub time_cost: u32,
    pub lanes: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams {
            memory_kib: 19_456,
            time_cost: 2,
            lanes: 1,
        }
    }
}

impl KdfParams {
    /// Acceptance limits on read: ≤ 1 GiB memory, ≤ 16 passes, ≤ 16 lanes, and the minimum valid for Argon2.
    pub fn is_sane(&self) -> bool {
        self.lanes >= 1
            && self.lanes <= 16
            && self.time_cost >= 1
            && self.time_cost <= 16
            && self.memory_kib >= 8 * self.lanes
            && self.memory_kib <= 1_048_576
    }
}

/// Errors of this crate. **No distinction between "wrong passphrase" and "tampered
/// data"** — both are only [`KeystoreError::Decryption`] (INV-K2; prevents leaking
/// information through the error message).
#[derive(Debug, PartialEq, Eq)]
pub enum KeystoreError {
    /// Authentication/decryption failed: a wrong passphrase or tampered data.
    Decryption,
    /// Key derivation via Argon2id failed (invalid parameters).
    Kdf,
    /// Encrypting the raw secret failed (should not happen for any valid input).
    Encryption,
    /// The binary backup format is invalid: insufficient length, an unknown version number, or KDF parameters out of bounds.
    Format,
}

/// An encrypted backup (data structure, before binary serialization).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedBackup {
    pub kdf: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

fn derive_key(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    kdf: &KdfParams,
) -> Result<Zeroizing<[u8; DERIVED_KEY_LEN]>, KeystoreError> {
    if !kdf.is_sane() {
        return Err(KeystoreError::Kdf);
    }
    let params = Params::new(
        kdf.memory_kib,
        kdf.time_cost,
        kdf.lanes,
        Some(DERIVED_KEY_LEN),
    )
    .map_err(|_| KeystoreError::Kdf)?;
    let mut key = Zeroizing::new([0u8; DERIVED_KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut *key)
        .map_err(|_| KeystoreError::Kdf)?;
    Ok(key)
}

/// Encrypts `secret` with the passphrase `passphrase` using the default KDF parameters. Salt and nonce are random (system CSPRNG) on every
/// call — the same secret and the same passphrase produce a different ciphertext every time (semantic security).
pub fn backup_secret(secret: &[u8], passphrase: &str) -> Result<EncryptedBackup, KeystoreError> {
    backup_secret_with(secret, passphrase, KdfParams::default())
}

/// Like `backup_secret` with explicit KDF parameters (stored in the file).
pub fn backup_secret_with(
    secret: &[u8],
    passphrase: &str,
    kdf: KdfParams,
) -> Result<EncryptedBackup, KeystoreError> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let key = derive_key(passphrase, &salt, &kdf)?;
    let cipher = ChaCha20Poly1305::new(key.as_slice().into());

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, secret)
        .map_err(|_| KeystoreError::Encryption)?;

    Ok(EncryptedBackup {
        kdf,
        salt,
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Recovers the raw secret from `backup` with the passphrase `passphrase`. Fails with the same
/// [`KeystoreError::Decryption`] whether the passphrase is wrong or `backup`
/// was tampered with (INV-K2) — never a partial recovery. The recovered secret is wrapped
/// in `Zeroizing` (INV-K3): it is wiped from memory automatically when it goes out of scope.
pub fn restore_secret(
    backup: &EncryptedBackup,
    passphrase: &str,
) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    let key = derive_key(passphrase, &backup.salt, &backup.kdf)?;
    let cipher = ChaCha20Poly1305::new(key.as_slice().into());
    let nonce = Nonce::from(backup.nonce);

    let plaintext = cipher
        .decrypt(&nonce, backup.ciphertext.as_ref())
        .map_err(|_| KeystoreError::Decryption)?;

    Ok(Zeroizing::new(plaintext))
}

impl EncryptedBackup {
    /// Binary serialization (version 2): `[2][m][t][lanes][salt][nonce][ciphertext]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(V2_HEADER + self.ciphertext.len());
        out.push(FORMAT_VERSION);
        out.extend_from_slice(&self.kdf.memory_kib.to_le_bytes());
        out.extend_from_slice(&self.kdf.time_cost.to_le_bytes());
        out.extend_from_slice(&self.kdf.lanes.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Deserializes (versions 1 and 2). Checks the minimum length (header + Poly1305 tag), the version number and the KDF
    /// parameter limits **before** any decryption attempt (INV-K4); no panic on any input.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KeystoreError> {
        let version = *bytes.first().ok_or(KeystoreError::Format)?;
        let (kdf, rest) = match version {
            LEGACY_FORMAT_VERSION => (KdfParams::default(), &bytes[1..]),
            FORMAT_VERSION => {
                if bytes.len() < V2_HEADER {
                    return Err(KeystoreError::Format);
                }
                let word = |i: usize| {
                    u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]])
                };
                let kdf = KdfParams {
                    memory_kib: word(1),
                    time_cost: word(5),
                    lanes: word(9),
                };
                if !kdf.is_sane() {
                    return Err(KeystoreError::Format);
                }
                (kdf, &bytes[13..])
            }
            _ => return Err(KeystoreError::Format),
        };
        // rest = salt ‖ nonce ‖ ciphertext(+tag). A header without ciphertext/tag can never be decrypted: rejected.
        if rest.len() < SALT_LEN + NONCE_LEN + TAG_LEN {
            return Err(KeystoreError::Format);
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&rest[..SALT_LEN]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&rest[SALT_LEN..SALT_LEN + NONCE_LEN]);
        Ok(EncryptedBackup {
            kdf,
            salt,
            nonce,
            ciphertext: rest[SALT_LEN + NONCE_LEN..].to_vec(),
        })
    }
}

/// Creates a secret file **only if new**: fails if the path already exists (no overwrite and no symlink following), with `0600` permissions
/// on Unix, and syncs to disk before returning.
pub fn create_new_secret_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let result = file.write_all(bytes).and_then(|_| file.sync_all());
    if result.is_err() {
        drop(file);
        let _ = std::fs::remove_file(path);
    }
    result
}

/// Writes a pair of key files (the encrypted `.enc` and the public `.pub`) **without overwriting any existing file**, rolls back the first if
/// the second fails, then verifies by reading back that `.enc` deserializes and decrypts with the passphrase to exactly `expected_secret`. Returns an error
/// (and leaves no files) on any failure — so success is never declared for an incomplete or undecryptable pair.
pub fn create_key_files(
    enc_path: &std::path::Path,
    enc_bytes: &[u8],
    pub_path: &std::path::Path,
    pub_bytes: &[u8],
    passphrase: &str,
    expected_secret: &[u8],
) -> Result<(), String> {
    for p in [enc_path, pub_path] {
        if p.exists() {
            return Err(format!(
                "{} already exists — will not overwrite an existing key (choose another ID/folder)",
                p.display()
            ));
        }
    }
    create_new_secret_file(enc_path, enc_bytes)
        .map_err(|e| format!("failed to write {}: {e}", enc_path.display()))?;
    if let Err(e) = create_new_secret_file(pub_path, pub_bytes) {
        let _ = std::fs::remove_file(enc_path);
        return Err(format!(
            "failed to write {}: {e} — the encrypted file was rolled back (no partial pair)",
            pub_path.display()
        ));
    }
    let verified = std::fs::read(enc_path)
        .map_err(|e| e.to_string())
        .and_then(|b| EncryptedBackup::from_bytes(&b).map_err(|e| format!("{e:?}")))
        .and_then(|b| restore_secret(&b, passphrase).map_err(|e| format!("{e:?}")))
        .map(|s| s.as_slice() == expected_secret);
    if verified != Ok(true) {
        let _ = std::fs::remove_file(enc_path);
        let _ = std::fs::remove_file(pub_path);
        return Err("read-back verification failed: the written file does not decrypt to the expected key — the write was rolled back".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_various_secret_lengths() {
        for secret in [
            Vec::new(),
            vec![0xAB; 32],
            vec![0xCD; 64],
            b"not-a-real-seed-just-a-test-string".to_vec(),
        ] {
            let backup = backup_secret(&secret, "correct horse battery staple").unwrap();
            let restored = restore_secret(&backup, "correct horse battery staple").unwrap();
            assert_eq!(&secret, &*restored);
        }
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let secret = vec![0x42; 32];
        let backup = backup_secret(&secret, "right passphrase").unwrap();
        let result = restore_secret(&backup, "wrong passphrase");
        assert_eq!(result.unwrap_err(), KeystoreError::Decryption);
    }

    #[test]
    fn tampering_each_field_is_detected() {
        let secret = vec![0x99; 32];
        let backup = backup_secret(&secret, "pw").unwrap();

        let mut tampered_salt = backup.clone();
        tampered_salt.salt[0] ^= 0xFF;
        assert_eq!(
            restore_secret(&tampered_salt, "pw").unwrap_err(),
            KeystoreError::Decryption
        );

        let mut tampered_nonce = backup.clone();
        tampered_nonce.nonce[0] ^= 0xFF;
        assert_eq!(
            restore_secret(&tampered_nonce, "pw").unwrap_err(),
            KeystoreError::Decryption
        );

        let mut tampered_ct = backup.clone();
        tampered_ct.ciphertext[0] ^= 0xFF;
        assert_eq!(
            restore_secret(&tampered_ct, "pw").unwrap_err(),
            KeystoreError::Decryption
        );
    }

    #[test]
    fn serialization_round_trip_preserves_restore() {
        let secret = vec![0x11; 32];
        let backup = backup_secret(&secret, "pw").unwrap();

        let bytes = backup.to_bytes();
        let decoded = EncryptedBackup::from_bytes(&bytes).unwrap();
        assert_eq!(backup, decoded);

        let restored = restore_secret(&decoded, "pw").unwrap();
        assert_eq!(&secret, &*restored);
    }

    #[test]
    fn unknown_format_version_is_rejected() {
        let secret = vec![0x22; 32];
        let backup = backup_secret(&secret, "pw").unwrap();
        let mut bytes = backup.to_bytes();
        bytes[0] = 0xFF; // unknown version
        assert_eq!(
            EncryptedBackup::from_bytes(&bytes).unwrap_err(),
            KeystoreError::Format
        );
    }

    #[test]
    fn from_bytes_never_panics_on_arbitrary_short_or_empty_input() {
        let cases: &[&[u8]] = &[
            &[],
            &[1],
            &[1, 2, 3],
            &[0u8; 10],
            &[1u8; 1 + SALT_LEN + NONCE_LEN - 1],
            &[0xFFu8; 5],
        ];
        for case in cases {
            // The result (Ok/Err) does not matter — what matters is no panic at all.
            let _ = EncryptedBackup::from_bytes(case);
        }
    }

    #[test]
    fn different_salts_produce_different_derived_keys_from_same_passphrase() {
        let salt_a = [1u8; SALT_LEN];
        let salt_b = [2u8; SALT_LEN];
        let key_a = derive_key("same passphrase", &salt_a, &KdfParams::default()).unwrap();
        let key_b = derive_key("same passphrase", &salt_b, &KdfParams::default()).unwrap();
        assert_ne!(&*key_a, &*key_b);
    }

    proptest::proptest! {
        /// A property-based generalization of `from_bytes_never_panics_on_arbitrary_short_or_empty_input`
        /// above — instead of 6 hand-picked cases, it generates thousands of random inputs
        /// (lengths 0–600 bytes) via `proptest` and checks the same
        /// property (INV-K4: never a panic on untrusted input). This is
        /// an actual search of the input space, not a repetition of the existing manual
        /// tests.
        #[test]
        fn from_bytes_never_panics_on_any_random_input(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..600)) {
            let _ = EncryptedBackup::from_bytes(&bytes);
        }

    }

    proptest::proptest! {
        // Argon2id is deliberately slow (a brute-force-resistant KDF) — a reduced
        // number of cases (20 instead of the default 256) keeps this test
        // time-bounded without unnecessary repetition, while keeping real coverage
        // of the input space (INV-K4 through the AEAD path, not format parsing).
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(20))]

        #[test]
        fn restore_secret_never_panics_on_random_ciphertext(
            salt in proptest::collection::vec(proptest::prelude::any::<u8>(), SALT_LEN..=SALT_LEN),
            nonce in proptest::collection::vec(proptest::prelude::any::<u8>(), NONCE_LEN..=NONCE_LEN),
            ciphertext in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..200),
        ) {
            let backup = EncryptedBackup {
                kdf: KdfParams::default(),
                salt: salt.try_into().unwrap(),
                nonce: nonce.try_into().unwrap(),
                ciphertext,
            };
            let _ = restore_secret(&backup, "any passphrase");
        }
    }
}

#[cfg(test)]
mod format_tests {
    use super::*;

    #[test]
    fn a_header_without_ciphertext_and_tag_is_rejected_structurally() {
        let header_only = vec![FORMAT_VERSION; 1 + SALT_LEN + NONCE_LEN];
        assert!(
            EncryptedBackup::from_bytes(&header_only).is_err(),
            "29-byte header cannot be a valid backup"
        );
        let mut short = header_only.clone();
        short.extend(vec![0u8; TAG_LEN - 1]);
        assert!(EncryptedBackup::from_bytes(&short).is_err());
    }

    #[test]
    fn a_real_backup_round_trips_through_the_stricter_format_check() {
        let b = backup_secret(b"", "p").unwrap(); // empty secret = tag only
        assert!(EncryptedBackup::from_bytes(&b.to_bytes()).is_ok());
        let b = backup_secret(b"secret", "p").unwrap();
        let parsed = EncryptedBackup::from_bytes(&b.to_bytes()).unwrap();
        assert_eq!(restore_secret(&parsed, "p").unwrap().as_slice(), b"secret");
    }
}

#[cfg(test)]
mod hardening_tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("madar-ks-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// An old version-1 file (without parameters) still opens with the default parameters it was written with.
    #[test]
    fn a_legacy_v1_file_is_still_readable_with_the_default_kdf() {
        let salt = [7u8; SALT_LEN];
        let nonce_bytes = [9u8; NONCE_LEN];
        let key = derive_key("correct horse battery", &salt, &KdfParams::default()).unwrap();
        // Matching the old version: Argon2::default() ≡ (19456, 2, 1).
        let mut legacy_key = [0u8; DERIVED_KEY_LEN];
        argon2::Argon2::default()
            .hash_password_into(b"correct horse battery", &salt, &mut legacy_key)
            .unwrap();
        assert_eq!(
            &*key, &legacy_key,
            "explicit default params equal the old implicit defaults"
        );
        let ct = ChaCha20Poly1305::new((&legacy_key).into())
            .encrypt(&Nonce::from(nonce_bytes), b"secret".as_slice())
            .unwrap();
        let mut file = vec![1u8];
        file.extend_from_slice(&salt);
        file.extend_from_slice(&nonce_bytes);
        file.extend_from_slice(&ct);
        let parsed = EncryptedBackup::from_bytes(&file).unwrap();
        assert_eq!(parsed.kdf, KdfParams::default());
        assert_eq!(
            restore_secret(&parsed, "correct horse battery")
                .unwrap()
                .as_slice(),
            b"secret"
        );
    }

    #[test]
    fn v2_stores_the_kdf_parameters_so_restore_does_not_depend_on_library_defaults() {
        let params = KdfParams {
            memory_kib: 64,
            time_cost: 3,
            lanes: 2,
        };
        let b = backup_secret_with(b"s3cret", "pass-pass-pass", params).unwrap();
        let bytes = b.to_bytes();
        assert_eq!(bytes[0], 2);
        let parsed = EncryptedBackup::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.kdf, params);
        assert_eq!(
            restore_secret(&parsed, "pass-pass-pass")
                .unwrap()
                .as_slice(),
            b"s3cret"
        );
        // Any tampering with the stored parameters prevents decryption (they are part of key derivation).
        let mut tampered = bytes.clone();
        tampered[5] = 4; // time_cost 3 -> 4
        assert_eq!(
            restore_secret(
                &EncryptedBackup::from_bytes(&tampered).unwrap(),
                "pass-pass-pass"
            )
            .unwrap_err(),
            KeystoreError::Decryption
        );
    }

    #[test]
    fn hostile_kdf_parameters_are_rejected_before_any_work() {
        let mut file = vec![2u8];
        file.extend_from_slice(&u32::MAX.to_le_bytes()); // enormous memory
        file.extend_from_slice(&2u32.to_le_bytes());
        file.extend_from_slice(&1u32.to_le_bytes());
        file.extend(vec![0u8; SALT_LEN + NONCE_LEN + TAG_LEN]);
        assert_eq!(
            EncryptedBackup::from_bytes(&file).unwrap_err(),
            KeystoreError::Format
        );
    }

    #[test]
    fn key_files_are_never_overwritten_and_a_half_written_pair_is_rolled_back() {
        let d = tmp("files");
        let secret = b"raw-secret-32-bytes-raw-secret-3";
        let enc = backup_secret(secret, "a-long-passphrase")
            .unwrap()
            .to_bytes();
        let (enc_path, pub_path) = (d.join("k.enc"), d.join("k.pub"));
        create_key_files(
            &enc_path,
            &enc,
            &pub_path,
            b"pubhex",
            "a-long-passphrase",
            secret,
        )
        .unwrap();

        // Repeating the command with the same ID: rejected, and nothing changes.
        let before = std::fs::read(&enc_path).unwrap();
        let other = backup_secret(b"different-secret", "another-passphrase")
            .unwrap()
            .to_bytes();
        let err = create_key_files(
            &enc_path,
            &other,
            &pub_path,
            b"x",
            "another-passphrase",
            b"different-secret",
        )
        .unwrap_err();
        assert!(err.contains("will not overwrite"), "{err}");
        assert_eq!(
            std::fs::read(&enc_path).unwrap(),
            before,
            "the existing key must be untouched"
        );

        // The second file fails to write (the path is a directory) => the first is rolled back and no partial pair remains.
        let (e2, p2) = (d.join("j.enc"), d.join("j.pub"));
        std::fs::create_dir(&p2).unwrap();
        // The path exists => rejected before any write; we simulate the second write failing with a path that cannot be created (missing parent folder).
        let p3 = d.join("missing-dir").join("j.pub");
        let err = create_key_files(&e2, &enc, &p3, b"x", "a-long-passphrase", secret).unwrap_err();
        assert!(err.contains("no partial pair"), "{err}");
        assert!(!e2.exists(), "the first file must be rolled back");
    }

    #[test]
    fn a_readback_that_does_not_decrypt_to_the_expected_secret_is_reported_and_removed() {
        let d = tmp("verify");
        let enc = backup_secret(b"actual", "a-long-passphrase")
            .unwrap()
            .to_bytes();
        let (e, p) = (d.join("v.enc"), d.join("v.pub"));
        let err = create_key_files(&e, &enc, &p, b"pub", "a-long-passphrase", b"expected-other")
            .unwrap_err();
        assert!(err.contains("read-back verification failed"), "{err}");
        assert!(!e.exists() && !p.exists());
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_are_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = tmp("mode");
        let p = d.join("s.enc");
        create_new_secret_file(&p, b"x").unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

/// A key ID safe as a file name: Latin letters/digits and `-` `_` `.` only, not starting with a dot, no path separators and no `..`.
pub fn is_safe_key_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && !id.starts_with('.')
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        && !id.contains("..")
}

#[cfg(test)]
mod key_id_tests {
    use super::is_safe_key_id;
    #[test]
    fn only_plain_file_names_are_accepted() {
        for ok in ["upgrade-committee-1", "madar-release-2026-09", "k_1.v2"] {
            assert!(is_safe_key_id(ok), "{ok}");
        }
        for bad in [
            "",
            "../x",
            "a/b",
            "a\\b",
            ".hidden",
            "a..b",
            "C:evil",
            "x y",
            &"a".repeat(65),
        ] {
            assert!(!is_safe_key_id(bad), "{bad}");
        }
    }
}
