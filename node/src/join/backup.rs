//! An encrypted backup of the operator account (`join export` / `join import`, optional, on the user's request, 2026-10-17):
//! the account's recovery phrase is re-encrypted with a password the user chooses (Argon2id + ChaCha20-Poly1305 via `madar-keystore`,
//! the same format as the `.enc` file) into a JSON file the user keeps wherever they like. The file also carries the public ID, so a restore
//! is refused if the decrypted phrase does not match it. The phrase and the account passphrase are never shown.

use super::account::{self, Account};
use madar_consensus::AccountId;
use sp_core::crypto::Ss58Codec;
use std::path::Path;
use zeroize::Zeroizing;

pub const FORMAT: &str = "madar-operator-backup-v1";
/// A backup file is always small (phrase + header); a defensive limit before any decryption.
pub const MAX_BACKUP: usize = 64 * 1024;

/// Argon2id parameters for the backup file (it leaves the computer, so guessing its password is made harder): 256 MiB, 3 passes, 1 lane.
pub const BACKUP_KDF: madar_keystore::KdfParams = madar_keystore::KdfParams {
    memory_kib: 262_144,
    time_cost: 3,
    lanes: 1,
};
/// The most accepted on restore (a file from outside the computer could ask for unbounded memory or time): 512 MiB, 10 passes, 4 lanes.
pub const MAX_IMPORT_MEMORY_KIB: u32 = 524_288;
pub const MAX_IMPORT_TIME: u32 = 10;
pub const MAX_IMPORT_LANES: u32 = 4;

/// Are a backup file's parameters acceptable on restore? (pure, tested)
pub fn import_kdf_ok(k: &madar_keystore::KdfParams) -> bool {
    k.memory_kib <= MAX_IMPORT_MEMORY_KIB
        && k.time_cost <= MAX_IMPORT_TIME
        && k.lanes <= MAX_IMPORT_LANES
}

/// The backup file's content (JSON) from an `.enc` account and its passphrase, encrypted with the backup password.
pub fn export(
    enc: &Path,
    passphrase: &str,
    backup_pass: &str,
) -> Result<(AccountId, String), String> {
    account::check_passphrase(backup_pass).map_err(|_| {
        "The backup password is too short (at least 12 characters) — nothing was written."
            .to_string()
    })?;
    let expect = account::read_public(enc)?;
    let phrase = Account::phrase_of(enc, passphrase)?;
    let id = Account::from_phrase_bytes(&phrase)?.id();
    if id != expect {
        return Err(
            "The encrypted file does not match the neighbouring .pub file — no backup.".into(),
        );
    }
    let enc_backup = madar_keystore::backup_secret_with(&phrase, backup_pass, BACKUP_KDF)
        .map_err(|e| format!("Failed to encrypt the backup: {e:?}"))?;
    let text = serde_json::to_string_pretty(&serde_json::json!({
        "format": FORMAT,
        "account_id_hex": hex::encode(<AccountId as AsRef<[u8]>>::as_ref(&id)),
        "ss58": id.to_ss58check(),
        "data": hex::encode(enc_backup.to_bytes()),
    }))
    .map_err(|e| e.to_string())?;
    // Read-back check: the backup decrypts with its password to the same account.
    if decrypt(text.as_bytes(), backup_pass)?.1 != id {
        return Err("The read-back check of the backup failed — no backup.".into());
    }
    Ok((id, text))
}

/// Decrypts a backup file: (phrase, ID) after checking the format and that the ID written in it matches. Fixed errors with no content.
pub fn decrypt(bytes: &[u8], backup_pass: &str) -> Result<(Zeroizing<Vec<u8>>, AccountId), String> {
    if bytes.len() > MAX_BACKUP {
        return Err("The backup file is larger than expected — it is not a MADAR backup.".into());
    }
    let v: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| "Not a MADAR operator account backup file.".to_string())?;
    if v["format"] != FORMAT {
        return Err("Not a MADAR operator account backup file (unknown format).".into());
    }
    let want = account::parse_address(&format!(
        "0x{}",
        v["account_id_hex"].as_str().unwrap_or_default()
    ))?;
    let data = hex::decode(v["data"].as_str().unwrap_or_default())
        .map_err(|_| "The backup file is corrupt.".to_string())?;
    let backup = madar_keystore::EncryptedBackup::from_bytes(&data)
        .map_err(|_| "The backup file is corrupt.".to_string())?;
    if !import_kdf_ok(&backup.kdf) {
        return Err("The backup file asks for more memory or time than allowed — refused.".into());
    }
    let phrase = madar_keystore::restore_secret(&backup, backup_pass)
        .map_err(|_| "Wrong backup password or corrupt file.".to_string())?;
    let id = Account::from_phrase_bytes(&phrase)?.id();
    if id != want {
        return Err("The backup file does not match the account written in it — refused.".into());
    }
    Ok((phrase, id))
}

/// Restores the account from the backup into `out` (new `.enc` + `.pub`, never replaced) with a new passphrase.
pub fn import(
    bytes: &[u8],
    backup_pass: &str,
    out: &Path,
    new_passphrase: &str,
) -> Result<AccountId, String> {
    let (phrase, id) = decrypt(bytes, backup_pass)?;
    let written = Account::import_phrase(out, &phrase, new_passphrase)?;
    if written != id {
        let _ = std::fs::remove_file(out);
        let _ = std::fs::remove_file(account::pub_path(out));
        return Err(
            "The written account does not match the backup — the write was cancelled.".into(),
        );
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("madar-bak-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_backup_round_trips_to_the_same_account_on_another_folder() {
        let d = temp("rt");
        let enc = d.join("operator.enc");
        let id = Account::create(&enc, "machine-passphrase-0123").unwrap();
        let (eid, text) = export(&enc, "machine-passphrase-0123", "my backup password").unwrap();
        assert_eq!(eid, id);
        // the file is public data + ciphertext only
        let phrase = Account::phrase_of(&enc, "machine-passphrase-0123").unwrap();
        let words = std::str::from_utf8(&phrase).unwrap().to_string();
        assert!(!words
            .split_whitespace()
            .any(|w| text.contains(&format!("\"{w}\"")) || text.contains(&format!(" {w} "))));
        assert!(!text.contains("machine-passphrase") && !text.contains("my backup password"));
        assert!(text.contains(FORMAT) && text.contains(&id.to_ss58check()));
        // restore on a "new computer" with a new machine passphrase
        let out = temp("rt2").join("operator.enc");
        assert_eq!(
            import(
                text.as_bytes(),
                "my backup password",
                &out,
                "new-machine-passphrase-9"
            )
            .unwrap(),
            id
        );
        assert_eq!(
            Account::load(&out, "new-machine-passphrase-9")
                .unwrap()
                .id(),
            id
        );
        assert_eq!(account::read_public(&out).unwrap(), id);
        // never overwrites
        assert!(import(
            text.as_bytes(),
            "my backup password",
            &out,
            "new-machine-passphrase-9"
        )
        .is_err());
    }

    #[test]
    fn a_wrong_password_a_short_one_or_a_tampered_file_is_refused() {
        let d = temp("bad");
        let enc = d.join("operator.enc");
        Account::create(&enc, "machine-passphrase-0123").unwrap();
        assert!(
            export(&enc, "machine-passphrase-0123", "short").is_err(),
            "minimum length"
        );
        assert!(export(&enc, "wrong-passphrase-0000", "my backup password").is_err());
        let (_, text) = export(&enc, "machine-passphrase-0123", "my backup password").unwrap();
        let out = d.join("restored.enc");
        assert!(import(
            text.as_bytes(),
            "another password!!",
            &out,
            "new-machine-passphrase-9"
        )
        .is_err());
        assert!(!out.exists());
        // another account id written in the file: refused even with the right password
        let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
        v["account_id_hex"] = serde_json::json!(hex::encode([3u8; 32]));
        assert!(import(
            v.to_string().as_bytes(),
            "my backup password",
            &out,
            "new-machine-passphrase-9"
        )
        .unwrap_err()
        .contains("does not match"));
        assert!(
            decrypt(b"not json", "x").is_err() && decrypt(br#"{"format":"other"}"#, "x").is_err()
        );
        assert!(decrypt(&vec![b' '; MAX_BACKUP + 1], "x").is_err());
        assert!(!out.exists());
    }

    #[test]
    fn the_backup_uses_strong_kdf_params_and_import_caps_what_it_accepts() {
        let d = temp("kdf");
        let enc = d.join("operator.enc");
        Account::create(&enc, "machine-passphrase-0123").unwrap();
        let (_, text) = export(&enc, "machine-passphrase-0123", "my backup password").unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        let data = hex::decode(v["data"].as_str().unwrap()).unwrap();
        let b = madar_keystore::EncryptedBackup::from_bytes(&data).unwrap();
        assert_eq!(b.kdf, BACKUP_KDF);
        assert_eq!(
            (b.kdf.memory_kib, b.kdf.time_cost, b.kdf.lanes),
            (262_144, 3, 1)
        );
        use madar_keystore::KdfParams as K;
        assert!(import_kdf_ok(&BACKUP_KDF) && import_kdf_ok(&K::default()));
        assert!(import_kdf_ok(&K {
            memory_kib: 524_288,
            time_cost: 10,
            lanes: 4
        }));
        for bad in [
            K {
                memory_kib: 524_289,
                time_cost: 3,
                lanes: 1,
            },
            K {
                memory_kib: 65_536,
                time_cost: 11,
                lanes: 1,
            },
            K {
                memory_kib: 65_536,
                time_cost: 3,
                lanes: 5,
            },
        ] {
            assert!(!import_kdf_ok(&bad), "{bad:?}");
        }
        // a file asking for more than the caps (still within the keystore's own limits) is refused before any Argon2 work
        let out = d.join("restored.enc");
        let mut v2 = v.clone();
        for (at, val) in [(1usize, 1_048_576u32), (5, 16), (9, 8)] {
            let mut bad = data.clone();
            bad[at..at + 4].copy_from_slice(&val.to_le_bytes());
            v2["data"] = serde_json::json!(hex::encode(&bad));
            assert!(
                import(
                    v2.to_string().as_bytes(),
                    "my backup password",
                    &out,
                    "new-machine-passphrase-9"
                )
                .unwrap_err()
                .contains("more memory or time than allowed"),
                "{at}"
            );
        }
        assert!(!out.exists());
        // the real file still restores
        assert!(import(
            text.as_bytes(),
            "my backup password",
            &out,
            "new-machine-passphrase-9"
        )
        .is_ok());
    }
}
