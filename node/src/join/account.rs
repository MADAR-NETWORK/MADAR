//! Operator account: an sr25519 recovery phrase **encrypted immediately** (Argon2id + ChaCha20-Poly1305 via `madar-keystore`, the same format as the committee tools) in
//! a `.enc` file created exclusively (never overwritten) alongside a public `.pub` file. The secret phrase is never displayed: the backup = the encrypted file + the passphrase.

use madar_consensus::AccountId;
use sp_core::{crypto::Ss58Codec, sr25519, Pair};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const MIN_PASSPHRASE: usize = 12;

/// No `Debug`/`Display`/`Clone` on purpose: there is no way to print the secret by mistake.
pub struct Account {
    pair: sr25519::Pair,
}

impl Account {
    pub fn id(&self) -> AccountId {
        AccountId::from(self.pair.public().0)
    }

    pub fn sign(&self, message: &[u8]) -> sr25519::Signature {
        self.pair.sign(message)
    }

    /// From a voting node's secret file (`key generate --output-type json`: field `secretPhrase`) — the key already lives on this machine
    /// because the node votes with it; reading it neither copies nor prints it (for automatic renewal of the genesis nodes).
    pub fn from_secret_json(path: &Path) -> Result<Account, String> {
        let text = Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|e| format!("Could not read {}: {e}", path.display()))?,
        );
        let v: serde_json::Value = serde_json::from_str(&text)
            .map_err(|_| "The secret file is not valid JSON".to_string())?;
        let phrase = Zeroizing::new(
            v.get("secretPhrase")
                .and_then(|p| p.as_str())
                .ok_or("The secret file has no secretPhrase")?
                .to_string(),
        );
        let (pair, _) = sr25519::Pair::from_phrase(&phrase, None)
            .map_err(|_| "The secret phrase in the file is invalid".to_string())?;
        Ok(Account { pair })
    }

    #[cfg(test)]
    pub fn from_pair_for_tests(pair: sr25519::Pair) -> Account {
        Account { pair }
    }

    /// Creates a new account and writes it encrypted. Returns only the public ID.
    pub fn create(enc_path: &Path, passphrase: &str) -> Result<AccountId, String> {
        check_passphrase(passphrase)?;
        let (pair, phrase, _seed) = sr25519::Pair::generate_with_phrase(None);
        let phrase = Zeroizing::new(phrase);
        let id = AccountId::from(pair.public().0);
        let backup = madar_keystore::backup_secret(phrase.as_bytes(), passphrase)
            .map_err(|e| format!("Failed to encrypt the account: {e:?}"))?;
        let public = format!(
            "account_id_hex={}\nss58={}\n",
            hex::encode(id.as_ref() as &[u8]),
            id.to_ss58check()
        );
        madar_keystore::create_key_files(
            enc_path,
            &backup.to_bytes(),
            &pub_path(enc_path),
            public.as_bytes(),
            passphrase,
            phrase.as_bytes(),
        )?;
        Ok(id)
    }

    pub fn load(enc_path: &Path, passphrase: &str) -> Result<Account, String> {
        let bytes = std::fs::read(enc_path)
            .map_err(|e| format!("Could not read {}: {e}", enc_path.display()))?;
        Self::from_encrypted(&bytes, passphrase)
    }

    /// From the contents of a `.enc` file in memory (e.g. a committee key read from a USB drive via the dashboard without saving it to disk).
    pub fn from_encrypted(bytes: &[u8], passphrase: &str) -> Result<Account, String> {
        let backup = madar_keystore::EncryptedBackup::from_bytes(bytes).map_err(|_| {
            "The account file is corrupt or not in madar-keystore format".to_string()
        })?;
        let phrase = madar_keystore::restore_secret(&backup, passphrase)
            .map_err(|_| "Wrong passphrase or corrupt file".to_string())?;
        let phrase = std::str::from_utf8(&phrase)
            .map_err(|_| "The account contents are invalid".to_string())?;
        let (pair, _) = sr25519::Pair::from_phrase(phrase, None)
            .map_err(|_| "The recovery phrase inside the file is invalid".to_string())?;
        Ok(Account { pair })
    }
}

fn check_passphrase(p: &str) -> Result<(), String> {
    if p.chars().count() < MIN_PASSPHRASE {
        return Err(format!(
            "The passphrase is shorter than {MIN_PASSPHRASE} characters — no file was written."
        ));
    }
    Ok(())
}

pub fn pub_path(enc_path: &Path) -> PathBuf {
    enc_path.with_extension("pub")
}

/// The public ID from the adjacent `.pub` file (no passphrase) — for read-only commands.
pub fn read_public(enc_path: &Path) -> Result<AccountId, String> {
    let text = std::fs::read_to_string(pub_path(enc_path))
        .map_err(|e| format!("Could not read {}: {e}", pub_path(enc_path).display()))?;
    let hex_id = text
        .lines()
        .find_map(|l| l.strip_prefix("account_id_hex="))
        .ok_or("The .pub file has no account_id_hex")?;
    parse_address(&format!("0x{}", hex_id.trim()))
}

/// An SS58 address or a Hex ID (`0x` + 64).
pub fn parse_address(s: &str) -> Result<AccountId, String> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x") {
        let b = hex::decode(h).map_err(|_| "Invalid Hex ID")?;
        let a: [u8; 32] = b.try_into().map_err(|_| "A Hex ID must be 32 bytes")?;
        return Ok(AccountId::from(a));
    }
    // Only the MADAR format (85) or the legacy format (42); the key is the same, only its rendering differs. Does not rely on the process-wide default format.
    let (who, v) = AccountId::from_ss58check_with_version(s)
        .map_err(|_| "Invalid SS58 address".to_string())?;
    match u16::from(v) {
        madar_protocol::SS58_PREFIX | madar_protocol::SS58_PREFIX_DEV => Ok(who),
        other => Err(format!(
            "The address belongs to another network (prefix {other}), not MADAR"
        )),
    }
}

/// The passphrase: from a file (`--passphrase-file`, for automation; a single line) or a hidden prompt with no echo (with confirmation on creation).
pub fn read_passphrase(file: Option<&Path>, confirm: bool) -> Result<Zeroizing<String>, String> {
    if let Some(f) = file {
        let raw = Zeroizing::new(
            std::fs::read_to_string(f)
                .map_err(|e| format!("Could not read {}: {e}", f.display()))?,
        );
        return Ok(Zeroizing::new(
            raw.trim_end_matches(['\r', '\n']).to_string(),
        ));
    }
    let p = Zeroizing::new(
        rpassword::prompt_password("Account file passphrase: ")
            .map_err(|e| format!("Could not read the passphrase: {e}"))?,
    );
    if confirm {
        let c = Zeroizing::new(
            rpassword::prompt_password("Re-enter it to confirm: ").map_err(|e| e.to_string())?,
        );
        if *p != *c {
            return Err("The passphrases do not match — no file was written.".into());
        }
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("madar-join-acct-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn madar_addresses_are_written_with_85_and_old_42_addresses_stay_valid() {
        use sp_core::crypto::Ss58AddressFormat;
        let who = AccountId::from([7u8; 32]);
        let old = who.to_ss58check_with_version(Ss58AddressFormat::custom(42));
        let new =
            who.to_ss58check_with_version(Ss58AddressFormat::custom(madar_protocol::SS58_PREFIX));
        assert_ne!(old, new, "the written form changes");
        assert_eq!(parse_address(&new).unwrap(), who);
        assert_eq!(
            parse_address(&old).unwrap(),
            who,
            "addresses already in configs keep working"
        );
        assert!(
            parse_address(&who.to_ss58check_with_version(Ss58AddressFormat::custom(0))).is_err(),
            "another network's prefix is refused"
        );
    }

    #[test]
    fn a_created_account_round_trips_and_only_public_data_is_ever_visible() {
        let d = dir("rt");
        let enc = d.join("me.enc");
        let id = Account::create(&enc, "a-strong-passphrase").unwrap();
        assert_eq!(
            read_public(&enc).unwrap(),
            id,
            "the .pub file identifies the account without a passphrase"
        );
        let acct = Account::load(&enc, "a-strong-passphrase").unwrap();
        assert_eq!(acct.id(), id);
        // The signature is valid for this ID.
        let sig = acct.sign(b"msg");
        assert!(sr25519::Pair::verify(
            &sig,
            b"msg",
            &sr25519::Public::from_raw(*id.as_ref())
        ));
        // The encrypted file contains no word of the recovery phrase in readable form (random bytes), and the public file contains only the ID.
        let enc_bytes = std::fs::read(&enc).unwrap();
        assert!(std::str::from_utf8(&enc_bytes).map_or(true, |t| t.split_whitespace().count() < 12));
        assert!(std::fs::read_to_string(pub_path(&enc))
            .unwrap()
            .contains(&id.to_ss58check()));
    }

    #[test]
    fn a_wrong_passphrase_a_short_one_and_an_existing_file_are_all_refused() {
        let d = dir("refuse");
        let enc = d.join("me.enc");
        assert!(Account::create(&enc, "short")
            .unwrap_err()
            .contains("shorter"));
        assert!(!enc.exists(), "nothing is written on a refused passphrase");
        Account::create(&enc, "a-strong-passphrase").unwrap();
        assert!(Account::load(&enc, "another-passphrase!").is_err());
        let before = std::fs::read(&enc).unwrap();
        assert!(
            Account::create(&enc, "a-strong-passphrase").is_err(),
            "never overwrite an existing account"
        );
        assert_eq!(std::fs::read(&enc).unwrap(), before);
    }

    #[test]
    fn addresses_parse_from_ss58_and_hex_and_reject_garbage() {
        let id = AccountId::from([5u8; 32]);
        assert_eq!(parse_address(&id.to_ss58check()).unwrap(), id);
        assert_eq!(
            parse_address(&format!("0x{}", hex::encode([5u8; 32]))).unwrap(),
            id
        );
        assert!(parse_address("0x1234").is_err() && parse_address("nonsense").is_err());
    }

    #[test]
    fn the_passphrase_file_is_read_without_the_trailing_newline() {
        let d = dir("pp");
        let f = d.join("pp.txt");
        std::fs::write(&f, "correct horse battery\r\n").unwrap();
        assert_eq!(
            read_passphrase(Some(&f), false).unwrap().as_str(),
            "correct horse battery"
        );
    }
}
