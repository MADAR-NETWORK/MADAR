//! Session keys **locally, with no unsafe RPC** (`join gen-keys` and `join register-keys --keys`, 2026-10-17):
//!
//! - `gen-keys`: with the node **stopped**, generates a BABE (sr25519) and a GRANDPA (ed25519) pair and writes them into the node's own Keystore in its
//!   own format (`sc-keystore`: file name = 4-byte key type in hex + public key in hex, content = a JSON string with the key phrase). Prints
//!   **only the public keys** (the `SessionKeys` encoding that `set_keys` expects). Refuses if the database is held by a running node, and holds
//!   its lock during the whole write so no node can start meanwhile.
//! - `register-keys --keys`: the ownership proof checked by `pallet_session::set_keys` (`OpaqueKeys::ownership_proof_is_valid`)
//!   is a tuple of "proof of possession" signatures, one per key, over `owner = AccountId.encode()` in the same order (babe, then grandpa), which is
//!   what `author_rotateKeysWithOwner` produces inside the node. It is produced here directly from the Keystore files and checked locally before sending.
//!
//! Secrets (the key phrases) are never printed, logged, or passed out of this module: they are read into `Zeroizing` and wiped after use.

use madar_consensus::{AccountId, SessionKeys};
use parity_scale_codec::Encode;
use sp_core::proof_of_possession::ProofOfPossessionGenerator;
use sp_core::{crypto::key_types, ed25519, sr25519, Pair};
use sp_runtime::traits::OpaqueKeys;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const BABE: [u8; 4] = key_types::BABE.0;
pub const GRANDPA: [u8; 4] = key_types::GRANDPA.0;
/// A Keystore key file is always small (a JSON string with a 12–24 word phrase or a hex seed).
const MAX_KEY_FILE: u64 = 4096;

/// A key file name in the Keystore (as in `sc-keystore`): the key type, then the public key, hex without `0x`.
pub fn key_file_name(key_type: [u8; 4], public: &[u8]) -> String {
    format!("{}{}", hex::encode(key_type), hex::encode(public))
}

/// The chain ID from the spec file (or `dev`/`local`): the `chains/<id>` folder the node itself uses.
pub fn chain_id(chain: &str) -> Result<String, String> {
    let spec: Box<dyn sc_service::ChainSpec> = match chain {
        "dev" => Box::new(crate::chain_spec::development_chain_spec()?),
        "" | "local" => Box::new(crate::chain_spec::local_chain_spec()?),
        path => Box::new(
            crate::chain_spec::ChainSpec::from_json_file(PathBuf::from(path))
                .map_err(|e| format!("Could not read the chain file {path}: {e}"))?,
        ),
    };
    Ok(spec.id().to_string())
}

/// `<base>/chains/<id>/keystore` (the same path as `sc-service`). The ID must be a single safe path segment.
pub fn keystore_dir(base: &Path, chain_id: &str) -> Result<PathBuf, String> {
    let safe = !chain_id.is_empty()
        && chain_id != "."
        && chain_id != ".."
        && chain_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if !safe {
        return Err(format!(
            "The chain ID is not valid as a folder name: {chain_id:?}"
        ));
    }
    Ok(base.join("chains").join(chain_id).join("keystore"))
}

// ---------------------------------------------------------------- Is the node stopped? (database lock)

/// Holds the database locks for its whole lifetime: no node can start on this folder until it is dropped.
pub struct NodeStopped {
    _held: Vec<File>,
}

const RUNNING: &str =
    "A node is running on this folder (the database is held) — stop it first. No key was written.";

/// Checks that no node runs on `<base>/chains/<id>` and holds the database lock:
/// ParityDB (`paritydb/full/lock`: an exclusive file lock, as `parity-db` does) and RocksDB (`db/full/LOCK`: on Windows RocksDB opens it with no
/// sharing, on Unix with an `fcntl` lock). Any failure of the check itself = refusal (no guessing).
pub fn ensure_node_stopped(base: &Path, chain_id: &str) -> Result<NodeStopped, String> {
    let chain = base.join("chains").join(chain_id);
    let mut held = Vec::new();
    let parity = chain.join("paritydb").join("full").join("lock");
    if parity.exists() {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&parity)
            .map_err(|e| {
                format!(
                    "Could not check the database lock {}: {e}",
                    parity.display()
                )
            })?;
        match f.try_lock() {
            Ok(()) => held.push(f),
            Err(std::fs::TryLockError::WouldBlock) => return Err(RUNNING.into()),
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(format!(
                    "Could not check the database lock {}: {e}",
                    parity.display()
                ))
            }
        }
    }
    let rocks = chain.join("db").join("full").join("LOCK");
    if rocks.exists() {
        held.push(lock_rocksdb(&rocks)?);
    }
    Ok(NodeStopped { _held: held })
}

#[cfg(windows)]
fn lock_rocksdb(p: &Path) -> Result<File, String> {
    use std::os::windows::fs::OpenOptionsExt;
    // RocksDB on Windows opens LOCK with no sharing at all; our no-sharing open fails while it holds it, and keeps it from starting while we hold it.
    match OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0)
        .open(p)
    {
        Ok(f) => Ok(f),
        // ERROR_SHARING_VIOLATION / ERROR_LOCK_VIOLATION
        Err(e) if matches!(e.raw_os_error(), Some(32 | 33)) => Err(RUNNING.into()),
        Err(e) => Err(format!(
            "Could not check the database lock {}: {e}",
            p.display()
        )),
    }
}

#[cfg(unix)]
#[allow(unsafe_code)] // A narrow exception: the fcntl lock (the mechanism RocksDB uses on Unix).
fn lock_rocksdb(p: &Path) -> Result<File, String> {
    use std::os::unix::io::AsRawFd;
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(p)
        .map_err(|e| format!("Could not check the database lock {}: {e}", p.display()))?;
    // SAFETY: a plain C struct whose fields are all integers; zero is a valid value for it.
    let mut fl: libc::flock = unsafe { std::mem::zeroed() };
    fl.l_type = libc::F_WRLCK as _;
    fl.l_whence = libc::SEEK_SET as _;
    fl.l_start = 0;
    fl.l_len = 0;
    // SAFETY: a valid file descriptor owned by `f` for the whole call, and a pointer to a valid local struct.
    let r = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_SETLK, &fl) };
    if r == 0 {
        return Ok(f);
    }
    let e = std::io::Error::last_os_error();
    if matches!(e.raw_os_error(), Some(libc::EAGAIN) | Some(libc::EACCES)) {
        Err(RUNNING.into())
    } else {
        Err(format!(
            "Could not check the database lock {}: {e}",
            p.display()
        ))
    }
}

#[cfg(not(any(windows, unix)))]
fn lock_rocksdb(_p: &Path) -> Result<File, String> {
    Err("The RocksDB lock cannot be checked on this system".into())
}

// ---------------------------------------------------------------- Generation and reading

/// The generated public keys (no secrets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Generated {
    pub babe: [u8; 32],
    pub grandpa: [u8; 32],
}

impl Generated {
    pub fn session_keys(&self) -> SessionKeys {
        session_keys(&self.babe, &self.grandpa)
    }
    /// The SCALE encoding of `SessionKeys` as `set_keys` takes it (and `--keys` in `register-keys`).
    pub fn encoded(&self) -> Vec<u8> {
        self.session_keys().encode()
    }
    pub fn file_names(&self) -> [String; 2] {
        [
            key_file_name(BABE, &self.babe),
            key_file_name(GRANDPA, &self.grandpa),
        ]
    }
    /// The `gen-keys --json` output: public only.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "keys": format!("0x{}", hex::encode(self.encoded())),
            "babe": format!("0x{}", hex::encode(self.babe)),
            "grandpa": format!("0x{}", hex::encode(self.grandpa)),
            "key_files": self.file_names(),
        })
    }
}

pub fn session_keys(babe: &[u8; 32], grandpa: &[u8; 32]) -> SessionKeys {
    SessionKeys {
        babe: sr25519::Public::from_raw(*babe).into(),
        grandpa: ed25519::Public::from_raw(*grandpa).into(),
    }
}

/// The two public keys from a `SessionKeys` encoding (hex with or without `0x`).
pub fn parse_keys(hex_keys: &str) -> Result<Generated, String> {
    let bytes = hex::decode(hex_keys.trim().trim_start_matches("0x"))
        .map_err(|_| "--keys is not valid hex".to_string())?;
    let (babe, grandpa) = super::rotation::raw_keys(&bytes)
        .ok_or("--keys is not a valid SessionKeys encoding (babe + grandpa)")?;
    let g = Generated { babe, grandpa };
    if g.encoded() != bytes {
        return Err("--keys has extra bytes".into());
    }
    Ok(g)
}

/// Writes a new key file only (never replaces one) in the `sc-keystore` format: a JSON string.
fn write_key(path: &Path, phrase: &str) -> Result<(), String> {
    let json = Zeroizing::new(
        serde_json::to_string(phrase).map_err(|_| "Could not encode the key file".to_string())?,
    );
    madar_keystore::create_new_secret_file(path, json.as_bytes())
        .map_err(|e| format!("Could not write the key file {}: {e}", path.display()))
}

fn read_phrase(path: &Path) -> Result<Zeroizing<String>, String> {
    let meta = std::fs::metadata(path).map_err(|_| {
        format!(
            "The key file is not in the Keystore: {}",
            path.file_name().and_then(|n| n.to_str()).unwrap_or("?")
        )
    })?;
    if !meta.is_file() || meta.len() > MAX_KEY_FILE {
        return Err("The key file in the Keystore is not a valid regular file".into());
    }
    let bytes = Zeroizing::new(
        std::fs::read(path).map_err(|e| format!("Could not read the key file: {e}"))?,
    );
    let s: String = serde_json::from_slice(&bytes)
        .map_err(|_| "The key file in the Keystore is not in sc-keystore format".to_string())?;
    Ok(Zeroizing::new(s))
}

pub fn load_babe(dir: &Path, public: &[u8; 32]) -> Result<sr25519::Pair, String> {
    let phrase = read_phrase(&dir.join(key_file_name(BABE, public)))?;
    let pair = sr25519::Pair::from_string(&phrase, None)
        .map_err(|_| "The BABE key in the Keystore is invalid".to_string())?;
    if pair.public().0 != *public {
        return Err("The BABE key in the Keystore does not match its file name".into());
    }
    Ok(pair)
}

pub fn load_grandpa(dir: &Path, public: &[u8; 32]) -> Result<ed25519::Pair, String> {
    let phrase = read_phrase(&dir.join(key_file_name(GRANDPA, public)))?;
    let pair = ed25519::Pair::from_string(&phrase, None)
        .map_err(|_| "The GRANDPA key in the Keystore is invalid".to_string())?;
    if pair.public().0 != *public {
        return Err("The GRANDPA key in the Keystore does not match its file name".into());
    }
    Ok(pair)
}

/// Generates the two session pairs and writes them into `dir` (created if missing), then checks them by reading back. Never touches an existing file.
/// The caller is responsible for `ensure_node_stopped` first (see `gen_keys`).
pub fn generate(dir: &Path) -> Result<Generated, String> {
    std::fs::create_dir_all(dir).map_err(|e| {
        format!(
            "Could not create the Keystore folder {}: {e}",
            dir.display()
        )
    })?;
    let (babe, babe_phrase, _) = sr25519::Pair::generate_with_phrase(None);
    let babe_phrase = Zeroizing::new(babe_phrase);
    let (grandpa, grandpa_phrase, _) = ed25519::Pair::generate_with_phrase(None);
    let grandpa_phrase = Zeroizing::new(grandpa_phrase);
    let g = Generated {
        babe: babe.public().0,
        grandpa: grandpa.public().0,
    };
    let [babe_name, grandpa_name] = g.file_names();
    write_key(&dir.join(&babe_name), &babe_phrase)?;
    if let Err(e) = write_key(&dir.join(&grandpa_name), &grandpa_phrase) {
        // A key that was just generated and never registered anywhere: no half pair.
        let _ = std::fs::remove_file(dir.join(&babe_name));
        return Err(e);
    }
    if load_babe(dir, &g.babe).is_err() || load_grandpa(dir, &g.grandpa).is_err() {
        let _ = std::fs::remove_file(dir.join(&babe_name));
        let _ = std::fs::remove_file(dir.join(&grandpa_name));
        return Err("The read-back check of the key files failed — the write was cancelled".into());
    }
    Ok(g)
}

/// `join gen-keys`: the node is stopped (its lock is held) → generation → the public keys.
pub fn gen_keys(base: &Path, chain: &str) -> Result<Generated, String> {
    let id = chain_id(chain)?;
    let dir = keystore_dir(base, &id)?;
    let _stopped = ensure_node_stopped(base, &id)?;
    generate(&dir)
}

/// Ownership proof of `keys` for the account `owner` from the Keystore files in `dir` (as `set_keys` checks it), with a local check before returning.
pub fn ownership_proof(dir: &Path, keys: &Generated, owner: &AccountId) -> Result<Vec<u8>, String> {
    let mut babe = load_babe(dir, &keys.babe)?;
    let mut grandpa = load_grandpa(dir, &keys.grandpa)?;
    let who = owner.encode();
    let proof = (
        babe.generate_proof_of_possession(&who),
        grandpa.generate_proof_of_possession(&who),
    )
        .encode();
    if !keys.session_keys().ownership_proof_is_valid(&who, &proof) {
        return Err(
            "The local ownership proof did not pass the check — it will not be sent.".into(),
        );
    }
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("madar-sk-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn generated_keys_are_written_in_the_node_keystore_format_and_only_public_keys_come_out() {
        let d = temp("gen");
        let ks = d.join("chains").join("madar").join("keystore");
        let g = generate(&ks).unwrap();
        let mut names: Vec<String> = std::fs::read_dir(&ks)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        let mut want = g.file_names().to_vec();
        want.sort();
        assert_eq!(names, want, "exactly the two key files");
        assert!(
            want.iter().any(|n| n.starts_with("62616265"))
                && want.iter().any(|n| n.starts_with("6772616e")),
            "babe + gran key types"
        );
        // sc-keystore format: a JSON string that Pair::from_string accepts
        let raw = std::fs::read_to_string(ks.join(key_file_name(BABE, &g.babe))).unwrap();
        let phrase: String = serde_json::from_str(&raw).unwrap();
        assert_eq!(
            sr25519::Pair::from_string(&phrase, None)
                .unwrap()
                .public()
                .0,
            g.babe
        );
        // the output: SCALE SessionKeys = babe ‖ grandpa, and no secret anywhere in it
        let out = g.to_json().to_string();
        assert!(
            !out.contains(&phrase)
                && !phrase
                    .split_whitespace()
                    .any(|w| out.contains(&format!(" {w} ")))
        );
        let keys = g.to_json()["keys"].as_str().unwrap().to_string();
        assert_eq!(
            keys,
            format!("0x{}{}", hex::encode(g.babe), hex::encode(g.grandpa))
        );
        assert_eq!(parse_keys(&keys).unwrap(), g);
        assert!(
            parse_keys("0x1234").is_err()
                && parse_keys(&format!("{keys}00")).is_err()
                && parse_keys("zz").is_err()
        );
        // a second run never touches the first pair
        let g2 = generate(&ks).unwrap();
        assert_ne!(g, g2);
        assert_eq!(std::fs::read_dir(&ks).unwrap().count(), 4);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_local_ownership_proof_is_what_set_keys_checks() {
        let d = temp("proof");
        let g = generate(&d).unwrap();
        let owner = AccountId::from([7u8; 32]);
        let proof = ownership_proof(&d, &g, &owner).unwrap();
        assert_eq!(proof.len(), 128, "two 64-byte signatures");
        let keys = g.session_keys();
        assert!(keys.ownership_proof_is_valid(&owner.encode(), &proof));
        assert!(
            !keys.ownership_proof_is_valid(&AccountId::from([8u8; 32]).encode(), &proof),
            "bound to the owner account"
        );
        let mut bad = proof.clone();
        bad[70] ^= 1;
        assert!(!keys.ownership_proof_is_valid(&owner.encode(), &bad));
        // same proof as the runtime's own generator (statement "POP_" ‖ owner, babe then grandpa)
        let babe = load_babe(&d, &g.babe).unwrap();
        let statement = sp_core::proof_of_possession::statement_of_ownership(&owner.encode());
        let sig = sr25519::Signature::try_from(&proof[..64]).unwrap();
        assert!(sr25519::Pair::verify(&sig, &statement, &babe.public()));
        // a key file missing or not matching its name: no proof
        std::fs::remove_file(d.join(key_file_name(GRANDPA, &g.grandpa))).unwrap();
        assert!(ownership_proof(&d, &g, &owner).is_err());
        let other = generate(&d).unwrap();
        std::fs::copy(
            d.join(key_file_name(BABE, &other.babe)),
            d.join(key_file_name(BABE, &[9u8; 32])),
        )
        .unwrap();
        assert!(load_babe(&d, &[9u8; 32])
            .err()
            .unwrap()
            .contains("does not match"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn keys_are_never_generated_while_a_node_holds_the_database() {
        let d = temp("lock");
        let id = "madar_testnet";
        assert!(
            ensure_node_stopped(&d, id).is_ok(),
            "no database yet: nothing runs here"
        );
        // ParityDB: the node holds an exclusive lock on paritydb/full/lock
        let pdir = d.join("chains").join(id).join("paritydb").join("full");
        std::fs::create_dir_all(&pdir).unwrap();
        let held = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(pdir.join("lock"))
            .unwrap();
        held.lock().unwrap();
        assert_eq!(ensure_node_stopped(&d, id).err().as_deref(), Some(RUNNING));
        held.unlock().unwrap();
        drop(held);
        {
            let guard = ensure_node_stopped(&d, id).unwrap();
            let other = OpenOptions::new()
                .read(true)
                .write(true)
                .open(pdir.join("lock"))
                .unwrap();
            assert!(
                matches!(other.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
                "a node cannot start while keys are written"
            );
            drop(guard);
        }
        // RocksDB
        let rdir = d.join("chains").join(id).join("db").join("full");
        std::fs::create_dir_all(&rdir).unwrap();
        std::fs::write(rdir.join("LOCK"), b"").unwrap();
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let rocks = OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(0)
                .open(rdir.join("LOCK"))
                .unwrap();
            assert_eq!(ensure_node_stopped(&d, id).err().as_deref(), Some(RUNNING));
            drop(rocks);
        }
        assert!(ensure_node_stopped(&d, id).is_ok());
        // gen_keys (the whole command) refuses while a node holds the database and writes nothing
        let dev = chain_id("dev").unwrap();
        let ddir = d.join("chains").join(&dev).join("paritydb").join("full");
        std::fs::create_dir_all(&ddir).unwrap();
        let held = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(ddir.join("lock"))
            .unwrap();
        held.lock().unwrap();
        assert_eq!(gen_keys(&d, "dev").err().as_deref(), Some(RUNNING));
        assert!(!keystore_dir(&d, &dev).unwrap().exists(), "nothing written");
        held.unlock().unwrap();
        drop(held);
        let g = gen_keys(&d, "dev").unwrap();
        for n in g.file_names() {
            assert!(keystore_dir(&d, &dev).unwrap().join(n).is_file());
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_keystore_path_is_the_node_path_and_a_bad_chain_id_is_refused() {
        let base = Path::new(r"C:\M\data\node");
        assert_eq!(
            keystore_dir(base, "madar_testnet").unwrap(),
            base.join("chains").join("madar_testnet").join("keystore")
        );
        for bad in ["", ".", "..", "a/b", r"a\b", "c:x"] {
            assert!(keystore_dir(base, bad).is_err(), "{bad:?}");
        }
        assert_eq!(key_file_name(BABE, &[0xab; 2]), "62616265abab");
        assert_eq!(key_file_name(GRANDPA, &[1]), "6772616e01");
        assert!(chain_id("dev").is_ok_and(|id| !id.is_empty()));
    }
}
