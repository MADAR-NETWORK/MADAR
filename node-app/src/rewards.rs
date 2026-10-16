//! "My earnings" (2026-10-13): the node's earnings card, recorded by the MADAR service.
//!
//! - The app signs «hello», «beat» and «me» with the node's own network key (`network/secret_ed25519`, the libp2p
//!   identity the node makes on its first start). So the service knows the node by its PeerId and counts a beat only
//!   while it sees that PeerId connected to the network. The key never leaves the computer; it is not a wallet key.
//! - "Link your wallet" asks the service for a one-time code and opens madar-network.com/node/#code in the user's normal
//!   browser (where their wallet is); the wallet signs there.
//! - While the node runs, one signed beat goes out in every 10-minute window (a little after it starts, so a clock a
//!   few seconds off never lands two beats in one window); after each beat the balance is read again.
//!
//! The pure parts (texts, key, response parsing) are tested; the network calls are made by the app over HTTPS.

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

pub const DEFAULT_BASE: &str = "https://madar-network.com/api/ops-pro/v1/node";
/// One beat in every 10-minute window (the service counts each window once), sent BEAT_AFTER seconds into it.
pub const SLOT: u64 = 600;
pub const BEAT_AFTER: u64 = 30;
/// While a link code is waiting, ask every 30 s whether the wallet signed.
pub const LINK_POLL_EVERY: u64 = 30;
pub const CODE_TTL: u64 = 30 * 60;
/// How often the app asks the service whether "My earnings" is open.
pub const STATE_EVERY: u64 = 30 * 60;

pub fn hello_text(key: &str, ts: u64) -> String {
    format!("MADAR Node: hello {key} {ts}")
}
/// A beat names the node's finalized block, so the service can see the node is in step with the chain.
pub fn beat_text(key: &str, ts: u64, number: u64, hash: &str) -> String {
    format!("MADAR Node: beat {key} {ts} {number} {hash}")
}
pub fn me_text(key: &str, ts: u64) -> String {
    format!("MADAR Node: me {key} {ts}")
}

pub fn public_hex(k: &SigningKey) -> String {
    hex(&k.verifying_key().to_bytes())
}

pub fn sign_hex(k: &SigningKey, text: &str) -> String {
    hex(&k.sign(text.as_bytes()).to_bytes())
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// The node's network identity, owned by the app (`data/node-key`, 64 hex letters): made once with system randomness
/// and given to the node with `--node-key-file`, so the app never reads files the node keeps for itself.
pub fn node_key_file(data: &Path) -> std::path::PathBuf {
    data.join("node-key")
}

/// Reads the node key, or makes it once. A damaged file is an error, never silently replaced (the node's identity and
/// its link to a wallet would be lost).
pub fn load_or_create_key(data: &Path) -> Result<SigningKey, String> {
    let f = node_key_file(data);
    match fs::read_to_string(&f) {
        Ok(t) => {
            let b: [u8; 32] = unhex(&t)
                .and_then(|v| v.try_into().ok())
                .ok_or("node-key is damaged")?;
            return Ok(SigningKey::from_bytes(&b));
        }
        // only a missing file makes a new key; any other error (e.g. a scanner holding the file) is an error, so the
        // node's identity and its wallet link are never replaced by accident
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|e| e.to_string())?;
    use std::io::Write;
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&f)
        .map_err(|e| e.to_string())?;
    out.write_all(hex(&b).as_bytes())
        .and_then(|_| out.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(SigningKey::from_bytes(&b))
}

/// The key if it exists (the card shows the node's name only once the node has an identity).
pub fn load_key(data: &Path) -> Option<SigningKey> {
    let b: [u8; 32] = unhex(&fs::read_to_string(node_key_file(data)).ok()?)?
        .try_into()
        .ok()?;
    Some(SigningKey::from_bytes(&b))
}

/// The libp2p PeerId of the key: base58 of the identity multihash of the protobuf ed25519 PublicKey ("12D3KooW…").
pub fn peer_id(k: &SigningKey) -> String {
    let mut b = vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
    b.extend_from_slice(&k.verifying_key().to_bytes());
    base58(&b)
}

/// The node as people see it: the last 8 letters of its PeerId (the link page shows the same).
pub fn short_peer(k: &SigningKey) -> String {
    let p = peer_id(k);
    format!("…{}", &p[p.len() - 8..])
}

fn base58(b: &[u8]) -> String {
    const A: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits: Vec<u8> = Vec::new();
    for &x in b {
        let mut carry = x as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let zeros = b.iter().take_while(|x| **x == 0).count();
    std::iter::repeat_n('1', zeros)
        .chain(digits.iter().rev().map(|d| A[*d as usize] as char))
        .collect()
}

/// Time for a beat: the window changed since the last beat and we are BEAT_AFTER seconds into it.
pub fn beat_due(now: u64, last_beat: u64) -> bool {
    now / SLOT != last_beat / SLOT && now % SLOT >= BEAT_AFTER
}

/// The app's rewards state (`data/rewards.json`): pending link code, linked or not, last beat, last «me» answer.
pub fn load_state(data: &Path) -> Value {
    fs::read_to_string(data.join("rewards.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}))
}

pub fn save_state(data: &Path, v: &Value) {
    let f = data.join("rewards.json");
    let tmp = f.with_extension("tmp");
    if fs::write(&tmp, serde_json::to_string_pretty(v).unwrap_or_default()).is_ok() {
        let _ = fs::rename(&tmp, &f);
    }
}

/// The signed bodies the service expects.
pub fn hello_body(k: &SigningKey, ts: u64) -> Value {
    let key = public_hex(k);
    json!({"key": key, "ts": ts, "sig": sign_hex(k, &hello_text(&key, ts))})
}
pub fn beat_body(k: &SigningKey, ts: u64, number: u64, hash: &str) -> Value {
    let key = public_hex(k);
    json!({"key": key, "ts": ts, "number": number, "hash": hash, "sig": sign_hex(k, &beat_text(&key, ts, number, hash))})
}
pub fn me_body(k: &SigningKey, ts: u64) -> Value {
    let key = public_hex(k);
    json!({"key": key, "ts": ts, "sig": sign_hex(k, &me_text(&key, ts))})
}

/// The link page address: only the service's own page (madar-network.com/node/#code), never another site.
pub fn link_url_ok(url: &str) -> bool {
    let rest = url
        .strip_prefix("https://madar-network.com/node/#")
        .unwrap_or("");
    (6..=16).contains(&rest.len()) && rest.bytes().all(|c| c.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn texts_match_the_service_and_signatures_verify() {
        let k = SigningKey::from_bytes(&[7; 32]);
        let key = public_hex(&k);
        assert_eq!(key.len(), 64);
        let b = beat_body(&k, 100, 7, "0xab");
        let sig: [u8; 64] = unhex(b["sig"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert!(k
            .verifying_key()
            .verify_strict(
                beat_text(&key, 100, 7, "0xab").as_bytes(),
                &ed25519_dalek::Signature::from_bytes(&sig)
            )
            .is_ok());
        assert_eq!(
            beat_text("ab", 5, 7, "0xab"),
            "MADAR Node: beat ab 5 7 0xab"
        );
        assert_eq!(hello_text("ab", 5), "MADAR Node: hello ab 5");
        assert_eq!(me_text("ab", 5), "MADAR Node: me ab 5");
    }

    #[test]
    fn the_node_key_is_made_once_kept_and_gives_the_libp2p_peer_id() {
        let dir = std::env::temp_dir().join(format!("madar-nk-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        assert!(load_key(&dir).is_none());
        let a = load_or_create_key(&dir).unwrap();
        let b = load_or_create_key(&dir).unwrap();
        assert_eq!(public_hex(&a), public_hex(&b));
        assert_eq!(public_hex(&load_key(&dir).unwrap()), public_hex(&a));
        assert_eq!(
            fs::read_to_string(node_key_file(&dir)).unwrap().len(),
            64,
            "hex, as --node-key-file reads it"
        );
        fs::write(node_key_file(&dir), "zz").unwrap();
        assert!(
            load_or_create_key(&dir).is_err(),
            "a damaged key is not silently replaced"
        );
        let _ = fs::remove_dir_all(&dir);
        // the primary server's PeerId from its public key (31d2…a31a), as libp2p prints it
        let mut m = vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
        m.extend(
            unhex("31d244b9cd0704307145d6b5ce173d99e96d252caa3e488e181b340116e9a31a").unwrap(),
        );
        assert_eq!(
            base58(&m),
            "12D3KooWDAr7FDtAeUx51zowWytNKeeuQfB5B2cyF4bZmDEp9j9K"
        );
        assert!(
            peer_id(&a).starts_with("12D3KooW")
                && peer_id(&a).ends_with(short_peer(&a).trim_start_matches('…'))
        );
    }

    #[test]
    fn one_beat_per_window_a_little_after_it_starts() {
        assert!(beat_due(6030, 0));
        assert!(!beat_due(6010, 0), "too early in the window");
        assert!(!beat_due(6500, 6030), "already beat in this window");
        assert!(beat_due(6630, 6030));
    }

    #[test]
    fn link_urls() {
        assert!(link_url_ok("https://madar-network.com/node/#AbCd1234"));
        for bad in [
            "https://evil.io/node/#AbCd1234",
            "https://madar-network.com/node/#a b",
            "https://madar-network.com/node/#x",
            "http://madar-network.com/node/#AbCd1234",
        ] {
            assert!(!link_url_ok(bad), "{bad}");
        }
    }
}
