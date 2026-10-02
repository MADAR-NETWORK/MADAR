//! Release tool (not shipped to users): generates the update-signing key once, and signs `latest.json`.
//!
//! - `madar-release-sign keygen <key-file>`: creates a private key (32 bytes hex) and prints the public key.
//! - `madar-release-sign sign <key-file> <latest.json>`: adds `signature` over the `madar_app::update_message` message.
//!
//! The private key stays outside the repository and is backed up; the public key is embedded in the app (`UPDATE_PUBKEY_HEX`).

use ed25519_dalek::{Signer, SigningKey};
use std::fs;

#[path = "../update_sig.rs"]
mod update_sig;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    (s.len() % 2 == 0).then_some(())?;
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn load(path: &str) -> SigningKey {
    let bytes = unhex(&fs::read_to_string(path).expect("read key")).expect("hex key");
    SigningKey::from_bytes(&bytes.try_into().expect("32-byte key"))
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("keygen") => {
            let path = a.get(2).expect("key file");
            if fs::metadata(path).is_ok() {
                eprintln!("refusing to overwrite existing key: {path}");
                std::process::exit(2);
            }
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).expect("os randomness");
            let key = SigningKey::from_bytes(&seed);
            fs::write(path, hex(&seed)).expect("write key");
            println!("{}", hex(key.verifying_key().as_bytes()));
        }
        Some("pubkey") => println!(
            "{}",
            hex(load(a.get(2).expect("key file")).verifying_key().as_bytes())
        ),
        Some("sign") => {
            let key = load(a.get(2).expect("key file"));
            let file = a.get(3).expect("latest.json");
            let text = fs::read_to_string(file).expect("read latest.json");
            let mut v: serde_json::Value =
                serde_json::from_str(text.trim_start_matches('\u{feff}')).expect("json");
            let msg = update_sig::update_message(&v);
            v["signature"] = serde_json::json!(hex(&key.sign(msg.as_bytes()).to_bytes()));
            fs::write(file, serde_json::to_string_pretty(&v).unwrap()).expect("write latest.json");
            println!("signed {file}");
        }
        _ => {
            eprintln!(
                "usage: madar-release-sign keygen <key> | pubkey <key> | sign <key> <latest.json>"
            );
            std::process::exit(2);
        }
    }
}
