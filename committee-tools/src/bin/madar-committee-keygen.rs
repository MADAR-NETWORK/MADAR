//! Generates a MADAR network upgrade-committee member account (D44) — **run this only on an
//! air-gapped machine with no network connection**. A key space **completely separate**
//! from the release-signing keys (D35/D43, Ed25519 off-chain) — never store
//! both on the same medium or mix them.
//!
//! The secret phrase (mnemonic, a standard 12 words) is encrypted immediately (the same mechanism as
//! `madar-keystore`: Argon2id + ChaCha20-Poly1305) before any
//! `std::fs::write` — no plain text is ever written to disk.

#![deny(unsafe_code)]

use sp_core::{
    crypto::{Pair as _, Ss58Codec},
    sr25519,
};
use zeroize::Zeroizing;

fn main() {
    let mut key_id: Option<String> = None;
    let mut out_dir = std::path::PathBuf::from(".");

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--key-id" => key_id = args.next(),
            "--out-dir" => {
                if let Some(v) = args.next() {
                    out_dir = std::path::PathBuf::from(v);
                }
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    let Some(key_id) = key_id else {
        eprintln!(
            "usage: madar-committee-keygen --key-id <ID, e.g. upgrade-committee-1> [--out-dir <folder>]"
        );
        std::process::exit(2);
    };
    if !madar_keystore::is_safe_key_id(&key_id) {
        eprintln!("--key-id accepts Latin letters, digits and - _ . only (no path separators) — rejected: {key_id:?}");
        std::process::exit(2);
    }

    eprintln!("=== Generating a MADAR upgrade-committee member account (D44) ===");
    eprintln!("⚠️  Run this only on an air-gapped machine with no network connection.");
    eprintln!(
        "⚠️  Do not mix this with D35 keys (release signing) — a completely different key space."
    );
    eprintln!();

    let passphrase = zeroize::Zeroizing::new(
        rpassword::prompt_password("Account encryption passphrase: ")
            .expect("could not read the passphrase"),
    );
    let confirm = zeroize::Zeroizing::new(
        rpassword::prompt_password("Type it again to confirm: ")
            .expect("could not read the passphrase"),
    );

    if passphrase != confirm {
        eprintln!("the passphrases do not match — stopped, no file was written.");
        std::process::exit(1);
    }
    if passphrase.len() < 12 {
        eprintln!("the passphrase is shorter than 12 characters — stopped for security reasons, no file was written.");
        std::process::exit(1);
    }

    let (pair, phrase, _seed) = sr25519::Pair::generate_with_phrase(None);
    let phrase = Zeroizing::new(phrase);

    let account_hex = hex::encode(pair.public().0);
    // Prefix 42 (generic dev) for display only — unrelated to the network's final
    // prefix; the identifier that is actually
    // trusted is the raw hex above, fixed regardless of any prefix.
    let ss58_dev = pair.public().to_ss58check();

    let backup = madar_keystore::backup_secret(phrase.as_bytes(), passphrase.as_str())
        .unwrap_or_else(|e| {
            eprintln!(
                "encrypting the secret phrase failed ({e:?}) — stopped, no file was written."
            );
            std::process::exit(1);
        });

    std::fs::create_dir_all(&out_dir).expect("could not create the output folder");
    let enc_path = out_dir.join(format!("{key_id}.enc"));
    let pub_path = out_dir.join(format!("{key_id}.pub"));

    std::fs::write(&enc_path, backup.to_bytes()).expect("failed to write the encrypted file");
    std::fs::write(
        &pub_path,
        format!("account_id_hex={account_hex}\nss58_dev_prefix42={ss58_dev}\n"),
    )
    .expect("failed to write the public file");

    println!("Account generated successfully:");
    println!(
        "  Encrypted file (private, never published or committed to Git): {}",
        enc_path.display()
    );
    println!(
        "  Public file (safe to publish/add to genesis): {}",
        pub_path.display()
    );
    println!("  AccountId (Hex): {account_hex}");
    println!();
    println!("Mandatory next steps (see the committee-key SOP):");
    println!(
        "  1. Copy {} immediately to exactly one of the three encrypted USB media.",
        enc_path.display()
    );
    println!("  2. Delete the file from this machine after confirming the copy succeeded.");
    println!("  3. Store the passphrase completely apart from the medium itself.");
    println!(
        "  4. Never repeat this on the same medium for another account — one medium per account."
    );
}
