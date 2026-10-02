//! Generates a MADAR release-signing key (D35) — **run this only on an
//! air-gapped machine with no network connection**, never on a regular development machine or a CI server.
//!
//! The raw private key **is never written to disk** — it is encrypted immediately
//! (Argon2id + ChaCha20-Poly1305 via `madar-keystore`) before any
//! `std::fs::write`. Only the encrypted file (`.enc`) and the public key
//! (`.pub`) are written. See the release-key SOP
//! for the full procedure after running it.

#![deny(unsafe_code)]

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
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
        eprintln!("usage: madar-release-keygen --key-id <ID, e.g. madar-release-2026-09> [--out-dir <folder>]");
        std::process::exit(2);
    };
    if !madar_keystore::is_safe_key_id(&key_id) {
        eprintln!("--key-id accepts Latin letters, digits and - _ . only (no path separators) — rejected: {key_id:?}");
        std::process::exit(2);
    }

    eprintln!("=== Generating a MADAR release-signing key ===");
    eprintln!("⚠️  Run this only on an air-gapped machine with no network connection.");
    eprintln!();

    let passphrase = zeroize::Zeroizing::new(
        rpassword::prompt_password("Key encryption passphrase: ")
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

    let signing_key = SigningKey::generate(&mut OsRng);
    let secret_bytes = Zeroizing::new(signing_key.to_bytes());
    let public_hex = hex::encode(signing_key.verifying_key().as_bytes());

    let backup =
        madar_keystore::backup_secret(&*secret_bytes, passphrase.as_str()).unwrap_or_else(|e| {
            eprintln!("key encryption failed ({e:?}) — stopped, no file was written.");
            std::process::exit(1);
        });

    std::fs::create_dir_all(&out_dir).expect("could not create the output folder");
    let enc_path = out_dir.join(format!("{key_id}.enc"));
    let pub_path = out_dir.join(format!("{key_id}.pub"));

    // Exclusive creation that never overwrites an existing key, a consistent pair or nothing, and read-back verification by decrypting the written file with the same passphrase.
    if let Err(e) = madar_keystore::create_key_files(
        &enc_path,
        &backup.to_bytes(),
        &pub_path,
        public_hex.as_bytes(),
        passphrase.as_str(),
        &*secret_bytes,
    ) {
        eprintln!("failed: {e}");
        std::process::exit(1);
    }

    println!("Key generated successfully:");
    println!(
        "  Encrypted file (private, never published or committed to Git): {}",
        enc_path.display()
    );
    println!("  Public file (safe to publish): {}", pub_path.display());
    println!("  Public key (hex): {public_hex}");
    println!();
    println!("Mandatory next steps (see the release-key SOP):");
    println!(
        "  1. Never add {} to any Git repository.",
        enc_path.display()
    );
    println!(
        "  2. Back up {} on a separate medium (encrypted USB) in a physically safe place.",
        enc_path.display()
    );
    println!("  3. Store the passphrase completely apart from the file itself (a password manager, or paper in a safe).");
    println!("  4. Add only the content of {} to docs/security/release-trusted-keys.json with key_id \"{key_id}\".", pub_path.display());
}
