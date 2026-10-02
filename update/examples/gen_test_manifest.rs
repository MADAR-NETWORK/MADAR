//! A local development tool only: generates a signed test manifest (a dummy test key, unrelated
//! to D35 or any production key) to use manually with
//! `madar-node check-update` during local development/verification. **Its output must never
//! be used for a real release.**
//!
//! Usage: `cargo run --example gen_test_manifest -- <seed-byte> <out-prefix> [key_id]`

use ed25519_dalek::{Signer, SigningKey};
use madar_update::{ReleaseArtifact, ReleaseChannel, ReleaseManifest};

fn main() {
    let mut args = std::env::args().skip(1);
    let seed_byte: u8 = args.next().and_then(|s| s.parse().ok()).unwrap_or(0xAA);
    let out_prefix = args.next().unwrap_or_else(|| "test-manifest".to_string());
    let key_id = args
        .next()
        .unwrap_or_else(|| "local-dev-test-key".to_string());

    let key = SigningKey::from_bytes(&[seed_byte; 32]);

    let manifest = ReleaseManifest {
        version: "9.9.9".to_string(),
        channel: ReleaseChannel::Development,
        artifacts: vec![ReleaseArtifact {
            platform: "x86_64-pc-windows-msvc".to_string(),
            url: "https://example.invalid/madar-node.exe".to_string(),
            sha256: "0".repeat(64),
        }],
        key_id,
    };

    let json = serde_json::to_vec_pretty(&manifest).unwrap();
    let signature = key.sign(&json);

    std::fs::write(format!("{out_prefix}.json"), &json).unwrap();
    std::fs::write(format!("{out_prefix}.sig"), signature.to_bytes()).unwrap();

    println!("wrote {out_prefix}.json / {out_prefix}.sig");
    println!(
        "trusted key (hex): {}",
        hex_encode(key.verifying_key().as_bytes())
    );
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
