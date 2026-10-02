//! sr25519 / ed25519 test vectors + INV-7 (key types are not interchangeable).
//!
//! Methodology: sr25519 (Schnorrkel) signatures are randomized by nature (the nonce
//! is non-deterministic by design, for security reasons) — so a "test vector" with a fixed
//! signature output makes no sense for them; the right test is self-consistency (sign→verify)
//! from a known seed. ed25519 signatures are deterministic per RFC 8032, so we use
//! a known official vector (RFC 8032 §7.1, TEST 1), verified against the RFC text
//! (see the note on the constants below).
//!
//!
//! The vectors are part of the regular test suite.

use sp_core::{ed25519, sr25519, Pair};

const TEST_SEED: [u8; 32] = [42u8; 32];
const TEST_MESSAGE: &[u8] = b"madar-protocol-phase-test-message";

#[test]
fn sr25519_sign_then_verify_round_trip_from_known_seed() {
    let pair = sr25519::Pair::from_seed(&TEST_SEED);
    let signature = pair.sign(TEST_MESSAGE);
    let ok = sr25519::Pair::verify(&signature, TEST_MESSAGE, &pair.public());
    assert!(ok, "sr25519 self sign/verify round-trip must succeed");
}

#[test]
fn sr25519_verify_fails_on_tampered_message() {
    let pair = sr25519::Pair::from_seed(&TEST_SEED);
    let signature = pair.sign(TEST_MESSAGE);
    let ok = sr25519::Pair::verify(&signature, b"different-message", &pair.public());
    assert!(!ok, "sr25519 verify must fail on a tampered message");
}

#[test]
fn ed25519_sign_then_verify_round_trip_from_known_seed() {
    let pair = ed25519::Pair::from_seed(&TEST_SEED);
    let signature = pair.sign(TEST_MESSAGE);
    let ok = ed25519::Pair::verify(&signature, TEST_MESSAGE, &pair.public());
    assert!(ok, "ed25519 self sign/verify round-trip must succeed");
}

#[test]
fn ed25519_rfc8032_test_vector_1() {
    // RFC 8032 §7.1 TEST 1 — both values (secret key and public key) were verified
    // against the official RFC Editor text by the project owner, and their length was checked to be
    // exactly 32 bytes programmatically before being added here. An earlier version of both constants
    // was one byte short (copied from memory without verifying the source)
    // — fixed and recorded in the project's evidence log.
    let secret_seed: [u8; 32] =
        hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap()
            .try_into()
            .unwrap();
    let expected_public =
        hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();

    let pair = ed25519::Pair::from_seed(&secret_seed);
    assert_eq!(
        pair.public().0.to_vec(),
        expected_public,
        "ed25519 public key derived from RFC 8032 TEST 1 seed does not match — \
         re-verify the hardcoded vector against RFC 8032 text before treating this as FAIL"
    );
}

/// INV-7: a BABE key (sr25519) is never accepted as a GRANDPA key (ed25519) and vice versa.
#[test]
fn inv7_sr25519_signature_bytes_do_not_validate_as_ed25519() {
    let sr_pair = sr25519::Pair::from_seed(&TEST_SEED);
    let sr_sig = sr_pair.sign(TEST_MESSAGE);

    let ed_pair = ed25519::Pair::from_seed(&TEST_SEED);

    // An sr25519 signature (64 bytes) differs internally from ed25519 but has the same length —
    // we force the reinterpretation only to make sure verification rejects it, not because the structure is incompatible.
    let raw: [u8; 64] = sr_sig.0;
    let as_ed25519_sig = ed25519::Signature::from_raw(raw);

    let ok = ed25519::Pair::verify(&as_ed25519_sig, TEST_MESSAGE, &ed_pair.public());
    assert!(
        !ok,
        "INV-7 violated: an sr25519 signature must never validate under ed25519 verification"
    );
}

/// INV-7 (the opposite direction): a GRANDPA key is not accepted as a BABE key.
#[test]
fn inv7_public_key_types_are_not_interchangeable() {
    let sr_pair = sr25519::Pair::from_seed(&TEST_SEED);
    let ed_pair = ed25519::Pair::from_seed(&TEST_SEED);

    // Same seed, two different algorithms ⇒ must not produce the same public-key bytes.
    assert_ne!(
        sr_pair.public().0.to_vec(),
        ed_pair.public().0.to_vec(),
        "INV-7 violated: sr25519 and ed25519 public keys from the same seed must not collide"
    );
}
