//! Blake2-256 test vectors — the first item of the Protocol gate (§5).
//!
//! **Methodology of matching against an "independent reference library":** since `sp_crypto_hashing::blake2_256`
//! is itself what everything is later built on, comparing it with itself makes no sense.
//! Here we use the `blake2` crate (an independent dependency, fully separate in implementation from
//! any internal `sp_core` code) to compute Blake2b with a 256-bit output for the same inputs,
//! and compare the two results byte by byte. This gives real cross-evidence between two independent
//! implementations, instead of relying on a manually copied reference number that could contain a copy error.
//!
//! Part of the regular test suite.
//!

use blake2::{digest::consts::U32, Blake2b, Digest};

type Blake2b256Ref = Blake2b<U32>;

fn independent_blake2_256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b256Ref::new();
    hasher.update(input);
    let out = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

#[test]
fn blake2_256_matches_independent_implementation_on_empty_input() {
    let a = sp_crypto_hashing::blake2_256(b"");
    let b = independent_blake2_256(b"");
    assert_eq!(
        a, b,
        "sp_crypto_hashing::blake2_256 diverges from independent blake2 crate on empty input"
    );
}

#[test]
fn blake2_256_matches_independent_implementation_on_known_string() {
    let input = b"abc";
    let a = sp_crypto_hashing::blake2_256(input);
    let b = independent_blake2_256(input);
    assert_eq!(
        a, b,
        "sp_crypto_hashing::blake2_256 diverges from independent blake2 crate on b\"abc\""
    );
}

#[test]
fn blake2_256_matches_independent_implementation_on_madar_domain_tag() {
    // The same actual bytes used later in the Admission puzzle (§2.7/§2.9).
    let input = madar_protocol::ADMISSION_PUZZLE_DOMAIN;
    let a = sp_crypto_hashing::blake2_256(input);
    let b = independent_blake2_256(input);
    assert_eq!(a, b);
}

#[test]
fn blake2_256_is_deterministic_across_repeated_calls_same_process() {
    let input = b"madar-determinism-check";
    let first = sp_crypto_hashing::blake2_256(input);
    let second = sp_crypto_hashing::blake2_256(input);
    assert_eq!(
        first, second,
        "INV-1 violated: same input produced different hash in the same process"
    );
}

#[test]
fn blake2_256_output_is_32_bytes() {
    assert_eq!(sp_crypto_hashing::blake2_256(b"anything").len(), 32);
}
