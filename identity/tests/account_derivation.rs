//! Deriving `AccountId` from sr25519/ed25519/ecdsa and SS58 round-trip.
//!
//! Proves D8/§2.4 in practice ("ed25519/ecdsa can additionally be supported... without custom code")
//! and not only in theory. Reuses `SS58_PREFIX_DEV` from `madar-protocol` (no
//! duplicated number here).

use madar_identity::{AccountId, AccountPublic};
use madar_protocol::SS58_PREFIX_DEV;
use sp_core::{crypto::Ss58AddressFormat, crypto::Ss58Codec, ecdsa, ed25519, sr25519, Pair};
use sp_runtime::traits::IdentifyAccount;

fn dev_prefix() -> Ss58AddressFormat {
    Ss58AddressFormat::from(SS58_PREFIX_DEV)
}

#[test]
fn sr25519_account_id_ss58_round_trips_with_dev_prefix() {
    let pair = sr25519::Pair::from_seed(&[3u8; 32]);
    let account: AccountId = AccountPublic::from(pair.public()).into_account();

    let encoded = account.to_ss58check_with_version(dev_prefix());
    let (decoded, decoded_prefix) =
        AccountId::from_ss58check_with_version(&encoded).expect("valid SS58 must decode");

    assert_eq!(
        decoded, account,
        "sr25519-derived AccountId must round-trip through SS58"
    );
    assert_eq!(decoded_prefix, dev_prefix());
}

#[test]
fn ed25519_account_id_ss58_round_trips_with_dev_prefix() {
    let pair = ed25519::Pair::from_seed(&[5u8; 32]);
    let account: AccountId = AccountPublic::from(pair.public()).into_account();

    let encoded = account.to_ss58check_with_version(dev_prefix());
    let (decoded, decoded_prefix) =
        AccountId::from_ss58check_with_version(&encoded).expect("valid SS58 must decode");

    assert_eq!(
        decoded, account,
        "ed25519-derived AccountId must round-trip through SS58"
    );
    assert_eq!(decoded_prefix, dev_prefix());
}

/// D8/§2.4: the text says ecdsa is supported "later", but it actually works now through
/// `MultiSigner`/`MultiSignature` without any additional code — this test proves it
/// experimentally at minimum cost (the dependencies already exist in the sp-core tree).
#[test]
fn ecdsa_account_id_ss58_round_trips_with_dev_prefix() {
    let pair = ecdsa::Pair::from_seed(&[7u8; 32]);
    let account: AccountId = AccountPublic::from(pair.public()).into_account();

    let encoded = account.to_ss58check_with_version(dev_prefix());
    let (decoded, decoded_prefix) =
        AccountId::from_ss58check_with_version(&encoded).expect("valid SS58 must decode");

    assert_eq!(
        decoded, account,
        "ecdsa-derived AccountId must round-trip through SS58"
    );
    assert_eq!(decoded_prefix, dev_prefix());
}

#[test]
fn different_seeds_never_derive_the_same_account_id() {
    let a: AccountId =
        AccountPublic::from(sr25519::Pair::from_seed(&[9u8; 32]).public()).into_account();
    let b: AccountId =
        AccountPublic::from(sr25519::Pair::from_seed(&[10u8; 32]).public()).into_account();

    assert_ne!(a, b, "distinct seeds must never derive the same AccountId");
}
