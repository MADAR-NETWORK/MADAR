//! SS58 round-trip tests with Prefix=42, and rejection/difference of every other prefix (§2.5, INV-3).
//!
//! The function names (`Ss58AddressFormat`, `to_ss58check_with_version`, ...) follow the
//! historically stable `sp_core::crypto` interface and must be re-checked against the pinned
//! version after any SDK upgrade.
//!

use madar_protocol::SS58_PREFIX_DEV;
use sp_core::crypto::{AccountId32, Ss58AddressFormat, Ss58Codec};

fn sample_account() -> AccountId32 {
    AccountId32::from([11u8; 32])
}

#[test]
fn round_trip_with_dev_prefix_recovers_same_account() {
    let account = sample_account();
    let prefix = Ss58AddressFormat::from(SS58_PREFIX_DEV);

    let encoded = account.to_ss58check_with_version(prefix);
    let (decoded_account, decoded_prefix) =
        AccountId32::from_ss58check_with_version(&encoded).expect("valid SS58 must decode");

    assert_eq!(
        decoded_account, account,
        "SS58 round-trip must recover the exact same account"
    );
    assert_eq!(
        decoded_prefix, prefix,
        "SS58 round-trip must recover the exact same prefix"
    );
}

#[test]
fn address_encoded_with_dev_prefix_decodes_to_different_prefix_than_an_arbitrary_other_prefix() {
    let account = sample_account();
    let dev_prefix = Ss58AddressFormat::from(SS58_PREFIX_DEV);
    let other_prefix = Ss58AddressFormat::from(7u16); // any other arbitrary prefix ≠ 42

    let encoded_dev = account.to_ss58check_with_version(dev_prefix);
    let encoded_other = account.to_ss58check_with_version(other_prefix);

    // Same account, different prefix ⇒ a completely different SS58 string (INV-3).
    assert_ne!(
        encoded_dev, encoded_other,
        "INV-3 violated: same account under different SS58 prefixes must not produce the same address string"
    );

    // And decoding a Prefix=42 string must explicitly read Prefix=42 and nothing else.
    let (_, decoded_prefix) =
        AccountId32::from_ss58check_with_version(&encoded_dev).expect("valid SS58 must decode");
    assert_eq!(decoded_prefix, dev_prefix);
    assert_ne!(decoded_prefix, other_prefix);
}

#[test]
fn malformed_ss58_string_is_rejected() {
    let garbage = "this-is-not-a-valid-ss58-address";
    let result = AccountId32::from_ss58check_with_version(garbage);
    assert!(
        result.is_err(),
        "a malformed string must never decode successfully as SS58"
    );
}
