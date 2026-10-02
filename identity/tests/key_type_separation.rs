//! IDN-1 (corrected after an actual finding — attempt 1,
//! decision log D39).
//!
//! **The original wording was experimentally wrong:** "the same raw bytes as sr25519
//! versus ed25519 never produce the same `AccountId`" — this is not true by the design of the standard
//! `AccountId32`/`MultiSigner` (there is no type tag for the 32-byte sr25519/ed25519 keys,
//! unlike ecdsa, which is hashed). **We do not rely on AccountId32 uniqueness as a security
//! boundary.**
//!
//! **The correct wording (this file tests it in practice):** the actual security protection
//! against key-type confusion happens at **signature verification** (INV-7, §2.11), through
//! the standard `Verify` interface in `sp-runtime` — the same principle tested at the raw level in
//! `protocol/tests/crypto_vectors.rs` (Protocol phase), extended here to the abstraction level of
//! `identity::Signature`/`identity::AccountId` that the later phases actually consume
//! (Transactions and beyond), not to the raw `sp-core` primitives
//! directly.

use madar_identity::{AccountId, AccountPublic, Signature};
use sp_core::{ed25519, sr25519, Pair};
use sp_runtime::traits::{IdentifyAccount, Verify};

const MESSAGE: &[u8] =
    b"IDN-1 (corrected): identity-layer type separation relies on signature verification (INV-7)";

fn account_of<P: Pair>(pair: &P) -> AccountId
where
    AccountPublic: From<P::Public>,
{
    AccountPublic::from(pair.public()).into_account()
}

#[test]
fn genuine_sr25519_signature_verifies_against_its_own_account() {
    let pair = sr25519::Pair::from_seed(&[42u8; 32]);
    let account = account_of(&pair);
    let signature: Signature = pair.sign(MESSAGE).into();

    assert!(
        signature.verify(MESSAGE, &account),
        "a genuine sr25519 signature must verify against its own AccountId through MultiSignature/MultiSigner"
    );
}

#[test]
fn genuine_ed25519_signature_verifies_against_its_own_account() {
    let pair = ed25519::Pair::from_seed(&[42u8; 32]);
    let account = account_of(&pair);
    let signature: Signature = pair.sign(MESSAGE).into();

    assert!(
        signature.verify(MESSAGE, &account),
        "a genuine ed25519 signature must verify against its own AccountId through MultiSignature/MultiSigner"
    );
}

/// IDN-1 (corrected): sr25519 signature bytes reinterpreted as ed25519 never verify
/// against the same account — even knowing that the `AccountId` itself (as the failed
/// attempt 1 proved) may match between the two schemes for the same raw bytes. This is the
/// actual line of defense we rely on, not AccountId uniqueness.
#[test]
fn sr25519_signature_bytes_reinterpreted_as_ed25519_never_verify_against_the_same_account() {
    let pair = sr25519::Pair::from_seed(&[7u8; 32]);
    let account = account_of(&pair);
    let sr25519_signature = pair.sign(MESSAGE);

    let raw: [u8; 64] = sr25519_signature.0;
    let reinterpreted: Signature = ed25519::Signature::from_raw(raw).into();

    assert!(
        !reinterpreted.verify(MESSAGE, &account),
        "IDN-1 (corrected) violated: sr25519 signature bytes reinterpreted as ed25519 verified against the same account"
    );
}

/// The opposite direction (mirrors `inv7_sr25519_signature_bytes_do_not_validate_as_ed25519`
/// and its sibling in the Protocol phase, but at the level of this phase).
#[test]
fn ed25519_signature_bytes_reinterpreted_as_sr25519_never_verify_against_the_same_account() {
    let pair = ed25519::Pair::from_seed(&[7u8; 32]);
    let account = account_of(&pair);
    let ed25519_signature = pair.sign(MESSAGE);

    let raw: [u8; 64] = ed25519_signature.0;
    let reinterpreted: Signature = sr25519::Signature::from_raw(raw).into();

    assert!(
        !reinterpreted.verify(MESSAGE, &account),
        "IDN-1 (corrected) violated: ed25519 signature bytes reinterpreted as sr25519 verified against the same account"
    );
}

/// An explicit record of the discovered fact (we do not hide it, we prove it as a standalone test):
/// the same raw bytes as sr25519 versus ed25519 **may match** as an `AccountId`
/// — and this is **expected and acceptable**, because the protection does not rely on this uniqueness at all.
#[test]
fn same_raw_bytes_may_collide_as_account_id_across_schemes_and_that_is_expected() {
    let bytes = [0u8; 32];
    let sr25519_account: AccountId =
        AccountPublic::from(sr25519::Public::from_raw(bytes)).into_account();
    let ed25519_account: AccountId =
        AccountPublic::from(ed25519::Public::from_raw(bytes)).into_account();

    assert_eq!(
        sr25519_account, ed25519_account,
        "documenting expected AccountId32 behavior: sr25519/ed25519 raw bytes are not scheme-tagged, \
         unlike ecdsa which is hashed — this is exactly why identity-layer security must rely on \
         signature verification (tested above), never on AccountId uniqueness"
    );
}
