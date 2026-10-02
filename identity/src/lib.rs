//! Account identity (`AccountId`/`AccountPublic`/`Signature`) — the Identity/Cryptography phase.
//!
//! Per D8/§2.4/§9 of the design document. There is no custom cryptography here —
//! the types are derived directly from `sp_runtime::{MultiSigner, MultiSignature}` as they are,
//! in the same standard way used across the whole Substrate ecosystem.
//!
//!
//! sr25519 is the default (D8), and ed25519/ecdsa are actually supported through the same type
//! without any additional code — this is proven experimentally in `tests/account_derivation.rs`
//! and is not merely a claim from reading the documentation.
//!
//! **Deliberately outside the scope of this phase**:
//! the BABE/GRANDPA `SessionKeys` (deferred to the Consensus phase), and any
//! actual node-identity code (deferred to the P2P networking phase; documented
//! only as text below, enforcing IDN-2).

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

use sp_runtime::{
    traits::{IdentifyAccount, Verify},
    MultiSignature,
};

/// The account signature — wraps sr25519/ed25519/ecdsa through the standard `MultiSignature`
/// (no custom cryptographic type).
pub type Signature = MultiSignature;

/// The account public key corresponding to [`Signature`] — through the standard `MultiSigner`.
pub type AccountPublic = <Signature as Verify>::Signer;

/// The account identifier (`AccountId`) derived from [`AccountPublic`] — the same `AccountId32`
/// used across the Substrate ecosystem (Blake2-256 hashing of non-default public keys,
/// or passing it directly for the standard sr25519/ed25519, according to the `IdentifyAccount`
/// implemented in `sp-runtime` itself — no reimplementation here).
pub type AccountId = <AccountPublic as IdentifyAccount>::AccountId;

// ============================================================================
// Mandatory architectural note — IDN-2 (separating account identity from node identity, §9, §4.8
// of the approved design document):
//
// This file neither defines nor imports any node identity type (Node/libp2p identity).
// The two spaces are completely separate by design: no `From`/`Into` between `AccountId` here
// and any future node identity type. The actual node identity code is built exclusively in the P2P
// networking phase (explicit owner decision: document the required interface only
// for now, no production placeholder). The interface required later: an independent key type
// (libp2p `Keypair`, not sr25519/ed25519 through `MultiSigner`), with no implicit or explicit
// conversion from/to the `AccountId` defined here.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use sp_core::{ecdsa, ed25519, sr25519, Pair};

    /// Actual proof (not an assumption) that `AccountPublic`/`AccountId` are derived from
    /// all three supported key types through `MultiSigner` without any additional code.
    #[test]
    fn account_id_derives_from_all_three_key_types_without_custom_code() {
        let sr25519_pair = sr25519::Pair::from_seed(&[1u8; 32]);
        let sr25519_account: AccountId = AccountPublic::from(sr25519_pair.public()).into_account();

        let ed25519_pair = ed25519::Pair::from_seed(&[1u8; 32]);
        let ed25519_account: AccountId = AccountPublic::from(ed25519_pair.public()).into_account();

        let ecdsa_pair = ecdsa::Pair::from_seed(&[1u8; 32]);
        let ecdsa_account: AccountId = AccountPublic::from(ecdsa_pair.public()).into_account();

        // IDN-1 (additional generalization): three different key types from the same base seed
        // (where applicable) produce completely different AccountIds — no collision.
        assert_ne!(sr25519_account, ed25519_account);
        assert_ne!(sr25519_account, ecdsa_account);
        assert_ne!(ed25519_account, ecdsa_account);
    }
}
