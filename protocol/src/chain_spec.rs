//! Chain identifiers, SS58 network prefix, and Genesis fields.
//!
//! Per §2.1, §2.5 and §2.10 of the design document.
//! There is no custom cryptography here — encoding and hashing are consumed directly from
//! `parity-scale-codec` and `sp-core` as they are (§2.12).

use alloc::{string::String, vec::Vec};
use parity_scale_codec::{Decode, Encode};
use sp_core::H256;

/// Chain ID (`protocolId`) — used **only** at the libp2p layer to isolate peer
/// discovery between different networks. It is never part of any cryptographic signature (§2.1).
pub mod chain_id {
    pub const DEV: &str = "madar-dev";
    pub const TESTNET: &str = "madar-testnet";
    /// Reserved for the future Mainnet — not used before the official Mainnet is approved.
    pub const MAINNET: &str = "madar";
}

/// SS58 Network Prefix.
///
/// - Local development: `42` — the same value as the generic `node-template`,
///   not a MADAR-specific identity (§2.5).
/// - The network itself uses `SS58_PREFIX` below; changing a prefix is treated
///   as a genesis-level decision (§26), never made silently.
///
pub const SS58_PREFIX_DEV: u16 = 42;

/// The MADAR network prefix (owner decision 2026-09-28, B5): **85**. The official `ss58-registry` has been archived since 2026-04-16 and
/// no longer accepts requests, and 85 is not reserved in its latest version; we adopt and announce it. Enters the runtime with spec 6. `SS58_PREFIX_DEV` remains for local development.
pub const SS58_PREFIX: u16 = 85;

/// The mandatory genesis fields per §2.10 of the design document.
///
/// This structure represents the **data** only, not the full FRAME `GenesisConfig`
/// (which comes in the later State/Ledger and Consensus phases) — its purpose in
/// this phase is only to prove encoding determinism (INV-1) and change sensitivity (INV-5).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct GenesisFields {
    /// Chain ID as in `chain_id` above.
    pub chain_id: String,
    /// SS58 Network Prefix.
    pub ss58_prefix: u16,
    /// The initial validator set (raw public keys) and their fixed weights
    /// (flat weight per §2.9 / §3 — not proportional to anything).
    pub initial_validators: Vec<([u8; 32], u64)>,
    /// The initial seed of the first epoch (§2.9: it must be unpredictable and derived from
    /// verifiable final state — in genesis itself it is an explicitly documented initial value).
    pub initial_epoch_seed: [u8; 32],
    /// Slot duration in seconds — a sensitive consensus constant since genesis (§2.8).
    pub slot_duration_secs: u64,
    /// Epoch length in slots — a sensitive consensus constant since genesis (§2.8).
    pub epoch_length_slots: u32,
    /// The initial maximum block size in bytes.
    pub max_block_size_bytes: u32,
    /// The initial maximum transaction size in bytes.
    pub max_transaction_size_bytes: u32,
}

impl GenesisFields {
    /// Genesis hash: Blake2-256 of the deterministic SCALE encoding of all fields (§2.3, §2.6).
    ///
    /// This is **not** necessarily the same genesis hash that `sp-runtime`/`frame-system`
    /// actually produce from the full block (that depends on the real block/header structure,
    /// which was not built yet at this phase) — this is a simplified field-level computation only, to prove INV-1/INV-5
    /// within the scope of the Protocol phase. It is replaced by the real genesis hash computed from the full
    /// block in the Blocks/State phase.
    pub fn fields_hash(&self) -> H256 {
        H256::from(sp_crypto_hashing::blake2_256(&self.encode()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_fields() -> GenesisFields {
        GenesisFields {
            chain_id: chain_id::DEV.to_string(),
            ss58_prefix: SS58_PREFIX_DEV,
            initial_validators: vec![([1u8; 32], 1u64), ([2u8; 32], 1u64)],
            initial_epoch_seed: [7u8; 32],
            slot_duration_secs: 8,
            epoch_length_slots: 900,
            max_block_size_bytes: 5 * 1024 * 1024,
            max_transaction_size_bytes: 512 * 1024,
        }
    }

    #[test]
    fn chain_ids_match_spec() {
        assert_eq!(chain_id::DEV, "madar-dev");
        assert_eq!(chain_id::TESTNET, "madar-testnet");
        assert_eq!(chain_id::MAINNET, "madar");
    }

    #[test]
    fn ss58_prefix_dev_is_42() {
        // §2.5: the ecosystem-wide dev placeholder value used before registering a dedicated prefix.
        assert_eq!(SS58_PREFIX_DEV, 42);
    }

    #[test]
    fn madar_prefix_is_85_and_distinct_from_dev() {
        assert_eq!(SS58_PREFIX, 85);
        assert_ne!(SS58_PREFIX, SS58_PREFIX_DEV);
    }

    #[test]
    fn slot_and_epoch_match_locked_constants() {
        // §2.8: Slot = 8s, Epoch = 900 slots (two hours) — fixed since genesis.
        let f = sample_fields();
        assert_eq!(f.slot_duration_secs, 8);
        assert_eq!(f.epoch_length_slots, 900);
    }

    /// INV-5: changing one genesis field produces a completely different genesis hash.
    #[test]
    fn changing_one_field_changes_the_hash_completely() {
        let base = sample_fields();
        let base_hash = base.fields_hash();

        let mut changed = base.clone();
        changed.epoch_length_slots += 1;
        let changed_hash = changed.fields_hash();

        assert_ne!(
            base_hash, changed_hash,
            "INV-5 violated: single-field change did not change the hash"
        );
    }
}
