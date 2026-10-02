//! A **read-only, versioned** runtime API for membership/admission (T5). Tools (`madar-node join`, and in the future `doctor` and the dashboard) read the state through it instead of decoding
//! chain storage and embedding its constants. No new storage, no new membership rules, no Argon2 inside the query, and no exposure of draw/entropy seeds.
//!
//! **Version:** the API is declared in `state_getRuntimeVersion().apis` under the name `MembershipApi` with its number (`#[api_version(1)]`), so clients discover it and reject incompatible ones.
//! Any later type change comes with a new API version (the `…V1` types never change), while V1 stays as long as it is supported.
//! **Consistency:** called through `state_call(method, data, block_hash)` at a **specific hash**, so all answers come from the same block.
//!
//! *What it exposes:* the state of one account, the operating parameters, and the current puzzle challenge (the current round seed is public anyway: whoever solves the puzzle needs it).
//! *What it does not expose:* lists of all rounds/candidates, the lottery draw seed, the entropy accumulator, any internal storage.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use sp_core::{crypto::AccountId32, H256};

/// The API name as it appears in `apis` (its ID = blake2_64 of this name).
pub const API_NAME: &str = "MembershipApi";
/// The version this crate understands (must equal `#[api_version(..)]` below).
pub const SUPPORTED_API_VERSION: u32 = 1;

/// The membership state of one account at a specific block.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, TypeInfo)]
pub struct MembershipStatusV1 {
    pub current_session: u32,
    /// In the declared validator set (`Admission.Validators`).
    pub is_member: bool,
    /// An actual authority now (`Session.Validators`).
    pub is_active_authority: bool,
    pub expiry_session: Option<u32>,
    pub is_banned: bool,
    pub exit_pending: bool,
    /// A candidate in an open round or a closed set awaiting the draw (a flag only, no lists).
    pub is_candidate: bool,
    /// The registered session keys (public) if any — to verify that the operator's node holds the matching private keys.
    pub session_keys: Option<Vec<u8>>,
}

/// The operating parameters needed by the tools.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, TypeInfo)]
pub struct AdmissionParamsV1 {
    pub membership_term_sessions: u32,
    pub renewal_grace_sessions: u32,
    pub puzzle_difficulty_bits: u32,
    pub argon_memory_kib: u32,
    pub argon_time_cost: u32,
    pub max_validators: u32,
    pub max_candidates_per_round: u32,
    pub admission_cap_per_round: u32,
    pub min_fresh_entropy_blocks: u32,
    pub epoch_duration_slots: u64,
}

/// The current candidacy challenge: the round seed the puzzle must be solved on and its validity context (it ends with the current epoch, when the seed changes).
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, TypeInfo)]
pub struct PuzzleChallengeV1 {
    pub round_seed: H256,
    pub current_session: u32,
    pub epoch_start_slot: u64,
    pub epoch_duration_slots: u64,
    pub current_slot: u64,
}

impl PuzzleChallengeV1 {
    /// Remaining slots before the seed changes (0 = the round ended at this block).
    pub fn slots_remaining(&self) -> u64 {
        self.epoch_start_slot
            .saturating_add(self.epoch_duration_slots)
            .saturating_sub(self.current_slot)
    }
}

sp_api::decl_runtime_apis! {
    /// Read-only. See the crate documentation.
    #[api_version(1)]
    pub trait MembershipApi {
        fn membership_status(who: AccountId32) -> MembershipStatusV1;
        fn admission_params() -> AdmissionParamsV1;
        fn puzzle_challenge() -> PuzzleChallengeV1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_remaining_never_underflows() {
        let c = PuzzleChallengeV1 {
            round_seed: H256::zero(),
            current_session: 1,
            epoch_start_slot: 100,
            epoch_duration_slots: 12,
            current_slot: 105,
        };
        assert_eq!(c.slots_remaining(), 7);
        assert_eq!(
            PuzzleChallengeV1 {
                current_slot: 200,
                ..c.clone()
            }
            .slots_remaining(),
            0
        );
    }

    #[test]
    fn v1_encoding_is_stable() {
        // Pinning the V1 encoding: any change to it breaks clients and requires a new API version.
        let s = MembershipStatusV1 {
            current_session: 7,
            is_member: true,
            is_active_authority: false,
            expiry_session: Some(9),
            is_banned: false,
            exit_pending: false,
            is_candidate: true,
            session_keys: None,
        };
        assert_eq!(
            s.encode(),
            vec![7, 0, 0, 0, 1, 0, 1, 9, 0, 0, 0, 0, 0, 1, 0]
        );
    }
}
