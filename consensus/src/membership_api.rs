//! The read logic behind `MembershipApi` (T5): pure functions that only read existing storage (no writes, no Argon2, no new storage, no new rules). Placed here
//! (not inside `impl_runtime_apis!`) so they can be tested directly in `TestExternalities` without a full runtime API call.

use crate::{AccountId, Runtime};
use frame_support::traits::{Get, Randomness};
use madar_admission_api::{AdmissionParamsV1, MembershipStatusV1, PuzzleChallengeV1};
use parity_scale_codec::Encode;

pub fn status(who: &AccountId) -> MembershipStatusV1 {
    MembershipStatusV1 {
        current_session: pallet_session::CurrentIndex::<Runtime>::get(),
        is_member: madar_admission::Validators::<Runtime>::get().contains(who),
        is_active_authority: pallet_session::Validators::<Runtime>::get().contains(who),
        expiry_session: madar_admission::MembershipExpiry::<Runtime>::get(who),
        is_banned: madar_admission::BannedKeys::<Runtime>::contains_key(who),
        exit_pending: madar_admission::PendingVoluntaryExit::<Runtime>::contains_key(who),
        is_candidate: madar_admission::Pallet::<Runtime>::is_candidate(who),
        session_keys: pallet_session::NextKeys::<Runtime>::get(who).map(|k| k.encode()),
    }
}

pub fn params() -> AdmissionParamsV1 {
    AdmissionParamsV1 {
        membership_term_sessions: <Runtime as madar_admission::Config>::MembershipTermSessions::get(
        ),
        renewal_grace_sessions: <Runtime as madar_admission::Config>::RenewalGraceSessions::get(),
        puzzle_difficulty_bits:
            <Runtime as madar_admission::Config>::DifficultyLeadingZeroBits::get(),
        argon_memory_kib: <Runtime as madar_admission::Config>::ArgonMemoryCostKib::get(),
        argon_time_cost: <Runtime as madar_admission::Config>::ArgonTimeCost::get(),
        max_validators: <Runtime as madar_admission::Config>::MaxValidators::get(),
        max_candidates_per_round: <Runtime as madar_admission::Config>::MaxCandidatesPerRound::get(
        ),
        admission_cap_per_round: <Runtime as madar_admission::Config>::AdmissionCapPerRound::get(),
        min_fresh_entropy_blocks: <Runtime as madar_admission::Config>::MinFreshEntropyBlocks::get(
        ),
        epoch_duration_slots: <Runtime as pallet_babe::Config>::EpochDuration::get(),
    }
}

/// The seed is **the same** one used by `submit_admission_solution` (`EpochRandomness::random(ADMISSION_PUZZLE_DOMAIN)`): a single source of truth.
pub fn challenge() -> PuzzleChallengeV1 {
    let (round_seed, _) = <<Runtime as madar_admission::Config>::EpochRandomness as Randomness<
        _,
        _,
    >>::random(madar_protocol::ADMISSION_PUZZLE_DOMAIN);
    PuzzleChallengeV1 {
        round_seed,
        current_session: pallet_session::CurrentIndex::<Runtime>::get(),
        epoch_start_slot: u64::from(pallet_babe::Pallet::<Runtime>::current_epoch_start()),
        epoch_duration_slots: <Runtime as pallet_babe::Config>::EpochDuration::get(),
        current_slot: u64::from(pallet_babe::Pallet::<Runtime>::current_slot()),
    }
}
