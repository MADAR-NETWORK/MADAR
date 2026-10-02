//! T5: `MembershipApi` (read logic in `madar_consensus::membership_api`) — status, parameters, challenge; round boundaries; and that it **writes nothing**
//! and does not change state transitions (the other Pallet tests were not modified and pass as-is).

mod common;

use common::{dev_validator, new_test_ext};
use frame_support::{traits::Get, BoundedVec};
use madar_consensus::{membership_api, AccountId, Runtime};
use parity_scale_codec::Encode;
use sp_consensus_babe::Slot;

fn account(i: u8) -> AccountId {
    AccountId::from([i; 32])
}

fn written_keys(ext: &sp_io::TestExternalities) -> usize {
    ext.overlayed_changes()
        .changes()
        .filter(|(k, _)| k.as_slice() != b":transaction_level:")
        .count()
}

#[test]
fn status_reports_each_flag_from_existing_storage_only() {
    let mut ext = new_test_ext(&[dev_validator(1)]);
    ext.execute_with(|| {
        let (member, banned, exiting, candidate, pending_candidate, keyed, nobody) = (
            account(10),
            account(11),
            account(12),
            account(13),
            account(14),
            account(15),
            account(99),
        );
        madar_admission::Validators::<Runtime>::put(
            BoundedVec::try_from(vec![member.clone(), exiting.clone()]).unwrap(),
        );
        madar_admission::MembershipExpiry::<Runtime>::insert(&member, 9u32);
        madar_admission::MembershipExpiry::<Runtime>::insert(&exiting, 4u32);
        madar_admission::PendingVoluntaryExit::<Runtime>::insert(&exiting, ());
        madar_admission::BannedKeys::<Runtime>::insert(&banned, ());
        let pool = |a: &AccountId| BoundedVec::try_from(vec![(a.clone(), [0u8; 32])]).unwrap();
        madar_admission::Round::<Runtime>::put((sp_core::H256::zero(), pool(&candidate)));
        madar_admission::Pending::<Runtime>::put(
            BoundedVec::try_from(vec![(1u32, 1u64, pool(&pending_candidate))]).unwrap(),
        );
        let d = dev_validator(2);
        pallet_session::NextKeys::<Runtime>::insert(
            &keyed,
            madar_consensus::SessionKeys {
                babe: d.babe.clone(),
                grandpa: d.grandpa.clone(),
            },
        );

        let s = membership_api::status(&member);
        assert!(
            s.is_member
                && s.expiry_session == Some(9)
                && !s.is_banned
                && !s.exit_pending
                && !s.is_candidate
                && s.session_keys.is_none()
        );
        let s = membership_api::status(&exiting);
        assert!(s.is_member && s.exit_pending && s.expiry_session == Some(4));
        assert!(membership_api::status(&banned).is_banned);
        assert!(
            membership_api::status(&candidate).is_candidate,
            "candidate in the open round"
        );
        assert!(
            membership_api::status(&pending_candidate).is_candidate,
            "candidate in a closed pool waiting for the draw"
        );
        let k = membership_api::status(&keyed);
        assert_eq!(
            k.session_keys,
            Some(
                madar_consensus::SessionKeys {
                    babe: d.babe,
                    grandpa: d.grandpa
                }
                .encode()
            )
        );
        let n = membership_api::status(&nobody);
        assert!(
            !n.is_member
                && !n.is_candidate
                && !n.is_banned
                && !n.exit_pending
                && n.expiry_session.is_none()
                && n.session_keys.is_none()
        );
        // The actual authority from Session.Validators (test Genesis: dev_validator(1)).
        assert!(membership_api::status(&dev_validator(1).account).is_active_authority);
        assert!(!membership_api::status(&member).is_active_authority);
    });
}

#[test]
fn a_candidate_who_wins_is_no_longer_reported_as_a_candidate_and_a_leaving_member_keeps_only_the_facts(
) {
    new_test_ext(&[dev_validator(1)]).execute_with(|| {
        let who = account(30);
        let pool = BoundedVec::try_from(vec![(who.clone(), [0u8; 32])]).unwrap();
        madar_admission::Round::<Runtime>::put((sp_core::H256::zero(), pool));
        assert!(membership_api::status(&who).is_candidate);
        // After the draw: it leaves the set and enters Validators (what new_session does) — reads follow storage only.
        madar_admission::Round::<Runtime>::kill();
        madar_admission::Validators::<Runtime>::put(
            BoundedVec::try_from(vec![who.clone()]).unwrap(),
        );
        madar_admission::MembershipExpiry::<Runtime>::insert(&who, 10u32);
        let s = membership_api::status(&who);
        assert!(!s.is_candidate && s.is_member && s.expiry_session == Some(10));
    });
}

#[test]
fn params_are_exactly_the_runtime_configuration() {
    new_test_ext(&[dev_validator(1)]).execute_with(|| {
        let p = membership_api::params();
        assert_eq!(p.membership_term_sessions, madar_consensus::MEMBERSHIP_TERM_SESSIONS);
        assert_eq!(p.renewal_grace_sessions, madar_consensus::RENEWAL_GRACE_SESSIONS);
        assert_eq!(p.puzzle_difficulty_bits, madar_consensus::PUZZLE_DIFFICULTY_BITS);
        assert_eq!(p.min_fresh_entropy_blocks, madar_consensus::MIN_FRESH_ENTROPY_BLOCKS);
        assert_eq!(p.epoch_duration_slots, madar_consensus::EPOCH_DURATION_IN_SLOTS);
        assert_eq!(p.max_validators, <<Runtime as madar_admission::Config>::MaxValidators as frame_support::traits::Get<u32>>::get());
        assert_eq!(p.argon_memory_kib, <<Runtime as madar_admission::Config>::ArgonMemoryCostKib as frame_support::traits::Get<u32>>::get());
        assert_eq!(p.argon_time_cost, <<Runtime as madar_admission::Config>::ArgonTimeCost as frame_support::traits::Get<u32>>::get());
    });
}

#[test]
fn the_challenge_seed_is_the_one_the_extrinsic_uses_and_its_validity_window_follows_the_epoch() {
    use frame_support::traits::Randomness;
    new_test_ext(&[dev_validator(1)]).execute_with(|| {
        let epoch = madar_consensus::EPOCH_DURATION_IN_SLOTS;
        pallet_babe::GenesisSlot::<Runtime>::put(Slot::from(1000));
        // Epoch start = slot 1000, current 1000 + 10.
        pallet_babe::CurrentSlot::<Runtime>::put(Slot::from(1010));
        pallet_babe::EpochIndex::<Runtime>::put(0u64);
        let c = membership_api::challenge();
        let (seed, _) = <<Runtime as madar_admission::Config>::EpochRandomness as Randomness<
            _,
            _,
        >>::random(madar_protocol::ADMISSION_PUZZLE_DOMAIN);
        assert_eq!(
            c.round_seed, seed,
            "one source of truth: the same call the pallet makes"
        );
        assert_eq!(c.epoch_duration_slots, epoch);
        assert_eq!(c.current_slot, 1010);
        assert_eq!(c.epoch_start_slot, 1000);
        assert_eq!(c.slots_remaining(), epoch - 10);
        // Round boundary: at the last slot and beyond, nothing remains.
        pallet_babe::CurrentSlot::<Runtime>::put(Slot::from(1000 + epoch - 1));
        assert_eq!(membership_api::challenge().slots_remaining(), 1);
        pallet_babe::CurrentSlot::<Runtime>::put(Slot::from(1000 + epoch));
        assert_eq!(
            membership_api::challenge().slots_remaining(),
            0,
            "the seed changes at the boundary"
        );
        pallet_babe::CurrentSlot::<Runtime>::put(Slot::from(1000 + epoch + 500));
        assert_eq!(
            membership_api::challenge().slots_remaining(),
            0,
            "never underflows if the epoch change is late"
        );
    });
}

#[test]
fn the_session_index_and_session_boundaries_are_reflected() {
    new_test_ext(&[dev_validator(1)]).execute_with(|| {
        let before = membership_api::status(&account(1)).current_session;
        pallet_babe::Initialized::<Runtime>::put(None::<sp_consensus_babe::digests::PreDigest>);
        pallet_session::Pallet::<Runtime>::rotate_session();
        assert_eq!(
            membership_api::status(&account(1)).current_session,
            before + 1
        );
        assert_eq!(membership_api::challenge().current_session, before + 1);
    });
}

#[test]
fn reading_the_api_writes_nothing() {
    let mut ext = new_test_ext(&[dev_validator(1)]);
    ext.commit_all().unwrap();
    ext.execute_with(|| {
        let _ = membership_api::status(&dev_validator(1).account);
        let _ = membership_api::status(&account(77));
        let _ = membership_api::params();
        let _ = membership_api::challenge();
    });
    assert_eq!(written_keys(&ext), 0, "the API is strictly read-only");
}
