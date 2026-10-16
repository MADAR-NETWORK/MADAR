//! spec 9 — the two Admission parameters (round cap, operator cap) on the actual Runtime: start values = D54 (2) and D52 (1)
//! with no migration, changed only by the 2-of-3 committee origin (same as `approve_operator`), and never above the two hard limits (16 and 4) even
//! with the whole committee's approval. `MembershipApi::admission_params` reads the stored value (clients follow it without a rebuild).

mod common;

use madar_consensus::{Runtime, RuntimeOrigin, UpgradeCommitteeInstance};
use pallet_collective::RawOrigin as CollectiveRawOrigin;
use sp_runtime::DispatchError;

type A = madar_admission::Pallet<Runtime>;

fn members(yes: u32) -> RuntimeOrigin {
    CollectiveRawOrigin::<sp_runtime::AccountId32, UpgradeCommitteeInstance>::Members(yes, 3).into()
}

#[test]
fn the_live_defaults_are_the_owner_decisions_and_the_hard_limits_are_compiled_in() {
    use frame_support::traits::Get;
    common::new_test_ext(&[]).execute_with(|| {
        assert_eq!(
            madar_admission::AdmissionCapPerRound::<Runtime>::get(),
            2,
            "D54"
        );
        assert_eq!(
            madar_admission::MaxVotesPerOperator::<Runtime>::get(),
            1,
            "D52"
        );
        assert_eq!(
            <<Runtime as madar_admission::Config>::AdmissionCapPerRoundLimit as Get<u32>>::get(),
            16
        );
        assert_eq!(
            <<Runtime as madar_admission::Config>::MaxVotesPerOperatorLimit as Get<u32>>::get(),
            4
        );
        assert_eq!(
            madar_consensus::membership_api::params().admission_cap_per_round,
            2
        );
    });
}

#[test]
fn only_two_of_three_can_set_them_and_never_past_the_limits() {
    common::new_test_ext(&[]).execute_with(|| {
        frame_system::Pallet::<Runtime>::set_block_number(1);
        // one member, a signed account, root-less paths: refused
        assert_eq!(
            A::set_admission_cap_per_round(members(1), 3),
            Err(DispatchError::BadOrigin)
        );
        assert_eq!(
            A::set_max_votes_per_operator(members(1), 2),
            Err(DispatchError::BadOrigin)
        );
        let someone = common::dev_validator(9).account;
        assert_eq!(
            A::set_admission_cap_per_round(RuntimeOrigin::signed(someone), 3),
            Err(DispatchError::BadOrigin)
        );
        assert_eq!(
            A::set_admission_cap_per_round(RuntimeOrigin::root(), 3),
            Err(DispatchError::BadOrigin),
            "no Root shortcut either"
        );

        // even the whole committee cannot pass the hard limits
        assert!(A::set_admission_cap_per_round(members(3), 17).is_err());
        assert!(A::set_max_votes_per_operator(members(3), 5).is_err());
        assert!(A::set_max_votes_per_operator(members(3), 0).is_err());

        // 2-of-3 within the limits
        A::set_admission_cap_per_round(members(2), 3).unwrap();
        A::set_max_votes_per_operator(members(2), 4).unwrap();
        assert_eq!(madar_admission::AdmissionCapPerRound::<Runtime>::get(), 3);
        assert_eq!(madar_admission::MaxVotesPerOperator::<Runtime>::get(), 4);
        assert_eq!(
            madar_consensus::membership_api::params().admission_cap_per_round,
            3,
            "clients read the stored value"
        );
    });
}

/// The committee tool signs exactly these calls; their encoding is fixed (Admission = 8, call 8 / call 9, u32 LE).
#[test]
fn the_setter_calls_have_stable_indices() {
    use parity_scale_codec::Encode;
    let cap = madar_consensus::RuntimeCall::Admission(
        madar_admission::Call::set_admission_cap_per_round { cap: 3 },
    );
    assert_eq!(cap.encode(), vec![8, 8, 3, 0, 0, 0]);
    let votes = madar_consensus::RuntimeCall::Admission(
        madar_admission::Call::set_max_votes_per_operator { votes: 2 },
    );
    assert_eq!(votes.encode(), vec![8, 9, 2, 0, 0, 0]);
}
