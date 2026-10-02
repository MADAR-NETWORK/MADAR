//! N1 ((internal design document)) — on the actual Runtime: `dev_only_force_set_validators`
//! and `ban_key` are reachable by no origin, not even the Root produced by the upgrade committee via `dispatch_as_root`
//! (with 2-of-3 or 3-of-3 approval). The inner call is rejected with `BadOrigin` and leaves no trace.

mod common;

use frame_support::assert_ok;
use madar_consensus::{
    Runtime, RuntimeCall, RuntimeEvent, RuntimeOrigin, UpgradeCommitteeInstance,
};
use pallet_collective::RawOrigin as CollectiveRawOrigin;
use sp_runtime::DispatchError;

fn members_origin(yes: u32, total: u32) -> RuntimeOrigin {
    CollectiveRawOrigin::<sp_runtime::AccountId32, UpgradeCommitteeInstance>::Members(yes, total)
        .into()
}

fn force_set(target: sp_runtime::AccountId32) -> Box<RuntimeCall> {
    Box::new(RuntimeCall::Admission(
        madar_admission::Call::dev_only_force_set_validators {
            validators: vec![target],
        },
    ))
}

fn ban(offender: sp_runtime::AccountId32) -> Box<RuntimeCall> {
    Box::new(RuntimeCall::Admission(madar_admission::Call::ban_key {
        offender,
    }))
}

/// Result of the last inner call executed by the committee (the outer wrapper always returns Ok by design).
fn last_committee_dispatch_result() -> sp_runtime::DispatchResult {
    frame_system::Pallet::<Runtime>::events()
        .into_iter()
        .rev()
        .find_map(|r| match r.event {
            RuntimeEvent::UpgradeAuthority(
                madar_upgrade_authority::Event::RootCallDispatched { result },
            ) => Some(result),
            _ => None,
        })
        .expect("the committee dispatch must emit RootCallDispatched")
}

#[test]
fn the_committee_cannot_force_set_validators() {
    common::new_test_ext(&[]).execute_with(|| {
        frame_system::Pallet::<Runtime>::set_block_number(1);
        let target = common::dev_validator(9).account;

        for (yes, total) in [(2, 3), (3, 3)] {
            assert_ok!(madar_consensus::UpgradeAuthority::dispatch_as_root(
                members_origin(yes, total),
                force_set(target.clone())
            ));
            assert_eq!(
                last_committee_dispatch_result(),
                Err(DispatchError::BadOrigin),
                "{yes}-of-{total}"
            );
            assert!(
                madar_admission::Pallet::<Runtime>::validators().is_empty(),
                "no validator set change"
            );
        }
    });
}

#[test]
fn the_committee_cannot_ban_a_key() {
    common::new_test_ext(&[]).execute_with(|| {
        frame_system::Pallet::<Runtime>::set_block_number(1);
        let offender = common::dev_validator(9).account;

        for (yes, total) in [(2, 3), (3, 3)] {
            assert_ok!(madar_consensus::UpgradeAuthority::dispatch_as_root(
                members_origin(yes, total),
                ban(offender.clone())
            ));
            assert_eq!(
                last_committee_dispatch_result(),
                Err(DispatchError::BadOrigin),
                "{yes}-of-{total}"
            );
            assert!(
                !madar_admission::BannedKeys::<Runtime>::contains_key(&offender),
                "no ban recorded"
            );
        }
    });
}

#[test]
fn a_direct_root_origin_is_rejected_for_both_calls() {
    common::new_test_ext(&[]).execute_with(|| {
        let who = common::dev_validator(9).account;
        assert_eq!(
            madar_admission::Pallet::<Runtime>::dev_only_force_set_validators(
                RuntimeOrigin::root(),
                vec![who.clone()]
            ),
            Err(DispatchError::BadOrigin)
        );
        assert_eq!(
            madar_admission::Pallet::<Runtime>::ban_key(RuntimeOrigin::root(), who.clone()),
            Err(DispatchError::BadOrigin)
        );
        assert!(madar_admission::Pallet::<Runtime>::validators().is_empty());
        assert!(!madar_admission::BannedKeys::<Runtime>::contains_key(&who));
    });
}
