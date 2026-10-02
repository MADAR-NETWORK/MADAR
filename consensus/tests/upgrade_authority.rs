//! 2-of-3 Runtime upgrade committee (D43) — actual proof (not an assumption) that the core
//! security control works at the level of the full Runtime, not only at the level of
//! the isolated Pallet: delegating `Root` via `UpgradeAuthority::dispatch_as_root`
//! succeeds with an origin carrying the approval of 2 of 3 members, and is explicitly rejected with the approval of
//! only one member — regardless of any internal timing/Threshold details chosen by whoever
//! submitted the proposal (see the module comment in `upgrade-authority/src/lib.rs`
//! for why this always holds). It is also proven that replacing a member of the committee
//! itself is subject to exactly the same threshold — there is no easier path to change membership.

mod common;

use frame_support::{assert_noop, assert_ok};
use madar_consensus::{Runtime, RuntimeCall, RuntimeOrigin, UpgradeCommitteeInstance};
use pallet_collective::RawOrigin as CollectiveRawOrigin;
use sp_runtime::traits::BadOrigin;

fn members_origin(yes: u32, total: u32) -> RuntimeOrigin {
    CollectiveRawOrigin::<sp_runtime::AccountId32, UpgradeCommitteeInstance>::Members(yes, total)
        .into()
}

/// A raw storage key written by `root_only_call` — an inspectable trace.
const ROOT_PROBE_KEY: &[u8] = b":madar:test:root-probe";

/// A real Root-only call (`frame_system::set_storage`, `ensure_root`) —
/// proves that `dispatch_as_root` actually produces a `Root` origin accepted by the
/// `ensure_root` check inside a completely different Pallet, not merely a formal success of the outer
/// call. (It used to be `dev_only_force_set_validators`, now closed in the Runtime — N1.)
fn root_only_call() -> Box<RuntimeCall> {
    Box::new(RuntimeCall::System(frame_system::Call::set_storage {
        items: vec![(ROOT_PROBE_KEY.to_vec(), b"executed".to_vec())],
    }))
}

fn root_call_executed() -> bool {
    frame_support::storage::unhashed::get_raw(ROOT_PROBE_KEY).is_some()
}

#[test]
fn two_of_three_committee_approval_successfully_dispatches_as_root() {
    common::new_test_ext(&[]).execute_with(|| {
        assert_ok!(madar_consensus::UpgradeAuthority::dispatch_as_root(
            members_origin(2, 3),
            root_only_call()
        ));

        // Actual evidence: the inner (Root-only) call really executed, not merely
        // the absence of an error from the outer wrapper (which always returns Ok by design,
        // matching `pallet_sudo::sudo` — the real result is in the event/trace).
        assert!(root_call_executed());
    });
}

#[test]
fn one_of_three_committee_approval_is_rejected_before_any_dispatch() {
    common::new_test_ext(&[]).execute_with(|| {
        assert_noop!(
            madar_consensus::UpgradeAuthority::dispatch_as_root(
                members_origin(1, 3),
                root_only_call()
            ),
            BadOrigin
        );

        // No side effect at all — the rejection happened before any attempt to execute.
        assert!(!root_call_executed());
    });
}

#[test]
fn signed_origin_from_a_single_committee_member_is_rejected() {
    common::new_test_ext(&[]).execute_with(|| {
        let [member_one, _, _] = common::dev_committee_accounts();

        // A single member only, with its own direct signature (no Collective Origin
        // at all) — must be rejected exactly like the (1-of-3) case, to prove there is
        // no shortcut path for a single member.
        assert_noop!(
            madar_consensus::UpgradeAuthority::dispatch_as_root(
                RuntimeOrigin::signed(member_one),
                root_only_call()
            ),
            BadOrigin
        );
    });
}

fn members() -> Vec<sp_runtime::AccountId32> {
    pallet_collective::Members::<Runtime, UpgradeCommitteeInstance>::get()
}

fn replace(
    origin: RuntimeOrigin,
    new: Vec<sp_runtime::AccountId32>,
) -> frame_support::dispatch::DispatchResult {
    madar_consensus::UpgradeAuthority::set_committee_members(origin, new)
}

/// Direct `pallet_collective::set_members` is disabled even with 3-of-3 unanimity (it used to accept any size).
#[test]
fn the_direct_collective_set_members_path_is_disabled() {
    common::new_test_ext(&[]).execute_with(|| {
        let before = members();
        assert_noop!(
            madar_consensus::UpgradeCommittee::set_members(
                members_origin(3, 3),
                vec![before[0].clone()],
                None,
                3
            ),
            BadOrigin
        );
        assert_eq!(members(), before);
    });
}

/// Replacing the membership requires 2-of-3 and keeps the size at exactly 3: 0/1/2/4 and duplicates are all rejected, and the membership does not change.
#[test]
fn committee_replacement_needs_two_of_three_and_keeps_the_size_exactly_three() {
    common::new_test_ext(&[]).execute_with(|| {
        let [a, b, c] = common::dev_committee_accounts();
        let (r1, r2) = (
            common::dev_validator(9).account,
            common::dev_validator(10).account,
        );
        let original = members();

        // A weaker threshold: rejected.
        assert_noop!(
            replace(members_origin(1, 3), vec![a.clone(), b.clone(), r1.clone()]),
            BadOrigin
        );
        assert_noop!(
            replace(
                RuntimeOrigin::signed(a.clone()),
                vec![a.clone(), b.clone(), r1.clone()]
            ),
            BadOrigin
        );

        // Sizes that weaken the ratio or disable governance: rejected despite 2-of-3.
        for bad in [
            vec![],
            vec![a.clone()],
            vec![a.clone(), b.clone()],
            vec![a.clone(), b.clone(), c.clone(), r1.clone()],
        ] {
            assert_noop!(
                replace(members_origin(2, 3), bad),
                madar_upgrade_authority::Error::<Runtime>::WrongCommitteeSize
            );
        }
        assert_noop!(
            replace(members_origin(2, 3), vec![a.clone(), a.clone(), b.clone()]),
            madar_upgrade_authority::Error::<Runtime>::DuplicateMember
        );
        assert_eq!(
            members(),
            original,
            "no rejected attempt changed the committee"
        );

        // A valid replacement: 2-of-3 and size 3.
        assert_ok!(replace(
            members_origin(2, 3),
            vec![a.clone(), b.clone(), r1.clone()]
        ));
        let mut expected = vec![a.clone(), b.clone(), r1.clone()];
        expected.sort();
        assert_eq!(members(), expected);

        // After the replacement the threshold is still 2-of-3 on the new membership (and 1-of-3 is still rejected).
        assert_noop!(replace(members_origin(1, 3), vec![a, b, r2]), BadOrigin);
    });
}

/// Genesis starts with a committee of exactly the fixed size.
#[test]
fn genesis_committee_has_exactly_the_fixed_size() {
    use frame_support::traits::Get;
    common::new_test_ext(&[]).execute_with(|| {
        assert_eq!(
            members().len() as u32,
            <<Runtime as madar_upgrade_authority::Config>::CommitteeSize as Get<u32>>::get()
        );
    });
}
