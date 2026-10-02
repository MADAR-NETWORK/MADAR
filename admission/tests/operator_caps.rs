//! D47 — resistance to identity duplication through one operator ("Sybil through many keys, one
//! operator"). Proves that solving the Admission puzzle (PoW) is still necessary but **no longer sufficient**:
//! winning the lottery also requires a vouch from an approved operator (by independent governance, not a name
//! typed by the operator itself), and a clear vote cap per operator.
//!
//! **Reproducing the original problem:** 20 different identities, all actually solving the puzzle
//! (exactly the same real cost as in production) under the control of one operator — proves
//! `twenty_identities_one_operator_are_capped_at_the_approved_vote_limit` that the number
//! of actual votes (live validators) never exceeds the approved cap of that
//! operator, regardless of how many identities it generates.

mod common;

use common::*;
use frame_support::traits::Randomness;
use madar_admission::{
    ApprovedOperators, Error, Event as AdmissionEvent, NodeOperator, OperatorNodes,
};
use pallet_session::SessionManager;
use sp_runtime::AccountId32;

type A = madar_admission::Pallet<TestRuntime>;

fn account(byte: u8) -> AccountId32 {
    AccountId32::from([byte; 32])
}

/// A test operator distinct from [`common::test_operator`] — for these tests only.
/// **A byte range completely separate from `account()`** (offset by 100) to avoid any accidental
/// collision between a node account and an operator account with the same visible number.
fn operator(byte: u8) -> AccountId32 {
    AccountId32::from([byte.wrapping_add(100); 32])
}

fn current_round_seed() -> sp_core::H256 {
    TestRandomness::random(madar_protocol::ADMISSION_PUZZLE_DOMAIN).0
}

/// Actually solves the puzzle and submits it — **without any automatic vouch** (unlike `submit()` in
/// `lifecycle.rs`) so each test here controls who vouches for whom.
fn submit_raw(who: &AccountId32) -> frame_support::dispatch::DispatchResultWithPostInfo {
    let nonce = find_valid_nonce(who, &current_round_seed());
    Admission::submit_admission_solution(RuntimeOrigin::signed(who.clone()), nonce)
}

fn mine(n: u64) {
    let start = frame_system::Pallet::<TestRuntime>::block_number();
    for b in start + 1..=start + n {
        frame_system::Pallet::<TestRuntime>::set_block_number(b);
        <A as frame_support::traits::Hooks<u64>>::on_initialize(b);
    }
}

fn rotate(index: u32) -> Vec<AccountId32> {
    mine(4);
    let set = A::new_session(index).expect("admission always returns a validator set");
    <A as SessionManager<AccountId32>>::start_session(index);
    set
}

fn events() -> Vec<madar_admission::Event<TestRuntime>> {
    frame_system::Pallet::<TestRuntime>::events()
        .into_iter()
        .filter_map(|r| match r.event {
            RuntimeEvent::Admission(e) => Some(e),
            _ => None,
        })
        .collect()
}

/// **Reproducing the original problem + proving the fix:** 20 different identities actually solve the puzzle
/// (exactly the production cost) under one approved operator with a cap of only 3 votes.
/// Result: however many lottery rounds repeat, the number of actual votes never exceeds 3.
#[test]
fn twenty_identities_one_operator_are_capped_at_the_approved_vote_limit() {
    new_test_ext().execute_with(|| {
        let op = operator(1);
        // Independent governance (here: Root in the mock, a 2-of-3 committee in production,
        // see consensus/src/lib.rs) approves the operator with a cap of only 3 votes.
        Admission::approve_operator(RuntimeOrigin::root(), op.clone(), 3).unwrap();

        let identities: Vec<AccountId32> = (0u8..20).map(account).collect();

        // The operator vouches for the first 3 identities only — the fourth is rejected at the vouch itself
        // (the first protection, before even attempting the lottery).
        for id in identities.iter().take(3) {
            Admission::vouch_node(RuntimeOrigin::signed(op.clone()), id.clone()).unwrap();
        }
        assert_eq!(
            Admission::vouch_node(RuntimeOrigin::signed(op.clone()), identities[3].clone()),
            Err(Error::<TestRuntime>::OperatorAtVouchCapacity.into()),
            "the operator cannot vouch beyond its own approved cap"
        );

        // All twenty identities — vouched and unvouched — actually solve the puzzle
        // (the same real cost) and enter candidacy in parallel over several rounds
        // (the set is limited by MaxCandidatesPerRound=4 in this mock).
        for chunk in identities.chunks(4) {
            for id in chunk {
                let _ = submit_raw(id); // some are rejected if the set is full of better ranks — irrelevant here
            }
            rotate(frame_system::Pallet::<TestRuntime>::block_number() as u32 / 4 + 1);
        }
        // Extra rounds to give everyone left in candidacy a chance to win the lottery.
        for i in 0..10u32 {
            rotate(100 + i);
        }

        let live_validators: Vec<_> = A::validators().into_iter().filter(|v| identities.contains(v)).collect();
        assert!(
            live_validators.len() <= 3,
            "at most the approved cap (3) of this operator's 20 identities may ever become live validators; got {}",
            live_validators.len()
        );
        assert!(!live_validators.is_empty(), "the 3 vouched identities should have won admission at some point");

        // All live vouched identities remaining in the live list (if any) are only from the three vouched ones.
        for v in &live_validators {
            assert!(identities[..3].contains(v), "only vouched identities may ever become validators");
        }

        // The seventeen unvouched identities **never became validators** despite actually solving the puzzle.
        for id in &identities[3..] {
            assert!(!A::validators().contains(id), "an unvouched identity must never become a validator");
        }

        // The explicit event for every win-without-vouch case actually appeared (no silent rejection).
        assert!(
            events().iter().any(|e| matches!(e, AdmissionEvent::NotAdmittedNoOperator { who } if identities[3..].contains(who))),
            "unvouched winners must be reported explicitly, not silently dropped"
        );
    });
}

/// An unapproved account cannot vouch for any node — any "name" typed by an unapproved
/// applicant itself is worthless; only accounts explicitly approved by governance.
#[test]
fn an_unapproved_account_cannot_vouch_for_anyone() {
    new_test_ext().execute_with(|| {
        let self_declared_operator = operator(99);
        let node = account(1);
        assert_eq!(
            Admission::vouch_node(RuntimeOrigin::signed(self_declared_operator), node),
            Err(Error::<TestRuntime>::OperatorNotApproved.into())
        );
    });
}

/// Matching proof: granting the approval itself is restricted to the governance origin (`OperatorApprovalOrigin`)
/// — a normally signed account (not Root/the committee) cannot approve itself as an operator.
#[test]
fn a_signed_account_cannot_approve_itself_as_an_operator() {
    new_test_ext().execute_with(|| {
        let attacker = operator(66);
        assert!(Admission::approve_operator(
            RuntimeOrigin::signed(attacker.clone()),
            attacker,
            100
        )
        .is_err());
    });
}

/// One node cannot be vouched for by more than one operator at once — prevents different
/// operators from "double voting" for the same node by both vouching for it.
#[test]
fn a_node_cannot_be_vouched_by_two_operators_at_once() {
    new_test_ext().execute_with(|| {
        let op_a = operator(1);
        let op_b = operator(2);
        Admission::approve_operator(RuntimeOrigin::root(), op_a.clone(), 5).unwrap();
        Admission::approve_operator(RuntimeOrigin::root(), op_b.clone(), 5).unwrap();

        let node = account(1);
        Admission::vouch_node(RuntimeOrigin::signed(op_a.clone()), node.clone()).unwrap();
        assert_eq!(
            Admission::vouch_node(RuntimeOrigin::signed(op_b), node),
            Err(Error::<TestRuntime>::NodeAlreadyVouched.into())
        );
    });
}

/// Fully revoking an operator's approval immediately removes all its vouched nodes from the
/// validator set — a real "revocation of the right to vote", not waiting for the membership term to end.
#[test]
fn revoking_an_operators_approval_evicts_its_live_validators_immediately() {
    new_test_ext().execute_with(|| {
        // Another voter unrelated to this operator, so revoking the approval does not empty
        // the network completely (the new liveness guard, D50) and reject the operation unintentionally.
        Admission::dev_only_force_set_validators(RuntimeOrigin::root(), vec![account(200)])
            .unwrap();

        let op = operator(1);
        Admission::approve_operator(RuntimeOrigin::root(), op.clone(), 2).unwrap();

        let a = account(1);
        let b = account(2);
        Admission::vouch_node(RuntimeOrigin::signed(op.clone()), a.clone()).unwrap();
        Admission::vouch_node(RuntimeOrigin::signed(op.clone()), b.clone()).unwrap();

        submit_raw(&a).unwrap();
        submit_raw(&b).unwrap();
        // Only 3 rotations (enough for the draw: LOTTERY_DELAY_ROTATIONS=2 + entropy) —
        // we avoid extra rotations that could end the Byzantine membership term of account(200)
        // (MembershipTermSessions=3 + RenewalGraceSessions=2 = 5).
        for i in 0..3u32 {
            rotate(i + 1);
        }
        assert!(
            A::validators().contains(&a) || A::validators().contains(&b),
            "at least one should have been admitted by now"
        );

        Admission::revoke_operator_approval(RuntimeOrigin::root(), op.clone()).unwrap();

        assert!(
            !A::validators().contains(&a),
            "revocation must evict live validators of that operator immediately"
        );
        assert!(!A::validators().contains(&b));
        assert!(NodeOperator::<TestRuntime>::get(&a).is_none());
        assert!(NodeOperator::<TestRuntime>::get(&b).is_none());
        assert!(ApprovedOperators::<TestRuntime>::get(&op).is_none());
        assert!(OperatorNodes::<TestRuntime>::get(&op).is_empty());
    });
}

/// The operator itself withdraws the vouch for one node (without revoking its own approval) — the node is evicted immediately.
#[test]
fn an_operator_can_revoke_a_single_nodes_vouch_and_it_is_evicted_immediately() {
    new_test_ext().execute_with(|| {
        // Another voter, so withdrawing this vouch does not empty the network completely (the new
        // liveness guard, D50).
        Admission::dev_only_force_set_validators(RuntimeOrigin::root(), vec![account(200)])
            .unwrap();

        let op = operator(1);
        Admission::approve_operator(RuntimeOrigin::root(), op.clone(), 2).unwrap();
        let node = account(1);
        Admission::vouch_node(RuntimeOrigin::signed(op.clone()), node.clone()).unwrap();
        submit_raw(&node).unwrap();
        // Only 3 rotations — the same note as the test above about account(200)'s term ending.
        for i in 0..3u32 {
            rotate(i + 1);
        }
        assert!(A::validators().contains(&node), "should have been admitted");

        Admission::revoke_vouch(RuntimeOrigin::signed(op.clone()), node.clone()).unwrap();
        assert!(
            !A::validators().contains(&node),
            "revoking the vouch evicts the node immediately"
        );
        assert!(NodeOperator::<TestRuntime>::get(&node).is_none());
    });
}

/// Only the operator that vouched for a node can withdraw its vouch — not another operator and not the node itself.
#[test]
fn only_the_vouching_operator_can_revoke_its_own_vouch() {
    new_test_ext().execute_with(|| {
        let op_a = operator(1);
        let op_b = operator(2);
        Admission::approve_operator(RuntimeOrigin::root(), op_a.clone(), 5).unwrap();
        Admission::approve_operator(RuntimeOrigin::root(), op_b.clone(), 5).unwrap();
        let node = account(1);
        Admission::vouch_node(RuntimeOrigin::signed(op_a), node.clone()).unwrap();

        assert_eq!(
            Admission::revoke_vouch(RuntimeOrigin::signed(op_b), node.clone()),
            Err(Error::<TestRuntime>::NotTheVouchingOperator.into())
        );
        assert_eq!(
            Admission::revoke_vouch(RuntimeOrigin::signed(node.clone()), node),
            Err(Error::<TestRuntime>::NotTheVouchingOperator.into())
        );
    });
}

/// **Codex #1:** an operator with 3 actually live nodes (real validators in this
/// pallet's record) then has its cap lowered to 1 — it must not keep 3 effective votes while waiting for
/// a future vacancy; the excess (2) is evicted immediately in the same `approve_operator` call.
#[test]
fn lowering_the_cap_below_currently_live_votes_evicts_the_excess_immediately() {
    new_test_ext().execute_with(|| {
        let op = operator(1);
        Admission::approve_operator(RuntimeOrigin::root(), op.clone(), 3).unwrap();
        let (a, b, c) = (account(1), account(2), account(3));
        for n in [&a, &b, &c] {
            Admission::vouch_node(RuntimeOrigin::signed(op.clone()), n.clone()).unwrap();
        }

        // AdmissionCapPerRound=2 in this mock: one set grants only two winners
        // and is then consumed, so three candidates can never win from the same set. So
        // we submit a,b in one round, draw it, then c in a separate later round.
        submit_raw(&a).unwrap();
        submit_raw(&b).unwrap();
        for i in 0..3u32 {
            rotate(i + 1); // sessions 1..3: a,b admitted at 3 (valid_until=6, actually removed at 8)
        }
        assert!(A::validators().contains(&a) && A::validators().contains(&b));

        submit_raw(&c).unwrap();
        for i in 0..3u32 {
            rotate(4 + i); // sessions 4..6: c admitted at 6 — a,b still live (actual removal at 8)
        }
        let live_before: Vec<_> = [&a, &b, &c].into_iter().filter(|n| A::validators().contains(*n)).collect();
        assert_eq!(live_before.len(), 3, "all three must be live validators (in this pallet's own bookkeeping) before the cap is lowered");

        Admission::approve_operator(RuntimeOrigin::root(), op.clone(), 1).unwrap();

        let live_after: Vec<_> = [&a, &b, &c].into_iter().filter(|n| A::validators().contains(*n)).collect();
        assert_eq!(
            live_after.len(),
            1,
            "exactly one must remain immediately after lowering the cap to 1 — in the SAME call, no rotation needed"
        );
        assert!(
            events().iter().any(|e| matches!(e, AdmissionEvent::OperatorCapLoweredEvictedExcess { operator, evicted } if operator == &op && *evicted == 2)),
            "the eviction must be reported explicitly with the exact count evicted"
        );
        for n in [&a, &b, &c] {
            if !A::validators().contains(n) {
                assert!(NodeOperator::<TestRuntime>::get(n).is_none(), "an evicted node's vouch must be cleared too, not left dangling");
            }
        }
    });
}

/// **Defense in depth:** even if the number of an operator's live vouched nodes becomes higher than
/// its current cap (e.g. governance lowered the cap after the vouching), `new_session`
/// itself never lets any new winner exceed the current cap — the guarantee does not rely only on
/// the check at vouching time.
#[test]
fn the_session_admission_cap_holds_even_if_the_approved_cap_is_lowered_after_vouching() {
    new_test_ext().execute_with(|| {
        let op = operator(1);
        Admission::approve_operator(RuntimeOrigin::root(), op.clone(), 5).unwrap();
        let a = account(1);
        let b = account(2);
        Admission::vouch_node(RuntimeOrigin::signed(op.clone()), a.clone()).unwrap();
        Admission::vouch_node(RuntimeOrigin::signed(op.clone()), b.clone()).unwrap();
        submit_raw(&a).unwrap();
        // Only 3 rotations (the minimum that guarantees the draw: LOTTERY_DELAY_ROTATIONS=2 +
        // enough entropy) — we deliberately avoid any extra rotation that could end the term of `a`
        // (MembershipTermSessions=3 + RenewalGraceSessions=2 in this mock).
        for i in 0..3u32 {
            rotate(i + 1);
        }
        assert!(A::validators().contains(&a), "first node admitted under the original cap of 5");

        // Governance lowers the cap to 1 (a stays the only live member of this operator).
        Admission::approve_operator(RuntimeOrigin::root(), op.clone(), 1).unwrap();
        submit_raw(&b).unwrap();
        for i in 0..3u32 {
            rotate(4 + i);
        }

        assert!(!A::validators().contains(&b), "the lowered cap (1, already used by `a`) must block a new winner from the same operator");
        assert!(
            events().iter().any(|e| matches!(e, AdmissionEvent::NotAdmittedOperatorCapReached { who, operator } if who == &b && operator == &op)),
            "the rejection must be reported explicitly"
        );
    });
}

/// The absolute cap (`MaxVotesPerOperator`) cannot be exceeded by governance itself by mistake.
#[test]
fn governance_cannot_approve_an_operator_above_the_absolute_ceiling() {
    new_test_ext().execute_with(|| {
        let op = operator(1);
        // The mock's absolute cap = 100 (see common/mod.rs).
        assert_eq!(
            Admission::approve_operator(RuntimeOrigin::root(), op, 101),
            Err(Error::<TestRuntime>::MaxVotesExceedsAbsoluteLimit.into())
        );
    });
}

/// **D49 (Codex review) — the root gap:** an operator whose account is already a validator entirely outside
/// the vouching system (like a "network genesis" seat via `dev_only_force_set_validators`,
/// dev-only) — its own seat must count immediately as a vote used from its cap,
/// so any attempt to vouch for an extra node beyond that actual cap is rejected. This was not
/// counted before because the count relied exclusively on `NodeOperator`/`vouch_node`.
#[test]
fn an_operators_own_preexisting_seat_counts_against_its_cap_and_blocks_a_second_vouch() {
    new_test_ext().execute_with(|| {
        let op = operator(1);
        // "Network genesis seat": op itself is already a validator, without any vouch —
        // exactly as the real network introduces validators through genesis /
        // dev_only_force_set_validators (D25), completely separate from `vouch_node`.
        Admission::dev_only_force_set_validators(RuntimeOrigin::root(), vec![op.clone()]).unwrap();
        Admission::approve_operator(RuntimeOrigin::root(), op.clone(), 1).unwrap();

        let winner = account(1);
        assert_eq!(
            Admission::vouch_node(RuntimeOrigin::signed(op.clone()), winner),
            Err(Error::<TestRuntime>::OperatorAtVouchCapacity.into()),
            "the operator's own pre-existing seat must already consume its cap of 1 — it must never end up controlling two votes under a cap of one"
        );
        assert_eq!(OperatorNodes::<TestRuntime>::get(&op).len(), 0, "no vouch should have been recorded");
    });
}
