//! spec 9 — Admission: the round cap for the whole rotation (D54), the two committee parameters (round cap and operator cap) with hard limits, and the
//! Argon2 attempt limit (free block fill), and the storage version. Every attack in the spec 9 Admission security review has a test here
//! or in `consensus/tests/spec9_*.rs`.

mod common;

use common::*;
use frame_support::traits::{Get, GetStorageVersion, OnRuntimeUpgrade, Randomness, StorageVersion};
use madar_admission::weights::WeightInfo as _;
use madar_admission::{
    AdmissionCapPerRound, ApprovedOperators, Error, Event as AdmissionEvent, MaxVotesPerOperator,
    SolutionAttempts, MAX_SOLUTION_ATTEMPTS_PER_ROUND,
};
use pallet_session::SessionManager;
use sp_runtime::{AccountId32, DispatchError};

type A = madar_admission::Pallet<TestRuntime>;
type W = <TestRuntime as madar_admission::Config>::WeightInfo;

fn account(byte: u8) -> AccountId32 {
    AccountId32::from([byte; 32])
}

fn operator(byte: u8) -> AccountId32 {
    AccountId32::from([byte.wrapping_add(100); 32])
}

fn seed() -> sp_core::H256 {
    TestRandomness::random(madar_protocol::ADMISSION_PUZZLE_DOMAIN).0
}

fn submit_raw(who: &AccountId32) -> frame_support::dispatch::DispatchResultWithPostInfo {
    let nonce = find_valid_nonce(who, &seed());
    Admission::submit_admission_solution(RuntimeOrigin::signed(who.clone()), nonce)
}

fn bad_nonce(who: &AccountId32) -> u64 {
    let s = seed();
    (0u64..)
        .find(|n| !A::solution_meets_difficulty(who, &s, *n))
        .unwrap()
}

fn mine(n: u64) {
    let start = frame_system::Pallet::<TestRuntime>::block_number();
    for b in start + 1..=start + n {
        frame_system::Pallet::<TestRuntime>::set_block_number(b);
        <A as frame_support::traits::Hooks<u64>>::on_initialize(b);
    }
}

fn rotate_raw(index: u32) -> Vec<AccountId32> {
    let set = A::new_session(index).expect("admission always returns a validator set");
    <A as SessionManager<AccountId32>>::start_session(index);
    set
}

fn events() -> Vec<AdmissionEvent<TestRuntime>> {
    frame_system::Pallet::<TestRuntime>::events()
        .into_iter()
        .filter_map(|r| match r.event {
            RuntimeEvent::Admission(e) => Some(e),
            _ => None,
        })
        .collect()
}

/// Each candidate gets its own approved operator (cap 1), so operator caps never limit the draw here.
fn vouch_alone(who: &AccountId32, op_byte: u8) {
    let op = operator(op_byte);
    Admission::approve_operator(RuntimeOrigin::root(), op.clone(), 1).unwrap();
    Admission::vouch_node(RuntimeOrigin::signed(op), who.clone()).unwrap();
    give_account(who);
}

/// Closes `pools` rounds without fresh entropy (block number fixed) so they all become ready in the same rotation.
/// `per_pool` candidates each; returns every candidate and the index of the rotation that will draw them all.
fn backlog(pools: u8, per_pool: u8, first: u8) -> (Vec<AccountId32>, u32) {
    let mut all = Vec::new();
    frame_system::Pallet::<TestRuntime>::set_block_number(1);
    for p in 0..pools {
        // block number stays at 1: no fresh VRF enters until the draw, so every pool becomes ready together
        for i in 0..per_pool {
            let who = account(first + p * per_pool + i);
            vouch_alone(&who, first + p * per_pool + i);
            submit_raw(&who).unwrap();
            all.push(who);
        }
        rotate_raw(p as u32 + 1);
    }
    // keep the block number and add nothing fresh until the draw rotation
    (all, pools as u32 + 3)
}

// ---------------------------------------------------------------------------------------------------- item 1 (D54)

/// D54: «2 per round» is per **rotation**. Four closed pools (2 candidates each) that become ready together are drawn
/// in one draw: exactly 2 seats open, not 2 per pool (8). Before spec 9 this admitted 8 in one rotation.
#[test]
fn the_cap_counts_across_every_pool_drawn_in_the_same_rotation() {
    new_test_ext().execute_with(|| {
        let (all, draw_at) = backlog(4, 2, 10);
        assert_eq!(
            madar_admission::Pending::<TestRuntime>::get().len(),
            4,
            "four pools wait for fresh entropy"
        );
        rotate_raw(draw_at - 1);
        assert!(
            A::validators().is_empty(),
            "no fresh entropy yet: nothing drawn"
        );
        mine(3);
        let set = rotate_raw(draw_at);
        let admitted = all.iter().filter(|a| set.contains(a)).count();
        assert_eq!(
            admitted, 2,
            "one rotation admits at most AdmissionCapPerRound (2) across all ready pools"
        );
        assert!(
            madar_admission::Pending::<TestRuntime>::get().is_empty(),
            "every ready pool was drawn (none left undrawn)"
        );
    });
}

/// Ordering attack: an attacker who stuffs an OLDER pool gains nothing — the merged draw ranks every ready candidate by
/// one seed, so the winners are the same whichever pool each candidate sat in.
#[test]
fn which_pool_a_candidate_sat_in_does_not_change_the_merged_draw() {
    let run = |order: [u8; 4]| {
        let mut winners = Vec::new();
        new_test_ext().execute_with(|| {
            // two pools of two, in the given order of candidates
            for (p, pair) in order.chunks(2).enumerate() {
                frame_system::Pallet::<TestRuntime>::set_block_number(1 + p as u64);
                for b in pair {
                    vouch_alone(&account(*b), *b);
                    submit_raw(&account(*b)).unwrap();
                }
                rotate_raw(p as u32 + 1);
            }
            rotate_raw(3);
            mine(3);
            let mut set = rotate_raw(4);
            set.sort();
            winners = set;
        });
        winners
    };
    let a = run([30, 31, 32, 33]);
    assert_eq!(a.len(), 2);
    assert_eq!(
        a,
        run([33, 32, 31, 30]),
        "swapping the pools' contents must not change the winners"
    );
    assert_eq!(a, run([30, 33, 32, 31]));
}

/// A candidate that sits in two ready pools (applied in two rounds) enters the merged draw once (no double ticket).
#[test]
fn a_candidate_in_two_ready_pools_gets_one_ticket() {
    new_test_ext().execute_with(|| {
        let dup = account(40);
        vouch_alone(&dup, 40);
        frame_system::Pallet::<TestRuntime>::set_block_number(1);
        submit_raw(&dup).unwrap();
        rotate_raw(1);
        frame_system::Pallet::<TestRuntime>::set_block_number(2);
        submit_raw(&dup).unwrap();
        rotate_raw(2);
        rotate_raw(3);
        mine(3);
        let set = rotate_raw(4);
        assert_eq!(
            set.iter().filter(|v| **v == dup).count(),
            1,
            "admitted once"
        );
    });
}

// ---------------------------------------------------------------------------------------------------- item 2

#[test]
fn the_parameters_start_at_their_defaults_without_any_storage_write() {
    new_test_ext().execute_with(|| {
        assert_eq!(AdmissionCapPerRound::<TestRuntime>::get(), 2);
        assert_eq!(MaxVotesPerOperator::<TestRuntime>::get(), 100);
        assert!(
            !AdmissionCapPerRound::<TestRuntime>::exists(),
            "a default, not a stored value (no migration needed)"
        );
    });
}

/// Governance abuse 1: only the committee origin (here Root, 2-of-3 in the runtime) may set them; a signed account
/// (even an approved operator) cannot.
#[test]
fn only_the_committee_origin_can_change_the_admission_parameters() {
    new_test_ext().execute_with(|| {
        let op = operator(1);
        Admission::approve_operator(RuntimeOrigin::root(), op.clone(), 1).unwrap();
        assert_eq!(
            Admission::set_admission_cap_per_round(RuntimeOrigin::signed(op.clone()), 4),
            Err(DispatchError::BadOrigin)
        );
        assert_eq!(
            Admission::set_max_votes_per_operator(RuntimeOrigin::signed(op), 2),
            Err(DispatchError::BadOrigin)
        );
        assert_eq!(AdmissionCapPerRound::<TestRuntime>::get(), 2);
    });
}

/// Governance abuse 2: even the committee cannot pass the hard limits compiled into the runtime.
#[test]
fn the_committee_cannot_pass_the_hard_limits() {
    new_test_ext().execute_with(|| {
        // mock limits: cap <= 4, votes in 1..=100
        assert_eq!(
            Admission::set_admission_cap_per_round(RuntimeOrigin::root(), 5),
            Err(Error::<TestRuntime>::AdmissionCapAboveLimit.into())
        );
        assert_eq!(
            Admission::set_admission_cap_per_round(RuntimeOrigin::root(), u32::MAX),
            Err(Error::<TestRuntime>::AdmissionCapAboveLimit.into())
        );
        assert_eq!(
            Admission::set_max_votes_per_operator(RuntimeOrigin::root(), 0),
            Err(Error::<TestRuntime>::MaxVotesOutOfRange.into())
        );
        assert_eq!(
            Admission::set_max_votes_per_operator(RuntimeOrigin::root(), 101),
            Err(Error::<TestRuntime>::MaxVotesOutOfRange.into())
        );
        assert_eq!(
            (
                AdmissionCapPerRound::<TestRuntime>::get(),
                MaxVotesPerOperator::<TestRuntime>::get()
            ),
            (2, 100)
        );

        frame_system::Pallet::<TestRuntime>::set_block_number(1);
        Admission::set_admission_cap_per_round(RuntimeOrigin::root(), 4).unwrap();
        Admission::set_max_votes_per_operator(RuntimeOrigin::root(), 3).unwrap();
        assert!(events().contains(&AdmissionEvent::AdmissionCapPerRoundSet { old: 2, new: 4 }));
        assert!(events().contains(&AdmissionEvent::MaxVotesPerOperatorSet { old: 100, new: 3 }));
        assert_eq!(
            Admission::approve_operator(RuntimeOrigin::root(), operator(2), 4),
            Err(Error::<TestRuntime>::MaxVotesExceedsAbsoluteLimit.into()),
            "approve_operator follows the stored committee cap"
        );
        Admission::approve_operator(RuntimeOrigin::root(), operator(2), 3).unwrap();
    });
}

/// A raised round cap opens more seats per rotation (still within the limit); cap 0 pauses new admissions (members and
/// renewals unaffected) — an emergency lever, not a way to remove anyone.
#[test]
fn the_round_cap_from_storage_drives_the_draw_and_zero_pauses_admissions() {
    new_test_ext().execute_with(|| {
        let (all, draw_at) = backlog(2, 3, 50);
        Admission::set_admission_cap_per_round(RuntimeOrigin::root(), 4).unwrap();
        rotate_raw(draw_at - 1);
        mine(3);
        let set = rotate_raw(draw_at);
        assert_eq!(
            all.iter().filter(|a| set.contains(a)).count(),
            4,
            "cap 4 => 4 seats in this rotation"
        );
    });
    new_test_ext().execute_with(|| {
        let keeper = account(90);
        force_validators(vec![keeper.clone()]);
        let (all, draw_at) = backlog(1, 3, 60);
        Admission::set_admission_cap_per_round(RuntimeOrigin::root(), 0).unwrap();
        rotate_raw(draw_at - 1);
        mine(3);
        let set = rotate_raw(draw_at);
        assert!(all.iter().all(|a| !set.contains(a)), "cap 0 => nobody new");
        assert!(set.contains(&keeper), "existing members are untouched");
    });
}

/// Lowering the committee cap below an operator's live seats evicts nobody (no finality loss from a governance
/// mistake), but blocks any further vouch or admission above the new cap.
#[test]
fn lowering_the_votes_cap_evicts_nobody_but_blocks_new_seats_above_it() {
    new_test_ext().execute_with(|| {
        let op = operator(5);
        let (a, b, c) = (account(1), account(2), account(3));
        Admission::approve_operator(RuntimeOrigin::root(), op.clone(), 3).unwrap();
        // 9 voters, so the hard bound (floor((n-1)/3), independent review #1) leaves room for 3 seats of one operator
        let mut set = vec![a.clone(), b.clone()];
        set.extend((11u8..=17).map(account));
        force_validators(set.clone());
        for n in [&a, &b] {
            Admission::vouch_node(RuntimeOrigin::signed(op.clone()), n.clone()).unwrap();
        }

        Admission::set_max_votes_per_operator(RuntimeOrigin::root(), 1).unwrap();
        assert_eq!(
            A::validators(),
            set,
            "nobody is evicted by the committee-wide cap"
        );
        assert_eq!(
            ApprovedOperators::<TestRuntime>::get(&op),
            Some(3),
            "the operator's own approval is untouched"
        );
        assert_eq!(
            Admission::vouch_node(RuntimeOrigin::signed(op.clone()), c.clone()),
            Err(Error::<TestRuntime>::OperatorAtVouchCapacity.into()),
            "no new vouch above the committee-wide cap"
        );
        assert_eq!(A::operator_cap(&op), 1);

        // a node vouched before the change cannot win a seat above the cap either
        Admission::set_max_votes_per_operator(RuntimeOrigin::root(), 3).unwrap();
        Admission::vouch_node(RuntimeOrigin::signed(op.clone()), c.clone()).unwrap();
        Admission::set_max_votes_per_operator(RuntimeOrigin::root(), 1).unwrap();
        frame_system::Pallet::<TestRuntime>::set_block_number(1);
        submit_raw(&c).unwrap();
        rotate_raw(1);
        mine(4);
        rotate_raw(2);
        mine(4);
        let set = rotate_raw(3);
        assert!(
            !set.contains(&c),
            "the committee cap (1, already used twice) blocks the new winner"
        );
        assert!(events().iter().any(
            |e| matches!(e, AdmissionEvent::NotAdmittedOperatorCapReached { who, .. } if *who == c)
        ));
    });
}

// ---------------------------------------------------------------------------------------------------- item 5

/// Free block fill closed: a vouched account's wrong solutions are counted (the Argon2 work is charged, and the call
/// succeeds with `SolutionRejected` so the count is not rolled back); after `MAX_SOLUTION_ATTEMPTS_PER_ROUND × cap`
/// Argon2 runs in a round, further calls are refused **before** Argon2 at the cheap early weight.
#[test]
fn wrong_solutions_are_counted_and_the_round_budget_is_enforced_before_argon2() {
    new_test_ext().execute_with(|| {
        frame_system::Pallet::<TestRuntime>::set_block_number(1);
        Admission::set_max_votes_per_operator(RuntimeOrigin::root(), 1).unwrap();
        let who = account(7);
        vouch_alone(&who, 7);
        let limit = MAX_SOLUTION_ATTEMPTS_PER_ROUND;
        for i in 1..=limit {
            let r = Admission::submit_admission_solution(
                RuntimeOrigin::signed(who.clone()),
                bad_nonce(&who),
            )
            .unwrap();
            assert_eq!(r.actual_weight, None, "attempt {i}: full Argon2 weight");
            assert!(events().contains(&AdmissionEvent::SolutionRejected {
                who: who.clone(),
                attempts_this_round: i,
                pool_full: false
            }));
        }
        let err = Admission::submit_admission_solution(
            RuntimeOrigin::signed(who.clone()),
            bad_nonce(&who),
        )
        .unwrap_err();
        assert_eq!(
            err.error,
            Error::<TestRuntime>::TooManySolutionAttempts.into()
        );
        assert_eq!(
            err.post_info.actual_weight,
            Some(W::submit_admission_rejected_early()),
            "refused cheaply, before Argon2"
        );
        // even a correct solution waits for the next round now
        assert_eq!(
            submit_raw(&who).unwrap_err().error,
            Error::<TestRuntime>::TooManySolutionAttempts.into()
        );

        // next round: a fresh budget
        rotate_raw(1);
        frame_system::Pallet::<TestRuntime>::set_block_number(2);
        submit_raw(&who).expect("a new round restores the attempts");
        assert!(A::candidates().contains(&who));
    });
}

/// Griefing / bypass: the budget belongs to the OPERATOR, so cycling fresh nodes (revoke vouch + vouch a new node) buys
/// no extra Argon2 runs in the same round; and one operator's spam never touches another operator's budget.
#[test]
fn cycling_fresh_nodes_does_not_reset_the_operators_attempt_budget() {
    new_test_ext().execute_with(|| {
        frame_system::Pallet::<TestRuntime>::set_block_number(1);
        Admission::set_max_votes_per_operator(RuntimeOrigin::root(), 1).unwrap();
        let op = operator(9);
        Admission::approve_operator(RuntimeOrigin::root(), op.clone(), 1).unwrap();
        let mut used = 0;
        for k in 0..3u8 {
            let node = account(200 + k);
            Admission::vouch_node(RuntimeOrigin::signed(op.clone()), node.clone()).unwrap();
            give_account(&node);
            for _ in 0..MAX_SOLUTION_ATTEMPTS_PER_ROUND {
                if Admission::submit_admission_solution(
                    RuntimeOrigin::signed(node.clone()),
                    bad_nonce(&node),
                )
                .is_ok()
                {
                    used += 1;
                }
            }
            Admission::revoke_vouch(RuntimeOrigin::signed(op.clone()), node).unwrap();
        }
        assert_eq!(
            used, MAX_SOLUTION_ATTEMPTS_PER_ROUND,
            "three nodes, one budget"
        );
        assert_eq!(
            SolutionAttempts::<TestRuntime>::get(&op),
            Some((0, MAX_SOLUTION_ATTEMPTS_PER_ROUND))
        );

        // another operator is unaffected
        let other = account(210);
        vouch_alone(&other, 210);
        submit_raw(&other).expect("another operator keeps its own budget");
    });
}

/// The budget scales with the committee cap (an operator with 2 seats may need 2 submissions) but never past
/// `MAX_SOLUTION_ATTEMPTS_PER_ROUND × MaxVotesPerOperator`.
#[test]
fn the_attempt_budget_scales_with_the_votes_cap() {
    new_test_ext().execute_with(|| {
        Admission::set_max_votes_per_operator(RuntimeOrigin::root(), 2).unwrap();
        let op = operator(11);
        Admission::approve_operator(RuntimeOrigin::root(), op.clone(), 2).unwrap();
        let node = account(220);
        Admission::vouch_node(RuntimeOrigin::signed(op), node.clone()).unwrap();
        give_account(&node);
        let mut ok = 0;
        for _ in 0..(3 * MAX_SOLUTION_ATTEMPTS_PER_ROUND) {
            if Admission::submit_admission_solution(
                RuntimeOrigin::signed(node.clone()),
                bad_nonce(&node),
            )
            .is_ok()
            {
                ok += 1;
            }
        }
        assert_eq!(ok, 2 * MAX_SOLUTION_ATTEMPTS_PER_ROUND);
    });
}

/// Renewals of a member without an operator (a founding seat) are budgeted on the member itself (spec 9, independent
/// review #3: every renewal is budgeted on the member, in `RenewalAttempts`).
#[test]
fn a_founding_member_renewal_is_budgeted_on_itself() {
    new_test_ext().execute_with(|| {
        frame_system::Pallet::<TestRuntime>::set_block_number(1);
        Admission::set_max_votes_per_operator(RuntimeOrigin::root(), 1).unwrap();
        let member = account(230);
        force_validators(vec![member.clone()]);
        rotate_raw(1); // expiry 3 < 1 + 3: a renewal is possible
        for _ in 0..MAX_SOLUTION_ATTEMPTS_PER_ROUND {
            Admission::submit_admission_solution(
                RuntimeOrigin::signed(member.clone()),
                bad_nonce(&member),
            )
            .unwrap();
        }
        let err = Admission::submit_admission_solution(
            RuntimeOrigin::signed(member.clone()),
            bad_nonce(&member),
        )
        .unwrap_err();
        assert_eq!(
            err.error,
            Error::<TestRuntime>::TooManySolutionAttempts.into()
        );
        assert_eq!(
            madar_admission::RenewalAttempts::<TestRuntime>::get(&member),
            Some((1, MAX_SOLUTION_ATTEMPTS_PER_ROUND))
        );
        assert_eq!(SolutionAttempts::<TestRuntime>::get(&member), None);
    });
}

/// Revoking an operator clears its attempt record (no per-account state outlives the approval).
#[test]
fn revoking_an_operator_clears_its_attempt_record() {
    new_test_ext().execute_with(|| {
        let keeper = account(240);
        force_validators(vec![keeper]);
        let node = account(241);
        vouch_alone(&node, 241);
        Admission::submit_admission_solution(RuntimeOrigin::signed(node.clone()), bad_nonce(&node))
            .unwrap();
        assert!(SolutionAttempts::<TestRuntime>::contains_key(operator(241)));
        Admission::revoke_operator_approval(RuntimeOrigin::root(), operator(241)).unwrap();
        assert!(!SolutionAttempts::<TestRuntime>::contains_key(operator(
            241
        )));
    });
}

// ---------------------------------------------------------------------------------------------------- item 8

/// StorageVersion: 0 on a pre-spec-9 chain, set to 1 once by the migration, which is then a no-op.
#[test]
fn the_storage_version_migration_runs_once() {
    new_test_ext().execute_with(|| {
        StorageVersion::new(0).put::<A>();
        assert_eq!(A::on_chain_storage_version(), 0);
        assert_eq!(A::in_code_storage_version(), 1);
        madar_admission::migrations::V0ToV1::<TestRuntime>::on_runtime_upgrade();
        assert_eq!(A::on_chain_storage_version(), 1);
        let again = madar_admission::migrations::V0ToV1::<TestRuntime>::on_runtime_upgrade();
        assert_eq!(A::on_chain_storage_version(), 1);
        let one_read: frame_support::weights::Weight =
            <<TestRuntime as frame_system::Config>::DbWeight as Get<
                frame_support::weights::RuntimeDbWeight,
            >>::get()
            .reads(1);
        assert_eq!(again, one_read, "second run only reads the version");
    });
}

/// The setters have a real (non-zero) declared weight.
#[test]
fn the_setters_have_a_declared_weight() {
    use frame_support::dispatch::GetDispatchInfo;
    let w = madar_admission::Call::<TestRuntime>::set_admission_cap_per_round { cap: 1 }
        .get_dispatch_info()
        .call_weight;
    assert_eq!(w, W::set_admission_param());
    assert!(w.ref_time() > 0 && w.proof_size() > 0);
}
