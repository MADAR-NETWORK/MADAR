//! spec 9 — independent security review fixes: the hard GRANDPA
//! bound per operator (#1), renewal budgets per member (#3), and no free replay of a refused first submission (#6).
//! Each finding has an attack test here.

mod common;

use common::*;
use frame_support::traits::Randomness;
use madar_admission::{
    byzantine_seat_bound, BannedKeys, Error, Event as AdmissionEvent, NodeOperator, RefusalReason,
    RenewalAttempts, SolutionAttempts, MAX_SOLUTION_ATTEMPTS_PER_ROUND,
};
use pallet_session::SessionManager;
use sp_runtime::AccountId32;

type A = madar_admission::Pallet<TestRuntime>;

fn account(byte: u8) -> AccountId32 {
    AccountId32::from([byte; 32])
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

fn founders(n: u8) -> Vec<AccountId32> {
    (1..=n).map(account).collect()
}

// ---------------------------------------------------------------------------------------------------- finding 1

#[test]
fn the_bound_is_floor_n_minus_1_over_3_and_at_least_1() {
    assert_eq!(
        (1..=13).map(byzantine_seat_bound).collect::<Vec<_>>(),
        vec![1, 1, 1, 1, 1, 1, 2, 2, 2, 3, 3, 3, 4]
    );
    assert_eq!(byzantine_seat_bound(0), 1);
}

/// Attack: the 2-of-3 committee raises the per-operator cap to the hard limit (4) and approves one operator with 4
/// votes. With 4–9 voters the operator still cannot vouch past floor((n'-1)/3) of the set its next node would join.
#[test]
fn a_cap_of_4_never_lets_one_operator_vouch_past_a_third_of_the_set() {
    for n in 4u8..=9 {
        new_test_ext().execute_with(|| {
            force_validators(founders(n));
            Admission::set_max_votes_per_operator(RuntimeOrigin::root(), 4).unwrap();
            let op = account(200);
            Admission::approve_operator(RuntimeOrigin::root(), op.clone(), 4).unwrap();
            let vouched = (0..4u8)
                .filter(|i| {
                    Admission::vouch_node(RuntimeOrigin::signed(op.clone()), account(100 + i))
                        .is_ok()
                })
                .count() as u32;
            let bound = byzantine_seat_bound(n as u32 + 1);
            assert_eq!(
                vouched,
                bound.min(4),
                "{n} voters: the operator may vouch {bound}, not 4"
            );
            assert_eq!(
                Admission::vouch_node(RuntimeOrigin::signed(op.clone()), account(150)),
                Err(Error::<TestRuntime>::OperatorAtVouchCapacity.into())
            );
        });
    }
}

/// Attack: an operator with cap 4 already has 4 vouched nodes (vouched while the set was larger, written directly here)
/// and all 4 win the lottery. For every starting set of 4–9 voters, the draw leaves that operator with at most
/// floor((n-1)/3) (min 1) of the resulting set — never the third that could stall finality.
#[test]
fn a_cap_of_4_never_lets_one_operator_win_past_a_third_of_the_set() {
    for n in 4u8..=9 {
        new_test_ext().execute_with(|| {
            frame_system::Pallet::<TestRuntime>::set_block_number(1);
            force_validators(founders(n));
            Admission::set_max_votes_per_operator(RuntimeOrigin::root(), 4).unwrap();
            Admission::set_admission_cap_per_round(RuntimeOrigin::root(), 4).unwrap();
            let op = account(200);
            Admission::approve_operator(RuntimeOrigin::root(), op.clone(), 4).unwrap();
            let nodes: Vec<AccountId32> = (0..4u8).map(|i| account(100 + i)).collect();
            for node in &nodes {
                NodeOperator::<TestRuntime>::insert(node, op.clone());
                give_account(node);
                submit_raw(node).expect("a vouched node enters the pool");
            }
            rotate_raw(1);
            mine(4);
            rotate_raw(2);
            mine(4);
            let set = rotate_raw(3);
            let held = nodes.iter().filter(|x| set.contains(x)).count() as u32;
            assert!(held >= 1, "{n} voters: the operator still gets a seat");
            assert!(
                held <= byzantine_seat_bound(set.len() as u32),
                "{n} voters: the operator holds {held} of {} (bound {})",
                set.len(),
                byzantine_seat_bound(set.len() as u32)
            );
            // GRANDPA tolerates f faulty voters only when n >= 3f + 1
            assert!(
                set.len() as u32 >= 3 * held + 1 || held == 1,
                "{n} voters: {held} of {}",
                set.len()
            );
            if n == 4 {
                assert_eq!(held, 1, "4 voters: one seat only");
                assert!(events()
                    .iter()
                    .any(|e| matches!(e, AdmissionEvent::NotAdmittedOperatorCapReached { .. })));
            }
        });
    }
}

// ---------------------------------------------------------------------------------------------------- finding 3

/// Attack (sibling starvation): two members of the same operator. One spends every renewal attempt of the round on wrong
/// solutions; the other still renews, because renewals are counted per member, not on the operator.
#[test]
fn one_node_cannot_exhaust_its_siblings_renewal_budget() {
    new_test_ext().execute_with(|| {
        frame_system::Pallet::<TestRuntime>::set_block_number(1);
        let (m1, m2) = (account(101), account(102));
        let mut set = vec![m1.clone(), m2.clone()];
        set.extend(founders(7));
        force_validators(set);
        Admission::set_max_votes_per_operator(RuntimeOrigin::root(), 2).unwrap();
        let op = account(200);
        Admission::approve_operator(RuntimeOrigin::root(), op.clone(), 2).unwrap();
        NodeOperator::<TestRuntime>::insert(&m1, op.clone());
        NodeOperator::<TestRuntime>::insert(&m2, op.clone());
        rotate_raw(1); // expiry 3 < 1 + 3: renewals possible

        for _ in 0..MAX_SOLUTION_ATTEMPTS_PER_ROUND {
            Admission::submit_admission_solution(RuntimeOrigin::signed(m1.clone()), bad_nonce(&m1))
                .unwrap();
        }
        let err =
            Admission::submit_admission_solution(RuntimeOrigin::signed(m1.clone()), bad_nonce(&m1))
                .unwrap_err();
        assert_eq!(
            err.error,
            Error::<TestRuntime>::TooManySolutionAttempts.into()
        );

        submit_raw(&m2).expect("the sibling still renews");
        assert!(events()
            .iter()
            .any(|e| matches!(e, AdmissionEvent::Renewed { who, .. } if *who == m2)));
        assert_eq!(
            RenewalAttempts::<TestRuntime>::get(&m1),
            Some((1, MAX_SOLUTION_ATTEMPTS_PER_ROUND))
        );
        assert_eq!(RenewalAttempts::<TestRuntime>::get(&m2), Some((1, 1)));
        assert_eq!(
            SolutionAttempts::<TestRuntime>::get(&op),
            None,
            "renewals never touch the operator's candidate budget"
        );
    });
}

/// A leaving member's renewal record is removed with its seat (no per-member state outlives membership).
#[test]
fn a_removed_members_renewal_record_is_cleared() {
    new_test_ext().execute_with(|| {
        frame_system::Pallet::<TestRuntime>::set_block_number(1);
        let m = account(101);
        let mut set = vec![m.clone()];
        set.extend(founders(3));
        force_validators(set);
        rotate_raw(1);
        Admission::submit_admission_solution(RuntimeOrigin::signed(m.clone()), bad_nonce(&m))
            .unwrap();
        assert!(RenewalAttempts::<TestRuntime>::get(&m).is_some());
        Admission::voluntary_exit(RuntimeOrigin::signed(m.clone())).unwrap();
        let set = rotate_raw(2);
        assert!(!set.contains(&m));
        assert_eq!(RenewalAttempts::<TestRuntime>::get(&m), None);
    });
}

// ---------------------------------------------------------------------------------------------------- finding 6

/// A first submission from a key without an account that fails an early check is a success with `SolutionRefused`
/// (so the runtime creates the account and moves the nonce); an existing account gets the error as before.
#[test]
fn an_early_refusal_of_a_first_submission_succeeds_with_an_event() {
    new_test_ext().execute_with(|| {
        frame_system::Pallet::<TestRuntime>::set_block_number(1);
        let who = account(120);
        NodeOperator::<TestRuntime>::insert(&who, account(201));
        BannedKeys::<TestRuntime>::insert(&who, ());
        assert_eq!(frame_system::Pallet::<TestRuntime>::providers(&who), 0);
        Admission::submit_admission_solution(RuntimeOrigin::signed(who.clone()), 1)
            .expect("refused, but Ok");
        assert!(events().contains(&AdmissionEvent::SolutionRefused {
            who: who.clone(),
            reason: RefusalReason::KeyPermanentlyBanned
        }));
        give_account(&who);
        let err = Admission::submit_admission_solution(RuntimeOrigin::signed(who.clone()), 1)
            .unwrap_err();
        assert_eq!(err.error, Error::<TestRuntime>::KeyPermanentlyBanned.into());
    });
}
