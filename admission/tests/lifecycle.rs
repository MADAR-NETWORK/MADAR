//! The Admission/Sybil puzzle — §2.9: the formula, cryptographic binding, the lottery, renewal, validity,
//! the permanent ban, voluntary exit, and the liveness guarantee.

mod common;

use common::*;
use frame_support::dispatch::{DispatchErrorWithPostInfo, Pays, PostDispatchInfo};
use frame_support::traits::Randomness;
use madar_admission::weights::WeightInfo as _;
use madar_admission::Error;
use pallet_session::SessionManager;
use sp_runtime::{AccountId32, DispatchError};

type A = madar_admission::Pallet<TestRuntime>;

/// Early rejection (before Argon2): the same error, but with the low actual weight, not the full Argon2 weight.
fn early_reject(error: Error<TestRuntime>) -> DispatchErrorWithPostInfo {
    DispatchErrorWithPostInfo {
        post_info: PostDispatchInfo {
            actual_weight: Some(<TestRuntime as madar_admission::Config>::WeightInfo::submit_admission_rejected_early()),
            pays_fee: Pays::Yes,
        },
        error: error.into(),
    }
}

fn account(byte: u8) -> AccountId32 {
    AccountId32::from([byte; 32])
}

fn current_round_seed() -> sp_core::H256 {
    TestRandomness::random(madar_protocol::ADMISSION_PUZZLE_DOMAIN).0
}

/// **D47:** automatically vouches for `who` with a test operator with a generous cap before submitting
/// the solution — the tests of this file check the lottery/validity/liveness engine
/// itself, not the operator caps (they have their own tests in `operator_caps.rs`).
fn submit(who: &AccountId32) -> frame_support::dispatch::DispatchResultWithPostInfo {
    common::ensure_vouched(who);
    let nonce = find_valid_nonce(who, &current_round_seed());
    Admission::submit_admission_solution(RuntimeOrigin::signed(who.clone()), nonce)
}

/// Produces `n` blocks (each with a fresh VRF entering the accumulator) after the current block.
fn mine(n: u64) {
    let start = frame_system::Pallet::<TestRuntime>::block_number();
    for b in start + 1..=start + n {
        frame_system::Pallet::<TestRuntime>::set_block_number(b);
        <A as frame_support::traits::Hooks<u64>>::on_initialize(b);
    }
}

/// A session rotation without producing blocks (no fresh VRF).
fn rotate_raw(index: u32) -> Vec<AccountId32> {
    let set = A::new_session(index).expect("admission always returns a validator set");
    <A as SessionManager<AccountId32>>::start_session(index);
    set
}

/// A rotation as on the network: new blocks (a VRF per block) during the epoch, then `new_session(i)` and the session start.
fn rotate(index: u32) -> Vec<AccountId32> {
    mine(4);
    rotate_raw(index)
}

#[test]
fn a_valid_solution_makes_the_account_a_candidate_and_only_the_rotation_admits_it() {
    new_test_ext().execute_with(|| {
        let who = account(1);
        submit(&who).expect("a valid solution must be accepted");
        assert!(A::candidates().contains(&who));
        assert!(
            !A::validators().contains(&who),
            "admission is decided at the epoch boundary, not immediately"
        );

        // Closing at rotation 1, and no draw before LOTTERY_DELAY_ROTATIONS (=2) rotations have passed.
        assert!(!rotate(1).contains(&who));
        assert!(
            A::candidates().is_empty(),
            "the round is closed at the first rotation"
        );
        assert!(
            !rotate(2).contains(&who),
            "still waiting: the draw uses randomness written after the close"
        );
        let set = rotate(3);
        assert!(set.contains(&who) && A::validators().contains(&who));
        assert!(madar_admission::MembershipExpiry::<TestRuntime>::get(&who).is_some());
    });
}

#[test]
fn an_insufficient_solution_is_rejected() {
    new_test_ext().execute_with(|| {
        let who = account(2);
        let seed = current_round_seed();
        let bad = (0u64..)
            .find(|n| !A::solution_meets_difficulty(&who, &seed, *n))
            .unwrap();
        let r = Admission::submit_admission_solution(RuntimeOrigin::signed(who.clone()), bad);
        assert_eq!(
            r.unwrap_err().error,
            Error::<TestRuntime>::SolutionDoesNotMeetDifficulty.into()
        );
        assert!(A::candidates().is_empty());
    });
}

#[test]
fn a_solution_cannot_be_transferred_to_a_different_identity() {
    new_test_ext().execute_with(|| {
        let (a, b) = (account(3), account(4));
        let seed = current_round_seed();
        let nonce = (0u64..)
            .find(|n| {
                A::solution_meets_difficulty(&a, &seed, *n)
                    && !A::solution_meets_difficulty(&b, &seed, *n)
            })
            .unwrap();
        assert!(Admission::submit_admission_solution(RuntimeOrigin::signed(b), nonce).is_err());
        assert!(Admission::submit_admission_solution(RuntimeOrigin::signed(a), nonce).is_ok());
    });
}

#[test]
fn the_same_account_cannot_be_a_candidate_twice_in_a_round() {
    new_test_ext().execute_with(|| {
        let who = account(5);
        submit(&who).unwrap();
        assert_eq!(
            submit(&who),
            Err(early_reject(Error::<TestRuntime>::AlreadyAdmittedThisRound))
        );
    });
}

/// A fair lottery: with 4 candidates and a cap of 2 winners, the winners are **the same** whatever the insertion order.
#[test]
fn the_lottery_winners_do_not_depend_on_submission_order() {
    let accounts: Vec<_> = (10u8..14).map(account).collect();
    let run = |order: Vec<AccountId32>| {
        let mut winners = Vec::new();
        new_test_ext().execute_with(|| {
            for who in &order {
                submit(who).unwrap();
            }
            rotate(1);
            rotate(2);
            let mut set = rotate(3);
            set.sort();
            winners = set;
        });
        winners
    };
    let forward = run(accounts.clone());
    let mut reversed = accounts.clone();
    reversed.reverse();
    assert_eq!(forward.len(), 2, "exactly AdmissionCapPerRound winners");
    assert_eq!(
        forward,
        run(reversed),
        "submission order must not change who wins"
    );
}

/// The Argon2 output of the first valid nonce for an identity (the candidate's ordering key).
fn output_of(who: &AccountId32) -> [u8; 32] {
    let seed = current_round_seed();
    A::compute_puzzle_output(who, &seed, find_valid_nonce(who, &seed))
}

/// The set is limited (4) **and its rank = the Argon2 output itself** (smaller is better): when full, only the holder of the worst output
/// is replaced by a candidate with a better output, and one whose output is worse than everyone is rejected (after paying the full Argon2, not for free).
#[test]
fn the_candidate_pool_is_bounded_and_ranked_by_the_argon2_output() {
    new_test_ext().execute_with(|| {
        let mut pool: Vec<(AccountId32, [u8; 32])> = (20u8..30)
            .map(account)
            .map(|a| {
                let o = output_of(&a);
                (a, o)
            })
            .collect();
        pool.sort_by_key(|(_, o)| *o); // the best first
        for (who, _) in pool.iter().rev().take(4) {
            submit(who).unwrap(); // the worst 4 outputs, starting with the worst
        }
        assert_eq!(A::candidates().len(), 4);

        let (best, _) = pool[0].clone();
        submit(&best).unwrap();
        assert_eq!(
            A::candidates().len(),
            4,
            "pool never exceeds MaxCandidatesPerRound"
        );
        assert!(A::candidates().contains(&best));
        let (worst, _) = pool.last().unwrap().clone();
        assert!(
            !A::candidates().contains(&worst),
            "the worst output was evicted"
        );

        // Its output is worse than everyone in the set now: rejected — but **after** Argon2 (full weight, not a free rejection).
        let err = submit(&worst).unwrap_err();
        assert_eq!(err.error, Error::<TestRuntime>::AdmissionCapReached.into());
        assert_eq!(
            err.post_info.actual_weight, None,
            "a rank rejection already paid the full Argon2 weight"
        );
    });
}

/// **Identity grinding (review #5-B):** the rank does not depend on any cheap key from the identity. We order many identities by the best cheap
/// hash key (`blake2(seed‖account)`, which was used before the fix), then fill the set with the best Argon2 outputs:
/// the holder of the best cheap key does **not** get in if its output is worse — getting in requires a better output, i.e. actually more work.
#[test]
fn grinding_identities_by_a_cheap_key_buys_no_pool_position() {
    new_test_ext().execute_with(|| {
        let seed = current_round_seed();
        let cheap = |who: &AccountId32| {
            let mut input = seed.as_ref().to_vec();
            input.extend_from_slice(&parity_scale_codec::Encode::encode(who));
            sp_io::hashing::blake2_256(&input)
        };
        let all: Vec<AccountId32> = (100u8..164).map(account).collect(); // 64 "ground" identities
        let mut by_cheap = all.clone();
        by_cheap.sort_by_key(|a| cheap(a));
        let cheap_champion = by_cheap[0].clone();
        let mut by_output: Vec<(AccountId32, [u8; 32])> = all.iter().map(|a| (a.clone(), output_of(a))).collect();
        by_output.sort_by_key(|(_, o)| *o);
        let champion_rank = by_output.iter().position(|(a, _)| *a == cheap_champion).unwrap();
        assert!(
            champion_rank >= 4,
            "for this fixed sample the cheap-key champion is not among the 4 best outputs (rank {champion_rank})"
        );

        // We fill the set (4) with the best 4 outputs: the cheap-key champion does not get in despite its cheap advantage.
        for (who, _) in by_output.iter().take(4) {
            submit(who).unwrap();
        }
        let err = submit(&cheap_champion).unwrap_err();
        assert_eq!(err.error, Error::<TestRuntime>::AdmissionCapReached.into());
        assert!(!A::candidates().contains(&cheap_champion));
        // And the same identity cannot improve its rank by resubmitting in the round: improving = a new identity + a new puzzle.
        let (in_pool, _) = by_output[0].clone();
        assert_eq!(submit(&in_pool), Err(early_reject(Error::<TestRuntime>::AlreadyAdmittedThisRound)));
    });
}

/// The draw does not happen without fresh entropy after the closing (`MinFreshEntropyBlocks` = 3): rotations without blocks are not enough,
/// and the VRFs that preceded the closing do not count.
#[test]
fn the_draw_is_deferred_until_enough_fresh_entropy_arrives_after_the_close() {
    new_test_ext().execute_with(|| {
        let who = account(200);
        mine(10); // entropy before candidacy (does not count)
        submit(&who).unwrap();
        rotate_raw(1); // closing without any new block
        rotate_raw(2);
        assert!(
            !rotate_raw(3).contains(&who),
            "no fresh VRF after the close => no draw, however many rotations pass"
        );
        assert_eq!(
            madar_admission::Pending::<TestRuntime>::get().len(),
            1,
            "the pool keeps waiting"
        );
        mine(2);
        assert!(!rotate_raw(4).contains(&who), "2 fresh VRFs < 3 required");
        mine(1);
        assert!(
            rotate_raw(5).contains(&who),
            "3 fresh VRFs after the close: the draw happens"
        );
    });
}

/// The same VRF is not counted twice (a block without a new VRF keeps the previous value in `AuthorVrfRandomness`).
#[test]
fn the_same_vrf_is_never_counted_twice() {
    new_test_ext().execute_with(|| {
        frame_system::Pallet::<TestRuntime>::set_block_number(7);
        for _ in 0..10 {
            <A as frame_support::traits::Hooks<u64>>::on_initialize(7);
        }
        assert_eq!(
            madar_admission::EntropyCount::<TestRuntime>::get(),
            1,
            "the same VRF is mixed once"
        );
    });
}

/// A core security property: the winners are determined by entropy **written after** the candidacy closed. The same candidates and the same history up to
/// the closing: the same later blocks => the same winners; different later blocks => different winners. So whoever committed cannot predict.
#[test]
fn winners_depend_on_entropy_written_only_after_the_close() {
    let accounts: Vec<_> = (30u8..38).map(account).collect(); // 8 candidates (set of 4), cap 2
    let run = |gap: u64| {
        let mut winners = Vec::new();
        new_test_ext().execute_with(|| {
            for who in accounts.iter().take(4) {
                submit(who).unwrap();
            }
            rotate_raw(1); // closing
            frame_system::Pallet::<TestRuntime>::set_block_number(50 + gap); // different later blocks depending on gap
            mine(3);
            rotate_raw(2);
            mine(3);
            let mut set = rotate_raw(3);
            set.sort();
            winners = set;
        });
        winners
    };
    let a = run(0);
    assert_eq!(a.len(), 2);
    assert_eq!(
        a,
        run(0),
        "same post-close entropy => same winners (deterministic)"
    );
    assert!(
        (1u64..40).any(|gap| run(gap) != a),
        "different post-close entropy must change the draw"
    );
}

/// Renewal for a current member: extends validity, with no round cap and no competition with the candidates.
#[test]
fn renewal_extends_the_term_and_is_accounted_separately_from_new_admissions() {
    new_test_ext().execute_with(|| {
        let member = account(40);
        Admission::dev_only_force_set_validators(RuntimeOrigin::root(), vec![member.clone()])
            .unwrap();
        rotate(1);
        assert_eq!(
            madar_admission::MembershipExpiry::<TestRuntime>::get(&member),
            Some(3)
        );

        for i in 50u8..54 {
            submit(&account(i)).unwrap(); // the candidate set is full
        }
        submit(&member).expect("renewal must not compete with new admissions");
        assert_eq!(
            madar_admission::MembershipExpiry::<TestRuntime>::get(&member),
            Some(1 + 3)
        );
        assert!(
            !A::candidates().contains(&member),
            "a renewal is not a candidacy"
        );
        assert_eq!(
            submit(&member),
            Err(early_reject(Error::<TestRuntime>::AlreadyRenewed))
        );
    });
}

/// Validity 3 + grace 2: the non-renewing member is removed at rotation 5, and the renewing one stays.
#[test]
fn a_membership_not_renewed_is_removed_after_term_plus_grace() {
    new_test_ext().execute_with(|| {
        let (stale, keeper) = (account(60), account(61));
        Admission::dev_only_force_set_validators(
            RuntimeOrigin::root(),
            vec![stale.clone(), keeper.clone()],
        )
        .unwrap();
        for i in 1..=4 {
            assert!(rotate(i).contains(&stale), "still a member at session {i}");
        }
        submit(&keeper).unwrap(); // renews in session 4 (extended to 7)
        let set = rotate(5);
        assert!(
            !set.contains(&stale),
            "removed at session 5 = term(3) + grace(2)"
        );
        assert!(set.contains(&keeper));
        assert!(madar_admission::MembershipExpiry::<TestRuntime>::get(&stale).is_none());
    });
}

/// Liveness guarantee: no removal (expiry/exit) empties the set.
#[test]
fn removals_never_empty_the_validator_set() {
    new_test_ext().execute_with(|| {
        let only = account(70);
        Admission::dev_only_force_set_validators(RuntimeOrigin::root(), vec![only.clone()])
            .unwrap();
        for i in 1..=8 {
            assert_eq!(
                rotate(i),
                vec![only.clone()],
                "the sole validator is kept at session {i}"
            );
        }
        Admission::voluntary_exit(RuntimeOrigin::signed(only.clone())).unwrap();
        assert_eq!(
            rotate(9),
            vec![only.clone()],
            "an exit that would empty the set is deferred"
        );
    });
}

#[test]
fn a_permanently_banned_key_is_never_admitted_again_and_is_removed_everywhere() {
    new_test_ext().execute_with(|| {
        let (offender, other) = (account(7), account(8));
        Admission::dev_only_force_set_validators(
            RuntimeOrigin::root(),
            vec![offender.clone(), other],
        )
        .unwrap();
        Admission::voluntary_exit(RuntimeOrigin::signed(offender.clone())).unwrap();
        Admission::ban_key(RuntimeOrigin::root(), offender.clone()).expect("root can ban");
        assert!(
            !A::validators().contains(&offender),
            "ban removes immediately"
        );
        assert!(madar_admission::MembershipExpiry::<TestRuntime>::get(&offender).is_none());
        assert!(!madar_admission::PendingVoluntaryExit::<TestRuntime>::contains_key(&offender));

        frame_system::Pallet::<TestRuntime>::set_block_number(1);
        assert_eq!(
            submit(&offender),
            Err(early_reject(Error::<TestRuntime>::KeyPermanentlyBanned))
        );
    });
}

/// **B12 (owner decision 2026-09-28):** the last live voter proven to have cheated is banned but stays — no empty set and no permanent halt —
/// and it neither returns nor renews, and it leaves automatically at the first rotation where a replacement is accepted.
#[test]
fn the_last_voter_banned_for_equivocation_is_kept_until_a_replacement_is_admitted() {
    new_test_ext().execute_with(|| {
        frame_system::Pallet::<TestRuntime>::set_block_number(1);
        let only = account(71);
        Admission::dev_only_force_set_validators(RuntimeOrigin::root(), vec![only.clone()]).unwrap();

        A::ban(&only);
        assert_eq!(A::validators(), vec![only.clone()], "banning the last live voter must not empty the set");
        assert!(madar_admission::BannedKeys::<TestRuntime>::contains_key(&only), "the ban itself is recorded");
        assert!(frame_system::Pallet::<TestRuntime>::events().iter().any(|e| matches!(
            &e.event,
            RuntimeEvent::Admission(madar_admission::Event::LastValidatorBannedButKept { who }) if *who == only
        )));
        assert_eq!(submit(&only), Err(early_reject(Error::<TestRuntime>::KeyPermanentlyBanned)), "it can never re-apply");

        for i in 1..=3 {
            assert_eq!(rotate(i), vec![only.clone()], "no replacement yet: the banned last voter keeps the chain alive ({i})");
        }

        let newcomer = account(72);
        submit(&newcomer).expect("a replacement applies");
        assert!(!rotate(4).contains(&newcomer));
        assert!(!rotate(5).contains(&newcomer));
        let set = rotate(6);
        assert_eq!(set, vec![newcomer.clone()], "the replacement is admitted and the banned voter leaves in the same rotation");
        assert!(!A::validators().contains(&only));
    });
}

/// B12 does not change the normal case: with another voter present, the offender is evicted immediately as before.
#[test]
fn a_banned_voter_that_is_not_the_last_is_still_removed_immediately() {
    new_test_ext().execute_with(|| {
        let (offender, honest) = (account(73), account(74));
        Admission::dev_only_force_set_validators(
            RuntimeOrigin::root(),
            vec![offender.clone(), honest.clone()],
        )
        .unwrap();
        A::ban(&offender);
        assert_eq!(A::validators(), vec![honest.clone()]);
        assert_eq!(rotate(1), vec![honest]);
    });
}

#[test]
fn ban_key_requires_root_origin() {
    new_test_ext().execute_with(|| {
        let r = Admission::ban_key(RuntimeOrigin::signed(account(1)), account(2));
        assert_eq!(r, Err(DispatchError::BadOrigin));
    });
}

#[test]
fn only_current_validators_can_register_a_voluntary_exit() {
    new_test_ext().execute_with(|| {
        let stranger = account(80);
        assert_eq!(
            Admission::voluntary_exit(RuntimeOrigin::signed(stranger.clone())),
            Err(Error::<TestRuntime>::NotAValidator.into())
        );
        assert!(!madar_admission::PendingVoluntaryExit::<TestRuntime>::contains_key(&stranger));
    });
}

/// Voluntary exit (§2.9): recorded immediately, executed at the session rotation only, with no unbonding.
#[test]
fn voluntary_exit_is_enacted_only_at_the_next_session_rotation() {
    new_test_ext().execute_with(|| {
        let (leaving, staying) = (account(90), account(91));
        Admission::dev_only_force_set_validators(
            RuntimeOrigin::root(),
            vec![leaving.clone(), staying.clone()],
        )
        .unwrap();
        Admission::voluntary_exit(RuntimeOrigin::signed(leaving.clone())).unwrap();
        assert!(
            A::validators().contains(&leaving),
            "not removed immediately"
        );
        let remaining = rotate(1);
        assert!(!remaining.contains(&leaving) && remaining.contains(&staying));
        assert!(!madar_admission::PendingVoluntaryExit::<TestRuntime>::contains_key(&leaving));
    });
}

/// No accumulation: every rotation clears the round, so the candidacy state does not grow across rounds.
#[test]
fn candidate_state_does_not_accumulate_across_rounds() {
    new_test_ext().execute_with(|| {
        for round in 0..5u64 {
            frame_system::Pallet::<TestRuntime>::set_block_number(round + 1);
            for i in 0..3u8 {
                submit(&account(100 + (round as u8) * 3 + i)).unwrap();
            }
            rotate(round as u32 + 1);
            assert_eq!(madar_admission::Round::<TestRuntime>::get(), None);
            assert!(
                madar_admission::Pending::<TestRuntime>::get().len() <= 2,
                "at most two closed pools in flight"
            );
        }
        assert!(A::validators().len() <= 5 * 2, "cap 2 per round");
    });
}

/// **Review #5 (1):** in the runtime `Session` precedes `Admission` in `on_initialize`, so at the closing the previous block's VRF
/// (produced before the closing) has not been accumulated yet. It must not count as "fresh" entropy after the closing.
#[test]
fn a_vrf_produced_before_the_close_never_counts_as_fresh_entropy() {
    new_test_ext().execute_with(|| {
        let who = account(210);
        mine(5); // blocks 1..5
        submit(&who).unwrap(); // at block 5
                               // Closing block 6: the session runs before Admission's own `on_initialize` (the real runtime order).
        frame_system::Pallet::<TestRuntime>::set_block_number(6);
        rotate_raw(1); // closing (block 5's VRF not yet accumulated inside the runtime)
        <A as frame_support::traits::Hooks<u64>>::on_initialize(6);
        mine(2); // blocks 7,8 => the VRFs of blocks 6,7 are fresh: only 2 (3 required)
        rotate_raw(2);
        assert!(
            !rotate_raw(3).contains(&who),
            "the block-5 VRF (pre-close) must not be counted: 2 fresh < 3"
        );
        mine(1); // block 9 => block 8's VRF: the third
        assert!(
            rotate_raw(4).contains(&who),
            "3 genuinely fresh VRFs: the draw happens"
        );
    });
}

/// **Review #5 (2):** a lack of entropy for more than four rounds drops no accepted set, storage stays bounded, and new
/// candidacy is restricted (instead of deleted) until a slot frees up; then the system recovers without stalling and every accepted candidacy is drawn.
#[test]
fn entropy_starvation_never_drops_accepted_candidates_and_recovers() {
    new_test_ext().execute_with(|| {
        // 4 rounds close without any later fresh VRF: the queue fills with four accepted sets.
        // The block stays fixed (1) during these rotations: no new VRF enters (otherwise every rotation would add a VRF and the fresh counter would grow).
        frame_system::Pallet::<TestRuntime>::set_block_number(1);
        for e in 0..4u64 {
            submit(&account(60 + e as u8)).unwrap();
            rotate_raw(e as u32 + 1);
        }
        assert_eq!(madar_admission::Pending::<TestRuntime>::get().len(), 4);

        // The fifth round: accepted into `Round` but there is no room in the queue to close it — it stays open (no deletion).
        submit(&account(64)).unwrap();
        rotate_raw(5);
        assert_eq!(
            madar_admission::Pending::<TestRuntime>::get().len(),
            4,
            "queue stays bounded"
        );
        assert_eq!(
            A::candidates(),
            vec![account(64)],
            "the open round is kept, not dropped"
        );

        // The sixth: new candidacy is restricted instead of deleting the accepted one.
        frame_system::Pallet::<TestRuntime>::set_block_number(2); // a new seed (a new epoch)
        assert_eq!(
            submit(&account(65)),
            Err(early_reject(Error::<TestRuntime>::CandidacyBacklogFull))
        );
        rotate_raw(6);
        assert_eq!(madar_admission::Pending::<TestRuntime>::get().len(), 4);
        assert_eq!(A::candidates(), vec![account(64)]);
        assert!(
            A::validators().is_empty(),
            "nothing drawn without fresh entropy"
        );

        // Recovery: fresh entropy => the four rounds are drawn (all older than the delay), and the open round closes in the freed slot.
        mine(3);
        rotate_raw(7);
        let admitted = A::validators();
        for e in 0..4u8 {
            assert!(
                admitted.contains(&account(60 + e)),
                "accepted candidate {e} must not be lost"
            );
        }
        assert_eq!(
            A::candidates(),
            Vec::<AccountId32>::new(),
            "the held round was closed into the freed slot"
        );
        assert_eq!(madar_admission::Pending::<TestRuntime>::get().len(), 1);

        // Candidacy opens again (no stall), and the held round's candidacy is drawn later.
        submit(&account(65)).expect("candidacy reopens after the backlog clears");
        mine(3);
        rotate_raw(8);
        mine(3);
        rotate_raw(9);
        assert!(
            A::validators().contains(&account(64)),
            "the held candidate is eventually admitted"
        );
    });
}

/// The validator set is full: the lottery winner is neither accepted nor silently deleted (a `NotAdmittedSetFull` event), and the set does not exceed its limit.
#[test]
fn a_winner_is_never_silently_dropped_when_the_validator_set_is_full() {
    new_test_ext().execute_with(|| {
        let full: Vec<AccountId32> = (0u8..100).map(|i| account(i.wrapping_add(120))).collect();
        Admission::dev_only_force_set_validators(RuntimeOrigin::root(), full.clone()).unwrap();
        let who = account(250);
        submit(&who).unwrap();
        rotate(1);
        rotate(2);
        rotate(3);
        assert_eq!(A::validators().len(), 100, "never above MaxValidators");
        assert!(!A::validators().contains(&who));
        let events = frame_system::Pallet::<TestRuntime>::events();
        assert!(
            events.iter().any(|e| matches!(&e.event, RuntimeEvent::Admission(madar_admission::Event::NotAdmittedSetFull { who: w }) if *w == who)),
            "the outcome is reported explicitly"
        );
    });
}

/// Review #23: every state tied to an account (`MembershipExpiry`, `PendingVoluntaryExit`) is reclaimed when the member leaves for whatever reason (expiry,
/// voluntary exit, ban), so it does not accumulate over sessions; and pending sets are bounded. Only `BannedKeys` is deliberately permanent (no return for a banned key).
#[test]
fn per_account_state_never_outlives_membership_across_many_rounds() {
    use madar_admission::{BannedKeys, MembershipExpiry, PendingVoluntaryExit};
    new_test_ext().execute_with(|| {
        Admission::dev_only_force_set_validators(RuntimeOrigin::root(), (1..=6).map(account).collect()).unwrap();
        let mut bans = 0usize;
        let mut ever: std::collections::BTreeSet<AccountId32> = A::validators().into_iter().collect();
        for round in 0..30u32 {
            frame_system::Pallet::<TestRuntime>::set_block_number(round as u64 + 1);
            for i in 0..3u8 {
                let _ = submit(&account(120 + ((round * 3 + i as u32) % 100) as u8));
            }
            // Voluntary exit and ban alternately for one of the current members (if any).
            let members = A::validators();
            if round % 4 == 1 {
                if let Some(m) = members.first() {
                    let _ = Admission::voluntary_exit(RuntimeOrigin::signed(m.clone()));
                }
            }
            if round % 7 == 3 && members.len() > 2 {
                let victim = members.last().unwrap().clone();
                if !BannedKeys::<TestRuntime>::contains_key(&victim) {
                    Admission::ban_key(RuntimeOrigin::root(), victim).unwrap();
                    bans += 1;
                }
            }
            rotate(round + 1);

            let members = A::validators();
            ever.extend(members.iter().cloned());
            for k in MembershipExpiry::<TestRuntime>::iter_keys() {
                assert!(members.contains(&k), "round {round}: leftover MembershipExpiry for a non-member");
            }
            for k in PendingVoluntaryExit::<TestRuntime>::iter_keys() {
                assert!(members.contains(&k), "round {round}: leftover PendingVoluntaryExit for a non-member");
            }
            assert!(madar_admission::Pending::<TestRuntime>::get().len() <= 2, "closed pools in flight stay bounded");
            assert!(members.len() <= 100, "MaxValidators");
        }
        assert!(ever.len() > A::validators().len(), "the scenario must actually remove members (expiry/exit/ban), or the checks above are vacuous");
        assert_eq!(BannedKeys::<TestRuntime>::iter_keys().count(), bans, "bans are the only permanent per-account state");
    });
}
