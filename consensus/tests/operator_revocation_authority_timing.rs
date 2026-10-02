//! D47 (Codex review #2) — revoking an operator's approval or a node's vouch removes the account immediately
//! from the `madar_admission` registry (`Validators`), but that **alone does not prove** it has stopped
//! actually participating in block production (BABE) or finality (GRANDPA) —
//! that is real authority managed by `pallet_session` with deferred scheduling (Queued then Active),
//! not directly by Admission. This test determines **exactly** how many session rotations are needed after
//! the call until the actual authority is gone — using the same methodology as `validator_lifecycle.rs`
//! (`a_voluntary_exit_removes_real_authority_two_rotations_later`), not by assumption.

mod common;

use common::{dev_validator, new_test_ext};
use madar_consensus::{AccountId, Runtime, RuntimeOrigin, SessionKeys, UpgradeCommitteeInstance};
use pallet_collective::RawOrigin as CollectiveRawOrigin;

fn active_session_validators() -> Vec<AccountId> {
    pallet_session::Pallet::<Runtime>::validators()
}
fn babe_authorities() -> usize {
    pallet_babe::Pallet::<Runtime>::authorities().len()
}
fn grandpa_authorities() -> usize {
    pallet_grandpa::Pallet::<Runtime>::grandpa_authorities().len()
}
fn feed_entropy() {
    for _ in 0..madar_consensus::MIN_FRESH_ENTROPY_BLOCKS {
        let block = frame_system::Pallet::<Runtime>::block_number() + 1;
        frame_system::Pallet::<Runtime>::set_block_number(block);
        pallet_babe::AuthorVrfRandomness::<Runtime>::put(Some([block as u8; 32]));
        <madar_admission::Pallet<Runtime> as frame_support::traits::Hooks<u32>>::on_initialize(
            block,
        );
    }
}
fn rotate() {
    feed_entropy();
    let block = frame_system::Pallet::<Runtime>::block_number() + 1;
    frame_system::Pallet::<Runtime>::set_block_number(block);
    pallet_babe::Initialized::<Runtime>::put(None::<sp_consensus_babe::digests::PreDigest>);
    pallet_session::Pallet::<Runtime>::rotate_session();
    <pallet_grandpa::Pallet<Runtime> as frame_support::traits::Hooks<u32>>::on_finalize(block);
}
fn committee_origin() -> RuntimeOrigin {
    CollectiveRawOrigin::<sp_runtime::AccountId32, UpgradeCommitteeInstance>::Members(2, 3).into()
}

/// Inserts `winner` as a lottery winner (by directly manipulating storage, as in
/// `validator_lifecycle.rs`) and runs rotations until it becomes a **real, actual authority**
/// in Session/BABE/GRANDPA together — not just in the Admission registry. `operator` must
/// be an account **completely separate** from any Genesis/Dev-only seat (D52:
/// the final cap = one vote per operator; an operator that already occupies its own seat
/// has no remaining cap to vouch for any other node — see
/// `an_operators_own_genesis_seat_counts_against_its_own_cap`).
fn admit_and_activate_as_real_authority(
    operator: &sp_runtime::AccountId32,
    winner: &common::DevValidator,
) {
    madar_admission::Pallet::<Runtime>::approve_operator(committee_origin(), operator.clone(), 1)
        .expect("committee approval must succeed");
    madar_admission::Pallet::<Runtime>::vouch_node(
        RuntimeOrigin::signed(operator.clone()),
        winner.account.clone(),
    )
    .expect("vouching must succeed");

    madar_admission::Round::<Runtime>::put((
        <Runtime as madar_admission::Config>::EpochRandomness::random(
            madar_protocol::ADMISSION_PUZZLE_DOMAIN,
        )
        .0,
        frame_support::BoundedVec::try_from(vec![(winner.account.clone(), [0u8; 32])]).unwrap(),
    ));
    pallet_session::NextKeys::<Runtime>::insert(
        &winner.account,
        SessionKeys {
            babe: winner.babe.clone(),
            grandpa: winner.grandpa.clone(),
        },
    );

    rotate(); // close candidacy
    rotate(); // wait for randomness after closing
    rotate(); // draw — now in the Admission registry (Validators)
    assert!(madar_admission::Pallet::<Runtime>::validators().contains(&winner.account));
    rotate(); // queue (Queued)
    rotate(); // activate (Active)
    assert!(
        active_session_validators().contains(&winner.account),
        "premise: winner must be a real active authority before we test its removal"
    );
}

use frame_support::traits::Randomness;

/// **Codex #2 — timing of a full operator approval revocation:** removed from the Admission registry
/// immediately, but remains an actual authority until two full session rotations complete — **exactly** the same
/// timing as a voluntary exit, no faster and no slower. **Updated (D52):** the operator here
/// is an account completely separate from alice (the final cap = one vote per operator, so
/// alice — a Genesis seat — cannot herself be an operator vouching for another node);
/// alice remains here only as a simple liveness guarantor entirely unaffected by this scenario.
#[test]
fn revoking_operator_approval_removes_real_authority_exactly_two_rotations_later() {
    let alice = dev_validator(1);
    let winner = dev_validator(77);
    let operator = sp_runtime::AccountId32::from([200u8; 32]);
    new_test_ext(&[dev_validator(1)]).execute_with(|| {
        admit_and_activate_as_real_authority(&operator, &winner);
        assert_eq!((babe_authorities(), grandpa_authorities()), (2, 2), "alice + winner");

        madar_admission::Pallet::<Runtime>::revoke_operator_approval(committee_origin(), operator.clone())
            .expect("revocation must succeed: alice remains as a live authority elsewhere, untouched by this operator");

        // Immediate in the Admission registry itself — no new production authority, but not yet in Session/BABE/GRANDPA.
        assert!(!madar_admission::Pallet::<Runtime>::validators().contains(&winner.account), "Admission's own bookkeeping drops it immediately");
        assert!(active_session_validators().contains(&winner.account), "real authority is NOT instant: still active right after the call");
        assert_eq!((babe_authorities(), grandpa_authorities()), (2, 2), "BABE/GRANDPA unaffected immediately after revocation");

        rotate(); // rotation 1 after revocation: the change is queued (Queued), not yet activated
        assert!(active_session_validators().contains(&winner.account), "still active after only one rotation — queued, not yet swapped in");
        assert_eq!((babe_authorities(), grandpa_authorities()), (2, 2));

        rotate(); // rotation 2: now the queued set actually takes effect
        assert!(!active_session_validators().contains(&winner.account), "exactly two rotations after revocation: real authority is finally gone");
        assert_eq!((babe_authorities(), grandpa_authorities()), (1, 1), "only alice remains — the network keeps running, entirely unaffected by this operator's revocation");
        assert!(active_session_validators().contains(&alice.account));
    });
}

/// **Codex #2 (single vouch):** exactly the same timing when revoking the vouch for a single node
/// (`revoke_vouch`) instead of revoking the operator's approval entirely. The operator here is also an account
/// separate from alice (D52: a cap of one vote per operator).
#[test]
fn revoking_a_single_nodes_vouch_removes_real_authority_exactly_two_rotations_later() {
    let alice = dev_validator(1);
    let winner = dev_validator(77);
    let operator = sp_runtime::AccountId32::from([200u8; 32]);
    new_test_ext(&[dev_validator(1)]).execute_with(|| {
        admit_and_activate_as_real_authority(&operator, &winner);

        madar_admission::Pallet::<Runtime>::revoke_vouch(
            RuntimeOrigin::signed(operator.clone()),
            winner.account.clone(),
        )
        .expect("revoking the vouch must succeed");

        assert!(!madar_admission::Pallet::<Runtime>::validators().contains(&winner.account));
        assert!(
            active_session_validators().contains(&winner.account),
            "not instant: still active right after the call"
        );

        rotate();
        assert!(
            active_session_validators().contains(&winner.account),
            "still active after one rotation (queued only)"
        );

        rotate();
        assert!(
            !active_session_validators().contains(&winner.account),
            "exactly two rotations after revoking the vouch: gone"
        );
        assert_eq!((babe_authorities(), grandpa_authorities()), (1, 1));
        assert!(
            active_session_validators().contains(&alice.account),
            "alice, unrelated to this operator, is untouched"
        );
    });
}

/// **Codex #3 (D49) — the root vulnerability:** an operator with cap 1 whose own account has been a Validator
/// since Genesis (Dev-only, never went through `vouch_node`) — an attempt to vouch for
/// a second node must be rejected immediately, because its own seat consumes its entire cap.
/// **It must never happen** that the operator ends up with two actual votes (its seat + a vouched node)
/// with a cap of 1 — proven here at the level of the real BABE/GRANDPA, not just the Admission registry.
#[test]
fn an_operators_own_genesis_seat_counts_against_its_own_cap() {
    let alice = dev_validator(1);
    let winner = dev_validator(77);
    new_test_ext(&[dev_validator(1)]).execute_with(|| {
        assert_eq!((babe_authorities(), grandpa_authorities()), (1, 1), "premise: alice alone is the real authority from genesis");

        madar_admission::Pallet::<Runtime>::approve_operator(committee_origin(), alice.account.clone(), 1)
            .expect("committee approval must succeed even though alice already occupies a seat");

        // An attempt to vouch for a second node under cap 1 — must be rejected: alice's own
        // (Genesis) seat already counts as a vote consumed from her cap.
        assert_eq!(
            madar_admission::Pallet::<Runtime>::vouch_node(RuntimeOrigin::signed(alice.account.clone()), winner.account.clone()),
            Err(madar_admission::Error::<Runtime>::OperatorAtVouchCapacity.into()),
            "alice's own genesis seat must already consume her cap of 1"
        );

        // Even if we try (by directly manipulating storage, as other tests in
        // this file do) to insert `winner` as a lottery winner without an actual vouch, it never
        // becomes an actual authority: the filtering in `new_session` requires a real vouch.
        madar_admission::Round::<Runtime>::put((
            <Runtime as madar_admission::Config>::EpochRandomness::random(madar_protocol::ADMISSION_PUZZLE_DOMAIN).0,
            frame_support::BoundedVec::try_from(vec![(winner.account.clone(), [0u8; 32])]).unwrap(),
        ));
        pallet_session::NextKeys::<Runtime>::insert(
            &winner.account,
            SessionKeys { babe: winner.babe.clone(), grandpa: winner.grandpa.clone() },
        );
        for _ in 0..5 {
            rotate();
        }
        assert!(!madar_admission::Pallet::<Runtime>::validators().contains(&winner.account), "unvouched: never even in Admission's own bookkeeping");
        assert!(!active_session_validators().contains(&winner.account));
        assert_eq!(
            (babe_authorities(), grandpa_authorities()),
            (1, 1),
            "the operator's real vote count (BABE+GRANDPA authorities), not just Admission's bookkeeping, must never exceed its cap of 1"
        );
    });
}

// Note D52: there used to be a test here
// (`lowering_the_cap_accounts_for_the_operators_own_genesis_seat_plus_its_vouched_node`)
// that assumed an operator with cap 2 (its own seat + a vouched node). After adopting the
// final cap = one vote per operator (D52), this scenario is **structurally impossible** —
// `approve_operator(op, 2)` is rejected on the very first call (`MaxVotesExceedsAbsoluteLimit`).
// The test was removed because its scenario can no longer actually occur, not because it failed;
// the "Genesis seat + cap 1" case is fully covered in
// `an_operators_own_genesis_seat_counts_against_its_own_cap` above.

/// **Codex #1 + #2 together:** lowering an operator's cap from 1 to 0 evicts its only vote immediately
/// from the Admission registry, but its real actual authority is subject to the same two-rotation delay —
/// no claim of immediate effect. **Updated (D52):** the operator is an account separate from alice
/// (the final cap = one vote, so it cannot hold both a Genesis seat and a node).
#[test]
fn lowering_the_operator_cap_below_live_votes_removes_real_authority_exactly_two_rotations_later() {
    let alice = dev_validator(1);
    let winner = dev_validator(77);
    let operator = sp_runtime::AccountId32::from([200u8; 32]);
    new_test_ext(&[dev_validator(1)]).execute_with(|| {
        admit_and_activate_as_real_authority(&operator, &winner);
        assert!(active_session_validators().contains(&winner.account));

        // Governance lowers the operator's cap from 1 (the absolute maximum) to 0 —
        // its only vote (winner) is evicted immediately from the Admission registry.
        madar_admission::Pallet::<Runtime>::approve_operator(
            committee_origin(),
            operator.clone(),
            0,
        )
        .expect(
            "lowering the cap must succeed: alice remains as a live authority elsewhere, untouched",
        );
        assert!(
            !madar_admission::Pallet::<Runtime>::validators().contains(&winner.account),
            "Admission's bookkeeping drops it immediately"
        );
        assert!(
            active_session_validators().contains(&winner.account),
            "real authority is not instant"
        );

        rotate();
        assert!(
            active_session_validators().contains(&winner.account),
            "queued only after one rotation"
        );
        rotate();
        assert!(
            !active_session_validators().contains(&winner.account),
            "gone after exactly two rotations"
        );
        assert_eq!(
            (babe_authorities(), grandpa_authorities()),
            (1, 1),
            "only alice remains"
        );
        assert!(active_session_validators().contains(&alice.account));
    });
}

/// **D50 (fourth Codex review) — the founding node itself is subject to the same cap and
/// revocation decision; it has no immunity.** An operator that is a real founding node (Genesis) in a network
/// with another founding node (bob) that guarantees its continuity — lowering its cap to 0 must evict
/// its own seat too, not just any vouched node, with the same two-rotation delay
/// known for every removal of actual authority.
#[test]
fn lowering_a_founding_operators_cap_to_zero_evicts_its_own_seat_with_the_same_two_rotation_delay()
{
    let alice = dev_validator(1);
    let bob = dev_validator(2);
    new_test_ext(&[dev_validator(1), dev_validator(2)]).execute_with(|| {
        assert_eq!((babe_authorities(), grandpa_authorities()), (2, 2), "premise: alice and bob are both real authorities from genesis");

        madar_admission::Pallet::<Runtime>::approve_operator(committee_origin(), alice.account.clone(), 1)
            .expect("committee approval must succeed even though alice already occupies a founding seat");

        madar_admission::Pallet::<Runtime>::approve_operator(committee_origin(), alice.account.clone(), 0)
            .expect("lowering the cap to zero must succeed: bob remains as a live authority elsewhere");

        // Immediate in the Admission registry — but not yet at the level of the real BABE/GRANDPA.
        assert!(!madar_admission::Pallet::<Runtime>::validators().contains(&alice.account), "Admission's own bookkeeping drops the founding seat immediately");
        assert!(active_session_validators().contains(&alice.account), "real authority is NOT instant: alice is still active right after the call");
        assert_eq!((babe_authorities(), grandpa_authorities()), (2, 2), "BABE/GRANDPA unaffected immediately after the cap reaches zero");

        rotate(); // rotation 1: the change is queued (Queued), not yet activated
        assert!(active_session_validators().contains(&alice.account), "still active after only one rotation");
        assert_eq!((babe_authorities(), grandpa_authorities()), (2, 2));

        rotate(); // rotation 2: now it actually takes effect
        assert!(!active_session_validators().contains(&alice.account), "exactly two rotations after the cap reached zero: alice's founding seat is finally gone");
        assert_eq!((babe_authorities(), grandpa_authorities()), (1, 1), "only bob remains — the network keeps running");
        assert!(active_session_validators().contains(&bob.account));
    });
}

/// **D50** — the same guarantee via `revoke_operator_approval` (revoking the approval entirely)
/// instead of gradually lowering the cap: the founding seat is evicted too, not just its vouched nodes.
#[test]
fn revoking_a_founding_operators_approval_entirely_evicts_its_own_seat_with_the_same_delay() {
    let alice = dev_validator(1);
    let bob = dev_validator(2);
    new_test_ext(&[dev_validator(1), dev_validator(2)]).execute_with(|| {
        madar_admission::Pallet::<Runtime>::approve_operator(
            committee_origin(),
            alice.account.clone(),
            1,
        )
        .expect("committee approval must succeed");

        madar_admission::Pallet::<Runtime>::revoke_operator_approval(
            committee_origin(),
            alice.account.clone(),
        )
        .expect("revocation must succeed: bob remains as a live authority elsewhere");

        assert!(
            !madar_admission::Pallet::<Runtime>::validators().contains(&alice.account),
            "Admission's own bookkeeping drops the founding seat immediately"
        );
        assert!(
            active_session_validators().contains(&alice.account),
            "real authority is not instant"
        );
        assert_eq!((babe_authorities(), grandpa_authorities()), (2, 2));

        rotate();
        assert!(
            active_session_validators().contains(&alice.account),
            "queued only after one rotation"
        );
        rotate();
        assert!(
            !active_session_validators().contains(&alice.account),
            "gone after exactly two rotations"
        );
        assert_eq!((babe_authorities(), grandpa_authorities()), (1, 1));
        assert!(
            active_session_validators().contains(&bob.account),
            "the network keeps running with bob alone"
        );
    });
}

/// **D50 — liveness guard:** with no other live alternative in the network — revoking the operator's approval
/// (or lowering its cap to zero) must be explicitly rejected instead of silently emptying the network or
/// reporting a fake success while an active vote remains beyond the two-rotation window.
#[test]
fn revoking_the_only_remaining_authority_in_the_whole_network_is_refused_outright() {
    let alice = dev_validator(1);
    new_test_ext(&[dev_validator(1)]).execute_with(|| {
        assert_eq!((babe_authorities(), grandpa_authorities()), (1, 1), "premise: alice is the sole authority in the entire network");

        madar_admission::Pallet::<Runtime>::approve_operator(committee_origin(), alice.account.clone(), 1)
            .expect("committee approval must succeed");

        assert_eq!(
            madar_admission::Pallet::<Runtime>::revoke_operator_approval(committee_origin(), alice.account.clone()),
            Err(madar_admission::Error::<Runtime>::EvictionWouldEmptyTheValidatorSet.into()),
            "revoking the sole remaining authority must be refused outright, not silently emptying the network"
        );
        assert_eq!(
            madar_admission::Pallet::<Runtime>::approve_operator(committee_origin(), alice.account.clone(), 0),
            Err(madar_admission::Error::<Runtime>::EvictionWouldEmptyTheValidatorSet.into()),
            "lowering the cap to zero for the sole remaining authority must be refused outright too"
        );

        // No fake success: nothing changed at all — neither in the Admission registry nor in the actual authority.
        assert!(madar_admission::Pallet::<Runtime>::validators().contains(&alice.account));
        assert_eq!(madar_admission::ApprovedOperators::<Runtime>::get(&alice.account), Some(1), "the cap must remain unchanged — the refused call must not partially apply");
        assert!(active_session_validators().contains(&alice.account));
        assert_eq!((babe_authorities(), grandpa_authorities()), (1, 1), "the network keeps running, untouched, exactly as before the refused calls");
    });
}

/// **D52 — several independent operators, each with exactly one vote.** Proves that the network
/// does not rely on the assumption that a single operator can fill several seats: three
/// completely independent approved operators (unrelated to each other and to alice), each
/// with cap 1 and vouching for exactly one node — all three become an actual authority together without
/// any of them exceeding its single vote, any attempt by one of them to vouch for a second node is rejected, and revoking
/// the approval of **only one operator** evicts its own node without touching the other two or alice.
/// Also covers: a node awaiting session activation within the same set (node3 is never
/// activated before the end of the test — it remains "waiting" the whole time, proving that its waiting
/// does not by itself grant an actual vote in BABE/GRANDPA).
#[test]
fn multiple_independent_operators_each_hold_exactly_one_vote_and_cannot_fill_the_network_alone() {
    let alice = dev_validator(1);
    let node1 = dev_validator(77);
    let node2 = dev_validator(78);
    let node3 = dev_validator(79);
    let op1 = sp_runtime::AccountId32::from([201u8; 32]);
    let op2 = sp_runtime::AccountId32::from([202u8; 32]);
    let op3 = sp_runtime::AccountId32::from([203u8; 32]);
    new_test_ext(&[dev_validator(1)]).execute_with(|| {
        for (op, node) in [(&op1, &node1), (&op2, &node2), (&op3, &node3)] {
            madar_admission::Pallet::<Runtime>::approve_operator(committee_origin(), op.clone(), 1)
                .expect("each independent operator's approval must succeed, cap = 1");
            madar_admission::Pallet::<Runtime>::vouch_node(RuntimeOrigin::signed(op.clone()), node.account.clone())
                .expect("each operator vouching its own single node must succeed");
        }

        // Every operator has already reached its cap — vouching for a second node under any of them is rejected immediately.
        let extra = dev_validator(80);
        assert_eq!(
            madar_admission::Pallet::<Runtime>::vouch_node(RuntimeOrigin::signed(op1.clone()), extra.account),
            Err(madar_admission::Error::<Runtime>::OperatorAtVouchCapacity.into()),
            "no single operator may ever hold more than its own one vote"
        );

        // Only node1 and node2 enter candidacy and are fully activated; node3 is vouched for
        // (above) but **never enters candidacy** — it effectively remains "waiting",
        // proving that a vouch alone (without a lottery win) grants it no authority.
        madar_admission::Round::<Runtime>::put((
            <Runtime as madar_admission::Config>::EpochRandomness::random(madar_protocol::ADMISSION_PUZZLE_DOMAIN).0,
            frame_support::BoundedVec::try_from(vec![
                (node1.account.clone(), [0u8; 32]),
                (node2.account.clone(), [1u8; 32]),
            ])
            .unwrap(),
        ));
        pallet_session::NextKeys::<Runtime>::insert(
            &node1.account,
            SessionKeys { babe: node1.babe.clone(), grandpa: node1.grandpa.clone() },
        );
        pallet_session::NextKeys::<Runtime>::insert(
            &node2.account,
            SessionKeys { babe: node2.babe.clone(), grandpa: node2.grandpa.clone() },
        );
        for _ in 0..5 {
            rotate();
        }
        assert!(active_session_validators().contains(&node1.account));
        assert!(active_session_validators().contains(&node2.account));
        assert!(!active_session_validators().contains(&node3.account), "node3 was vouched but never entered candidacy — waiting confers no authority by itself");
        assert_eq!((babe_authorities(), grandpa_authorities()), (3, 3), "alice + node1 + node2 — never 4, node3's mere vouching adds nothing");

        // Revoking op2's approval alone evicts only node2 — op1/node1 and alice are entirely unaffected.
        madar_admission::Pallet::<Runtime>::revoke_operator_approval(committee_origin(), op2)
            .expect("revoking one independent operator must succeed: the other two operators and alice remain live");
        assert!(!madar_admission::Pallet::<Runtime>::validators().contains(&node2.account), "Admission's bookkeeping drops node2 immediately");
        assert!(madar_admission::Pallet::<Runtime>::validators().contains(&node1.account), "node1 (a different, independent operator) is untouched");
        assert!(active_session_validators().contains(&node2.account), "real authority is not instant");

        rotate();
        rotate();
        assert!(!active_session_validators().contains(&node2.account), "gone after exactly two rotations");
        assert!(active_session_validators().contains(&node1.account), "node1 remains live throughout — one operator's revocation never touches another's vote");
        assert!(active_session_validators().contains(&alice.account));
        assert_eq!((babe_authorities(), grandpa_authorities()), (2, 2), "alice + node1 only");

        // op3 remains approved with its latent vote (node3 vouched for but not activated) —
        // proving that a single operator (op3) alone, whatever it does, cannot fill the network.
        assert_eq!(madar_admission::ApprovedOperators::<Runtime>::get(&op3), Some(1));
        assert!(!active_session_validators().contains(&node3.account));
    });
}
