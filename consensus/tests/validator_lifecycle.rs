//! Reviews #4/#5/#7 via the **real Session/BABE/GRANDPA** (not an isolated `new_session`):
//! when a candidate is actually accepted and when a leaver's authority is actually removed.

mod common;

use common::{dev_validator, new_test_ext};
use madar_consensus::{AccountId, Runtime, RuntimeOrigin, SessionKeys, UpgradeCommitteeInstance};
use pallet_collective::RawOrigin as CollectiveRawOrigin;

/// D47: a 2-of-3 approval origin (exactly what `OperatorApprovalOrigin` actually requires) —
/// this file tests the real Session/BABE/GRANDPA lifecycle, not the operator
/// cap itself (which has its own tests in `admission/tests/operator_caps.rs`).
fn committee_origin() -> RuntimeOrigin {
    CollectiveRawOrigin::<sp_runtime::AccountId32, UpgradeCommitteeInstance>::Members(2, 3).into()
}

fn active_session_validators() -> Vec<AccountId> {
    pallet_session::Pallet::<Runtime>::validators()
}
fn babe_authorities() -> usize {
    pallet_babe::Pallet::<Runtime>::authorities().len()
}
fn grandpa_authorities() -> usize {
    pallet_grandpa::Pallet::<Runtime>::grandpa_authorities().len()
}
/// Fresh entropy before every rotation (blocks each with a different VRF) as on the network; otherwise the draw is deferred.
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
    // BABE requires `initialize` (Pre-runtime digest) before any rotation; we initialize it as a real block without a Digest would.
    pallet_babe::Initialized::<Runtime>::put(None::<sp_consensus_babe::digests::PreDigest>);
    pallet_session::Pallet::<Runtime>::rotate_session();
    // GRANDPA applies its scheduled authority change (delay 0) in `on_finalize` of the same block.
    <pallet_grandpa::Pallet<Runtime> as frame_support::traits::Hooks<u32>>::on_finalize(block);
}

/// Voluntary exit: registering does not remove authority. After the first rotation the actual authority still exists
/// (the set is queued then activated), and it is removed at the second rotation — in Session, BABE and GRANDPA together.
#[test]
fn a_voluntary_exit_removes_real_authority_two_rotations_later() {
    let (alice, bob) = (dev_validator(1), dev_validator(2));
    new_test_ext(&[dev_validator(1), dev_validator(2)]).execute_with(|| {
        assert_eq!(
            (
                active_session_validators().len(),
                babe_authorities(),
                grandpa_authorities()
            ),
            (2, 2, 2)
        );

        madar_admission::Pallet::<Runtime>::voluntary_exit(RuntimeOrigin::signed(
            bob.account.clone(),
        ))
        .unwrap();
        assert_eq!(
            active_session_validators().len(),
            2,
            "registering the exit changes nothing yet"
        );

        rotate();
        assert_eq!(
            active_session_validators().len(),
            2,
            "authority persists through the queued rotation"
        );
        assert_eq!(babe_authorities(), 2);

        rotate();
        assert_eq!(active_session_validators(), vec![alice.account.clone()]);
        assert_eq!(
            (babe_authorities(), grandpa_authorities()),
            (1, 1),
            "BABE and GRANDPA drop the exited authority"
        );
    });
}

/// Liveness guarantee on the real Session: everyone exiting does not empty the actual set.
#[test]
fn collective_exit_never_empties_the_real_authority_set() {
    new_test_ext(&[dev_validator(1), dev_validator(2)]).execute_with(|| {
        for v in [dev_validator(1), dev_validator(2)] {
            madar_admission::Pallet::<Runtime>::voluntary_exit(RuntimeOrigin::signed(v.account))
                .unwrap();
        }
        rotate();
        rotate();
        rotate();
        assert!(!active_session_validators().is_empty());
        assert!(babe_authorities() >= 1 && grandpa_authorities() >= 1);
    });
}

/// A winning candidate with Session keys becomes an actual authority after two rotations; one without keys is not accepted.
#[test]
fn a_lottery_winner_with_session_keys_becomes_real_authority_and_one_without_keys_does_not() {
    let alice = dev_validator(1);
    new_test_ext(&[dev_validator(1)]).execute_with(|| {
        frame_system::Pallet::<Runtime>::set_block_number(13);
        let winner = dev_validator(77);
        let no_keys = dev_validator(78);

        // Both candidates enter the set directly (the valid solution for 77 is known; 78 is inserted by bypassing
        // the puzzle only via the same storage path, to test the key filter, not the puzzle).
        madar_admission::Round::<Runtime>::put((
            <Runtime as madar_admission::Config>::EpochRandomness::random(
                madar_protocol::ADMISSION_PUZZLE_DOMAIN,
            )
            .0,
            frame_support::BoundedVec::try_from(vec![
                (winner.account.clone(), [0u8; 32]),
                (no_keys.account.clone(), [0u8; 32]),
            ])
            .unwrap(),
        ));
        // 77 registers its keys (`NextKeys` is Session's own storage; proof of ownership via `set_keys` requires
        // a real signing key in the Keystore and has its own Session test).
        pallet_session::NextKeys::<Runtime>::insert(
            &winner.account,
            SessionKeys {
                babe: winner.babe.clone(),
                grandpa: winner.grandpa.clone(),
            },
        );
        // D47/D52: winning the lottery alone is no longer sufficient — it needs a vouch from
        // an operator approved by committee governance. `no_keys` intentionally stays without a vouch (it is rejected
        // anyway for lacking session keys). **The final cap = one vote per
        // operator (D52)** — the operator cannot be `alice` (her own seat from
        // Genesis consumes her entire cap, D49); we use a completely separate operator.
        let winner_operator = sp_runtime::AccountId32::from([200u8; 32]);
        madar_admission::Pallet::<Runtime>::approve_operator(
            committee_origin(),
            winner_operator.clone(),
            1,
        )
        .expect("committee approval must succeed");
        madar_admission::Pallet::<Runtime>::vouch_node(
            RuntimeOrigin::signed(winner_operator),
            winner.account.clone(),
        )
        .expect("vouching must succeed");

        rotate(); // close candidacy
        rotate(); // wait for randomness written after closing
        assert!(
            !madar_admission::Pallet::<Runtime>::validators().contains(&winner.account),
            "not drawn yet"
        );
        rotate(); // draw
        assert!(madar_admission::Pallet::<Runtime>::validators().contains(&winner.account));
        assert!(
            !madar_admission::Pallet::<Runtime>::validators().contains(&no_keys.account),
            "no keys => not admitted"
        );
        rotate(); // queue
        rotate(); // activate
        assert!(active_session_validators().contains(&winner.account));
        assert!(active_session_validators().contains(&alice.account));
        assert_eq!((babe_authorities(), grandpa_authorities()), (2, 2));
    });
}

use frame_support::traits::Randomness;
