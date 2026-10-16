//! spec 9 — the offender is disabled in BABE **immediately** through `pallet_session::DisabledValidators` (before, `DisabledValidators = ()`:
//! a proven offender stayed a fully valid block producer until it left the set after two rotations). The tests go through the real pipeline:
//! unsigned Equivocation report ⇒ `BanOnOffence` ⇒ `ban_and_disable` ⇒ `pallet_babe` rejects its block.
//! And the liveness guards: the last one is never disabled (B12), never more than `floor((n-1)/3)`, and no disabling that leaves the set with no remaining producer.

mod common;

use common::{dev_validator, new_test_ext, DevValidator};
use finality_grandpa as grandpa;
use frame_support::traits::{DisabledValidators, KeyOwnerProofSystem, OnFinalize};
use madar_consensus::{
    AccountId, Executive, Historical, Runtime, RuntimeCall, RuntimeOrigin, UncheckedExtrinsic,
};
use sp_consensus_grandpa::{
    AuthorityId, AuthoritySignature, Equivocation, EquivocationProof, KEY_TYPE,
};
use sp_core::{ed25519, Pair, H256};

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
    pallet_babe::Initialized::<Runtime>::put(None::<sp_consensus_babe::digests::PreDigest>);
    let block = frame_system::Pallet::<Runtime>::block_number() + 1;
    frame_system::Pallet::<Runtime>::set_block_number(block);
    pallet_session::Pallet::<Runtime>::rotate_session();
    <pallet_grandpa::Pallet<Runtime> as OnFinalize<u32>>::on_finalize(block);
}

fn double_precommit(v: &DevValidator, set_id: u64, round: u64) -> EquivocationProof<H256, u32> {
    let pair = ed25519::Pair::from_seed(&[v.seed; 32]);
    let id: AuthorityId = pair.public().into();
    let sign = |target: H256| {
        let precommit = grandpa::Precommit {
            target_hash: target,
            target_number: 10,
        };
        let msg = grandpa::Message::Precommit(precommit.clone());
        let payload = sp_consensus_grandpa::localized_payload(round, set_id, &msg);
        let sig: AuthoritySignature = pair.sign(&payload).into();
        (precommit, sig)
    };
    EquivocationProof::new(
        set_id,
        Equivocation::Precommit(grandpa::Equivocation {
            round_number: round,
            identity: id,
            first: sign(H256::repeat_byte(1)),
            second: sign(H256::repeat_byte(2)),
        }),
    )
}

/// A proven GRANDPA equivocation of `v` through the real unsigned-transaction path.
fn report(v: &DevValidator, round: u64) {
    let set_id = pallet_grandpa::Pallet::<Runtime>::current_set_id();
    let key_owner_proof =
        Historical::prove((KEY_TYPE, v.grandpa.clone())).expect("membership proof");
    let call = RuntimeCall::Grandpa(pallet_grandpa::Call::report_equivocation_unsigned {
        equivocation_proof: Box::new(double_precommit(v, set_id, round)),
        key_owner_proof,
    });
    frame_system::BlockWeight::<Runtime>::kill(); // a fresh block (the rotations above registered their Mandatory weight)
    let outcome = Executive::apply_extrinsic(UncheckedExtrinsic::new_bare(call))
        .unwrap_or_else(|e| panic!("report of {:?} refused: {e:?}", v.seed));
    assert!(outcome.is_ok(), "{outcome:?}");
    assert!(madar_admission::BannedKeys::<Runtime>::contains_key(
        &v.account
    ));
}

fn index_of(who: &AccountId) -> Option<u32> {
    pallet_session::Validators::<Runtime>::get()
        .iter()
        .position(|v| v == who)
        .map(|i| i as u32)
}

/// What BABE itself checks for every block (`pallet_babe::Config::DisabledValidators`).
fn babe_disabled(who: &AccountId) -> bool {
    index_of(who).map_or(
        false,
        <Runtime as pallet_babe::Config>::DisabledValidators::is_disabled,
    )
}

/// `pallet_babe::on_finalize` of a block authored by `who` (the check that rejects a disabled author's block).
fn babe_accepts_a_block_from(who: &AccountId) -> bool {
    let idx = index_of(who).expect("in the active set");
    let slot = pallet_babe::CurrentSlot::<Runtime>::get();
    pallet_babe::Initialized::<Runtime>::put(Some(
        sp_consensus_babe::digests::PreDigest::SecondaryPlain(
            sp_consensus_babe::digests::SecondaryPlainPreDigest {
                authority_index: idx,
                slot,
            },
        ),
    ));
    let block = frame_system::Pallet::<Runtime>::block_number();
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        <pallet_babe::Pallet<Runtime> as OnFinalize<u32>>::on_finalize(block);
    }))
    .is_ok()
}

/// Five genesis validators, the fifth exits: four in the active set with a GRANDPA set id bound to a session.
fn four_active() -> [DevValidator; 4] {
    madar_admission::Pallet::<Runtime>::voluntary_exit(RuntimeOrigin::signed(
        dev_validator(5).account,
    ))
    .unwrap();
    rotate();
    rotate();
    assert_eq!(pallet_session::Validators::<Runtime>::get().len(), 4);
    [
        dev_validator(1),
        dev_validator(2),
        dev_validator(3),
        dev_validator(4),
    ]
}

fn five() -> Vec<DevValidator> {
    (1..=5).map(dev_validator).collect()
}

#[test]
fn an_equivocating_validator_is_disabled_in_babe_at_once_and_its_blocks_are_refused() {
    new_test_ext(&five()).execute_with(|| {
        let [alice, bob, ..] = four_active();
        assert!(babe_accepts_a_block_from(&bob.account), "premise: bob authors normally");
        frame_system::Pallet::<Runtime>::set_block_number(frame_system::Pallet::<Runtime>::block_number() + 1);

        report(&bob, 1);

        assert!(babe_disabled(&bob.account), "disabled in BABE in the same block as the report");
        assert!(frame_system::Pallet::<Runtime>::events().iter().any(|e| matches!(
            &e.event,
            madar_consensus::RuntimeEvent::Session(pallet_session::Event::ValidatorDisabled { validator }) if *validator == bob.account
        )));
        assert!(!babe_accepts_a_block_from(&bob.account), "a block authored by the disabled validator is refused");
        assert!(babe_accepts_a_block_from(&alice.account), "the others still author");
        // GRANDPA has no disabling: the voter set (finality threshold) is unchanged until the normal rotation
        assert_eq!(pallet_grandpa::Pallet::<Runtime>::grandpa_authorities().len(), 4);
    });
}

/// `pallet_session` clears the disabled list at every rotation, but the offender is still in the active set for one more
/// session (it was already queued): it must be disabled again there, then it is gone.
#[test]
fn the_offender_stays_disabled_until_it_has_left_the_active_set() {
    new_test_ext(&five()).execute_with(|| {
        let [_, bob, ..] = four_active();
        report(&bob, 1);
        assert!(babe_disabled(&bob.account));

        rotate();
        assert!(
            index_of(&bob.account).is_some(),
            "still in the active set (it was queued before the ban)"
        );
        assert!(
            babe_disabled(&bob.account),
            "disabled again at the start of the new session"
        );
        assert!(!babe_accepts_a_block_from(&bob.account));

        rotate();
        assert!(
            index_of(&bob.account).is_none(),
            "gone from the active set two rotations after the ban"
        );
        assert!(
            pallet_session::DisabledValidators::<Runtime>::get().is_empty(),
            "nothing left disabled"
        );
        assert_eq!(
            pallet_grandpa::Pallet::<Runtime>::grandpa_authorities().len(),
            3,
            "and from GRANDPA at the normal rotation"
        );
    });
}

/// Disabling-induced liveness loss: never more than `floor((n-1)/3)` disabled. With 4 active only 1; a second offender
/// in the same session is banned but keeps authoring until the rotation removes it.
#[test]
fn no_more_than_a_third_is_ever_disabled() {
    new_test_ext(&five()).execute_with(|| {
        let [alice, bob, carol, _] = four_active();
        report(&bob, 1);
        report(&carol, 2);
        assert!(babe_disabled(&bob.account));
        assert!(
            !babe_disabled(&carol.account),
            "limit floor((4-1)/3) = 1 reached"
        );
        assert!(
            madar_admission::BannedKeys::<Runtime>::contains_key(&carol.account),
            "but banned all the same"
        );
        assert_eq!(
            pallet_session::DisabledValidators::<Runtime>::get().len(),
            1
        );
        assert!(babe_accepts_a_block_from(&alice.account));
    });
}

/// With three or fewer voters (today's network has four, B9) nobody is disabled: losing one author of three would
/// hurt liveness more than the offender's blocks could.
#[test]
fn three_voters_disable_nobody() {
    let three: Vec<DevValidator> = (1..=3).map(dev_validator).collect();
    new_test_ext(&three).execute_with(|| {
        rotate();
        rotate();
        let bob = dev_validator(2);
        report(&bob, 1);
        assert!(!babe_disabled(&bob.account));
        assert!(pallet_session::DisabledValidators::<Runtime>::get().is_empty());
    });
}

/// B12: the last live voter that equivocates is banned but kept (`LastValidatorBannedButKept`) and is NEVER disabled,
/// even if the active set still lists members that already left Admission (they may be offline: no author would remain).
#[test]
fn the_last_voter_banned_but_kept_is_never_disabled() {
    new_test_ext(&five()).execute_with(|| {
        let [alice, bob, carol, dave] = four_active();
        for v in [&alice, &bob, &carol] {
            madar_admission::Pallet::<Runtime>::voluntary_exit(RuntimeOrigin::signed(
                v.account.clone(),
            ))
            .unwrap();
        }
        rotate(); // they leave Admission now, but stay in the active session set for this and the next session
        assert_eq!(
            madar_admission::Pallet::<Runtime>::validators(),
            vec![dave.account.clone()]
        );
        assert_eq!(
            pallet_session::Validators::<Runtime>::get().len(),
            4,
            "premise: the leaving members are still active"
        );

        report(&dave, 1);
        assert_eq!(
            madar_admission::Pallet::<Runtime>::validators(),
            vec![dave.account.clone()],
            "kept (B12)"
        );
        assert!(frame_system::Pallet::<Runtime>::events()
            .iter()
            .any(|e| matches!(
                &e.event,
                madar_consensus::RuntimeEvent::Admission(
                    madar_admission::Event::LastValidatorBannedButKept { .. }
                )
            )));
        assert!(
            !babe_disabled(&dave.account),
            "the only author that stays is never disabled"
        );

        rotate();
        rotate();
        assert_eq!(
            pallet_session::Validators::<Runtime>::get(),
            vec![dave.account.clone()]
        );
        assert!(
            !babe_disabled(&dave.account),
            "alone: never disabled, the chain keeps producing"
        );
        assert!(babe_accepts_a_block_from(&dave.account));
    });
}

/// A banned member that is NOT the last, while the only other authors are leaving: still not disabled (the strategy
/// counts only authors that stay in Admission and are not banned).
#[test]
fn an_offender_is_not_disabled_when_only_leaving_members_would_remain() {
    let eight: Vec<DevValidator> = (1..=8).map(dev_validator).collect();
    new_test_ext(&eight).execute_with(|| {
        madar_admission::Pallet::<Runtime>::voluntary_exit(RuntimeOrigin::signed(
            dev_validator(8).account,
        ))
        .unwrap();
        rotate();
        rotate();
        assert_eq!(
            pallet_session::Validators::<Runtime>::get().len(),
            7,
            "limit floor((7-1)/3) = 2"
        );
        for i in 1..=5 {
            madar_admission::Pallet::<Runtime>::voluntary_exit(RuntimeOrigin::signed(
                dev_validator(i).account,
            ))
            .unwrap();
        }
        rotate(); // Admission = {6, 7}; 1..5 still in the active set
        let (six, seven) = (dev_validator(6), dev_validator(7));
        report(&six, 1);
        assert!(babe_disabled(&six.account), "seven stays: six is disabled");
        report(&seven, 2);
        assert_eq!(
            madar_admission::Pallet::<Runtime>::validators(),
            vec![seven.account.clone()],
            "kept (B12)"
        );
        assert_eq!(
            pallet_session::DisabledValidators::<Runtime>::get().len(),
            1,
            "the limit (2) would allow it, the B12 rule does not"
        );
        assert!(
            !babe_disabled(&seven.account),
            "no staying, enabled author would be left"
        );
    });
}
