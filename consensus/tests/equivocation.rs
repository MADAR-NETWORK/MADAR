//! Review #6: Equivocation → an actual permanent ban through the real pipeline. Two conflicting signed votes
//! from a Validator's GRANDPA key (a double Precommit in the same round), with a key ownership proof from
//! the Session history, submitted as an **unsigned** transaction via `Executive` ⇒ `BanOnOffence` ⇒
//! `Admission::ban`.

mod common;

use common::{dev_validator, new_test_ext, DevValidator};
use finality_grandpa as grandpa;
use frame_support::traits::{KeyOwnerProofSystem, OnFinalize};
use madar_consensus::{
    Executive, Historical, Runtime, RuntimeCall, RuntimeOrigin, UncheckedExtrinsic,
};
use sp_consensus_grandpa::{
    AuthorityId, AuthoritySignature, Equivocation, EquivocationProof, KEY_TYPE,
};
use sp_core::{ed25519, Pair, H256};

fn rotate() {
    pallet_babe::Initialized::<Runtime>::put(None::<sp_consensus_babe::digests::PreDigest>);
    let block = frame_system::Pallet::<Runtime>::block_number() + 1;
    frame_system::Pallet::<Runtime>::set_block_number(block);
    pallet_session::Pallet::<Runtime>::rotate_session();
    <pallet_grandpa::Pallet<Runtime> as OnFinalize<u32>>::on_finalize(block);
}

fn double_precommit(v: &DevValidator, set_id: u64) -> EquivocationProof<H256, u32> {
    let pair = ed25519::Pair::from_seed(&[v.seed; 32]);
    let id: AuthorityId = pair.public().into();
    let round = 1u64;
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

#[test]
fn a_proven_grandpa_equivocation_bans_the_validator_permanently() {
    let (alice, bob, carol) = (dev_validator(1), dev_validator(2), dev_validator(3));
    new_test_ext(&[dev_validator(1), dev_validator(2), dev_validator(3)]).execute_with(|| {
        // carol leaves ⇒ the GRANDPA authorities change ⇒ a new set-id tied to a session for which ownership can be proven.
        madar_admission::Pallet::<Runtime>::voluntary_exit(RuntimeOrigin::signed(
            carol.account.clone(),
        ))
        .unwrap();
        rotate();
        rotate();
        assert_eq!(
            pallet_grandpa::Pallet::<Runtime>::grandpa_authorities().len(),
            2
        );

        let set_id = pallet_grandpa::Pallet::<Runtime>::current_set_id();
        let bob_grandpa: AuthorityId = bob.grandpa.clone();
        let key_owner_proof = Historical::prove((KEY_TYPE, bob_grandpa))
            .expect("membership proof for the current session");
        let proof = double_precommit(&bob, set_id);

        let call = RuntimeCall::Grandpa(pallet_grandpa::Call::report_equivocation_unsigned {
            equivocation_proof: Box::new(proof),
            key_owner_proof,
        });
        let outcome = Executive::apply_extrinsic(UncheckedExtrinsic::new_bare(call))
            .expect("an equivocation report is a valid unsigned transaction");
        assert!(outcome.is_ok(), "{outcome:?}");

        assert!(
            madar_admission::BannedKeys::<Runtime>::contains_key(&bob.account),
            "offender is banned"
        );
        assert!(!madar_admission::Pallet::<Runtime>::validators().contains(&bob.account));
        assert!(
            madar_admission::Pallet::<Runtime>::validators().contains(&alice.account),
            "others unaffected"
        );
    });
}

#[test]
fn a_forged_or_non_conflicting_report_bans_nobody() {
    let bob = dev_validator(2);
    new_test_ext(&[dev_validator(1), dev_validator(2), dev_validator(3)]).execute_with(|| {
        madar_admission::Pallet::<Runtime>::voluntary_exit(RuntimeOrigin::signed(
            dev_validator(3).account,
        ))
        .unwrap();
        rotate();
        rotate();
        let set_id = pallet_grandpa::Pallet::<Runtime>::current_set_id();
        let key_owner_proof = Historical::prove((KEY_TYPE, bob.grandpa.clone())).unwrap();

        // A "conflict" with the same message twice (not an Equivocation) — rejected.
        let pair = ed25519::Pair::from_seed(&[bob.seed; 32]);
        let precommit = grandpa::Precommit {
            target_hash: H256::repeat_byte(1),
            target_number: 10,
        };
        let msg = grandpa::Message::Precommit(precommit.clone());
        let sig: AuthoritySignature = pair
            .sign(&sp_consensus_grandpa::localized_payload(1, set_id, &msg))
            .into();
        let same = EquivocationProof::new(
            set_id,
            Equivocation::Precommit(grandpa::Equivocation {
                round_number: 1,
                identity: pair.public().into(),
                first: (precommit.clone(), sig.clone()),
                second: (precommit, sig),
            }),
        );
        let call = RuntimeCall::Grandpa(pallet_grandpa::Call::report_equivocation_unsigned {
            equivocation_proof: Box::new(same),
            key_owner_proof,
        });
        let rejected = match Executive::apply_extrinsic(UncheckedExtrinsic::new_bare(call)) {
            Err(_) => true,
            Ok(dispatch) => dispatch.is_err(),
        };
        assert!(rejected, "a report that is not a real conflict must fail");
        assert!(
            madar_admission::BannedKeys::<Runtime>::iter().count() == 0,
            "no ban without a real conflict"
        );
    });
}

/// The same valid report twice: the second is rejected in the Pool (`Stale`) — it is not re-included in every block.
#[test]
fn a_repeated_valid_report_is_rejected_instead_of_being_included_again() {
    let bob = dev_validator(2);
    new_test_ext(&[dev_validator(1), dev_validator(2), dev_validator(3)]).execute_with(|| {
        madar_admission::Pallet::<Runtime>::voluntary_exit(RuntimeOrigin::signed(
            dev_validator(3).account,
        ))
        .unwrap();
        rotate();
        rotate();
        let set_id = pallet_grandpa::Pallet::<Runtime>::current_set_id();
        let report = || {
            RuntimeCall::Grandpa(pallet_grandpa::Call::report_equivocation_unsigned {
                equivocation_proof: Box::new(double_precommit(&bob, set_id)),
                key_owner_proof: Historical::prove((KEY_TYPE, bob.grandpa.clone())).unwrap(),
            })
        };
        let first = Executive::apply_extrinsic(UncheckedExtrinsic::new_bare(report()))
            .expect("first report accepted");
        assert!(first.is_ok(), "{first:?}");
        assert!(madar_admission::BannedKeys::<Runtime>::contains_key(
            &bob.account
        ));
        assert!(
            Executive::apply_extrinsic(UncheckedExtrinsic::new_bare(report())).is_err(),
            "a report for an already-punished offender must be rejected before inclusion"
        );
    });
}

/// BABE headers without a Seal (as passed by the sc-consensus-babe client in this SDK version — observed live) cannot
/// have their signature proven: they are rejected in the Pool and not included in every block only to fail, and they punish no one.
#[test]
fn a_seal_less_babe_report_is_rejected_at_validation_and_punishes_nobody() {
    use sp_consensus_babe::digests::{CompatibleDigestItem, PreDigest, SecondaryPlainPreDigest};
    use sp_runtime::{
        generic::Header,
        traits::{BlakeTwo256, Header as _},
    };
    let bob = dev_validator(2);
    new_test_ext(&[dev_validator(1), dev_validator(2), dev_validator(3)]).execute_with(|| {
        madar_admission::Pallet::<Runtime>::voluntary_exit(RuntimeOrigin::signed(
            dev_validator(3).account,
        ))
        .unwrap();
        rotate();
        rotate();
        let slot = sp_consensus_babe::Slot::from(5u64);
        let header = |n: u32| {
            let mut h = Header::<u32, BlakeTwo256>::new(
                n,
                H256::zero(),
                H256::zero(),
                H256::zero(),
                Default::default(),
            );
            h.digest.push(
                <sp_runtime::DigestItem as CompatibleDigestItem>::babe_pre_digest(
                    PreDigest::SecondaryPlain(SecondaryPlainPreDigest {
                        authority_index: 1,
                        slot,
                    }),
                ),
            );
            h
        };
        let proof = sp_consensus_babe::EquivocationProof {
            offender: bob.babe.clone(),
            slot,
            first_header: header(1),
            second_header: header(2),
        };
        let call = RuntimeCall::Babe(pallet_babe::Call::report_equivocation_unsigned {
            equivocation_proof: Box::new(proof),
            key_owner_proof: Historical::prove((sp_consensus_babe::KEY_TYPE, bob.babe.clone()))
                .unwrap(),
        });
        assert!(Executive::apply_extrinsic(UncheckedExtrinsic::new_bare(call)).is_err());
        assert_eq!(madar_admission::BannedKeys::<Runtime>::iter().count(), 0);
    });
}
