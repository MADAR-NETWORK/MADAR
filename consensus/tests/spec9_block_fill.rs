//! spec 9 — free block fill (B2 §2.4 "side note" and §5): can a **vouched** node fill the Normal space of blocks
//! with wrong solutions at no cost? **Before spec 9: yes.** A wrong solution failed after Argon2 (108.6 ms of block weight) with no trace: no account,
//! no Nonce (the spec 8 test `a_failed_admission_leaves_no_account_nonce_or_admission_state` proved exactly that) — so the same transaction
//! could be replayed without limit until it expired, and from any number of consecutive transactions: 13 per block fill the whole Normal part. And any
//! new unvouched key also entered the Pool (it failed cheaply at execution and was replayed without limit).
//! **After spec 9:** (1) an unvouched one is refused before inclusion; (2) a wrong solution is counted (success + event) so the Nonce advances and it is not replayed;
//! (3) after `MAX_SOLUTION_ATTEMPTS_PER_ROUND × MaxVotesPerOperator` Argon2 runs per operator in the round, the rest are refused before
//! Argon2 at the early-refusal weight.

mod common;

use common::new_test_ext;
use frame_support::dispatch::{DispatchClass, GetDispatchInfo};
use madar_admission::weights::WeightInfo;
use madar_consensus::{
    AccountId, Address, Executive, OnboardingPolicy, Runtime, RuntimeCall, SignedExtra,
    UncheckedExtrinsic,
};
use parity_scale_codec::Encode;
use sp_core::Pair;
use sp_runtime::{
    generic::Era,
    transaction_validity::{InvalidTransaction, TransactionValidityError},
};

type Onboard = madar_transactions::CheckNonceOrOnboard<Runtime, OnboardingPolicy>;
type W = <Runtime as madar_admission::Config>::WeightInfo;

fn signer(seed: u8) -> (sp_core::sr25519::Pair, AccountId) {
    let pair = sp_core::sr25519::Pair::from_seed(&[seed; 32]);
    let account = AccountId::from(pair.public().0);
    (pair, account)
}

fn signed(
    pair: &sp_core::sr25519::Pair,
    account: &AccountId,
    call: RuntimeCall,
    nonce: u32,
) -> UncheckedExtrinsic {
    let extra: SignedExtra = (
        frame_system::CheckSpecVersion::<Runtime>::new(),
        frame_system::CheckTxVersion::<Runtime>::new(),
        frame_system::CheckGenesis::<Runtime>::new(),
        madar_transactions::CheckMortalOnly::<Runtime>::from(Era::mortal(4, 12)),
        Onboard::from(nonce),
        frame_system::CheckWeight::<Runtime>::new(),
    );
    let payload = sp_runtime::generic::SignedPayload::new(call.clone(), extra.clone()).unwrap();
    let signature = payload.using_encoded(|p| pair.sign(p));
    UncheckedExtrinsic::new_signed(call, Address::Id(account.clone()), signature.into(), extra)
}

fn start_block() {
    frame_system::Pallet::<Runtime>::set_block_number(13);
    frame_system::BlockHash::<Runtime>::insert(12u32, sp_core::H256::repeat_byte(1));
}

fn normal_used() -> u64 {
    frame_system::BlockWeight::<Runtime>::get()
        .get(DispatchClass::Normal)
        .ref_time()
}

fn wrong_nonce(who: &AccountId) -> u64 {
    use frame_support::traits::Randomness;
    let seed = <Runtime as madar_admission::Config>::EpochRandomness::random(
        madar_protocol::ADMISSION_PUZZLE_DOMAIN,
    )
    .0;
    (1u64..)
        .find(|n| !madar_admission::Pallet::<Runtime>::solution_meets_difficulty(who, &seed, *n))
        .unwrap()
}

#[test]
fn a_vouched_node_cannot_fill_blocks_with_wrong_solutions() {
    new_test_ext(&[]).execute_with(|| {
        start_block();
        let (pair, who) = signer(120);
        let operator = AccountId::from([201u8; 32]);
        madar_admission::ApprovedOperators::<Runtime>::insert(&operator, 1);
        madar_admission::NodeOperator::<Runtime>::insert(&who, operator.clone());
        let bad = wrong_nonce(&who);
        let full = W::submit_admission_solution().ref_time();
        let early = W::submit_admission_rejected_early().ref_time();
        let budget = madar_admission::MAX_SOLUTION_ATTEMPTS_PER_ROUND;

        // the attacker sends 40 wrong solutions with consecutive nonces (13 would have filled the Normal class before)
        let mut included_full = 0;
        let mut refused_early = 0;
        for nonce in 0..40u32 {
            let call = RuntimeCall::Admission(madar_admission::Call::submit_admission_solution {
                nonce: bad,
            });
            let xt = signed(&pair, &who, call, nonce);
            let before = normal_used();
            match Executive::apply_extrinsic(xt) {
                Ok(Ok(_)) => included_full += 1,
                Ok(Err(e)) => {
                    assert_eq!(
                        e,
                        madar_admission::Error::<Runtime>::TooManySolutionAttempts.into()
                    );
                    refused_early += 1;
                    let charged = normal_used() - before;
                    assert!(
                        charged < full / 50,
                        "a refused attempt costs the early weight only ({charged} ps)"
                    );
                }
                Err(e) => panic!("nonce {nonce}: not includable: {e:?}"),
            }
        }
        assert_eq!(
            included_full, budget,
            "only the round budget reaches Argon2"
        );
        assert_eq!(refused_early, 40 - budget);
        let max_normal = <Runtime as frame_system::Config>::BlockWeights::get()
            .get(DispatchClass::Normal)
            .max_total
            .unwrap()
            .ref_time();
        let used = normal_used();
        assert!(
            used < max_normal / 2,
            "40 attempts use {used} ps of {max_normal} ps Normal (before spec 9, 13 filled it)"
        );
        assert!(
            used <= budget as u64 * (full + 1_000_000_000)
                + (40 - budget as u64) * (early + 1_000_000_000)
        );
    });
}

/// The replay half: the same failed transaction cannot be included twice (the nonce moved), and a fresh unvouched key
/// is refused before inclusion — no free block space from new keys either.
#[test]
fn failed_solutions_are_not_replayable_and_unvouched_keys_never_reach_a_block() {
    new_test_ext(&[]).execute_with(|| {
        start_block();
        let (pair, who) = signer(121);
        madar_admission::NodeOperator::<Runtime>::insert(&who, AccountId::from([202u8; 32]));
        let call = RuntimeCall::Admission(madar_admission::Call::submit_admission_solution {
            nonce: wrong_nonce(&who),
        });
        let xt = signed(&pair, &who, call.clone(), 0);
        assert!(Executive::apply_extrinsic(xt.clone()).unwrap().is_ok());
        assert_eq!(
            Executive::apply_extrinsic(xt).err(),
            Some(TransactionValidityError::Invalid(InvalidTransaction::Stale))
        );

        let before = normal_used();
        for seed in 130u8..170 {
            let (p, fresh) = signer(seed);
            let c = RuntimeCall::Admission(madar_admission::Call::submit_admission_solution {
                nonce: 1,
            });
            assert_eq!(
                Executive::apply_extrinsic(signed(&p, &fresh, c, 0)).err(),
                Some(TransactionValidityError::Invalid(
                    InvalidTransaction::Payment
                )),
                "an unvouched new key is refused before inclusion"
            );
        }
        assert_eq!(normal_used(), before, "no block space used by refused keys");
        assert!(call.get_dispatch_info().call_weight.ref_time() > 0);
    });
}
