//! Madar Stamp through the real pipeline (the actual `Executive` + `SignedExtra`): the new registrar
//! account (no balance and no reference) is created on its first submission **only** if the committee approved it, and any other account is rejected.

mod common;

use common::new_test_ext;
use madar_consensus::{
    AccountId, Address, Executive, OnboardingPolicy, Runtime, RuntimeCall, RuntimeOrigin,
    SignedExtra, UncheckedExtrinsic,
};
use madar_stamp::{Entry, Stamps};
use parity_scale_codec::Encode;
use sp_core::Pair;
use sp_runtime::{
    generic::Era,
    transaction_validity::{InvalidTransaction, TransactionValidityError},
    BoundedVec,
};

type Onboard = madar_transactions::CheckNonceOrOnboard<Runtime, OnboardingPolicy>;

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
    run_spec9_upgrade();
}

/// The spec 9 upgrade as it runs on the live chain (Names storage 0 -> 1, Stamp 1 -> 2): v1 messages are accepted until
/// the upgrade time + 72 h (independent review #2). A chain started from genesis with spec 9 code refuses v1 at once.
fn run_spec9_upgrade() {
    use frame_support::traits::{OnRuntimeUpgrade, StorageVersion};
    StorageVersion::new(0).put::<madar_names::Pallet<Runtime>>();
    StorageVersion::new(1).put::<madar_stamp::Pallet<Runtime>>();
    <madar_names::Pallet<Runtime> as OnRuntimeUpgrade>::on_runtime_upgrade();
    <madar_stamp::Pallet<Runtime> as OnRuntimeUpgrade>::on_runtime_upgrade();
}

fn stamp_call(fp: u8) -> RuntimeCall {
    let entries: BoundedVec<Entry, _> = BoundedVec::try_from(vec![Entry {
        fingerprint: [fp; 32],
        name_hash: None,
        proof: None,
    }])
    .unwrap();
    RuntimeCall::Stamp(madar_stamp::Call::stamp { entries })
}

#[test]
fn unapproved_account_cannot_stamp_or_onboard() {
    new_test_ext(&[]).execute_with(|| {
        start_block();
        let (pair, who) = signer(90);
        let r = Executive::apply_extrinsic(signed(&pair, &who, stamp_call(1), 0));
        assert_eq!(
            r.err(),
            Some(TransactionValidityError::Invalid(
                InvalidTransaction::Payment
            ))
        );
        assert!(Stamps::<Runtime>::get([1u8; 32]).is_none());
        assert_eq!(frame_system::Account::<Runtime>::get(&who).providers, 0);
    });
}

#[test]
fn committee_approved_stamper_onboards_and_stamps_first_wins() {
    new_test_ext(&[]).execute_with(|| {
        start_block();
        let (pair, who) = signer(91);
        // On the live network: a 2-of-3 committee proposal. Here: the approved origin itself, directly.
        assert!(madar_stamp::Pallet::<Runtime>::add_stamper(RuntimeOrigin::root(), who.clone()).is_err());
        frame_support::assert_ok!(madar_stamp::Pallet::<Runtime>::add_stamper(
            pallet_collective::RawOrigin::<AccountId, madar_consensus::UpgradeCommitteeInstance>::Members(2, 3).into(),
            who.clone()
        ));
        assert!(Executive::apply_extrinsic(signed(&pair, &who, stamp_call(2), 0)).unwrap().is_ok());
        assert_eq!(Stamps::<Runtime>::get([2u8; 32]).unwrap().block, 13);
        assert_eq!(frame_system::Account::<Runtime>::get(&who).providers, 1);

        frame_system::Pallet::<Runtime>::set_block_number(14);
        frame_system::BlockHash::<Runtime>::insert(13u32, sp_core::H256::repeat_byte(2));
        assert!(Executive::apply_extrinsic(signed(&pair, &who, stamp_call(2), 1)).unwrap().is_ok());
        assert_eq!(Stamps::<Runtime>::get([2u8; 32]).unwrap().block, 13, "the first registration stays the reference");
    });
}

/// spec 9: `stamp_v2` through the real pipeline. Only an approved stamper is onboarded; the wallet signature is bound to
/// this chain's genesis and to its time window.
#[test]
fn stamp_v2_through_the_real_pipeline_binds_the_genesis() {
    new_test_ext(&[]).execute_with(|| {
        start_block();
        pallet_timestamp::Now::<Runtime>::put(1_790_000_000_000u64);
        let genesis = frame_system::BlockHash::<Runtime>::get(0u32).as_ref().to_vec();
        let until = 1_790_000_000_000u64 + 60_000;
        let pair = sp_core::ed25519::Pair::from_seed(&[5; 32]);
        let entry = |fp: u8, net: &[u8]| madar_stamp::EntryV2 {
            fingerprint: [fp; 32],
            name_hash: None,
            proof: Some(madar_stamp::WalletProof::Solana {
                public: pair.public().0,
                signature: pair.sign(&madar_stamp::signed_message_v2(&[fp; 32], &None, net, until)).0,
            }),
            valid_until: until,
        };
        let call = RuntimeCall::Stamp(madar_stamp::Call::stamp_v2 {
            entries: BoundedVec::try_from(vec![entry(7, &genesis), entry(8, &[0x42; 32])]).unwrap(),
        });
        let (spair, stranger) = signer(93);
        let r = Executive::apply_extrinsic(signed(&spair, &stranger, call.clone(), 0));
        assert_eq!(r.err(), Some(TransactionValidityError::Invalid(InvalidTransaction::Payment)));
        let (pair2, who) = signer(94);
        frame_support::assert_ok!(madar_stamp::Pallet::<Runtime>::add_stamper(
            pallet_collective::RawOrigin::<AccountId, madar_consensus::UpgradeCommitteeInstance>::Members(2, 3).into(),
            who.clone()
        ));
        assert!(Executive::apply_extrinsic(signed(&pair2, &who, call, 0)).unwrap().is_ok());
        assert_eq!(Stamps::<Runtime>::get([7u8; 32]).unwrap().wallet, Some(madar_stamp::Wallet::Solana(pair.public().0)));
        assert!(Stamps::<Runtime>::get([8u8; 32]).is_none(), "signed for another chain");
    });
}
