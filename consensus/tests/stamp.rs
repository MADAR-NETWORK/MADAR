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

/// D55 migration: seeds the first service account once, and does not overwrite a later committee decision.
#[test]
fn upgrade_migration_seeds_the_first_stamper_once() {
    use frame_support::traits::OnRuntimeUpgrade;
    new_test_ext(&[]).execute_with(|| {
        let first = AccountId::from(madar_consensus::FIRST_STAMPER);
        assert!(!madar_stamp::Pallet::<Runtime>::is_stamper(&first));
        // As on the live network after adding the Pallet: FRAME set its storage version to 1 before the migration — and seeding must happen regardless.
        frame_support::traits::StorageVersion::new(1).put::<madar_stamp::Pallet<Runtime>>();
        assert!(!frame_support::storage::unhashed::exists(
            madar_consensus::FIRST_STAMPER_SEEDED_KEY
        ));
        madar_consensus::SeedFirstStamper::on_runtime_upgrade();
        assert_eq!(
            madar_stamp::Stampers::<Runtime>::get().into_inner(),
            vec![first.clone()]
        );
        // The committee later replaced it: re-running the migration does not restore it.
        let committee = pallet_collective::RawOrigin::<
            AccountId,
            madar_consensus::UpgradeCommitteeInstance,
        >::Members(2, 3);
        frame_support::assert_ok!(madar_stamp::Pallet::<Runtime>::remove_stamper(
            committee.clone().into(),
            first.clone()
        ));
        let (_, other) = signer(92);
        frame_support::assert_ok!(madar_stamp::Pallet::<Runtime>::add_stamper(
            committee.into(),
            other.clone()
        ));
        madar_consensus::SeedFirstStamper::on_runtime_upgrade();
        assert_eq!(
            madar_stamp::Stampers::<Runtime>::get().into_inner(),
            vec![other.clone()]
        );
        // Even a list the committee deliberately emptied is not refilled by a later upgrade.
        let committee = pallet_collective::RawOrigin::<
            AccountId,
            madar_consensus::UpgradeCommitteeInstance,
        >::Members(2, 3);
        frame_support::assert_ok!(madar_stamp::Pallet::<Runtime>::remove_stamper(
            committee.into(),
            other
        ));
        madar_consensus::SeedFirstStamper::on_runtime_upgrade();
        assert!(madar_stamp::Stampers::<Runtime>::get().is_empty());
    });
}
