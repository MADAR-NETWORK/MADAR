//! D18 — mortal only: `Era::Immortal` is always rejected; a valid `Era::mortal` works
//! normally (the standard `frame_system::CheckMortality` logic).

mod common;

use common::{new_test_ext, TestRuntime};
use frame_support::dispatch::{DispatchClass, DispatchInfo, Pays};
use frame_support::weights::Weight;
use madar_transactions::{CheckMortalOnly, MORTAL_ONLY_ERROR};
use sp_runtime::{
    generic::Era,
    traits::{DispatchTransaction, TransactionExtension},
    transaction_validity::{InvalidTransaction, TransactionSource, TransactionValidityError},
};

fn dummy_call() -> <TestRuntime as frame_system::Config>::RuntimeCall {
    frame_system::Call::<TestRuntime>::remark { remark: vec![] }.into()
}

fn dummy_info() -> DispatchInfo {
    DispatchInfo {
        call_weight: Weight::from_parts(100, 0),
        extension_weight: Weight::zero(),
        class: DispatchClass::Normal,
        pays_fee: Pays::Yes,
    }
}

#[test]
fn immortal_era_is_rejected_by_validate() {
    new_test_ext().execute_with(|| {
        let who = sp_runtime::AccountId32::from([1u8; 32]);
        let origin: <TestRuntime as frame_system::Config>::RuntimeOrigin =
            frame_system::RawOrigin::Signed(who).into();
        let call = dummy_call();
        let info = dummy_info();

        let ext = CheckMortalOnly::<TestRuntime>::from(Era::Immortal);
        let result = ext.validate_only(origin, &call, &info, 0, TransactionSource::External, 0);

        assert_eq!(
            result.err(),
            Some(TransactionValidityError::Invalid(
                InvalidTransaction::Custom(MORTAL_ONLY_ERROR)
            )),
            "D18 violated: an Immortal era must always be rejected by CheckMortalOnly::validate"
        );
    });
}

#[test]
fn immortal_era_is_rejected_by_pre_dispatch() {
    new_test_ext().execute_with(|| {
        let who = sp_runtime::AccountId32::from([1u8; 32]);
        let origin: <TestRuntime as frame_system::Config>::RuntimeOrigin =
            frame_system::RawOrigin::Signed(who).into();
        let call = dummy_call();
        let info = dummy_info();

        let ext = CheckMortalOnly::<TestRuntime>::from(Era::Immortal);
        let result = ext.validate_and_prepare(origin, &call, &info, 0, 0);

        assert_eq!(
            result.err(),
            Some(TransactionValidityError::Invalid(
                InvalidTransaction::Custom(MORTAL_ONLY_ERROR)
            )),
            "D18 violated: an Immortal era must always be rejected by CheckMortalOnly::prepare"
        );
    });
}

#[test]
fn immortal_era_is_rejected_by_additional_signed() {
    new_test_ext().execute_with(|| {
        let ext = CheckMortalOnly::<TestRuntime>::from(Era::Immortal);
        let result = ext.implicit();

        assert_eq!(
            result,
            Err(TransactionValidityError::Invalid(
                InvalidTransaction::Custom(MORTAL_ONLY_ERROR)
            ))
        );
    });
}

/// A valid mortal transaction (known/unpruned birth block) must pass —
/// proving that the new guard does not break the normal behavior of `CheckMortality`.
#[test]
fn well_formed_mortal_era_with_known_birth_block_is_accepted() {
    new_test_ext().execute_with(|| {
        frame_system::Pallet::<TestRuntime>::set_block_number(13);
        frame_system::BlockHash::<TestRuntime>::insert(12u64, sp_core::H256::repeat_byte(1));

        let who = sp_runtime::AccountId32::from([1u8; 32]);
        let origin: <TestRuntime as frame_system::Config>::RuntimeOrigin =
            frame_system::RawOrigin::Signed(who).into();
        let call = dummy_call();
        let info = dummy_info();

        let ext = CheckMortalOnly::<TestRuntime>::from(Era::mortal(4, 12));

        assert!(ext
            .validate_only(origin, &call, &info, 0, TransactionSource::External, 0)
            .is_ok());
        assert!(ext.implicit().is_ok());
    });
}

/// A mortal transaction whose birth block is not in storage (pruned/unknown)
/// must be rejected — the same behavior as the original `frame_system::CheckMortality`, unchanged.
#[test]
fn mortal_era_with_unknown_birth_block_is_rejected() {
    new_test_ext().execute_with(|| {
        frame_system::Pallet::<TestRuntime>::set_block_number(4);

        let ext = CheckMortalOnly::<TestRuntime>::from(Era::mortal(4, 2));
        let result = ext.implicit();

        assert_eq!(
            result,
            Err(TransactionValidityError::Invalid(
                InvalidTransaction::AncientBirthBlock
            ))
        );
    });
}
