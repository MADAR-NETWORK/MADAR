//! Proves that `SignedExtra` (the full D17/D18 bundle) works as one unit, not only
//! each element separately — this is the actual shape a signed transaction consumes.

mod common;

use common::{new_test_ext, TestRuntime};
use frame_support::dispatch::{DispatchClass, DispatchInfo, Pays};
use frame_support::weights::Weight;
use madar_transactions::{CheckMortalOnly, SignedExtra};
use sp_runtime::{
    generic::Era, traits::DispatchTransaction, transaction_validity::TransactionSource,
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
fn full_signed_extra_tuple_accepts_a_well_formed_mortal_transaction() {
    new_test_ext().execute_with(|| {
        frame_system::Pallet::<TestRuntime>::set_block_number(13);
        frame_system::BlockHash::<TestRuntime>::insert(12u64, sp_core::H256::repeat_byte(1));

        let who = sp_runtime::AccountId32::from([9u8; 32]);
        frame_system::Pallet::<TestRuntime>::inc_providers(&who);
        let origin: <TestRuntime as frame_system::Config>::RuntimeOrigin =
            frame_system::RawOrigin::Signed(who).into();

        let extra: SignedExtra<TestRuntime> = (
            frame_system::CheckSpecVersion::new(),
            frame_system::CheckTxVersion::new(),
            frame_system::CheckGenesis::new(),
            CheckMortalOnly::from(Era::mortal(4, 12)),
            madar_transactions::CheckNonceOrOnboard::from(0),
            frame_system::CheckWeight::new(),
        );

        let call = dummy_call();
        let info = dummy_info();
        let result = extra.validate_only(origin, &call, &info, 0, TransactionSource::External, 0);

        assert!(
            result.is_ok(),
            "a well-formed mortal transaction must pass the full SignedExtra tuple: {result:?}"
        );
    });
}

#[test]
fn full_signed_extra_tuple_rejects_an_immortal_transaction_end_to_end() {
    new_test_ext().execute_with(|| {
        frame_system::Pallet::<TestRuntime>::set_block_number(1);
        let who = sp_runtime::AccountId32::from([10u8; 32]);
        frame_system::Pallet::<TestRuntime>::inc_providers(&who);
        let origin: <TestRuntime as frame_system::Config>::RuntimeOrigin =
            frame_system::RawOrigin::Signed(who).into();

        let extra: SignedExtra<TestRuntime> = (
            frame_system::CheckSpecVersion::new(),
            frame_system::CheckTxVersion::new(),
            frame_system::CheckGenesis::new(),
            CheckMortalOnly::from(Era::Immortal),
            madar_transactions::CheckNonceOrOnboard::from(0),
            frame_system::CheckWeight::new(),
        );

        let call = dummy_call();
        let info = dummy_info();
        let result = extra.validate_only(origin, &call, &info, 0, TransactionSource::External, 0);

        assert!(
            result.is_err(),
            "D18 violated: the full SignedExtra tuple must reject an Immortal era end-to-end"
        );
    });
}
