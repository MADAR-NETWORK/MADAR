//! Replay protection via the nonce (§8, the standard `frame_system::CheckNonce`,
//! consumed as it is, unmodified).

mod common;

use common::{new_test_ext, TestRuntime};
use frame_support::dispatch::{DispatchClass, DispatchInfo, Pays};
use frame_support::weights::Weight;
use sp_runtime::traits::DispatchTransaction;
use sp_runtime::transaction_validity::InvalidTransaction;

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

fn origin_of(who: sp_runtime::AccountId32) -> <TestRuntime as frame_system::Config>::RuntimeOrigin {
    frame_system::RawOrigin::Signed(who).into()
}

/// The same nonce is never accepted twice for the same account (INV-4, §2.11).
#[test]
fn same_nonce_is_never_accepted_twice_for_the_same_account() {
    new_test_ext().execute_with(|| {
        let who = sp_runtime::AccountId32::from([2u8; 32]);
        frame_system::Pallet::<TestRuntime>::inc_providers(&who);

        let call = dummy_call();
        let info = dummy_info();

        let first_use = frame_system::CheckNonce::<TestRuntime>::from(0);
        first_use
            .validate_and_prepare(origin_of(who.clone()), &call, &info, 0, 0)
            .expect("first use of nonce 0 must succeed");

        // Reusing the same nonce (0) after the account moved to nonce=1.
        let replay = frame_system::CheckNonce::<TestRuntime>::from(0);
        let result = replay.validate_only(
            origin_of(who),
            &call,
            &info,
            0,
            sp_runtime::transaction_validity::TransactionSource::External,
            0,
        );

        assert_eq!(
            result.err(),
            Some(InvalidTransaction::Stale.into()),
            "INV-4 violated: a used nonce must never be accepted again for the same account"
        );
    });
}

/// A correct sequential nonce (0 then 1) is accepted without problems — proving that the rejection above is caused
/// specifically by reuse, not by a general defect in the mechanism.
#[test]
fn sequential_nonces_are_accepted() {
    new_test_ext().execute_with(|| {
        let who = sp_runtime::AccountId32::from([3u8; 32]);
        frame_system::Pallet::<TestRuntime>::inc_providers(&who);

        let call = dummy_call();
        let info = dummy_info();

        frame_system::CheckNonce::<TestRuntime>::from(0)
            .validate_and_prepare(origin_of(who.clone()), &call, &info, 0, 0)
            .expect("nonce 0 must succeed for a fresh account");
        frame_system::CheckNonce::<TestRuntime>::from(1)
            .validate_and_prepare(origin_of(who), &call, &info, 0, 0)
            .expect("nonce 1 must succeed after nonce 0 was consumed");
    });
}

/// Two different accounts have completely independent nonce spaces — using nonce=0 for another
/// account is unaffected by the state of the first account.
#[test]
fn nonce_spaces_are_independent_per_account() {
    new_test_ext().execute_with(|| {
        let who_a = sp_runtime::AccountId32::from([4u8; 32]);
        let who_b = sp_runtime::AccountId32::from([5u8; 32]);
        frame_system::Pallet::<TestRuntime>::inc_providers(&who_a);
        frame_system::Pallet::<TestRuntime>::inc_providers(&who_b);

        let call = dummy_call();
        let info = dummy_info();

        frame_system::CheckNonce::<TestRuntime>::from(0)
            .validate_and_prepare(origin_of(who_a), &call, &info, 0, 0)
            .expect("account A nonce 0 must succeed");

        // Account B is still at nonce=0 although A moved to nonce=1.
        frame_system::CheckNonce::<TestRuntime>::from(0)
            .validate_and_prepare(origin_of(who_b), &call, &info, 0, 0)
            .expect("account B nonce 0 must independently succeed");
    });
}
