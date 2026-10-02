//! `CheckNonceOrOnboard`: the default policy `()` matches the standard `CheckNonce`
//! exactly (rejects an account without a reference), and an allowing policy creates exactly one reference at the
//! first transaction, then follows the standard path (nonce/replay).

mod common;

use common::{new_test_ext, TestRuntime};
use frame_support::dispatch::{DispatchClass, DispatchInfo, Pays};
use frame_support::weights::Weight;
use madar_transactions::{AccountCreationPolicy, CheckNonceOrOnboard};
use sp_runtime::traits::{DispatchTransaction, TransactionExtension};
use sp_runtime::transaction_validity::{InvalidTransaction, TransactionSource};

type Call = <TestRuntime as frame_system::Config>::RuntimeCall;

struct AllowAll;
impl AccountCreationPolicy<sp_runtime::AccountId32, Call> for AllowAll {
    fn may_create_account(_: &sp_runtime::AccountId32, _: &Call) -> bool {
        true
    }
}

fn call() -> Call {
    frame_system::Call::<TestRuntime>::remark { remark: vec![] }.into()
}

fn info() -> DispatchInfo {
    DispatchInfo {
        call_weight: Weight::from_parts(100, 0),
        extension_weight: Weight::zero(),
        class: DispatchClass::Normal,
        pays_fee: Pays::Yes,
    }
}

fn finish(
    pre: <CheckNonceOrOnboard<TestRuntime, AllowAll> as TransactionExtension<Call>>::Pre,
    result: sp_runtime::DispatchResult,
) {
    let mut post = Default::default();
    <CheckNonceOrOnboard<TestRuntime, AllowAll> as TransactionExtension<Call>>::post_dispatch(
        pre,
        &info(),
        &mut post,
        0,
        &result,
    )
    .expect("post_dispatch");
}

fn succeed(pre: <CheckNonceOrOnboard<TestRuntime, AllowAll> as TransactionExtension<Call>>::Pre) {
    finish(pre, Ok(()));
}

fn origin(who: &sp_runtime::AccountId32) -> <TestRuntime as frame_system::Config>::RuntimeOrigin {
    frame_system::RawOrigin::Signed(who.clone()).into()
}

#[test]
fn default_policy_rejects_an_account_without_a_reference_exactly_like_check_nonce() {
    new_test_ext().execute_with(|| {
        let who = sp_runtime::AccountId32::from([7u8; 32]);
        let ext = CheckNonceOrOnboard::<TestRuntime, ()>::from(0);
        let result = ext.validate_only(
            origin(&who),
            &call(),
            &info(),
            0,
            TransactionSource::External,
            0,
        );
        assert_eq!(result.err(), Some(InvalidTransaction::Payment.into()));
        assert_eq!(frame_system::Account::<TestRuntime>::get(&who).providers, 0);
    });
}

#[test]
fn allowed_policy_creates_one_reference_then_nonce_replay_protection_applies() {
    new_test_ext().execute_with(|| {
        let who = sp_runtime::AccountId32::from([8u8; 32]);
        let first = CheckNonceOrOnboard::<TestRuntime, AllowAll>::from(0);
        let (pre, _) = first
            .validate_and_prepare(origin(&who), &call(), &info(), 0, 0)
            .expect("first tx is accepted");
        // No state is written before the call succeeds.
        assert_eq!(frame_system::Account::<TestRuntime>::get(&who).providers, 0);
        succeed(pre);
        let account = frame_system::Account::<TestRuntime>::get(&who);
        assert_eq!((account.providers, account.nonce), (1, 1));

        // Repeating the same nonce: stale, and no second reference.
        let replay = CheckNonceOrOnboard::<TestRuntime, AllowAll>::from(0);
        let r = replay.validate_only(
            origin(&who),
            &call(),
            &info(),
            0,
            TransactionSource::External,
            0,
        );
        assert_eq!(r.err(), Some(InvalidTransaction::Stale.into()));

        let second = CheckNonceOrOnboard::<TestRuntime, AllowAll>::from(1);
        let (pre, _) = second
            .validate_and_prepare(origin(&who), &call(), &info(), 0, 0)
            .expect("second tx uses the standard path");
        succeed(pre);
        let account = frame_system::Account::<TestRuntime>::get(&who);
        assert_eq!((account.providers, account.nonce), (1, 2));
    });
}

#[test]
fn a_future_nonce_is_never_accepted_for_a_new_account() {
    new_test_ext().execute_with(|| {
        let who = sp_runtime::AccountId32::from([9u8; 32]);
        let ext = CheckNonceOrOnboard::<TestRuntime, AllowAll>::from(5);
        let r = ext.validate_and_prepare(origin(&who), &call(), &info(), 0, 0);
        assert_eq!(r.err(), Some(InvalidTransaction::Future.into()));
        assert_eq!(
            frame_system::Account::<TestRuntime>::get(&who).providers,
            0,
            "no state change on rejection"
        );
    });
}

/// A failed call from a new account: no reference, no nonce and no permanent effect.
#[test]
fn a_failed_first_call_leaves_no_account_state_at_all() {
    new_test_ext().execute_with(|| {
        let who = sp_runtime::AccountId32::from([10u8; 32]);
        let ext = CheckNonceOrOnboard::<TestRuntime, AllowAll>::from(0);
        let (pre, _) = ext
            .validate_and_prepare(origin(&who), &call(), &info(), 0, 0)
            .unwrap();
        finish(pre, Err(sp_runtime::DispatchError::Other("failed")));

        assert!(
            !frame_system::Account::<TestRuntime>::contains_key(&who),
            "no Account entry may exist"
        );
        // The accompanying result: the nonce was not consumed, so the failed transaction can be re-included but builds no state.
        assert_eq!(frame_system::Pallet::<TestRuntime>::account_nonce(&who), 0);
    });
}
