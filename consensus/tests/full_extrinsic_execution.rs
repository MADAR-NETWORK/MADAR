//! Actual proof that the full Runtime API (Executive/Core/BlockBuilder) works
//! as a single real pipeline — not just separate Pallet calls as in the tests
//! of earlier phases. This is the first test in the project that builds a genuinely signed transaction
//! (SignedPayload → sr25519 signature → UncheckedExtrinsic) and passes it through
//! the real `Executive::apply_extrinsic` — practically tying together the output of the Identity phases
//! (signing), Transactions (SignedExtra), Blocks (weight/length limits),
//! and Consensus (Runtime API) for the first time.

mod common;

use common::{dev_validator, new_test_ext};
use madar_consensus::{
    AccountId, Address, Executive, OnboardingPolicy, Runtime, RuntimeCall, SignedExtra,
    UncheckedExtrinsic,
};
use parity_scale_codec::Encode;
use sp_core::Pair;
use sp_runtime::generic::Era;

fn build_signed_extrinsic(
    signer: &sp_core::sr25519::Pair,
    account: &AccountId,
    call: RuntimeCall,
    nonce: u32,
    era: Era,
) -> UncheckedExtrinsic {
    let extra: SignedExtra = (
        frame_system::CheckSpecVersion::<Runtime>::new(),
        frame_system::CheckTxVersion::<Runtime>::new(),
        frame_system::CheckGenesis::<Runtime>::new(),
        madar_transactions::CheckMortalOnly::<Runtime>::from(era),
        madar_transactions::CheckNonceOrOnboard::<Runtime, OnboardingPolicy>::from(nonce),
        frame_system::CheckWeight::<Runtime>::new(),
    );

    let raw_payload = sp_runtime::generic::SignedPayload::new(call.clone(), extra.clone())
        .expect("SignedPayload::new must succeed for a well-formed call/extra pair");
    let signature = raw_payload.using_encoded(|payload| signer.sign(payload));

    UncheckedExtrinsic::new_signed(call, Address::Id(account.clone()), signature.into(), extra)
}

#[test]
fn a_genuinely_signed_extrinsic_executes_successfully_through_the_real_executive() {
    let alice = dev_validator(1);
    // Alice is a real Genesis validator: her account reference (provider) is created by `pallet_session` itself
    // when building Genesis — no manual state injection here. (The paths for new accounts without a reference
    // are tested in `account_onboarding.rs`.)
    new_test_ext(&[dev_validator(1)]).execute_with(|| {
        frame_system::Pallet::<Runtime>::set_block_number(13);
        frame_system::BlockHash::<Runtime>::insert(12u32, sp_core::H256::repeat_byte(1));

        let signer = sp_core::sr25519::Pair::from_seed(&[1u8; 32]);
        let call = RuntimeCall::System(frame_system::Call::remark { remark: b"madar".to_vec() });
        let extrinsic =
            build_signed_extrinsic(&signer, &alice.account, call, 0, Era::mortal(4, 12));

        let result = Executive::apply_extrinsic(extrinsic);

        assert!(
            result.is_ok() && result.unwrap().is_ok(),
            "a well-formed, genuinely-signed extrinsic must execute successfully through the real Executive pipeline: {result:?}"
        );
        assert_eq!(
            frame_system::Pallet::<Runtime>::account_nonce(&alice.account),
            1,
            "successful execution must increment the signer's nonce exactly once"
        );
    });
}

/// The same scenario, but with an Immortal Era — it must be rejected **even before** building
/// the signature (when computing `additional_signed` for `CheckMortalOnly`), meaning that
/// a valid signed transaction with Immortal cannot even be formed in the first place — a stronger rejection
/// than merely failing later at `apply_extrinsic`.
#[test]
fn an_immortal_signed_payload_can_never_even_be_constructed() {
    new_test_ext(&[]).execute_with(|| {
        frame_system::Pallet::<Runtime>::set_block_number(1);

        let call = RuntimeCall::System(frame_system::Call::remark { remark: vec![] });
        let extra: SignedExtra = (
            frame_system::CheckSpecVersion::<Runtime>::new(),
            frame_system::CheckTxVersion::<Runtime>::new(),
            frame_system::CheckGenesis::<Runtime>::new(),
            madar_transactions::CheckMortalOnly::<Runtime>::from(Era::Immortal),
            madar_transactions::CheckNonceOrOnboard::<Runtime, OnboardingPolicy>::from(0u32),
            frame_system::CheckWeight::<Runtime>::new(),
        );

        let result = sp_runtime::generic::SignedPayload::new(call, extra);

        assert!(
            result.is_err(),
            "D18 violated: it must be impossible to even construct a signed payload with an Immortal era through the real SignedExtra"
        );
    });
}
