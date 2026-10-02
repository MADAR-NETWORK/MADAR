//! Review issue #3: Admission weights reflect the actual work cost (Argon2), and early
//! rejection neither pays the Argon2 cost nor drains the block budget.

mod common;

use common::*;
use frame_support::{dispatch::GetDispatchInfo, traits::Randomness};
use madar_admission::weights::{WeightInfo as _, ARGON2_PS_PER_KIB_PASS};
use sp_runtime::AccountId32;

type W = <TestRuntime as madar_admission::Config>::WeightInfo;

fn account(byte: u8) -> AccountId32 {
    AccountId32::from([byte; 32])
}

#[test]
fn the_declared_weight_of_a_solution_includes_the_argon2_cost_derived_from_config() {
    // The test mock: m=8 KiB, t=1 → 8 KiB-pass.
    let declared = W::submit_admission_solution();
    assert!(
        declared.ref_time() >= 8 * ARGON2_PS_PER_KIB_PASS,
        "the declared ref_time must at least cover the Argon2 work implied by Config"
    );

    // The weight declared on the call itself (what CheckWeight sees) = the WeightInfo weight, not zero.
    let call = madar_admission::Call::<TestRuntime>::submit_admission_solution { nonce: 0 };
    assert_eq!(call.get_dispatch_info().call_weight, declared);
    assert!(declared.ref_time() > 0);
}

#[test]
fn cheap_rejections_are_refunded_but_a_failed_puzzle_pays_the_full_argon2_weight() {
    use frame_support::dispatch::Pays;
    new_test_ext().execute_with(|| {
        // 1) Banned: early rejection with a low actual weight.
        let banned = account(60);
        Admission::ban_key(RuntimeOrigin::root(), banned.clone()).unwrap();
        let err =
            Admission::submit_admission_solution(RuntimeOrigin::signed(banned), 0).unwrap_err();
        assert_eq!(
            err.post_info.actual_weight,
            Some(W::submit_admission_rejected_early())
        );
        assert!(
            W::submit_admission_rejected_early().ref_time()
                < W::submit_admission_solution().ref_time()
        );
        assert_eq!(err.post_info.pays_fee, Pays::Yes);

        // 2) Wrong solution: Argon2 actually ran → no refund (actual_weight = None ⇒ the full weight).
        let who = account(61);
        let seed = TestRandomness::random(madar_protocol::ADMISSION_PUZZLE_DOMAIN).0;
        let bad_nonce = (0u64..)
            .find(|n| !Admission::solution_meets_difficulty(&who, &seed, *n))
            .unwrap();
        let err = Admission::submit_admission_solution(RuntimeOrigin::signed(who), bad_nonce)
            .unwrap_err();
        assert_eq!(
            err.post_info.actual_weight, None,
            "a failed puzzle already spent the Argon2 work: no refund"
        );
    });
}
