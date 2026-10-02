//! D24 — proves that the `MadarBlockWeights`/`MadarBlockLength` limits (placeholders,
//! non-final) are actually load-bearing in `frame_system::CheckWeight`,
//! not merely unused constants.

mod common;

use common::{new_test_ext, TestRuntime};
use frame_support::dispatch::{DispatchClass, DispatchInfo, Pays};
use frame_support::weights::{constants::WEIGHT_REF_TIME_PER_SECOND, Weight};

fn info_with_weight(weight: Weight) -> DispatchInfo {
    DispatchInfo {
        call_weight: weight,
        extension_weight: Weight::zero(),
        class: DispatchClass::Normal,
        pays_fee: Pays::Yes,
    }
}

#[test]
fn small_extrinsic_within_length_and_weight_limits_is_accepted() {
    new_test_ext().execute_with(|| {
        let info = info_with_weight(Weight::from_parts(1_000, 0));
        let result = frame_system::CheckWeight::<TestRuntime>::do_validate(&info, 1_000);

        assert!(
            result.is_ok(),
            "a small, well-formed extrinsic must pass D24's limits: {result:?}"
        );
    });
}

/// D24: a transaction larger than its class share (Normal = 75% of `MAX_BLOCK_SIZE_BYTES`)
/// is rejected — the numeric limit is actually enforced, not merely documented.
#[test]
fn extrinsic_longer_than_the_normal_class_length_share_is_rejected() {
    new_test_ext().execute_with(|| {
        let info = info_with_weight(Weight::from_parts(1_000, 0));
        // Clearly larger than 75% × 5MB (~3.93MB).
        let oversized_len = 10 * 1024 * 1024;

        let result = frame_system::CheckWeight::<TestRuntime>::do_validate(&info, oversized_len);

        assert!(
            result.is_err(),
            "D24 violated: an extrinsic exceeding the normal-class block length share must be rejected"
        );
    });
}

/// D24: a transaction whose computational weight exceeds its class share is rejected too (not only size).
#[test]
fn extrinsic_heavier_than_the_normal_class_weight_share_is_rejected() {
    new_test_ext().execute_with(|| {
        // Heavier than the whole block budget (two seconds) — exceeds even the operational share.
        let far_too_heavy = Weight::from_parts(WEIGHT_REF_TIME_PER_SECOND.saturating_mul(10), 0);
        let info = info_with_weight(far_too_heavy);

        let result = frame_system::CheckWeight::<TestRuntime>::do_validate(&info, 100);

        assert!(
            result.is_err(),
            "D24 violated: an extrinsic exceeding the block weight budget must be rejected"
        );
    });
}
