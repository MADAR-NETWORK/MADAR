//! Cleanliness review (2026-09-19): the production build (default features) carries no constant from the two isolated live-test features
//! (`fast-test-runtime`, `upgrade-fixture`). This test fails if either leaks into the default build; it is intentionally skipped when the feature
//! is explicitly enabled (live tests only, in the separate `live-tests/` workspace).
#![cfg(not(any(feature = "fast-test-runtime", feature = "upgrade-fixture")))]

use frame_support::traits::Get;
use madar_consensus::{
    EPOCH_DURATION_IN_SLOTS, MEMBERSHIP_TERM_SESSIONS, MIN_FRESH_ENTROPY_BLOCKS,
    PUZZLE_DIFFICULTY_BITS, RENEWAL_GRACE_SESSIONS, SLOT_DURATION_MILLIS, VERSION,
};

#[test]
fn the_default_build_carries_only_production_constants() {
    assert_eq!(
        EPOCH_DURATION_IN_SLOTS, 900,
        "fast-test-runtime leaked into the default build"
    );
    assert_eq!(SLOT_DURATION_MILLIS, 8_000);
    assert_eq!(MEMBERSHIP_TERM_SESSIONS, 84);
    assert_eq!(RENEWAL_GRACE_SESSIONS, 12);
    assert_eq!(PUZZLE_DIFFICULTY_BITS, 13); // B2: owner decision 2026-09-28 (~5 minutes on an ordinary computer)
    assert_eq!(MIN_FRESH_ENTROPY_BLOCKS, 16);
    assert_eq!(
        VERSION.spec_version, 6,
        "upgrade-fixture leaked into the default build"
    );
    assert_eq!(<<madar_consensus::Runtime as madar_admission::Config>::AdmissionCapPerRound as Get<u32>>::get(), 2, "D54: testnet admission cap");
}
