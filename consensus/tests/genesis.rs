//! Actual Genesis build with BABE+GRANDPA+Session together — **Dev-only** (D25).
//! The Validator set here must never be taken as the basis for any public network.

mod common;

use common::{dev_validator, new_test_ext};
use frame_support::traits::Get;
use madar_consensus::Runtime;

#[test]
fn dev_genesis_with_local_validators_builds_and_initializes_authorities() {
    let validators = vec![dev_validator(1), dev_validator(2), dev_validator(3)];

    new_test_ext(&validators).execute_with(|| {
        let babe_authorities = pallet_babe::Authorities::<Runtime>::get();
        assert_eq!(
            babe_authorities.len(),
            3,
            "all 3 dev BABE authorities must be present at genesis"
        );

        let grandpa_authorities = pallet_grandpa::Pallet::<Runtime>::grandpa_authorities();
        assert_eq!(
            grandpa_authorities.len(),
            3,
            "all 3 dev GRANDPA authorities must be present at genesis"
        );

        // INV-7 (generalized): the BABE and GRANDPA keys of each Validator differ byte-wise despite
        // being derived from the same numeric seed (two completely different algorithms).
        for v in &validators {
            let babe_bytes: &[u8] = v.babe.as_ref();
            let grandpa_bytes: &[u8] = v.grandpa.as_ref();
            assert_ne!(babe_bytes, grandpa_bytes);
        }
    });
}

#[test]
fn epoch_duration_matches_the_locked_protocol_constant() {
    let configured: u64 = <Runtime as pallet_babe::Config>::EpochDuration::get();
    assert_eq!(configured, madar_consensus::EPOCH_DURATION_IN_SLOTS);
    assert_eq!(
        configured, 900,
        "D11/D12: Epoch length must remain 900 slots"
    );
}
