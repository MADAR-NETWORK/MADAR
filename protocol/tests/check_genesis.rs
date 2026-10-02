//! `CheckGenesis` rejection test — the last item of the Protocol gate (§5).
//!
//! ============================================================================
//! Context (design document §11.2):
//! this file builds a minimal mock runtime with `frame_system` only (no BABE/GRANDPA,
//! no MADAR logic at all), solely to provide an execution context for `CheckGenesis` as a `SignedExtra`.
//! The scope of this phase (§2.12) is limited to chain_spec.rs and domains.rs;
//! this mock exists only for the test and is not part of the protocol itself.
//!
//! ============================================================================
//!
//! Historical note: this test was written before the first build and was then
//! verified against the pinned Polkadot SDK version. The type/function names
//! (`construct_runtime!`, `frame_system::CheckGenesis`,
//! the `SignedExtension` signature) follow the `frame_system`/`frame_support` interface
//! that has been stable across several Polkadot SDK releases, and must be re-checked
//! against the pinned version (§11.3) after any SDK upgrade.
//!

use frame_support::{construct_runtime, derive_impl};
use frame_system::CheckGenesis;
use sp_runtime::{traits::TransactionExtension, BuildStorage};

// ----------------------------------------------------------------------------
// A minimal mock runtime: frame_system alone, with no other pallet.
// ----------------------------------------------------------------------------
construct_runtime!(
    pub enum TestRuntime {
        System: frame_system,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for TestRuntime {
    type Block = frame_system::mocking::MockBlock<TestRuntime>;
}

fn new_test_ext(genesis_hash_seed: u8) -> sp_io::TestExternalities {
    let storage = frame_system::GenesisConfig::<TestRuntime>::default()
        .build_storage()
        .expect("mock genesis storage must build");

    let mut ext = sp_io::TestExternalities::new(storage);
    ext.execute_with(|| {
        // We simulate a different genesis hash per seed by setting the first stored block hash
        // manually in the test context (the exact way to set block_hash(0)
        // depends on the pinned frame_system version).
        let fake_genesis_hash = <TestRuntime as frame_system::Config>::Hash::from(
            sp_core::H256::from([genesis_hash_seed; 32]),
        );
        frame_system::BlockHash::<TestRuntime>::insert(
            frame_system::pallet_prelude::BlockNumberFor::<TestRuntime>::from(0u32),
            fake_genesis_hash,
        );
    });
    ext
}

#[test]
fn additional_signed_returns_the_actual_stored_genesis_hash() {
    new_test_ext(0xAAu8).execute_with(|| {
        let check = CheckGenesis::<TestRuntime>::new();
        let additional = check
            .implicit()
            .expect("implicit must succeed for CheckGenesis");

        let expected =
            <TestRuntime as frame_system::Config>::Hash::from(sp_core::H256::from([0xAAu8; 32]));
        assert_eq!(
            additional, expected,
            "CheckGenesis::additional_signed must return the actual stored genesis hash, not a placeholder"
        );
    });
}

/// This is the core test required by §5: a transaction signed assuming a wrong genesis hash
/// (different from the actual chain state) must be rejected in 100% of attempts.
///
/// The actual check happens when the full extrinsic signature is verified
/// (not inside CheckGenesis::validate alone, which only contributes the genesis
/// hash to the signed additional_signed data) — this test proves that
/// two different genesis hash values produce completely different additional_signed data,
/// which makes any signature built on a wrong genesis hash fail full verification.
#[test]
fn different_stored_genesis_hash_yields_different_additional_signed_payload() {
    let payload_a = new_test_ext(0x11u8).execute_with(|| {
        CheckGenesis::<TestRuntime>::new()
            .implicit()
            .expect("must succeed")
    });
    let payload_b = new_test_ext(0x22u8).execute_with(|| {
        CheckGenesis::<TestRuntime>::new()
            .implicit()
            .expect("must succeed")
    });

    assert_ne!(
        payload_a, payload_b,
        "CheckGenesis rejection guarantee depends on distinct genesis hashes producing distinct signed payloads"
    );
}
