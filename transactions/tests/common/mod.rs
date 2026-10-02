//! Shared Mock Runtime for the Transactions-phase tests — `frame_system` only
//! (without BABE/GRANDPA), in the same style as `protocol/tests/check_genesis.rs`.
//!
//! Uses `SolochainDefaultConfig` (not `TestDefaultConfig`) because the `AccountId`
//! there is `sp_runtime::AccountId32` — exactly the same family as `madar_identity::AccountId`
//! (both are `AccountId32` via `IdentifyAccount for MultiSigner`).

use frame_support::{construct_runtime, derive_impl};
use sp_runtime::BuildStorage;

construct_runtime!(
    pub enum TestRuntime {
        System: frame_system,
    }
);

#[derive_impl(frame_system::config_preludes::SolochainDefaultConfig)]
impl frame_system::Config for TestRuntime {
    type Block = frame_system::mocking::MockBlock<TestRuntime>;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let storage = frame_system::GenesisConfig::<TestRuntime>::default()
        .build_storage()
        .expect("mock genesis storage must build");
    sp_io::TestExternalities::new(storage)
}
