//! Mock Runtime for the Blocks-phase tests — `frame_system` actually wired to the limits
//! `madar_blocks::{MadarBlockWeights, MadarBlockLength}` instead of the default `()`.

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
    type BlockWeights = madar_blocks::MadarBlockWeights;
    type BlockLength = madar_blocks::MadarBlockLength;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let storage = frame_system::GenesisConfig::<TestRuntime>::default()
        .build_storage()
        .expect("mock genesis storage must build");
    sp_io::TestExternalities::new(storage)
}
