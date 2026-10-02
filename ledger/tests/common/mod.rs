//! Mock Runtime for the State/Ledger-phase tests: `frame_system` + `madar-ledger`.

use frame_support::{construct_runtime, derive_impl, traits::ConstU32};
use sp_runtime::BuildStorage;

construct_runtime!(
    pub enum TestRuntime {
        System: frame_system,
        Ledger: madar_ledger,
    }
);

#[derive_impl(frame_system::config_preludes::SolochainDefaultConfig)]
impl frame_system::Config for TestRuntime {
    type Block = frame_system::mocking::MockBlock<TestRuntime>;
}

impl madar_ledger::Config for TestRuntime {
    type MaxItemsPerAccount = ConstU32<2>;
    type MaxItemSize = ConstU32<8>;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let storage = frame_system::GenesisConfig::<TestRuntime>::default()
        .build_storage()
        .expect("mock genesis storage must build");
    sp_io::TestExternalities::new(storage)
}
