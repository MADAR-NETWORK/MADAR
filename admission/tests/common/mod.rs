//! Mock runtime for the Admission tests — `frame_system` + `madar_admission`
//! only (no real BABE/GRANDPA/Session; deliberate isolation to test this
//! pallet's logic alone, like the other phases of this project).
//!
//! **`TestRandomness` is purely for tests** — derived from the current block number (set
//! manually with `System::set_block_number`) instead of real BABE randomness
//! (the `RandomnessFromOneEpochAgo` actually used in `madar_consensus`) —
//! it allows simulating a "round change" with full control during the test, without building
//! a full runtime with BABE here.
//!
//! **The Argon2id/difficulty values here are deliberately small for fast automated testing** — unrelated
//! to the placeholder values in `madar_consensus::Runtime` (D26).

#![allow(dead_code)] // shared helpers: each test file uses part of them

use frame_support::traits::Randomness;
use frame_support::{construct_runtime, derive_impl, traits::ConstU32};
use sp_core::H256;
use sp_runtime::BuildStorage;

construct_runtime!(
    pub enum TestRuntime {
        System: frame_system,
        Admission: madar_admission,
    }
);

#[derive_impl(frame_system::config_preludes::SolochainDefaultConfig)]
impl frame_system::Config for TestRuntime {
    type Block = frame_system::mocking::MockBlock<TestRuntime>;
}

pub struct TestRandomness;
impl Randomness<H256, u64> for TestRandomness {
    fn random(subject: &[u8]) -> (H256, u64) {
        let block_number = frame_system::Pallet::<TestRuntime>::block_number();
        let mut input = subject.to_vec();
        input.extend_from_slice(&block_number.to_le_bytes());
        (H256::from(sp_io::hashing::blake2_256(&input)), block_number)
    }
}

/// The per-block VRF in the mock: a hash of (subject ‖ block number) — a different value per block, as in real BABE.
pub struct TestVrf;
impl Randomness<Option<H256>, u64> for TestVrf {
    fn random(subject: &[u8]) -> (Option<H256>, u64) {
        // The **previous** block's VRF (as `ParentBlockRandomness` does: BABE writes it in `on_finalize` for block n-1).
        let n = frame_system::Pallet::<TestRuntime>::block_number().saturating_sub(1);
        let mut input = b"vrf".to_vec();
        input.extend_from_slice(subject);
        input.extend_from_slice(&n.to_le_bytes());
        (Some(H256::from(sp_io::hashing::blake2_256(&input))), n)
    }
}

impl madar_admission::Config for TestRuntime {
    type BlockRandomness = TestVrf;
    type MinFreshEntropyBlocks = ConstU32<3>;
    type RuntimeEvent = RuntimeEvent;
    type MembershipTermSessions = ConstU32<3>;
    type RenewalGraceSessions = ConstU32<2>;
    type MaxCandidatesPerRound = ConstU32<4>;
    type HasSessionKeys = frame_support::traits::Everything;
    type EpochRandomness = TestRandomness;
    type DifficultyLeadingZeroBits = ConstU32<4>; // deliberately small for speed, purely for tests.
    type AdmissionCapPerRound = ConstU32<2>;
    type MaxValidators = ConstU32<100>;
    type ArgonMemoryCostKib = ConstU32<8>; // the minimum valid value for Argon2 (8×Parallelism=1).
    type ArgonTimeCost = ConstU32<1>;
    // Purely for tests: `EnsureRoot` stands for "independent governance" in a fully simplified way (no
    // `pallet_collective` in this isolated mock) — the actual runtime
    // uses a 2-of-3 committee (D44/D45), not a single Root.
    type OperatorApprovalOrigin = frame_system::EnsureRoot<sp_runtime::AccountId32>;
    // Test only: the isolated mock keeps the two administrative calls through Root to cover their logic;
    // the actual runtime uses `EnsureNever` (N1).
    type AdminOrigin = frame_system::EnsureRoot<sp_runtime::AccountId32>;
    // A generous absolute cap (equal to MaxValidators) — it does not restrict the existing lottery/entropy
    // engine tests (they use one test operator with a large cap via `ensure_vouched`).
    // The dedicated D47 tests approve another operator with a small explicit cap of their own choosing.
    type MaxVotesPerOperator = ConstU32<100>;
    type WeightInfo = madar_admission::weights::ArgonMeteredWeight<TestRuntime>;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let storage = frame_system::GenesisConfig::<TestRuntime>::default()
        .build_storage()
        .expect("mock genesis storage must build");
    sp_io::TestExternalities::new(storage)
}

/// **D47 support:** a fixed "test operator" account approved automatically with a generous cap
/// (100) in all the existing lifecycle tests (`lifecycle.rs`) —
/// those tests check the lottery/entropy/validity engine itself, not
/// the operator caps (which have their own dedicated tests in `operator_caps.rs`
/// with other operators and small explicit caps). The byte `0xEE` is deliberately chosen outside
/// all byte ranges used by the current dev_only_force_set_validators
/// tests (roughly 0x01–0xDB) to avoid any collision.
pub fn test_operator() -> sp_runtime::AccountId32 {
    sp_runtime::AccountId32::from([0xEE; 32])
}

/// Ensures `who` is vouched for by [`test_operator`] before submitting the puzzle solution — without this
/// vouch, `who` would never become a validator however many lotteries it wins (D47). Idempotent:
/// safe to call for the same `who` more than once (renewal/repeated attempts).
pub fn ensure_vouched(who: &sp_runtime::AccountId32) {
    let operator = test_operator();
    if madar_admission::ApprovedOperators::<TestRuntime>::get(&operator).is_none() {
        madar_admission::Pallet::<TestRuntime>::approve_operator(
            frame_system::RawOrigin::Root.into(),
            operator.clone(),
            100,
        )
        .expect("test operator approval must succeed");
    }
    if madar_admission::NodeOperator::<TestRuntime>::get(who).is_none() {
        madar_admission::Pallet::<TestRuntime>::vouch_node(
            frame_system::RawOrigin::Signed(operator).into(),
            who.clone(),
        )
        .expect(
            "test vouching must succeed — raise the mock's MaxVotesPerOperator if this ever fires",
        );
    }
}

/// Brute-forces the first `nonce` that meets the current puzzle difficulty for a given account/round
/// — a test tool (not part of the production logic) that proves correct solutions
/// are *actually findable* at the low test difficulty, not a theoretical assumption.
pub fn find_valid_nonce(who: &sp_runtime::AccountId32, round_seed: &H256) -> u64 {
    (0u64..1_000_000)
        .find(|nonce| madar_admission::Pallet::<TestRuntime>::solution_meets_difficulty(who, round_seed, *nonce))
        .expect("a valid nonce must be found within a reasonable search bound at this low test difficulty")
}
