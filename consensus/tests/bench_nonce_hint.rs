//! B1 benchmarks helper (only with `runtime-benchmarks`): finds the puzzle nonce the Admission benchmark candidate needs
//! under the benchmark epoch randomness and the production puzzle parameters, so the benchmark setup does not have to
//! search for minutes in WASM. Put the printed value in `madar_admission::benchmarking::NONCE_HINT`.
//!
//! `cargo test --release -p madar-consensus --features runtime-benchmarks --test bench_nonce_hint -- --ignored --nocapture`
#![cfg(feature = "runtime-benchmarks")]

use frame_support::traits::Randomness;
use madar_admission::benchmarking::{find_nonce, BENCH_EPOCH_RANDOMNESS, NONCE_HINT};
use madar_consensus::{pallet_babe, AccountId, Runtime};

#[test]
#[ignore = "slow (Argon2 search); run explicitly when the puzzle parameters change"]
fn bench_nonce_hint() {
    sp_io::TestExternalities::default().execute_with(|| {
        pallet_babe::NextRandomness::<Runtime>::put(BENCH_EPOCH_RANDOMNESS);
        let who: AccountId = frame_benchmarking::account("candidate", 0, 0);
        let seed =
            <<Runtime as madar_admission::Config>::EpochRandomness as Randomness<_, _>>::random(
                madar_protocol::ADMISSION_PUZZLE_DOMAIN,
            )
            .0;
        let nonce = find_nonce::<Runtime>(&who, &seed);
        println!("NONCE_HINT = {nonce} (current constant {NONCE_HINT})");
        assert!(madar_admission::Pallet::<Runtime>::solution_meets_difficulty(&who, &seed, nonce));
    });
}
