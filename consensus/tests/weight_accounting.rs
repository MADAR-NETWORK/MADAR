//! Review #3: weight accounting matches actual execution **in the worst-case size** (1000 Validators, full candidate
//! sets). We measure the number of storage keys actually written (not an estimate) for each path and verify it is ≤ what the weight functions assume
//! (`*_ops`). Reads are reviewed analytically in `weights.rs` (there is no read counter in `TestExternalities`).

mod common;

use common::{dev_validator, new_test_ext};
use frame_support::{traits::Get, BoundedVec};
use madar_admission::weights::{ArgonMeteredWeight, WeightInfo};
use madar_consensus::{AccountId, Runtime, RuntimeOrigin};
use pallet_session::SessionManager;

type W = ArgonMeteredWeight<Runtime>;

fn account(i: u32) -> AccountId {
    AccountId::from(sp_io::hashing::blake2_256(&i.to_le_bytes()))
}

fn v_max() -> u32 {
    <Runtime as madar_admission::Config>::MaxValidators::get()
}
fn c_max() -> u32 {
    <Runtime as madar_admission::Config>::MaxCandidatesPerRound::get()
}

/// Worst case: all members are eligible, all of them (except the first) have registered an exit, and every set is full of candidates
/// holding Session keys, with enough entropy for the draw.
fn worst_case_ext() -> sp_io::TestExternalities {
    let mut ext = new_test_ext(&[]);
    ext.execute_with(|| {
        let members: Vec<AccountId> = (0..v_max()).map(account).collect();
        for (i, m) in members.iter().enumerate() {
            madar_admission::MembershipExpiry::<Runtime>::insert(m, 1u32);
            if i != 0 {
                madar_admission::PendingVoluntaryExit::<Runtime>::insert(m, ());
            }
        }
        madar_admission::Validators::<Runtime>::put(BoundedVec::try_from(members).unwrap());

        let keys = {
            let d = dev_validator(1);
            madar_consensus::SessionKeys {
                babe: d.babe,
                grandpa: d.grandpa,
            }
        };
        let pool = |base: u32| -> BoundedVec<
            (AccountId, [u8; 32]),
            <Runtime as madar_admission::Config>::MaxCandidatesPerRound,
        > {
            BoundedVec::try_from(
                (0..c_max())
                    .map(|i| {
                        let a = account(1_000_000 + base * 1000 + i);
                        pallet_session::NextKeys::<Runtime>::insert(&a, keys.clone());
                        (a, [i as u8; 32])
                    })
                    .collect::<Vec<_>>(),
            )
            .unwrap()
        };
        madar_admission::Round::<Runtime>::put((sp_core::H256::zero(), pool(0)));
        madar_admission::Pending::<Runtime>::put(
            BoundedVec::try_from(
                (1..=madar_admission::MAX_PENDING_POOLS as u32)
                    .map(|b| (0u32, 0u64, pool(b)))
                    .collect::<Vec<_>>(),
            )
            .unwrap(),
        );
        madar_admission::EntropyCount::<Runtime>::put(1_000u64);
        frame_system::Pallet::<Runtime>::set_block_number(5);
    });
    ext.commit_all().unwrap();
    ext
}

fn written_keys(ext: &sp_io::TestExternalities) -> u64 {
    // `:transaction_level:` is an internal key of the in-memory transactional layer (not a database write).
    ext.overlayed_changes()
        .changes()
        .filter(|(k, _)| k.as_slice() != b":transaction_level:")
        .count() as u64
}

#[test]
fn voluntary_exit_writes_no_more_than_declared() {
    let mut ext = worst_case_ext();
    ext.execute_with(|| {
        madar_admission::Pallet::<Runtime>::voluntary_exit(RuntimeOrigin::signed(account(1)))
            .unwrap();
    });
    let w = written_keys(&ext);
    assert!(
        w <= W::exit_ops().writes,
        "voluntary_exit wrote {w} keys > declared {}",
        W::exit_ops().writes
    );
}

#[test]
fn ban_writes_no_more_than_declared_even_when_the_offender_is_everywhere() {
    let mut ext = worst_case_ext();
    ext.execute_with(|| {
        // The offender is a member with a registered exit and is a candidate in every set.
        let offender = account(1);
        let (seed, mut round) = madar_admission::Round::<Runtime>::get().unwrap();
        round[0].0 = offender.clone();
        madar_admission::Round::<Runtime>::put((seed, round));
        madar_admission::Pending::<Runtime>::mutate(|p| {
            for (_, _, pool) in p.iter_mut() {
                pool[0].0 = offender.clone();
            }
        });
    });
    ext.commit_all().unwrap();
    ext.execute_with(|| {
        madar_admission::Pallet::<Runtime>::ban(&account(1)); // production ban path (Equivocation); `ban_key` is closed (N1)
    });
    let w = written_keys(&ext);
    assert!(
        w <= W::ban_ops().writes,
        "ban wrote {w} keys > declared {}",
        W::ban_ops().writes
    );
}

// `dev_only_force_set_validators` is no longer callable in this Runtime (`AdminOrigin = EnsureNever`, N1),
// so there is no write path to measure here; its rejection is proven in `tests/admin_calls_closed.rs`.

#[test]
fn new_session_writes_no_more_than_declared_in_the_worst_state() {
    let mut ext = worst_case_ext();
    ext.execute_with(|| {
        let next = madar_admission::Pallet::<Runtime>::new_session(50).expect("a validator set");
        assert!(!next.is_empty());
        // All ready sets were drawn (none remain pending) and the incoming ones have no duplicates.
        assert_eq!(
            madar_admission::Pending::<Runtime>::get().len(),
            1,
            "only the round closed just now is pending"
        );
    });
    let w = written_keys(&ext);
    assert!(
        w <= W::new_session_ops().writes,
        "new_session wrote {w} keys > declared {}",
        W::new_session_ops().writes
    );
}

#[test]
fn on_initialize_accumulator_writes_no_more_than_declared() {
    let mut ext = worst_case_ext();
    ext.execute_with(|| {
        pallet_babe::AuthorVrfRandomness::<Runtime>::put(Some([9u8; 32]));
    });
    ext.commit_all().unwrap();
    ext.execute_with(|| {
        <madar_admission::Pallet<Runtime> as frame_support::traits::Hooks<u32>>::on_initialize(6);
    });
    let w = written_keys(&ext);
    assert!(
        w <= W::on_initialize_ops().writes,
        "on_initialize wrote {w} keys > {}",
        W::on_initialize_ops().writes
    );
}

/// Weights grow with set sizes (not constants) and stay within a reasonable block budget for normal paths.
#[test]
fn declared_weights_scale_with_set_sizes_and_stay_within_a_block() {
    use frame_support::dispatch::DispatchClass;
    let block = <Runtime as frame_system::Config>::BlockWeights::get();
    let normal = block.get(DispatchClass::Normal).max_total.unwrap();
    for (name, w) in [
        ("voluntary_exit", W::voluntary_exit()),
        ("ban_key", W::ban_key()),
        ("rejected_early", W::submit_admission_rejected_early()),
        ("submit", W::submit_admission_solution()),
    ] {
        assert!(
            w.ref_time() < normal.ref_time(),
            "{name} must fit inside one Normal block: {w:?}"
        );
    }
    // Early rejection scales with the maximum list sizes (not a fixed 50µs): scanning 1000 members + a set of 64.
    let early = W::submit_admission_rejected_early().ref_time();
    assert!(
        early >= (v_max() as u64 + c_max() as u64) * madar_admission::weights::SCAN_PS_PER_ITEM
    );
    assert!(
        W::voluntary_exit().proof_size() >= v_max() as u64 * 32,
        "exit reads the whole validator list"
    );
    assert!(
        W::ban_key().proof_size() > W::voluntary_exit().proof_size(),
        "ban also touches the pools"
    );
    // new_session (Mandatory) is weighed and registered: larger than any normal transaction but only once per Epoch.
    assert!(W::new_session().ref_time() > W::ban_key().ref_time());
}

/// Native/in-memory calibration only. No debug normalization and no claim of disk or WASM coverage.
#[test]
#[ignore = "timing calibration: run explicitly with --release --ignored --nocapture --test-threads=1"]
fn worst_case_compute_time_is_covered_by_the_declared_ref_time() {
    use std::time::Instant;
    assert!(!cfg!(debug_assertions), "calibration requires --release");
    for scenario in [
        "exit_and_draw",
        "expiry_and_draw",
        "grace_and_full",
        "deferred",
        "ban",
    ] {
        let mut samples = Vec::new();
        let mut max_keys = 0;
        for _ in 0..100 {
            let mut ext = worst_case_ext();
            ext.execute_with(|| {
                assert_eq!(
                    madar_admission::Pending::<Runtime>::get().len(),
                    madar_admission::MAX_PENDING_POOLS
                );
                // Exercise the entropy-mixing branch too.
                pallet_babe::AuthorVrfRandomness::<Runtime>::put(Some([9u8; 32]));
                if scenario == "expiry_and_draw" || scenario == "grace_and_full" {
                    for i in 0..v_max() {
                        madar_admission::PendingVoluntaryExit::<Runtime>::remove(account(i));
                        if scenario == "grace_and_full" {
                            madar_admission::MembershipExpiry::<Runtime>::insert(account(i), 50u32);
                        }
                    }
                }
                if scenario == "deferred" {
                    madar_admission::EntropyCount::<Runtime>::put(0u64);
                }
            });
            ext.commit_all().unwrap();
            let start = Instant::now();
            ext.execute_with(|| {
                if scenario == "ban" {
                    madar_admission::Pallet::<Runtime>::ban(&account(1)); // production ban path (Equivocation); `ban_key` is closed (N1)
                } else {
                    let next = madar_admission::Pallet::<Runtime>::new_session(50).unwrap();
                    assert!(!next.is_empty());
                    if scenario == "deferred" {
                        assert_eq!(
                            madar_admission::Pending::<Runtime>::get().len(),
                            madar_admission::MAX_PENDING_POOLS
                        );
                    }
                }
            });
            samples.push(start.elapsed().as_nanos() as u64);
            max_keys = max_keys.max(written_keys(&ext));
        }
        samples.sort_unstable();
        let (weight, ops) = if scenario == "ban" {
            (W::ban_key(), W::ban_ops())
        } else {
            (W::new_session(), W::new_session_ops())
        };
        println!("B1 {scenario}: n=100 p50_ns={} p95_ns={} max_ns={} declared_ps={} max_written_keys={} declared_writes={} native_margin=5",
            samples[49], samples[94], samples[99], weight.ref_time(), max_keys, ops.writes);
        assert!(max_keys <= ops.writes, "{scenario}: storage-write bound");
        assert!(
            samples[99].saturating_mul(5_000) < weight.ref_time(),
            "{scenario}: measured maximum x5 exceeds declared ref_time"
        );
    }
}
