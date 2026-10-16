//! B1 benchmark wiring — compiled only with `runtime-benchmarks` (never part of a production runtime).
//!
//! Lists every benchmarked pallet for `madar-node benchmark pallet` and adds one runtime-level benchmark,
//! `madar_session_transition`: the complete `pallet_session::rotate_session` (Admission `new_session` hook +
//! historical root + BABE epoch change + GRANDPA set change + session key loading) on the worst Admission states, with
//! `MaxValidators` members holding session keys. It needs several pallets at once, so it cannot live in one pallet.
//!
//! The helpers below give the MADAR pallets access to state owned by SDK pallets (session keys, BABE randomness,
//! committee motions); they exist only in this feature build.

use super::*;
use alloc::{boxed::Box, vec::Vec};

frame_benchmarking::define_benchmarks!(
    [frame_benchmarking, BaselineBench::<Runtime>]
    [frame_system, SystemBench::<Runtime>]
    [pallet_timestamp, Timestamp]
    [pallet_balances, Balances]
    [pallet_babe, Babe]
    [pallet_grandpa, Grandpa]
    [pallet_collective, UpgradeCommittee]
    [madar_admission, Admission]
    [madar_names, Names]
    [madar_stamp, Stamp]
    [madar_upgrade_authority, UpgradeAuthority]
    [madar_session_transition, SessionTransitionBench::<Runtime>]
);

use frame_benchmarking::baseline::Pallet as BaselineBench;
use frame_system_benchmarking::Pallet as SystemBench;
use session_transition::Pallet as SessionTransitionBench;

impl frame_system_benchmarking::Config for Runtime {}
impl frame_benchmarking::baseline::Config for Runtime {}

/// `Benchmark::benchmark_metadata` of the runtime API.
pub fn metadata(
    extra: bool,
) -> (
    Vec<frame_benchmarking::BenchmarkList>,
    Vec<frame_support::traits::StorageInfo>,
) {
    use frame_support::traits::StorageInfoTrait;
    let mut list = Vec::<frame_benchmarking::BenchmarkList>::new();
    list_benchmarks!(list, extra);
    (list, AllPalletsWithSystem::storage_info())
}

/// `Benchmark::dispatch_benchmark` of the runtime API.
pub fn dispatch(
    config: frame_benchmarking::BenchmarkConfig,
) -> Result<Vec<frame_benchmarking::BenchmarkBatch>, alloc::string::String> {
    use frame_support::traits::WhitelistedStorageKeys;
    let whitelist = AllPalletsWithSystem::whitelisted_storage_keys();
    let mut batches = Vec::<frame_benchmarking::BenchmarkBatch>::new();
    let params = (&config, &whitelist);
    add_benchmarks!(params, batches);
    Ok(batches)
}

/// Admission benchmark helper: session keys, BABE per-block VRF and epoch randomness.
impl madar_admission::BenchmarkHelper for Runtime {
    fn register_session_keys(who: &AccountId) {
        let raw: [u8; 32] = *who.as_ref();
        let keys = SessionKeys {
            babe: sp_consensus_babe::AuthorityId::from(sp_core::sr25519::Public::from_raw(raw)),
            grandpa: sp_consensus_grandpa::AuthorityId::from(sp_core::ed25519::Public::from_raw(
                raw,
            )),
        };
        pallet_session::NextKeys::<Runtime>::insert(who, keys);
    }

    fn set_block_vrf(seed: u8) {
        pallet_babe::AuthorVrfRandomness::<Runtime>::put(Some([seed; 32]));
    }

    fn set_epoch_randomness(randomness: [u8; 32]) {
        pallet_babe::NextRandomness::<Runtime>::put(randomness);
    }
}

/// Committee helper for `UpgradeAuthority::set_committee_members`: `members` become the committee and `proposals`
/// motions are opened, each voted by every member.
impl madar_upgrade_authority::BenchmarkHelper for Runtime {
    fn committee_setup(members: &[AccountId], proposals: u32) {
        committee_bench_setup(members, proposals)
    }
}

fn committee_bench_setup(members: &[AccountId], proposals: u32) {
    use frame_support::traits::ChangeMembers;
    use sp_runtime::traits::Hash;
    type Collective = pallet_collective::Pallet<Runtime, UpgradeCommitteeInstance>;
    let old = pallet_collective::Members::<Runtime, UpgradeCommitteeInstance>::get();
    Collective::set_members_sorted(members, &old);
    for i in 0..proposals {
        let call = RuntimeCall::System(frame_system::Call::remark {
            remark: i.to_le_bytes().to_vec(),
        });
        let hash = <Runtime as frame_system::Config>::Hashing::hash_of(&call);
        Collective::do_propose_proposed(members[0].clone(), 2, Box::new(call), u32::MAX)
            .expect("benchmark motion");
        let index =
            pallet_collective::ProposalCount::<Runtime, UpgradeCommitteeInstance>::get() - 1;
        for m in members {
            Collective::do_vote(m.clone(), hash, index, true).expect("benchmark vote");
        }
    }
}

/// Runtime-level benchmark: a full worst-case session rotation.
pub mod session_transition {
    use super::*;
    use frame_benchmarking::v2::*;
    use madar_admission::benchmarking::{setup_new_session, SessionCase};

    pub struct Pallet<T: Config>(core::marker::PhantomData<T>);
    pub trait Config: frame_system::Config {}
    impl Config for Runtime {}

    /// Worst Admission state for `case`, the same members as the current session set, all queued with keys.
    fn setup(case: SessionCase) {
        let new_index = setup_new_session::<Runtime>(case);
        let validators: Vec<AccountId> = madar_admission::Validators::<Runtime>::get().into_inner();
        let queued: Vec<(AccountId, SessionKeys)> = validators
            .iter()
            .map(|v| {
                (
                    v.clone(),
                    pallet_session::NextKeys::<Runtime>::get(v).expect("keys registered in setup"),
                )
            })
            .collect();
        pallet_session::Validators::<Runtime>::put(validators);
        pallet_session::QueuedKeys::<Runtime>::put(queued);
        pallet_session::QueuedChanged::<Runtime>::put(true);
        // `rotate_session` starts session CurrentIndex + 1 and plans CurrentIndex + 2 (= the Admission hook's index).
        pallet_session::CurrentIndex::<Runtime>::put(new_index - 2);
    }

    #[benchmarks]
    mod benches {
        use super::*;

        /// 999 of 1000 members exit, four full pools drawn.
        #[benchmark]
        fn rotate_session_exits() {
            setup(SessionCase::Exits);

            #[block]
            {
                pallet_session::Pallet::<Runtime>::rotate_session();
            }
        }

        /// 999 of 1000 members expire, four full pools drawn.
        #[benchmark]
        fn rotate_session_expiry() {
            setup(SessionCase::Expiry);

            #[block]
            {
                pallet_session::Pallet::<Runtime>::rotate_session();
            }
        }

        /// 1000 members stay (all in grace): 1000 keys loaded, historical trie of 1000, BABE/GRANDPA sets of 1000.
        #[benchmark]
        fn rotate_session_grace_full_set() {
            setup(SessionCase::GraceFullSet);

            #[block]
            {
                pallet_session::Pallet::<Runtime>::rotate_session();
            }

            assert_eq!(
                pallet_session::QueuedKeys::<Runtime>::get().len() as u32,
                1_000
            );
        }
    }
}
