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
use alloc::{boxed::Box, vec, vec::Vec};
use frame_support::traits::Get;

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
    [madar_session_keys, SessionKeysBench::<Runtime>]
    [madar_committee, CommitteeBench::<Runtime>]
);

use committee::Pallet as CommitteeBench;
use frame_benchmarking::baseline::Pallet as BaselineBench;
use frame_system_benchmarking::Pallet as SystemBench;
use session_keys::Pallet as SessionKeysBench;
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

        /// spec 9 — the penalty of a proven equivocation (`crate::ban_and_disable`), worst case for the disabling scan: 1000
        /// members in the active session set, `floor((n-1)/3) - 1` of them already disabled at the front, all the others
        /// already gone from Admission except one author just before the offender (so every member is looked up before an
        /// author is found), the offender last and in every full pool. (`Pallet::ban` with a full set is the separate
        /// `madar_admission::ban` benchmark; both are declared, see `sdk_weights::equivocation_penalty`.)
        #[benchmark]
        fn ban_and_disable() {
            let max: u32 = <<Runtime as madar_admission::Config>::MaxValidators as Get<u32>>::get();
            let offender: AccountId = frame_benchmarking::account("offender", 0, 0);
            let mut members: Vec<AccountId> = (0..max - 1)
                .map(|i| frame_benchmarking::account("validator", i, 0))
                .collect();
            let author = members.last().cloned().expect("max > 1");
            members.push(offender.clone());
            madar_admission::benchmarking::set_validators::<Runtime>(
                0,
                &[author, offender.clone()],
            );
            madar_admission::benchmarking::fill_pools::<Runtime>(Some(&offender));
            pallet_session::Validators::<Runtime>::put(members);
            let limit = pallet_session::disabling::UpToLimitDisablingStrategy::<3>::disable_limit(
                max as usize,
            ) as u32;
            let disabled: Vec<(u32, sp_staking::offence::OffenceSeverity)> = (0..limit - 1)
                .map(|i| {
                    (
                        i,
                        sp_staking::offence::OffenceSeverity(sp_runtime::Perbill::one()),
                    )
                })
                .collect();
            pallet_session::DisabledValidators::<Runtime>::put(disabled);

            #[block]
            {
                crate::ban_and_disable(&offender);
            }

            assert!(pallet_session::Pallet::<Runtime>::disabled_validators().contains(&(max - 1)));
        }
    }
}

/// spec 9 — `pallet_session` `set_keys`/`purge_keys` measured on MADAR's runtime (the SDK benchmarks need
/// `pallet_staking`, which MADAR does not have). Keys and ownership proofs are made by the runtime itself in the
/// benchmark keystore, exactly as `author_rotateKeysWithOwner` does on a node.
pub mod session_keys {
    use super::*;
    use frame_benchmarking::v2::*;
    use parity_scale_codec::Encode;

    pub struct Pallet<T: Config>(core::marker::PhantomData<T>);
    pub trait Config: frame_system::Config {}
    impl Config for Runtime {}

    /// A funded-less account that can hold session keys (one provider, as after its first admission transaction).
    fn holder(i: u32) -> AccountId {
        let who: AccountId = frame_benchmarking::account("session_holder", i, 0);
        frame_system::Pallet::<Runtime>::inc_providers(&who);
        who
    }

    fn keys_for(who: &AccountId) -> (SessionKeys, Vec<u8>) {
        let generated = SessionKeys::generate(&who.encode(), None);
        (generated.keys, generated.proof.encode())
    }

    #[benchmarks]
    mod benches {
        use super::*;

        /// First registration: account gets its consumer reference, two `KeyOwner` entries, `NextKeys`.
        #[benchmark]
        fn set_keys_first() {
            let who = holder(0);
            let (keys, proof) = keys_for(&who);

            #[block]
            {
                pallet_session::Pallet::<Runtime>::set_keys(
                    RuntimeOrigin::signed(who.clone()),
                    keys,
                    proof,
                )
                .expect("set_keys");
            }

            assert!(pallet_session::NextKeys::<Runtime>::contains_key(&who));
        }

        /// Replacement (key rotation): two old `KeyOwner` entries removed, two new written.
        #[benchmark]
        fn set_keys_replace() {
            let who = holder(1);
            let (old, old_proof) = keys_for(&who);
            pallet_session::Pallet::<Runtime>::set_keys(
                RuntimeOrigin::signed(who.clone()),
                old,
                old_proof,
            )
            .expect("first keys");
            let (keys, proof) = keys_for(&who);

            #[block]
            {
                pallet_session::Pallet::<Runtime>::set_keys(
                    RuntimeOrigin::signed(who.clone()),
                    keys.clone(),
                    proof,
                )
                .expect("set_keys");
            }

            assert_eq!(pallet_session::NextKeys::<Runtime>::get(&who), Some(keys));
        }

        #[benchmark]
        fn purge_keys() {
            let who = holder(2);
            let (keys, proof) = keys_for(&who);
            pallet_session::Pallet::<Runtime>::set_keys(
                RuntimeOrigin::signed(who.clone()),
                keys,
                proof,
            )
            .expect("keys");

            #[block]
            {
                pallet_session::Pallet::<Runtime>::purge_keys(RuntimeOrigin::signed(who.clone()))
                    .expect("purge_keys");
            }

            assert!(!pallet_session::NextKeys::<Runtime>::contains_key(&who));
        }
    }
}

/// spec 9 — `pallet_collective` `vote`/`close_*` with MADAR's fixed committee of **3** (the SDK benchmarks start at
/// 4+ members and fail here). `p` = open motions (up to `MaxProposals` = 16), `b` = encoded proposal length.
pub mod committee {
    use super::*;
    use frame_benchmarking::v2::*;
    use parity_scale_codec::Encode;
    use sp_runtime::traits::Hash;

    pub struct Pallet<T: Config>(core::marker::PhantomData<T>);
    pub trait Config: frame_system::Config {}
    impl Config for Runtime {}

    type Collective = pallet_collective::Pallet<Runtime, UpgradeCommitteeInstance>;
    const MAX_PROPOSALS: u32 = 16;
    const MAX_BYTES: u32 = 1_024;

    fn members() -> Vec<AccountId> {
        use frame_support::traits::ChangeMembers;
        let m: Vec<AccountId> = (0..3)
            .map(|i| frame_benchmarking::account("member", i, 0))
            .collect();
        let mut sorted = m.clone();
        sorted.sort();
        let old = pallet_collective::Members::<Runtime, UpgradeCommitteeInstance>::get();
        Collective::set_members_sorted(&sorted, &old);
        sorted
    }

    /// `p - 1` other open motions, then the target motion (a `remark` of `b` bytes); returns (hash, index, call).
    fn motions(
        m: &[AccountId],
        p: u32,
        b: u32,
    ) -> (<Runtime as frame_system::Config>::Hash, u32, RuntimeCall) {
        for i in 0..p.saturating_sub(1) {
            let call = RuntimeCall::System(frame_system::Call::remark {
                remark: (i + 1_000_000).to_le_bytes().to_vec(),
            });
            Collective::do_propose_proposed(m[0].clone(), 2, Box::new(call), u32::MAX)
                .expect("motion");
        }
        let call = RuntimeCall::System(frame_system::Call::remark {
            remark: vec![7u8; b as usize],
        });
        let hash = <Runtime as frame_system::Config>::Hashing::hash_of(&call);
        Collective::do_propose_proposed(m[0].clone(), 2, Box::new(call.clone()), u32::MAX)
            .expect("target motion");
        let index =
            pallet_collective::ProposalCount::<Runtime, UpgradeCommitteeInstance>::get() - 1;
        (hash, index, call)
    }

    #[benchmarks]
    mod benches {
        use super::*;

        /// A member flips an existing vote (aye → nay): the larger branch (removes from one list, adds to the other).
        #[benchmark]
        fn vote(p: Linear<1, MAX_PROPOSALS>) {
            let m = members();
            let (hash, index, _) = motions(&m, p, 4);
            Collective::do_vote(m[1].clone(), hash, index, true).expect("first vote");

            #[block]
            {
                Collective::vote(RuntimeOrigin::signed(m[1].clone()), hash, index, false)
                    .expect("vote");
            }
        }

        /// Two nays out of three: rejected early.
        #[benchmark]
        fn close_early_disapproved(p: Linear<1, MAX_PROPOSALS>) {
            let m = members();
            let (hash, index, call) = motions(&m, p, 4);
            Collective::do_vote(m[0].clone(), hash, index, false).expect("vote");
            Collective::do_vote(m[1].clone(), hash, index, false).expect("vote");
            let len = call.encoded_size() as u32;

            #[block]
            {
                Collective::close(
                    RuntimeOrigin::signed(m[2].clone()),
                    hash,
                    index,
                    Weight::MAX,
                    len,
                )
                .expect("close");
            }

            assert!(!pallet_collective::ProposalOf::<
                Runtime,
                UpgradeCommitteeInstance,
            >::contains_key(hash));
        }

        /// Two ayes out of three: approved early and executed (a `remark` of `b` bytes).
        #[benchmark]
        fn close_early_approved(b: Linear<2, MAX_BYTES>, p: Linear<1, MAX_PROPOSALS>) {
            let m = members();
            let (hash, index, call) = motions(&m, p, b);
            Collective::do_vote(m[0].clone(), hash, index, true).expect("vote");
            Collective::do_vote(m[1].clone(), hash, index, true).expect("vote");
            let len = call.encoded_size() as u32;

            #[block]
            {
                Collective::close(
                    RuntimeOrigin::signed(m[2].clone()),
                    hash,
                    index,
                    Weight::MAX,
                    len,
                )
                .expect("close");
            }

            assert!(!pallet_collective::ProposalOf::<
                Runtime,
                UpgradeCommitteeInstance,
            >::contains_key(hash));
        }

        /// One aye, no other vote, after the motion's end: the default vote (no prime ⇒ nay) rejects it.
        #[benchmark]
        fn close_disapproved(p: Linear<1, MAX_PROPOSALS>) {
            let m = members();
            let (hash, index, call) = motions(&m, p, 4);
            Collective::do_vote(m[0].clone(), hash, index, true).expect("vote");
            let len = call.encoded_size() as u32;
            let end = frame_system::Pallet::<Runtime>::block_number() + 901;
            frame_system::Pallet::<Runtime>::set_block_number(end);

            #[block]
            {
                Collective::close(
                    RuntimeOrigin::signed(m[2].clone()),
                    hash,
                    index,
                    Weight::MAX,
                    len,
                )
                .expect("close");
            }

            assert!(!pallet_collective::ProposalOf::<
                Runtime,
                UpgradeCommitteeInstance,
            >::contains_key(hash));
        }
    }
}
