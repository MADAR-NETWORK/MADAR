//! Admission benchmarks (FRAME v2) — B1 measurement only, compiled with `runtime-benchmarks`.
//!
//! Every benchmark builds the worst case that `weights.rs` assumes: `Validators` at `MaxValidators`, the open round
//! plus all `MAX_PENDING_POOLS` closed pools full (`MaxCandidatesPerRound` each), the target account last in every
//! list it is scanned from. `ban_key` and `dev_only_force_set_validators` are closed in the runtime
//! (`AdminOrigin = EnsureNever`), so their benchmarks run the body directly (`Pallet::ban`, used by equivocation
//! reports, and `set_validators_with_fresh_terms`). `new_session` is a hook, not a call: it is run directly in three
//! worst-case shapes (mass exits, mass expiry, full set in grace), each with four closed pools ready to draw.

use super::*;
use alloc::{vec, vec::Vec};
use frame_benchmarking::v2::*;
use frame_support::{
    pallet_prelude::*,
    traits::{EnsureOrigin, Hooks, Randomness},
};
use frame_system::RawOrigin;
use pallet_session::SessionManager;

const SEED: u32 = 0;

/// Value the benchmarks give BABE's `NextRandomness`, so the puzzle seed is fixed and known.
pub const BENCH_EPOCH_RANDOMNESS: [u8; 32] = [7u8; 32];

/// First nonce tried for the benchmark candidate (`account("candidate", 0, 0)`) under [`BENCH_EPOCH_RANDOMNESS`] with the
/// production puzzle (13 bits, Argon2id m=19456 KiB t=2). Found natively by `consensus/tests/bench_nonce_hint.rs`; if
/// the runtime parameters change the setup still finds a valid nonce by searching upward (only slower).
pub const NONCE_HINT: u64 = 9061;

fn acc<T: Config>(name: &'static str, i: u32) -> T::AccountId {
    account(name, i, SEED)
}

/// `Validators` = `n` filler accounts followed by `extra` (last), each with a running membership term.
pub fn set_validators<T: Config>(n: u32, extra: &[T::AccountId]) -> Vec<T::AccountId> {
    let mut v: Vec<T::AccountId> = (0..n).map(|i| acc::<T>("validator", i)).collect();
    v.extend(extra.iter().cloned());
    let until = CurrentSession::<T>::get().saturating_add(T::MembershipTermSessions::get());
    for a in &v {
        MembershipExpiry::<T>::insert(a, until);
    }
    Validators::<T>::put(BoundedVec::<_, T::MaxValidators>::truncate_from(v.clone()));
    v
}

/// A full candidate pool of distinct accounts (worst ranking output), `last` (if any) in the last slot.
fn full_pool<T: Config>(tag: &'static str, pool: u32, last: Option<&T::AccountId>) -> Pool<T> {
    let c = T::MaxCandidatesPerRound::get();
    let mut p: Vec<Candidate<T>> = (0..c)
        .map(|i| (acc::<T>(tag, pool * 100_000 + i), [0xffu8; 32]))
        .collect();
    if let (Some(w), Some(l)) = (last, p.last_mut()) {
        *l = (w.clone(), [0xffu8; 32]);
    }
    BoundedVec::truncate_from(p)
}

/// Open round (current seed) and all closed pools, every one full; `who` (if any) sits last in each.
pub fn fill_pools<T: Config>(who: Option<&T::AccountId>) {
    let seed = T::EpochRandomness::random(madar_protocol::ADMISSION_PUZZLE_DOMAIN).0;
    Round::<T>::put((seed, full_pool::<T>("round", 0, who)));
    let pending: Vec<(u32, u64, Pool<T>)> = (0..MAX_PENDING_POOLS as u32)
        .map(|i| (0u32, 0u64, full_pool::<T>("pending", i + 1, who)))
        .collect();
    Pending::<T>::put(BoundedVec::truncate_from(pending));
}

/// Smallest valid nonce at or above [`NONCE_HINT`] (setup only, never inside the measured part).
pub fn find_nonce<T: Config>(who: &T::AccountId, seed: &T::Hash) -> u64 {
    let mut nonce = NONCE_HINT;
    while !Pallet::<T>::solution_meets_difficulty(who, seed, nonce) {
        nonce += 1;
    }
    nonce
}

/// Worst-case shapes for the session hook.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SessionCase {
    /// All but one member asked to exit (max removals + events), four pools drawn.
    Exits,
    /// All but one member past term + grace (max removals + events), four pools drawn.
    Expiry,
    /// Every member stays but is in grace (one event each, full set), four pools drawn, winners refused (set full).
    GraceFullSet,
}

/// Builds the worst state for `new_session` and returns the index to pass to it.
///
/// Every member is an approved operator of itself and not vouched (two reads each in both operator-count loops) and has
/// session keys; the open round and four ready closed pools are full of distinct eligible candidates (session keys,
/// vouched by their own approved operator with room), enough fresh entropy, and a new parent VRF to mix.
pub fn setup_new_session<T: crate::BenchmarkHelper>(case: SessionCase) -> u32 {
    let max = T::MaxValidators::get();
    let term = T::MembershipTermSessions::get();
    let grace = T::RenewalGraceSessions::get();
    let new_index: u32 = term.saturating_add(grace).saturating_add(10);
    CurrentSession::<T>::put(new_index - 1);

    let validators: Vec<T::AccountId> = (0..max).map(|i| acc::<T>("validator", i)).collect();
    for (i, v) in validators.iter().enumerate() {
        ApprovedOperators::<T>::insert(v, T::MaxVotesPerOperator::get());
        T::register_session_keys(v);
        let expiry = match case {
            SessionCase::Exits => new_index + term,
            SessionCase::Expiry if i == 0 => new_index + term,
            SessionCase::Expiry => new_index - grace - 1,
            SessionCase::GraceFullSet => new_index - 1,
        };
        MembershipExpiry::<T>::insert(v, expiry);
        if case == SessionCase::Exits && i != 0 {
            PendingVoluntaryExit::<T>::insert(v, ());
        }
    }
    Validators::<T>::put(BoundedVec::<_, T::MaxValidators>::truncate_from(validators));

    let eligible_pool = |pool: u32| -> Pool<T> {
        let c = T::MaxCandidatesPerRound::get();
        let p: Vec<Candidate<T>> = (0..c)
            .map(|i| {
                let id = pool * 100_000 + i;
                let cand = acc::<T>("session_candidate", id);
                let op = acc::<T>("session_candidate_operator", id);
                T::register_session_keys(&cand);
                ApprovedOperators::<T>::insert(&op, T::MaxVotesPerOperator::get());
                NodeOperator::<T>::insert(&cand, op);
                (cand, [0xffu8; 32])
            })
            .collect();
        BoundedVec::truncate_from(p)
    };
    let seed = T::EpochRandomness::random(madar_protocol::ADMISSION_PUZZLE_DOMAIN).0;
    Round::<T>::put((seed, eligible_pool(0)));
    let pending: Vec<(u32, u64, Pool<T>)> = (0..MAX_PENDING_POOLS as u32)
        .map(|i| (0u32, 0u64, eligible_pool(i + 1)))
        .collect();
    Pending::<T>::put(BoundedVec::truncate_from(pending));
    EntropyCount::<T>::put(1_000_000u64);
    T::set_block_vrf(9);
    new_index
}

fn run_new_session<T: Config>(index: u32) -> Option<Vec<T::AccountId>> {
    <Pallet<T> as SessionManager<T::AccountId>>::new_session(index)
}

#[benchmarks(where T: crate::BenchmarkHelper)]
mod benchmarks {
    use super::*;

    /// Full candidacy path: vouched candidate, Argon2id verification, full pool (worst entry replaced), full validator
    /// set scanned.
    #[benchmark]
    fn submit_admission_solution() -> Result<(), BenchmarkError> {
        T::set_epoch_randomness(BENCH_EPOCH_RANDOMNESS);
        let who = acc::<T>("candidate", 0);
        let op = acc::<T>("operator", 0);
        ApprovedOperators::<T>::insert(&op, T::MaxVotesPerOperator::get());
        NodeOperator::<T>::insert(&who, op);
        set_validators::<T>(T::MaxValidators::get(), &[]);
        let seed = T::EpochRandomness::random(madar_protocol::ADMISSION_PUZZLE_DOMAIN).0;
        Round::<T>::put((seed, full_pool::<T>("round", 0, None)));
        let nonce = find_nonce::<T>(&who, &seed);

        #[extrinsic_call]
        _(RawOrigin::Signed(who.clone()), nonce);

        assert!(Pallet::<T>::candidates().contains(&who));
        Ok(())
    }

    /// Most expensive early rejection (before Argon2): full validator set scanned, then the full pool scanned with the
    /// caller in the last slot (`AlreadyAdmittedThisRound`).
    #[benchmark]
    fn submit_admission_rejected_early() -> Result<(), BenchmarkError> {
        let who = acc::<T>("candidate", 0);
        let op = acc::<T>("operator", 0);
        ApprovedOperators::<T>::insert(&op, T::MaxVotesPerOperator::get());
        NodeOperator::<T>::insert(&who, op);
        set_validators::<T>(T::MaxValidators::get(), &[]);
        let seed = T::EpochRandomness::random(madar_protocol::ADMISSION_PUZZLE_DOMAIN).0;
        Round::<T>::put((seed, full_pool::<T>("round", 0, Some(&who))));
        let result;

        #[block]
        {
            result =
                Pallet::<T>::submit_admission_solution(RawOrigin::Signed(who.clone()).into(), 0);
        }

        assert!(result.is_err());
        Ok(())
    }

    #[benchmark]
    fn voluntary_exit() -> Result<(), BenchmarkError> {
        let who = acc::<T>("leaving", 0);
        set_validators::<T>(T::MaxValidators::get() - 1, &[who.clone()]);

        #[extrinsic_call]
        _(RawOrigin::Signed(who.clone()));

        assert!(PendingVoluntaryExit::<T>::contains_key(&who));
        Ok(())
    }

    /// `ban_key` body (`Pallet::ban`, also the equivocation path): member last in a full set and in every full pool.
    #[benchmark]
    fn ban_key() -> Result<(), BenchmarkError> {
        let who = acc::<T>("offender", 0);
        set_validators::<T>(T::MaxValidators::get() - 1, &[who.clone()]);
        fill_pools::<T>(Some(&who));
        PendingVoluntaryExit::<T>::insert(&who, ());

        #[block]
        {
            Pallet::<T>::ban(&who);
        }

        assert!(BannedKeys::<T>::contains_key(&who));
        assert!(!Validators::<T>::get().contains(&who));
        Ok(())
    }

    /// `dev_only_force_set_validators` body: a full old set fully replaced by `n` new members.
    #[benchmark]
    fn dev_only_force_set_validators(
        n: Linear<1, { T::MaxValidators::get() }>,
    ) -> Result<(), BenchmarkError> {
        set_validators::<T>(T::MaxValidators::get(), &[]);
        let new: Vec<T::AccountId> = (0..n).map(|i| acc::<T>("new_validator", i)).collect();

        #[block]
        {
            let bounded: BoundedVec<T::AccountId, T::MaxValidators> =
                new.try_into().expect("n <= MaxValidators");
            Pallet::<T>::set_validators_with_fresh_terms(bounded);
        }

        assert_eq!(Validators::<T>::get().len() as u32, n);
        Ok(())
    }

    /// Session hook, mass voluntary exits (999 of 1000 leave) + four full pools drawn + open round closed.
    #[benchmark]
    fn new_session() -> Result<(), BenchmarkError> {
        let index = setup_new_session::<T>(SessionCase::Exits);
        let out;

        #[block]
        {
            out = run_new_session::<T>(index);
        }

        assert!(out.map_or(0, |v| v.len()) > 1);
        Ok(())
    }

    /// Session hook, mass expiry (999 of 1000 past term + grace) + four full pools drawn.
    #[benchmark]
    fn new_session_expiry() -> Result<(), BenchmarkError> {
        let index = setup_new_session::<T>(SessionCase::Expiry);
        let out;

        #[block]
        {
            out = run_new_session::<T>(index);
        }

        assert!(out.map_or(0, |v| v.len()) > 1);
        Ok(())
    }

    /// Session hook, full set with every member in grace + four full pools drawn (winners refused: set full).
    #[benchmark]
    fn new_session_grace_full_set() -> Result<(), BenchmarkError> {
        let index = setup_new_session::<T>(SessionCase::GraceFullSet);
        let out;

        #[block]
        {
            out = run_new_session::<T>(index);
        }

        assert_eq!(out.map_or(0, |v| v.len()) as u32, T::MaxValidators::get());
        Ok(())
    }

    /// Per-block entropy accumulator with a fresh parent VRF (the writing branch).
    #[benchmark]
    fn on_initialize() -> Result<(), BenchmarkError> {
        T::set_block_vrf(1);
        let before = EntropyCount::<T>::get();

        #[block]
        {
            Pallet::<T>::on_initialize(1u32.into());
        }

        assert_eq!(EntropyCount::<T>::get(), before + 1);
        Ok(())
    }

    /// Lower a cap to 0 with the operator's own seat and its vouched node live: full set scanned (`NodeOperator` read
    /// per member), both evicted from the set and from every full pool.
    #[benchmark]
    fn approve_operator() -> Result<(), BenchmarkError> {
        let op = acc::<T>("operator", 0);
        let node = acc::<T>("operator_node", 0);
        set_validators::<T>(T::MaxValidators::get() - 2, &[op.clone(), node.clone()]);
        ApprovedOperators::<T>::insert(&op, T::MaxVotesPerOperator::get());
        NodeOperator::<T>::insert(&node, op.clone());
        OperatorNodes::<T>::insert(&op, BoundedVec::truncate_from(vec![node.clone()]));
        fill_pools::<T>(Some(&node));
        let origin = T::OperatorApprovalOrigin::try_successful_origin()
            .map_err(|_| BenchmarkError::Weightless)?;

        #[extrinsic_call]
        _(origin as T::RuntimeOrigin, op.clone(), 0u32);

        assert_eq!(ApprovedOperators::<T>::get(&op), Some(0));
        assert!(!Validators::<T>::get().contains(&node));
        Ok(())
    }

    /// Revoke an operator holding its own seat and a full vouch list, all live and in every full pool.
    #[benchmark]
    fn revoke_operator_approval() -> Result<(), BenchmarkError> {
        let op = acc::<T>("operator", 0);
        let node = acc::<T>("operator_node", 0);
        set_validators::<T>(T::MaxValidators::get() - 2, &[op.clone(), node.clone()]);
        ApprovedOperators::<T>::insert(&op, T::MaxVotesPerOperator::get());
        NodeOperator::<T>::insert(&node, op.clone());
        OperatorNodes::<T>::insert(&op, BoundedVec::truncate_from(vec![node.clone()]));
        fill_pools::<T>(Some(&node));
        let origin = T::OperatorApprovalOrigin::try_successful_origin()
            .map_err(|_| BenchmarkError::Weightless)?;

        #[extrinsic_call]
        _(origin as T::RuntimeOrigin, op.clone());

        assert!(!ApprovedOperators::<T>::contains_key(&op));
        assert!(!Validators::<T>::get().contains(&op));
        Ok(())
    }

    /// Vouch with a full validator set scanned for the operator's own seat.
    #[benchmark]
    fn vouch_node() -> Result<(), BenchmarkError> {
        let op = acc::<T>("operator", 0);
        let node = acc::<T>("operator_node", 0);
        set_validators::<T>(T::MaxValidators::get(), &[]);
        ApprovedOperators::<T>::insert(&op, T::MaxVotesPerOperator::get());

        #[extrinsic_call]
        _(RawOrigin::Signed(op.clone()), node.clone());

        assert_eq!(NodeOperator::<T>::get(&node), Some(op));
        Ok(())
    }

    /// Revoke a vouch for a node last in a full set and in every full pool.
    #[benchmark]
    fn revoke_vouch() -> Result<(), BenchmarkError> {
        let op = acc::<T>("operator", 0);
        let node = acc::<T>("operator_node", 0);
        set_validators::<T>(T::MaxValidators::get() - 1, &[node.clone()]);
        ApprovedOperators::<T>::insert(&op, T::MaxVotesPerOperator::get());
        NodeOperator::<T>::insert(&node, op.clone());
        OperatorNodes::<T>::insert(&op, BoundedVec::truncate_from(vec![node.clone()]));
        fill_pools::<T>(Some(&node));

        #[extrinsic_call]
        _(RawOrigin::Signed(op.clone()), node.clone());

        assert!(!NodeOperator::<T>::contains_key(&node));
        assert!(!Validators::<T>::get().contains(&node));
        Ok(())
    }
}
