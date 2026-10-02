//! Admission weights — based on **the actual work cost of each path**, scaling with the set sizes (not constants).
//!
//! **Argon2 (actual measurement):** `m=19456 KiB, t=2` ≈ 14 ms native (≈358–491 ns/KiB-pass) and inside WASM ≈ 35–37 ms
//! (a WASM benchmark live test). The constant `ARGON2_PS_PER_KIB_PASS` (2500 ns) ≈ 5–7× native and ≈3× WASM
//! as measured on x86; it is recalibrated on ARM64 (D23) before the public testnet.
//!
//! **Storage (path-by-path analysis, see every `*_ops` function):** every read/write is listed or covered by an upper bound. The cost
//! tied to a list size (validators up to `MaxValidators`, candidate sets up to `MaxCandidatesPerRound` × 5)
//! is added with a fixed maximum, not with an expected actual size. The tests in `consensus/tests/weight_accounting.rs` measure the number
//! of keys actually written in the worst case and confirm it is ≤ what these functions assume.

use core::marker::PhantomData;
use frame_support::{traits::Get, weights::Weight};

/// Picoseconds (ref_time) per Argon2id KiB-pass — see the calibration above.
pub const ARGON2_PS_PER_KIB_PASS: u64 = 2_500_000;
/// The cost of scanning/comparing one list element (32 bytes + decoding), with a conservative bound (0.5 µs).
pub const SCAN_PS_PER_ITEM: u64 = 500_000;
/// The cost of hashing/sorting one element in the draw (ordering) — conservative.
pub const SORT_PS_PER_ITEM: u64 = 5_000_000;
/// Additional proof size per single storage key.
pub const POV_PER_KEY: u64 = 200;
/// The maximum number of pending sets + the open round.
pub const POOLS: u64 = 5;

/// The assumed number of storage operations of a path: (reads, writes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ops {
    pub reads: u64,
    pub writes: u64,
}

/// Weights of this pallet's calls and hooks.
pub trait WeightInfo {
    /// The full path: Argon2id verification + every read/write of the call's worst branches.
    fn submit_admission_solution() -> Weight;
    /// Early rejection before Argon2 (banned/duplicate/already renewed): reads and list scans only. Refunded as the actual weight.
    fn submit_admission_rejected_early() -> Weight;
    fn voluntary_exit() -> Weight;
    fn ban_key() -> Weight;
    /// `n` = the number of validators in the request.
    fn dev_only_force_set_validators(n: u32) -> Weight;
    /// The `new_session` hook (runs inside `Session::on_initialize`; registered as mandatory).
    fn new_session() -> Weight;
    /// The per-block entropy accumulator.
    fn on_initialize() -> Weight;
    /// **D47** — approve/change an operator cap (one write, no scan).
    fn approve_operator() -> Weight;
    /// **D47** — revoke an operator approval: evicts up to `MaxVotesPerOperator` nodes (worst case).
    fn revoke_operator_approval() -> Weight;
    /// **D47** — vouch for one node by its operator.
    fn vouch_node() -> Weight;
    /// **D47** — withdraw the vouch for one node (including evicting it from every set).
    fn revoke_vouch() -> Weight;
}

/// The actual implementation: the Argon2 cost from the `Config` parameters + the storage cost from `DbWeight` and the set sizes.
pub struct ArgonMeteredWeight<T>(PhantomData<T>);

impl<T: crate::Config> ArgonMeteredWeight<T> {
    fn v() -> u64 {
        T::MaxValidators::get() as u64
    }
    fn c() -> u64 {
        T::MaxCandidatesPerRound::get() as u64
    }
    /// The maximum encoded size of `Validators`.
    fn validators_pov() -> u64 {
        Self::v().saturating_mul(32).saturating_add(8)
    }
    /// The size of one candidate set (account 32 + output 32 per candidate).
    fn pool_pov() -> u64 {
        Self::c().saturating_mul(64).saturating_add(8)
    }
    fn db(ops: Ops) -> Weight {
        T::DbWeight::get().reads_writes(ops.reads, ops.writes)
    }

    /// `submit_admission_solution` (worst branch): reads {Banned, CurrentSession, Validators, MembershipExpiry,
    /// NextRandomness, Round, Events} and writes {MembershipExpiry|Round, Events, EventCount, topics}.
    pub fn submit_ops() -> Ops {
        Ops {
            reads: 9,
            writes: 5,
        }
    }
    /// Early rejection: {Banned, CurrentSession, Validators, MembershipExpiry, NextRandomness, Round}.
    pub fn early_ops() -> Ops {
        Ops {
            reads: 8,
            writes: 0,
        }
    }
    /// `voluntary_exit`: read `Validators` (scan) + write `PendingVoluntaryExit`.
    pub fn exit_ops() -> Ops {
        Ops {
            reads: 1,
            writes: 1,
        }
    }
    /// `ban`: reads {Validators, Round, Pending}, writes {Banned, Validators, MembershipExpiry,
    /// PendingVoluntaryExit, Round, Pending}.
    pub fn ban_ops() -> Ops {
        Ops {
            reads: 3,
            writes: 6,
        }
    }
    /// `dev_only_force_set_validators(n)`: `Validators` is read and written, and each member's validity is removed/written.
    pub fn force_set_ops(n: u64) -> Ops {
        Ops {
            reads: 1,
            writes: 1 + Self::v() + n,
        }
    }
    /// `new_session`: reads {Validators, Round, Pending, CurrentSession/EntropyCount, randomness ×3} + per member
    /// {exit, validity} + per candidate in every set {Banned, NextKeys}; writes {Validators, Pending, Round} +
    /// per departing member {exit, validity} + per member event (grace/expiry/exit) 3 keys + for the accepted {validity + event}.
    pub fn new_session_ops() -> Ops {
        let v = Self::v();
        let c = Self::c();
        let cap = T::AdmissionCapPerRound::get() as u64;
        Ops {
            reads: 12 + 2 * v + 2 * c * POOLS,
            writes: 6 + 2 * v + 3 * v + 4 * cap.saturating_add(POOLS * cap),
        }
    }
    /// `on_initialize`: reads {AuthorVrfRandomness, Accumulator, Last, Count} and writes {Accumulator, Count, Last}.
    pub fn on_initialize_ops() -> Ops {
        Ops {
            reads: 4,
            writes: 3,
        }
    }
    /// **D47** `approve_operator` (worst case: lowers the cap below `MaxVotesPerOperator` live nodes):
    /// read `Validators` + scan every node to match its operator (`NodeOperator`), then for every excess node a full
    /// eviction (the same as `revoke_operator_ops`, without `BannedKeys`), and write `ApprovedOperators` itself.
    pub fn approve_operator_ops() -> Ops {
        let n = T::MaxVotesPerOperator::get() as u64;
        Ops {
            reads: 1 + Self::v(),
            writes: 1 + n * 5,
        }
    }
    /// **D47** `revoke_operator_approval` (worst case: `MaxVotesPerOperator` bound nodes): two reads of
    /// `ApprovedOperators`/`OperatorNodes` + a full eviction per node (about the cost of `ban` without `BannedKeys`).
    pub fn revoke_operator_ops() -> Ops {
        let n = T::MaxVotesPerOperator::get() as u64;
        Ops {
            reads: 2,
            writes: 2 + n * 5,
        }
    }
    /// **D47** `vouch_node`: reads {ApprovedOperators, NodeOperator, OperatorNodes}, writes
    /// {OperatorNodes, NodeOperator}.
    pub fn vouch_node_ops() -> Ops {
        Ops {
            reads: 3,
            writes: 2,
        }
    }
    /// **D47** `revoke_vouch`: read `NodeOperator` + a full eviction (~5 writes, like `ban` without `BannedKeys`).
    pub fn revoke_vouch_ops() -> Ops {
        Ops {
            reads: 1,
            writes: 2 + 5,
        }
    }
}

impl<T: crate::Config> WeightInfo for ArgonMeteredWeight<T> {
    fn submit_admission_solution() -> Weight {
        let blocks =
            (T::ArgonMemoryCostKib::get() as u64).saturating_mul(T::ArgonTimeCost::get() as u64);
        let argon_ps = blocks.saturating_mul(ARGON2_PS_PER_KIB_PASS);
        // Scan Validators (contains) + scan the set (any + the worst element).
        let scans = (Self::v() + 3 * Self::c()).saturating_mul(SCAN_PS_PER_ITEM);
        Weight::from_parts(
            argon_ps
                .saturating_add(10_000_000_000)
                .saturating_add(scans),
            Self::validators_pov()
                .saturating_add(Self::pool_pov())
                .saturating_add(8 * POV_PER_KEY * 4),
        )
        .saturating_add(Self::db(Self::submit_ops()))
    }

    fn submit_admission_rejected_early() -> Weight {
        let scans = (Self::v() + Self::c()).saturating_mul(SCAN_PS_PER_ITEM);
        Weight::from_parts(
            50_000_000u64.saturating_add(scans),
            Self::validators_pov()
                .saturating_add(Self::pool_pov())
                .saturating_add(8 * POV_PER_KEY),
        )
        .saturating_add(Self::db(Self::early_ops()))
    }

    fn voluntary_exit() -> Weight {
        Weight::from_parts(
            50_000_000u64.saturating_add(Self::v().saturating_mul(SCAN_PS_PER_ITEM)),
            Self::validators_pov().saturating_add(2 * POV_PER_KEY),
        )
        .saturating_add(Self::db(Self::exit_ops()))
    }

    fn ban_key() -> Weight {
        let scans = (Self::v() + Self::c() * POOLS).saturating_mul(SCAN_PS_PER_ITEM);
        Weight::from_parts(
            // B1 2026-09-21: 100 release samples at maximum occupancy reached
            // 385 us native. Reserve >= 5x that CPU time before DB charges;
            // ARM64/WASM calibration is still required (see B1 evidence).
            2_000_000_000u64.saturating_add(scans),
            Self::validators_pov()
                .saturating_add(POOLS * Self::pool_pov())
                .saturating_add(6 * POV_PER_KEY),
        )
        .saturating_add(Self::db(Self::ban_ops()))
    }

    fn dev_only_force_set_validators(n: u32) -> Weight {
        let n = n as u64;
        Weight::from_parts(
            50_000_000u64.saturating_add((Self::v() + n).saturating_mul(SCAN_PS_PER_ITEM)),
            Self::validators_pov()
                .saturating_mul(2)
                .saturating_add((Self::v() + n) * POV_PER_KEY),
        )
        .saturating_add(Self::db(Self::force_set_ops(n)))
    }

    fn new_session() -> Weight {
        let v = Self::v();
        let c = Self::c();
        // Scan departing/staying members (quadratic in `contains` during filtering) + sort the candidates.
        let quad = v.saturating_mul(16).saturating_mul(SCAN_PS_PER_ITEM); // O(V log V) (BTreeSet), conservative
        let scans = (v + POOLS * c).saturating_mul(SCAN_PS_PER_ITEM);
        let sorts = (POOLS * c).saturating_mul(SORT_PS_PER_ITEM);
        Weight::from_parts(
            100_000_000u64
                .saturating_add(quad)
                .saturating_add(scans)
                .saturating_add(sorts),
            Self::validators_pov()
                .saturating_add(POOLS * Self::pool_pov())
                .saturating_add((2 * v + 2 * c * POOLS) * POV_PER_KEY),
        )
        .saturating_add(Self::db(Self::new_session_ops()))
    }

    fn on_initialize() -> Weight {
        Weight::from_parts(30_000_000, 256).saturating_add(Self::db(Self::on_initialize_ops()))
    }

    // D47 — operator caps for identity-duplication resistance. Conservative placeholder weights (the same pattern as
    // the Argon2/difficulty above), awaiting actual benchmarking before the public testnet.
    fn approve_operator() -> Weight {
        let n = T::MaxVotesPerOperator::get() as u64;
        let scans = (Self::v() + n).saturating_mul(SCAN_PS_PER_ITEM.saturating_mul(2));
        Weight::from_parts(
            30_000_000u64.saturating_add(scans),
            (Self::v() + n * 6 + 8) * POV_PER_KEY,
        )
        .saturating_add(Self::db(Self::approve_operator_ops()))
    }

    fn revoke_operator_approval() -> Weight {
        let n = T::MaxVotesPerOperator::get() as u64;
        let scans = n.saturating_mul(SCAN_PS_PER_ITEM.saturating_mul(4));
        Weight::from_parts(
            50_000_000u64.saturating_add(scans),
            (n * 6 + 8) * POV_PER_KEY,
        )
        .saturating_add(Self::db(Self::revoke_operator_ops()))
    }

    fn vouch_node() -> Weight {
        Weight::from_parts(30_000_000, 8 * POV_PER_KEY)
            .saturating_add(Self::db(Self::vouch_node_ops()))
    }

    fn revoke_vouch() -> Weight {
        let scans = (Self::v() + Self::c() * POOLS).saturating_mul(SCAN_PS_PER_ITEM);
        Weight::from_parts(
            50_000_000u64.saturating_add(scans),
            Self::validators_pov().saturating_add(8 * POV_PER_KEY),
        )
        .saturating_add(Self::db(Self::revoke_vouch_ops()))
    }
}
