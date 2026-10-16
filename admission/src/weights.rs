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
pub const ARGON2_PS_PER_KIB_PASS: u64 = 3_000_000; // spec 9 final (2026-10-16): 2.5 -> 3.0 us, 59.3 ms measured (spec9-final-weights.md)
/// The cost of scanning/comparing one list element (32 bytes + decoding), with a conservative bound (0.5 µs).
pub const SCAN_PS_PER_ITEM: u64 = 500_000;
/// The cost of hashing/sorting one element in the draw (ordering) — conservative.
pub const SORT_PS_PER_ITEM: u64 = 5_000_000;
/// Additional proof size per single storage key.
pub const POV_PER_KEY: u64 = 200;
/// The maximum number of pending sets + the open round.
pub const POOLS: u64 = 5;
/// B1 (2026-10-15, WASM on x86): `new_session` cost per validator. The worst measured shape (1000 members, all in grace)
/// = 25.4 ms median and 27.3 ms max => 55 µs per member covers >= 2× the measured max (was 8 µs: 16 × `SCAN_PS_PER_ITEM`).
pub const NEW_SESSION_PS_PER_VALIDATOR: u64 = 55_000_000;
/// B1: `approve_operator` reads `NodeOperator` for every validator (1000) — 1.86 ms measured => 4 µs per item (>= 2×).
pub const OPERATOR_SCAN_PS_PER_ITEM: u64 = 7_000_000; // spec 9 final: 4 -> 7 us (3.72 ms measured for 1000)

/// B1: the proof actually recorded exceeds the size of the encoded values by the trie nodes (up to ~10%). Margin of 1/8 above the estimate.
pub const fn with_trie_margin(pov: u64) -> u64 {
    pov.saturating_add(pov / 8)
}

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
    /// The ban body (`Pallet::ban`) — not a call (`ban_key` was removed in spec 9); included in the weight of the Equivocation report in the Runtime.
    fn ban() -> Weight;
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
    /// spec 9 — `set_admission_cap_per_round` and `set_max_votes_per_operator` (read and write one value + event).
    fn set_admission_param() -> Weight;
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
    /// NextRandomness, NodeOperator ×2, Round, Events, MaxVotesPerOperator, SolutionAttempts} and writes
    /// {MembershipExpiry|Round, SolutionAttempts, Events, EventCount, topics}.
    pub fn submit_ops() -> Ops {
        Ops {
            reads: 13,
            writes: 6,
        }
    }
    /// Early refusal: {Banned, CurrentSession, Validators, MembershipExpiry, NextRandomness, NodeOperator ×2, Round,
    /// MaxVotesPerOperator, SolutionAttempts} (spec 9: the attempt limit is checked before Argon2), + `System::Account` (spec 9, independent
    /// review #6: an account with no references gets a success with an event, so the event writes are counted too).
    pub fn early_ops() -> Ops {
        Ops {
            reads: 13,
            writes: 3,
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
            writes: 7,
        } // spec 9 (review #3): + `RenewalAttempts` removed with the seat
    }
    /// `new_session`: reads {Validators, Round, Pending, CurrentSession/EntropyCount, randomness ×3} + per member
    /// {exit, validity} + per candidate in every set {Banned, NextKeys}; writes {Validators, Pending, Round} +
    /// per departing member {exit, validity} + per member event (grace/expiry/exit) 3 keys + for the accepted {validity + event} + an event per unvouched candidate.
    pub fn new_session_ops() -> Ops {
        let v = Self::v();
        let c = Self::c();
        // spec 9: winners per rotation ≤ the round cap (all pools together) ≤ the hard limit; the old formula (cap per pool)
        // is kept as a conservative upper bound.
        let cap = T::AdmissionCapPerRoundLimit::get() as u64;
        Ops {
            // per staying validator also {BannedKeys, NodeOperator, ApprovedOperators} (operator counts, twice: before the
            // draw and for the cap check) and per candidate {ApprovedOperators}; per winner {NodeOperator, ApprovedOperators}
            reads: 13 + 2 * v + 6 * v + 4 * c * POOLS + 2 * cap.saturating_add(POOLS * cap),
            writes: 6 + 3 * v + 3 * v + 4 * cap.saturating_add(POOLS * cap) + c * POOLS,
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
    ///
    /// B1: up to `n + 1` evicted (the vouched nodes **and the operator's own seat**, D50). Per evicted: reads {Validators,
    /// OperatorNodes, Round, Pending} and writes {NodeOperator, OperatorNodes, Validators, MembershipExpiry,
    /// PendingVoluntaryExit, Round, Pending}. Measured (n = 1, two evicted): 1003 reads / 11 writes.
    pub fn approve_operator_ops() -> Ops {
        let evicted = T::MaxVotesPerOperatorLimit::get() as u64 + 1;
        // spec 9: + read `MaxVotesPerOperator`.
        Ops {
            reads: 2 + Self::v() + 4 * evicted,
            writes: 1 + 8 * evicted,
        } // spec 9: + `RenewalAttempts` per evicted
    }
    /// **D47** `revoke_operator_approval` (worst case: `MaxVotesPerOperator` bound nodes + its own seat): reads
    /// {ApprovedOperators, OperatorNodes} + per evicted {Validators, Round, Pending}; writes {ApprovedOperators,
    /// OperatorNodes} + per evicted a full eviction {NodeOperator, Validators, MembershipExpiry, PendingVoluntaryExit, Round,
    /// Pending}. Measured (n = 1): 5 reads / 11 writes.
    pub fn revoke_operator_ops() -> Ops {
        let evicted = T::MaxVotesPerOperatorLimit::get() as u64 + 1;
        // spec 9: + remove the operator's `SolutionAttempts`.
        Ops {
            reads: 2 + 3 * evicted,
            writes: 3 + 7 * evicted,
        } // spec 9: + `RenewalAttempts` per evicted
    }
    /// **D47** `vouch_node`: reads {ApprovedOperators, NodeOperator, Validators, OperatorNodes}, writes
    /// {OperatorNodes, NodeOperator}. (B1: was 3 reads; `Validators` was not counted.)
    pub fn vouch_node_ops() -> Ops {
        // spec 9: + read `MaxVotesPerOperator`.
        Ops {
            reads: 5,
            writes: 2,
        }
    }
    /// **D47** `revoke_vouch`: reads {NodeOperator, Validators, OperatorNodes, Round, Pending} + a full eviction
    /// {NodeOperator, OperatorNodes, Validators, MembershipExpiry, PendingVoluntaryExit, Round, Pending}.
    pub fn revoke_vouch_ops() -> Ops {
        Ops {
            reads: 5,
            writes: 2 + 6,
        } // spec 9: + `RenewalAttempts`
    }
    /// spec 9 — set a value: read the old one + write it + the event (Events, EventCount).
    pub fn set_admission_param_ops() -> Ops {
        Ops {
            reads: 2,
            writes: 3,
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
            with_trie_margin(
                Self::validators_pov()
                    .saturating_add(Self::pool_pov())
                    .saturating_add(8 * POV_PER_KEY * 4),
            ),
        )
        .saturating_add(Self::db(Self::submit_ops()))
    }

    fn submit_admission_rejected_early() -> Weight {
        let scans = (Self::v() + Self::c()).saturating_mul(SCAN_PS_PER_ITEM);
        Weight::from_parts(
            50_000_000u64.saturating_add(scans),
            with_trie_margin(
                Self::validators_pov()
                    .saturating_add(Self::pool_pov())
                    .saturating_add(8 * POV_PER_KEY),
            ),
        )
        .saturating_add(Self::db(Self::early_ops()))
    }

    fn voluntary_exit() -> Weight {
        Weight::from_parts(
            50_000_000u64.saturating_add(Self::v().saturating_mul(SCAN_PS_PER_ITEM)),
            with_trie_margin(Self::validators_pov().saturating_add(2 * POV_PER_KEY)),
        )
        .saturating_add(Self::db(Self::exit_ops()))
    }

    fn ban() -> Weight {
        let scans = (Self::v() + Self::c() * POOLS).saturating_mul(SCAN_PS_PER_ITEM);
        Weight::from_parts(
            // B1 2026-09-21: 100 release samples at maximum occupancy reached
            // 385 us native. Reserve >= 5x that CPU time before DB charges;
            // B1 2026-10-15: 83.6 us WASM median (x86) — still >= 2x.
            2_000_000_000u64.saturating_add(scans),
            with_trie_margin(
                Self::validators_pov()
                    .saturating_add(POOLS * Self::pool_pov())
                    .saturating_add(6 * POV_PER_KEY),
            ),
        )
        .saturating_add(Self::db(Self::ban_ops()))
    }

    fn new_session() -> Weight {
        let v = Self::v();
        let c = Self::c();
        // B1: the per-member work (filtering staying/departing, reading validity and keys, building the new set) dominates.
        let per_validator = v.saturating_mul(NEW_SESSION_PS_PER_VALIDATOR);
        let scans = (v + POOLS * c).saturating_mul(SCAN_PS_PER_ITEM);
        let sorts = (POOLS * c).saturating_mul(SORT_PS_PER_ITEM);
        Weight::from_parts(
            100_000_000u64
                .saturating_add(per_validator)
                .saturating_add(scans)
                .saturating_add(sorts),
            Self::validators_pov()
                .saturating_add(POOLS * Self::pool_pov())
                .saturating_add(
                    (8 * v
                        + 4 * c * POOLS
                        + 2 * POOLS * T::AdmissionCapPerRoundLimit::get() as u64)
                        * POV_PER_KEY,
                ),
        )
        .saturating_add(Self::db(Self::new_session_ops()))
    }

    fn on_initialize() -> Weight {
        // B1: 12.4 us WASM median (30 us >= 2×); recorded proof 360 bytes (256 were declared).
        // spec 9 final (2026-10-16): 23.5 us measured => 55 us.
        Weight::from_parts(55_000_000, 400).saturating_add(Self::db(Self::on_initialize_ops()))
    }

    // D47 — operator caps for identity-duplication resistance. B1 (2026-10-15): measured in WASM in the worst case (1000 members, full pools).
    fn approve_operator() -> Weight {
        let n = T::MaxVotesPerOperatorLimit::get() as u64;
        let scans = (Self::v() + n).saturating_mul(OPERATOR_SCAN_PS_PER_ITEM);
        Weight::from_parts(
            30_000_000u64.saturating_add(scans),
            (Self::v() + n * 6 + 8) * POV_PER_KEY,
        )
        .saturating_add(Self::db(Self::approve_operator_ops()))
    }

    fn revoke_operator_approval() -> Weight {
        let evicted = T::MaxVotesPerOperatorLimit::get() as u64 + 1;
        // per evicted: scan `Validators` (liveness guard + removal) and every pool — like `revoke_vouch` per evicted.
        let scans = evicted
            .saturating_mul((Self::v() + Self::c() * POOLS).saturating_mul(SCAN_PS_PER_ITEM));
        Weight::from_parts(
            50_000_000u64.saturating_add(scans),
            with_trie_margin(
                Self::validators_pov()
                    .saturating_add(POOLS * Self::pool_pov())
                    .saturating_add((evicted * 6 + 8) * POV_PER_KEY),
            ),
        )
        .saturating_add(Self::db(Self::revoke_operator_ops()))
    }

    fn vouch_node() -> Weight {
        // B1: reads all of `Validators` (does the operator itself hold a seat?) — 60.3 us WASM and 32 KB proof.
        Weight::from_parts(
            50_000_000u64.saturating_add(Self::v().saturating_mul(SCAN_PS_PER_ITEM)),
            with_trie_margin(Self::validators_pov().saturating_add(8 * POV_PER_KEY)),
        )
        .saturating_add(Self::db(Self::vouch_node_ops()))
    }

    fn revoke_vouch() -> Weight {
        let scans = (Self::v() + Self::c() * POOLS).saturating_mul(SCAN_PS_PER_ITEM);
        Weight::from_parts(
            50_000_000u64.saturating_add(scans),
            with_trie_margin(
                Self::validators_pov()
                    .saturating_add(POOLS * Self::pool_pov())
                    .saturating_add(8 * POV_PER_KEY),
            ),
        )
        .saturating_add(Self::db(Self::revoke_vouch_ops()))
    }

    fn set_admission_param() -> Weight {
        // spec 9: check the limit, then write one u32 value and an event.
        Weight::from_parts(30_000_000, with_trie_margin(3 * POV_PER_KEY))
            .saturating_add(Self::db(Self::set_admission_param_ops()))
    }
}
