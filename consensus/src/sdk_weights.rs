//! B1 (2026-10-15) — weights of the SDK pallets used in MADAR: the **larger** (per component) of the SDK reference
//! weight `()` and a floor measured on MADAR itself: `2 × measured execution time (WASM, median, at the component
//! value) + measured reads/writes × MADAR's own DbWeight + the estimated proof size`. No weight ever drops below the
//! SDK value.
//!
//! Source: the raw `madar-node benchmark pallet` output (i7-12700KF, 50 steps × 20 repeats). Why this is needed: the
//! SDK `()` weights count reads/writes with their built-in `RocksDbWeight` constants, not MADAR's own `DbWeight`, and
//! their execution part is only ~1× of what was measured here (no 2× margin).
//!
//! spec 9: `pallet_collective` `vote`/`close_*` (the SDK benchmark needs 4+ members and Madar fixes them at 3) and `pallet_session`
//! `set_keys`/`purge_keys` were measured with Madar's own benchmarks (`consensus/src/benchmarks.rs`: `madar_committee`, `madar_session_keys`)
//! — see the spec 9 weights report. What remains at the SDK weight: `plan_config_change` in BABE (closed: Root only).

use crate::Runtime;
use frame_support::traits::Get;
use frame_support::weights::Weight;

type Db = <Runtime as frame_system::Config>::DbWeight;

/// Measured floor: `exec_ps` = the measured execution time (picoseconds), doubled; reads/writes use MADAR's `DbWeight`.
fn floor(exec_ps: u64, reads: u64, writes: u64, proof: u64) -> Weight {
    Weight::from_parts(exec_ps.saturating_mul(2), proof)
        .saturating_add(Db::get().reads_writes(reads, writes))
}

/// Like `floor` for a function of a component (a regression-fitted line): the measured median sits up to 5.8% above
/// the line at some values (`kill_prefix` 1.058, `kill_storage` 1.053, `set_storage` 1.050, `upgrade_accounts` 1.015),
/// so the multiplier is 2.2.
fn floor_c(exec_ps: u64, reads: u64, writes: u64, proof: u64) -> Weight {
    Weight::from_parts(exec_ps.saturating_mul(22) / 10, proof)
        .saturating_add(Db::get().reads_writes(reads, writes))
}

/// `frame_system`.
pub struct SystemWeights;
impl frame_system::WeightInfo for SystemWeights {
    fn remark(b: u32) -> Weight {
        let b = b as u64;
        <() as frame_system::WeightInfo>::remark(b as u32).max(floor_c(
            2_000_000 + 591 * b,
            0,
            0,
            0,
        ))
    }
    fn remark_with_event(b: u32) -> Weight {
        let b = b as u64;
        <() as frame_system::WeightInfo>::remark_with_event(b as u32).max(floor_c(
            5_400_000 + 1_412 * b,
            0,
            0,
            0,
        ))
    }
    fn set_heap_pages() -> Weight {
        <() as frame_system::WeightInfo>::set_heap_pages().max(floor(4_400_000, 0, 1, 0))
    }
    fn set_code() -> Weight {
        <() as frame_system::WeightInfo>::set_code().max(floor(109_738_300_000, 0, 1, 0))
    }
    fn set_storage(i: u32) -> Weight {
        let i = i as u64;
        <() as frame_system::WeightInfo>::set_storage(i as u32).max(floor_c(
            2_000_000 + 687_096 * i,
            0,
            i,
            0,
        ))
    }
    fn kill_storage(i: u32) -> Weight {
        let i = i as u64;
        <() as frame_system::WeightInfo>::kill_storage(i as u32).max(floor_c(
            2_100_000 + 514_175 * i,
            0,
            i,
            0,
        ))
    }
    fn kill_prefix(p: u32) -> Weight {
        let p = p as u64;
        <() as frame_system::WeightInfo>::kill_prefix(p as u32).max(floor_c(
            3_900_000 + 1_187_753 * p,
            p,
            p,
            60 + 70 * p,
        ))
    }
    fn authorize_upgrade() -> Weight {
        <() as frame_system::WeightInfo>::authorize_upgrade().max(floor(15_400_000, 0, 1, 0))
    }
    fn apply_authorized_upgrade() -> Weight {
        <() as frame_system::WeightInfo>::apply_authorized_upgrade().max(floor(
            111_886_900_000,
            1,
            2,
            1_518,
        ))
    }
}

/// `pallet_timestamp`.
pub struct TimestampWeights;
impl pallet_timestamp::WeightInfo for TimestampWeights {
    fn set() -> Weight {
        <() as pallet_timestamp::WeightInfo>::set().max(floor(6_200_000, 2, 1, 1_493))
    }
    fn on_finalize() -> Weight {
        <() as pallet_timestamp::WeightInfo>::on_finalize().max(floor(1_000_000, 0, 0, 0))
    }
}

/// `pallet_balances`.
pub struct BalancesWeights;
impl pallet_balances::WeightInfo for BalancesWeights {
    fn transfer_allow_death() -> Weight {
        <() as pallet_balances::WeightInfo>::transfer_allow_death()
            .max(floor(48_900_000, 1, 1, 3_593))
    }
    fn transfer_keep_alive() -> Weight {
        <() as pallet_balances::WeightInfo>::transfer_keep_alive()
            .max(floor(37_600_000, 1, 1, 3_593))
    }
    fn force_set_balance_creating() -> Weight {
        <() as pallet_balances::WeightInfo>::force_set_balance_creating()
            .max(floor(20_400_000, 1, 1, 3_593))
    }
    fn force_set_balance_killing() -> Weight {
        <() as pallet_balances::WeightInfo>::force_set_balance_killing()
            .max(floor(20_900_000, 1, 1, 3_593))
    }
    fn force_transfer() -> Weight {
        <() as pallet_balances::WeightInfo>::force_transfer().max(floor(50_600_000, 2, 2, 6_196))
    }
    fn transfer_all() -> Weight {
        <() as pallet_balances::WeightInfo>::transfer_all().max(floor(46_700_000, 1, 1, 3_593))
    }
    fn force_unreserve() -> Weight {
        <() as pallet_balances::WeightInfo>::force_unreserve().max(floor(16_600_000, 1, 1, 3_593))
    }
    fn upgrade_accounts(u: u32) -> Weight {
        let u = u as u64;
        <() as pallet_balances::WeightInfo>::upgrade_accounts(u as u32).max(floor_c(
            16_000_000 + 13_311_810 * u,
            u,
            u,
            990 + 2_603 * u,
        ))
    }
    fn force_adjust_total_issuance() -> Weight {
        <() as pallet_balances::WeightInfo>::force_adjust_total_issuance()
            .max(floor(6_200_000, 0, 0, 0))
    }
    fn burn_allow_death() -> Weight {
        <() as pallet_balances::WeightInfo>::burn_allow_death().max(floor(31_900_000, 0, 0, 0))
    }
    fn burn_keep_alive() -> Weight {
        <() as pallet_balances::WeightInfo>::burn_keep_alive().max(floor(20_600_000, 0, 0, 0))
    }
}

/// `pallet_collective` (the upgrade committee, 3 fixed members). `vote`/`close_*` measured with m = 3 (spec 9); the floor is computed at
/// m = 3 always (`MaxMembers` = 3), with `p` up to `MaxProposals` and `b` the proposal length.
pub struct CollectiveWeights;
impl pallet_collective::WeightInfo for CollectiveWeights {
    fn set_members(m: u32, n: u32, p: u32) -> Weight {
        let (mm, pp) = (m as u64, p as u64);
        <() as pallet_collective::WeightInfo>::set_members(m, n, p).max(floor_c(
            6_900_000 + 9_348_521 * mm + 2_673_270 * pp,
            2 + 2 * mm + pp,
            2 + 2 * mm + pp,
            1_513 + 254 * mm + 2_558 * pp,
        ))
    }
    fn execute(b: u32, m: u32) -> Weight {
        let (bb, mm) = (b as u64, m as u64);
        <() as pallet_collective::WeightInfo>::execute(b, m).max(floor_c(
            11_217_205 + 1_088 * bb + 57_026 * mm,
            1,
            0,
            1_515 + 33 * mm,
        ))
    }
    fn propose_execute(b: u32, m: u32) -> Weight {
        let (bb, mm) = (b as u64, m as u64);
        <() as pallet_collective::WeightInfo>::propose_execute(b, m).max(floor_c(
            13_303_471 + 1_034 * bb + 53_644 * mm,
            2,
            0,
            3_495 + 33 * mm,
        ))
    }
    fn propose_proposed(b: u32, m: u32, p: u32) -> Weight {
        let (bb, mm, pp) = (b as u64, m as u64, p as u64);
        <() as pallet_collective::WeightInfo>::propose_proposed(b, m, p).max(floor_c(
            18_186_555 + 1_943 * bb + 169_220 * mm + 432_403 * pp,
            4,
            4,
            3_465 + 43 * mm + 58 * pp,
        ))
    }
    fn vote(m: u32) -> Weight {
        <() as pallet_collective::WeightInfo>::vote(m).max(floor(VOTE_EXEC_PS, 2, 1, VOTE_PROOF))
    }
    fn close_early_disapproved(m: u32, p: u32) -> Weight {
        let pp = p as u64;
        <() as pallet_collective::WeightInfo>::close_early_disapproved(m, p).max(floor_c(
            CLOSE_DISAPPROVED_EXEC_PS + CLOSE_PER_P_PS * pp,
            3,
            3,
            CLOSE_PROOF + CLOSE_PROOF_PER_P * pp,
        ))
    }
    fn close_early_approved(b: u32, m: u32, p: u32) -> Weight {
        let (bb, pp) = (b as u64, p as u64);
        <() as pallet_collective::WeightInfo>::close_early_approved(b, m, p).max(floor_c(
            CLOSE_APPROVED_EXEC_PS + CLOSE_PER_B_PS * bb + CLOSE_PER_P_PS * pp,
            4,
            3,
            CLOSE_PROOF + bb + CLOSE_PROOF_PER_P * pp,
        ))
    }
    fn close_disapproved(m: u32, p: u32) -> Weight {
        let pp = p as u64;
        <() as pallet_collective::WeightInfo>::close_disapproved(m, p).max(floor_c(
            CLOSE_DISAPPROVED_EXEC_PS + CLOSE_PER_P_PS * pp,
            4,
            3,
            CLOSE_PROOF + CLOSE_PROOF_PER_P * pp,
        ))
    }
    /// unreachable in Madar (`PrimeDefaultVote` with no Prime ⇒ abstention is "no", so approval after the deadline = the early approval
    /// itself); even so, it reserves the measured early-approval weight.
    fn close_approved(b: u32, m: u32, p: u32) -> Weight {
        <() as pallet_collective::WeightInfo>::close_approved(b, m, p)
            .max(Self::close_early_approved(b, m, p))
    }
    fn disapprove_proposal(p: u32) -> Weight {
        let pp = p as u64;
        <() as pallet_collective::WeightInfo>::disapprove_proposal(p).max(floor_c(
            12_643_503 + 226_654 * pp,
            1,
            3,
            1_673 + 32 * pp,
        ))
    }
    fn kill(d: u32, p: u32) -> Weight {
        let (dd, pp) = (d as u64, p as u64);
        <() as pallet_collective::WeightInfo>::kill(d, p).max(floor_c(
            18_325_373 + 978_810 * dd + 391_730 * pp,
            3,
            3,
            4_669 + 35 * dd + 56 * pp,
        ))
    }
    fn release_proposal_cost() -> Weight {
        <() as pallet_collective::WeightInfo>::release_proposal_cost()
            .max(floor(10_400_000, 2, 0, 4_000))
    }
}

/// B1: Equivocation proof verification measured 70 µs (BABE) and 60 µs (GRANDPA); the SDK weight reserves 95 + 110 µs for verification, and we add 110 µs
/// (≥ 2× the verification). spec 9: **the full penalty weight** is added on top (`ban_and_disable`): the declared weight of `Admission::ban` +
/// the measured disabling floor (`madar_session_transition::ban_and_disable`). Before this, the 84 µs ban was covered by the 110 µs alone.
const EQUIVOCATION_EXTRA_PS: u64 = 110_000_000;

/// spec 9: the penalty weight (`crate::ban_and_disable`) inside the Equivocation report.
pub fn equivocation_penalty() -> Weight {
    use madar_admission::weights::WeightInfo;
    let v = <<Runtime as madar_admission::Config>::MaxValidators as Get<u32>>::get() as u64;
    // Disabling: read Session::Validators, DisabledValidators, Admission::Validators and BannedKeys (at most twice: the banned validator remaining
    // in Admission is only the kept last one) + write DisabledValidators, the event and the Digest. The scan uses sorted sets (O(n log n)).
    let disable = floor(
        DISABLE_EXEC_PS + DISABLE_PER_VALIDATOR_PS * v,
        5,
        4,
        2 * (v * 32 + 8) + v * 48,
    );
    <Runtime as madar_admission::Config>::WeightInfo::ban().saturating_add(disable)
}

// spec 9 — Madar measurements (WASM compiled, i7-12700KF, 50 steps × 20; spec 9 weights report), rounded up.
// `floor` doubles them (2×), and `floor_c` (when following a component) 2.2×.
/// `vote` (m = 3): measured 15.35 + 0.216·p µs ⇒ 18.8 µs at p = 16; proof 314 + 27·p.
const VOTE_EXEC_PS: u64 = 40_000_000; // spec 9 final (2026-10-16): 32.2 us measured at p = 16
const VOTE_PROOF: u64 = 4_000;
/// `close_early_disapproved` 22.0 + 0.366·p and `close_disapproved` 23.6 + 0.355·p µs (m = 3).
const CLOSE_DISAPPROVED_EXEC_PS: u64 = 42_000_000; // spec 9 final: 50.1 us measured at p = 16
/// `close_early_approved` (m = 3, a `remark` proposal up to 1024 bytes): 31.4 + 0.53·p µs, and the length has no measured effect.
const CLOSE_APPROVED_EXEC_PS: u64 = 60_000_000; // spec 9 final: 69.9 us measured at p = 16, b = 1024
const CLOSE_PER_B_PS: u64 = 2_000;
const CLOSE_PER_P_PS: u64 = 550_000;
/// The measured proof up to 344 + b + 86·p.
const CLOSE_PROOF: u64 = 5_000;
const CLOSE_PROOF_PER_P: u64 = 96;
/// `ban_and_disable` (worst scan: 1000 active members, 332 disabled, all outside Admission except one producer): 106.5 µs including the ban
/// (with a small set); the ban alone with a full set is 75.1 µs (`madar_admission::ban`, declared separately). 60 + 0.1·n µs ⇒ 160 µs × 2.
const DISABLE_EXEC_PS: u64 = 60_000_000;
const DISABLE_PER_VALIDATOR_PS: u64 = 100_000;
/// `set_keys` (two keys BABE + GRANDPA with ownership proof verification): first registration 137.4 µs (4 r / 4 w), replacement 127.3 µs (4 r /
/// 5 w, proof 398); `purge_keys` 46.4 µs (4 r / 5 w, proof 379).
const SET_KEYS_EXEC_PS: u64 = 170_000_000; // spec 9 final: replace 225.8 us (4 r / 5 w) measured
const PURGE_KEYS_EXEC_PS: u64 = 50_000_000;

/// `pallet_session` (spec 9, it was `()` with no Madar floor).
pub struct SessionWeights;
impl pallet_session::WeightInfo for SessionWeights {
    fn set_keys() -> Weight {
        // NextKeys, KeyOwner ×4 (remove the old + insert the new), System::Account (consumers), Holds (the deposit is zero).
        <() as pallet_session::WeightInfo>::set_keys().max(floor(SET_KEYS_EXEC_PS, 6, 6, 6_000))
    }
    fn purge_keys() -> Weight {
        <() as pallet_session::WeightInfo>::purge_keys().max(floor(PURGE_KEYS_EXEC_PS, 4, 5, 6_000))
    }
}

/// `pallet_grandpa`.
pub struct GrandpaWeights;
impl pallet_grandpa::WeightInfo for GrandpaWeights {
    fn report_equivocation(validator_count: u32, max_nominators_per_validator: u32) -> Weight {
        <() as pallet_grandpa::WeightInfo>::report_equivocation(
            validator_count,
            max_nominators_per_validator,
        )
        .saturating_add(Weight::from_parts(EQUIVOCATION_EXTRA_PS, 0))
        .saturating_add(equivocation_penalty())
    }
    fn note_stalled() -> Weight {
        <() as pallet_grandpa::WeightInfo>::note_stalled().max(floor(2_600_000, 0, 1, 0))
    }
}

/// `pallet_babe`.
pub struct BabeWeights;
impl pallet_babe::WeightInfo for BabeWeights {
    fn plan_config_change() -> Weight {
        <() as pallet_babe::WeightInfo>::plan_config_change()
    }
    fn report_equivocation(validator_count: u32, max_nominators_per_validator: u32) -> Weight {
        <() as pallet_babe::WeightInfo>::report_equivocation(
            validator_count,
            max_nominators_per_validator,
        )
        .saturating_add(Weight::from_parts(EQUIVOCATION_EXTRA_PS, 0))
        .saturating_add(equivocation_penalty())
    }
}
