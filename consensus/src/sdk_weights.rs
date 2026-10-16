//! B1 (2026-10-15) — weights of the SDK pallets used in MADAR: the **larger** (per component) of the SDK reference
//! weight `()` and a floor measured on MADAR itself: `2 × measured execution time (WASM, median, at the component
//! value) + measured reads/writes × MADAR's own DbWeight + the estimated proof size`. No weight ever drops below the
//! SDK value.
//!
//! Source: the raw `madar-node benchmark pallet` output (i7-12700KF, 50 steps × 20 repeats). Why this is needed: the
//! SDK `()` weights count reads/writes with their built-in `RocksDbWeight` constants, not MADAR's own `DbWeight`, and
//! their execution part is only ~1× of what was measured here (no 2× margin).
//!
//! What was not measured keeps the SDK weight unchanged: the `pallet_collective` `vote`/`close_*` calls (the SDK
//! benchmark needs 4+ members and MADAR fixes them at 3), and BABE `plan_config_change` (closed: Root only).

use crate::Runtime;
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

/// `pallet_collective` (the upgrade committee). `vote` and `close_*` were not measured (see the file header), so they
/// keep the SDK weight.
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
        <() as pallet_collective::WeightInfo>::vote(m)
    }
    fn close_early_disapproved(m: u32, p: u32) -> Weight {
        <() as pallet_collective::WeightInfo>::close_early_disapproved(m, p)
    }
    fn close_early_approved(b: u32, m: u32, p: u32) -> Weight {
        <() as pallet_collective::WeightInfo>::close_early_approved(b, m, p)
    }
    fn close_disapproved(m: u32, p: u32) -> Weight {
        <() as pallet_collective::WeightInfo>::close_disapproved(m, p)
    }
    fn close_approved(b: u32, m: u32, p: u32) -> Weight {
        <() as pallet_collective::WeightInfo>::close_approved(b, m, p)
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

/// B1: the equivocation proof check measured 70 µs (BABE) and 60 µs (GRANDPA), and the ban in MADAR
/// (`Admission::ban`) 84 µs; the SDK weight reserves 95 + 110 µs for them. We add 110 µs so the reservation is >= 2× the
/// measurement: (95 + 110 + 110) >= 2 × (70 + 84).
const EQUIVOCATION_EXTRA_PS: u64 = 110_000_000;

/// `pallet_grandpa`.
pub struct GrandpaWeights;
impl pallet_grandpa::WeightInfo for GrandpaWeights {
    fn report_equivocation(validator_count: u32, max_nominators_per_validator: u32) -> Weight {
        <() as pallet_grandpa::WeightInfo>::report_equivocation(
            validator_count,
            max_nominators_per_validator,
        )
        .saturating_add(Weight::from_parts(EQUIVOCATION_EXTRA_PS, 0))
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
    }
}
