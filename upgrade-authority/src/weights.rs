//! Weights of `dispatch_as_root`: the wrapper's own weight only — the inner call's weight is added
//! in the call declaration (review issue #3: `dev_mode` gave the wrapper a zero weight,
//! hiding the cost of any inner Root call such as `set_code`).

use core::marker::PhantomData;
use frame_support::{traits::Get, weights::Weight};

pub trait WeightInfo {
    /// Origin check + emitting the event (upper bound, excluding the inner call).
    fn dispatch_as_root() -> Weight;
    /// Replacing the committee membership (3 members, rewriting the membership and resetting the prime).
    /// `p` = the maximum number of open proposals: replacing the membership reads `Members` and `Proposals` and processes `Voting` for every proposal.
    fn set_committee_members(p: u32) -> Weight;
}

/// A conservative upper bound based on `DbWeight` (event reads/writes) — the wrapper touches no
/// other storage and does no heavy work, so the real cost is always the inner call's.
pub struct ConservativeWeight<T>(PhantomData<T>);

impl<T: frame_system::Config> WeightInfo for ConservativeWeight<T> {
    fn dispatch_as_root() -> Weight {
        Weight::from_parts(50_000_000, 3_500).saturating_add(T::DbWeight::get().reads_writes(1, 2))
    }

    fn set_committee_members(p: u32) -> Weight {
        let p = p as u64;
        // Reads {Members, Proposals} + Voting per proposal; writes {Members, Prime, event ×3} + Voting per proposal.
        // B1 (WASM, x86): 10.3 us + ~4.3 us per proposal (79 us at p=16) => 10 us per proposal (was 0.5 us) covers >= 2x.
        Weight::from_parts(
            100_000_000u64.saturating_add(p.saturating_mul(10_000_000)),
            4_000u64.saturating_add(p.saturating_mul(2_048)),
        )
        .saturating_add(T::DbWeight::get().reads_writes(3 + p, 6 + p))
    }
}
