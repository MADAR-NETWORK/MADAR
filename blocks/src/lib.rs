//! Blocks — block size/weight limits (D23/D24).
//!
//! **D23 (hardware target):** the design target — a light ARM64/SBC class (~4
//! cores, 4–8 GB RAM, a modest SSD). This is a performance/design target and **not a reason to lower
//! security** (explicit owner wording, D23) — no security limit is relaxed because the
//! hardware is light.
//!
//! **D24 (block size/weight):** the values below are **non-final placeholders** — they are settled
//! by benchmarking on the hardware target (D23) before a Mainnet candidate, with a
//! review gate before the public testnet if they affect safety/operation. **These numbers
//! must not be treated as a final production decision in any later phase without a documented review.**
//!
//! **Important reconciliation note (stated openly, no hidden contradiction):** `protocol::chain_spec`
//! (Protocol phase, closed) contains similar sample values (`5MB`/`512KB`) inside
//! a test function (`sample_fields`) describing **genesis** fields (data), while the constants
//! here describe the compiled **runtime** limits (`BlockWeights`/`BlockLength`) — two different
//! concepts in real Substrate (genesis data versus runtime constants). Both are
//! non-final placeholders for now; actually unifying them (reading runtime limits from genesis,
//! or pinning them as a single runtime constant) is an engineering decision settled when building the
//! full real runtime assembly (after consensus), not now.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

use frame_support::{
    dispatch::DispatchClass,
    parameter_types,
    weights::{
        constants::{BlockExecutionWeight, ExtrinsicBaseWeight, WEIGHT_REF_TIME_PER_SECOND},
        Weight,
    },
};
use frame_system::limits::{BlockLength, BlockWeights};
use sp_runtime::Perbill;

/// Placeholder maximum transaction size (matches D19 — see `protocol::chain_spec`
/// for the same number at the genesis-data level; reconciling them is deferred, see above).
///
/// **Honesty note:** this constant is **documentation only here** — `frame_system` has no separate
/// standard mechanism for a "single transaction size" limit independent of the total block share;
/// `CheckWeight` (below, through `MadarBlockLength`) actually enforces that any single
/// transaction does not exceed its class share (Normal/Operational) of the total block size —
/// and that is what is actually tested in `tests/`. A separate, smaller "per transaction" limit (if wanted)
/// belongs to the mempool/RPC layer (a later phase), not to this base rule.
pub const MAX_TRANSACTION_SIZE_BYTES: u32 = 512 * 1024;

/// Placeholder maximum block size (matches D24).
pub const MAX_BLOCK_SIZE_BYTES: u32 = 5 * 1024 * 1024;

/// The share of the block reserved for normal transactions versus operational/mandatory
/// — a common standard value in the Substrate ecosystem (75%), not yet derived from a
/// MADAR-specific measurement.
const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);

/// Placeholder maximum computational block weight — two seconds of reference execution
/// time, a common standard value (the Polkadot/Substrate default), **not yet derived
/// from actual benchmarking on the hardware target (D23)** — see the D24 warning above.
const MAX_BLOCK_WEIGHT: Weight =
    Weight::from_parts(WEIGHT_REF_TIME_PER_SECOND.saturating_mul(2), u64::MAX);

parameter_types! {
    /// Wired through `frame_system::Config::BlockLength` in any real runtime.
    pub MadarBlockLength: BlockLength =
        BlockLength::max_with_normal_ratio(MAX_BLOCK_SIZE_BYTES, NORMAL_DISPATCH_RATIO);

    /// Wired through `frame_system::Config::BlockWeights`.
    pub MadarBlockWeights: BlockWeights = BlockWeights::builder()
        .base_block(BlockExecutionWeight::get())
        .for_class(DispatchClass::all(), |weights| {
            // A real base cost per transaction (decoding + signature verification + ...): without it, it was
            // zero, so small transactions were not accounted at all. The standard SDK value (placeholder D24).
            weights.base_extrinsic = ExtrinsicBaseWeight::get();
        })
        .for_class(DispatchClass::Normal, |weights| {
            weights.max_total = Some(NORMAL_DISPATCH_RATIO * MAX_BLOCK_WEIGHT);
        })
        .for_class(DispatchClass::Operational, |weights| {
            weights.max_total = Some(MAX_BLOCK_WEIGHT);
            weights.reserved = Some(
                MAX_BLOCK_WEIGHT - NORMAL_DISPATCH_RATIO * MAX_BLOCK_WEIGHT,
            );
        })
        .avg_block_initialization(Perbill::from_percent(10))
        .build_or_panic();
}
