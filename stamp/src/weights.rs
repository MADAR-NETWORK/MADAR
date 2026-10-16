//! Madar Stamp weights: a conservative upper bound (not a FRAME benchmark) based on `DbWeight`.
//! The heaviest part of one entry is secp256k1 key recovery or Ed25519 verification (tens of microseconds).

use core::marker::PhantomData;
use frame_support::{traits::Get, weights::Weight};

pub trait WeightInfo {
    /// A batch of `n` entries.
    fn stamp(n: u32) -> Weight;
    /// Adding/removing a stamper.
    fn set_stamper() -> Weight;
    /// (spec 9) A v2 batch of `n` entries (a message bound to the network and to a deadline).
    fn stamp_v2(n: u32) -> Weight;
}

pub struct ConservativeWeight<T>(PhantomData<T>);

impl<T: frame_system::Config> WeightInfo for ConservativeWeight<T> {
    fn stamp(n: u32) -> Weight {
        let n = n as u64;
        // Base: reading the stamper list and `Timestamp` (B1: two fixed reads, measured). Per entry: read + write +
        // signature check + event. B1 (WASM, x86): 75 us at n=1 and 2.69 ms at n=50 (EVM); 250 us per entry is >= 2x at every n.
        // spec 9: + read `LegacyAcceptedUntil`.
        Weight::from_parts(30_000_000, 2_000)
            .saturating_add(Weight::from_parts(
                n.saturating_mul(250_000_000),
                n.saturating_mul(1_200),
            ))
            .saturating_add(T::DbWeight::get().reads_writes(3 + n, 2 * n))
    }

    fn set_stamper() -> Weight {
        Weight::from_parts(30_000_000, 2_000).saturating_add(T::DbWeight::get().reads_writes(1, 2))
    }

    fn stamp_v2(n: u32) -> Weight {
        let n = n as u64;
        // base: {Stampers, Timestamp, BlockHash(0)}; per entry as in `stamp` (the message is two lines longer).
        Weight::from_parts(30_000_000, 2_000)
            .saturating_add(Weight::from_parts(
                n.saturating_mul(250_000_000),
                n.saturating_mul(1_200),
            ))
            .saturating_add(T::DbWeight::get().reads_writes(3 + n, 2 * n))
    }
}

impl WeightInfo for () {
    fn stamp(n: u32) -> Weight {
        Weight::from_parts(1_000_000 * (1 + n as u64), 0)
    }
    fn set_stamper() -> Weight {
        Weight::from_parts(1_000_000, 0)
    }
    fn stamp_v2(n: u32) -> Weight {
        Weight::from_parts(1_000_000 * (1 + n as u64), 0)
    }
}
