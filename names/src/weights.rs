//! Madar Names weights: a conservative upper bound (not a FRAME benchmark) built on `DbWeight`.
//! The heaviest part of registration is recovering a secp256k1 key or verifying an Ed25519 signature.

use core::marker::PhantomData;
use frame_support::{traits::Get, weights::Weight};

pub trait WeightInfo {
    fn register() -> Weight;
    fn renew() -> Weight;
    fn admin() -> Weight;
    /// Sale lock: two signature checks (seller and buyer).
    fn sale() -> Weight;
}

pub struct ConservativeWeight<T>(PhantomData<T>);

impl<T: frame_system::Config> WeightInfo for ConservativeWeight<T> {
    fn register() -> Weight {
        // Read registrars + reserved + the name, write the name, one signature check, one event.
        Weight::from_parts(300_000_000, 3_000).saturating_add(T::DbWeight::get().reads_writes(3, 2))
    }
    fn renew() -> Weight {
        Weight::from_parts(40_000_000, 2_000).saturating_add(T::DbWeight::get().reads_writes(2, 2))
    }
    fn admin() -> Weight {
        Weight::from_parts(30_000_000, 2_000).saturating_add(T::DbWeight::get().reads_writes(1, 2))
    }
    fn sale() -> Weight {
        Weight::from_parts(600_000_000, 4_000).saturating_add(T::DbWeight::get().reads_writes(4, 2))
    }
}

impl WeightInfo for () {
    fn register() -> Weight {
        Weight::from_parts(1_000_000, 0)
    }
    fn renew() -> Weight {
        Weight::from_parts(1_000_000, 0)
    }
    fn admin() -> Weight {
        Weight::from_parts(1_000_000, 0)
    }
    fn sale() -> Weight {
        Weight::from_parts(1_000_000, 0)
    }
}
