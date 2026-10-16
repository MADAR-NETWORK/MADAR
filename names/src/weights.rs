//! Madar Names weights: a conservative upper bound (not a FRAME benchmark) built on `DbWeight`.
//! The heaviest part of registration is recovering a secp256k1 key or verifying an Ed25519 signature.

use core::marker::PhantomData;
use frame_support::{traits::Get, weights::Weight};

pub trait WeightInfo {
    fn register() -> Weight;
    fn renew() -> Weight;
    fn admin() -> Weight;
    /// (B1) Name revocation: reads {Names, SaleNonce}; writes {Names, Reserved, SaleNonce, Locks, LockTerms}.
    fn revoke() -> Weight;
    /// Sale lock: two signature checks (seller and buyer).
    fn sale() -> Weight;
    /// (spec 8) v2 sale lock: like `sale` + writing the payment terms.
    fn sale_v2() -> Weight;
    /// (spec 8) v2 sale completion: read the lock, the terms, the reference and the name; write the name, the nonce and the reference, and clear the lock and the terms.
    fn complete_v2() -> Weight;
}

pub struct ConservativeWeight<T>(PhantomData<T>);

/// B1 (2026-10-15, WASM on x86): the CPU part is >= 2× the measured median,
/// and the reads/writes are >= the measured ones on the worst path.
impl<T: frame_system::Config> WeightInfo for ConservativeWeight<T> {
    fn register() -> Weight {
        // Reads {Registrars, Reserved, Timestamp, Names, SaleNonce}; new-owner writes {Names, SaleNonce, Locks,
        // LockTerms}; one signature check (82 us measured). Also covers `cancel_offer` (5 reads, 3 writes, 88 us).
        Weight::from_parts(300_000_000, 3_000).saturating_add(T::DbWeight::get().reads_writes(5, 4))
    }
    fn renew() -> Weight {
        // Reads {Registrars, Timestamp, Names}; 30.2 us measured.
        Weight::from_parts(80_000_000, 2_000).saturating_add(T::DbWeight::get().reads_writes(3, 2))
    }
    fn admin() -> Weight {
        Weight::from_parts(30_000_000, 2_000).saturating_add(T::DbWeight::get().reads_writes(1, 2))
    }
    fn revoke() -> Weight {
        // 21.3 us measured; two reads and five writes (was `admin()`: one read and two writes).
        Weight::from_parts(60_000_000, 2_000).saturating_add(T::DbWeight::get().reads_writes(2, 5))
    }
    fn sale() -> Weight {
        Weight::from_parts(600_000_000, 4_000).saturating_add(T::DbWeight::get().reads_writes(4, 2))
    }
    fn sale_v2() -> Weight {
        // Reads {Registrars, Timestamp, Names, Locks, SaleNonce}; 141 us measured.
        Weight::from_parts(600_000_000, 4_500).saturating_add(T::DbWeight::get().reads_writes(5, 3))
    }
    fn complete_v2() -> Weight {
        // Reads {Registrars, Timestamp, Locks, LockTerms, UsedPaymentRefs, Names, SaleNonce}; 54.9 us measured.
        Weight::from_parts(120_000_000, 4_000).saturating_add(T::DbWeight::get().reads_writes(7, 5))
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
    fn revoke() -> Weight {
        Weight::from_parts(1_000_000, 0)
    }
    fn sale() -> Weight {
        Weight::from_parts(1_000_000, 0)
    }
    fn sale_v2() -> Weight {
        Weight::from_parts(1_000_000, 0)
    }
    fn complete_v2() -> Weight {
        Weight::from_parts(1_000_000, 0)
    }
}
