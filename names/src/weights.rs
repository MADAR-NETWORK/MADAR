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
    /// (spec 8) v2 sale lock: two signature verifications + writing the lock and payment terms.
    fn sale_v2() -> Weight;
    /// (spec 8) v2 sale completion: read the lock, the terms, the reference and the name; write the name, the nonce and the reference, and clear the lock and the terms.
    fn complete_v2() -> Weight;
    /// (spec 9) Registration with a v2 message (network + deadline).
    fn register_v2() -> Weight;
    /// (spec 9) v3 sale lock (v2 messages).
    fn sale_v3() -> Weight;
    /// (spec 9) Offer cancellation with a v2 message.
    fn cancel_v2() -> Weight;
    /// (spec 9) Transfer with two signatures.
    fn transfer() -> Weight;
    /// (spec 9) Return of a name by committee decision.
    fn reassign() -> Weight;
    /// (spec 9) `on_idle` cleanup in the worst case: `MAX_CLEANUP` locks, all expired.
    fn cleanup() -> Weight;
}

pub struct ConservativeWeight<T>(PhantomData<T>);

/// spec 9 final (2026-10-16): values raised so they stay ≥ 2× the last measurement (spec 9 final weights report).
/// B1 (2026-10-15, WASM on x86): the CPU part is >= 2× the measured median,
/// and reads/writes ≥ those measured on the worst path, and proof ≥ 1.1× the recorded one. spec 9 (v2 messages): measured in
/// the spec 9 names v2 review, and the values are not lower than a similar old call.
impl<T: frame_system::Config> WeightInfo for ConservativeWeight<T> {
    fn register() -> Weight {
        // reads {Registrars, LegacyAcceptedUntil, Reserved, Timestamp, Names, SaleNonce}; writes for a new owner {Names,
        // SaleNonce, Locks, LockTerms}; signature verification. spec 9: 180 us measured (machine busy; B1 was 82). Also covers `cancel_offer`
        // (6 reads, 3 writes, 126 us).
        Weight::from_parts(500_000_000, 3_000).saturating_add(T::DbWeight::get().reads_writes(6, 4))
    }
    fn renew() -> Weight {
        // reads {Registrars, Timestamp, Names}; spec 9: 77.8 us measured (B1: 30.2).
        Weight::from_parts(160_000_000, 2_000).saturating_add(T::DbWeight::get().reads_writes(3, 2))
    }
    fn admin() -> Weight {
        // add/remove_registrar, set_reserved, set_legacy_accepted_until: up to 18.4 us measured (spec 9).
        Weight::from_parts(40_000_000, 2_000).saturating_add(T::DbWeight::get().reads_writes(1, 2))
    }
    fn revoke() -> Weight {
        // spec 9: 37.1 us measured (B1: 21.3); two reads and five writes.
        Weight::from_parts(120_000_000, 2_000).saturating_add(T::DbWeight::get().reads_writes(2, 5))
    }
    fn sale_v2() -> Weight {
        // reads {Registrars, LegacyAcceptedUntil, Timestamp, Names, Locks, SaleNonce}; spec 9: 203.8 us measured.
        Weight::from_parts(650_000_000, 4_500).saturating_add(T::DbWeight::get().reads_writes(6, 3))
    }
    fn complete_v2() -> Weight {
        // reads {Registrars, Timestamp, Locks, LockTerms, UsedPaymentRefs, Names, SaleNonce}; spec 9: 106.7 us measured.
        Weight::from_parts(280_000_000, 4_000).saturating_add(T::DbWeight::get().reads_writes(7, 5))
    }
    fn register_v2() -> Weight {
        // reads {Registrars, Reserved, Timestamp, BlockHash(0), Names, SaleNonce}; writes for a new owner (4); 122.7 us
        // measured; not lower than `register`.
        Weight::from_parts(500_000_000, 3_000).saturating_add(T::DbWeight::get().reads_writes(6, 4))
    }
    fn sale_v3() -> Weight {
        // reads {Registrars, Timestamp, Names, Locks, SaleNonce, BlockHash(0)}; writes {Locks, LockTerms}; 209.9 us
        // measured; not lower than `sale_v2`.
        Weight::from_parts(650_000_000, 4_500).saturating_add(T::DbWeight::get().reads_writes(6, 3))
    }
    fn cancel_v2() -> Weight {
        // reads {Registrars, Timestamp, BlockHash(0), Names, Locks, SaleNonce}; writes {SaleNonce, Locks, LockTerms};
        // 166.7 us measured.
        Weight::from_parts(480_000_000, 3_000).saturating_add(T::DbWeight::get().reads_writes(6, 3))
    }
    fn transfer() -> Weight {
        // two signature verifications; reads {Registrars, Timestamp, Names, Locks, SaleNonce, BlockHash(0)};
        // writes {Names, SaleNonce, Locks, LockTerms}; 296.6 us measured (transfer to a Solana wallet, the heaviest).
        Weight::from_parts(720_000_000, 4_500).saturating_add(T::DbWeight::get().reads_writes(6, 4))
    }
    fn reassign() -> Weight {
        // reads {Timestamp, Names, SaleNonce}; writes {Names, SaleNonce, Locks, LockTerms}; 112.6 us measured.
        Weight::from_parts(240_000_000, 2_000).saturating_add(T::DbWeight::get().reads_writes(3, 4))
    }
    fn cleanup() -> Weight {
        // reads {CleanupCursor, Timestamp, next Locks} + per lock {Locks, LockTerms}; writes {CleanupCursor} + per
        // lock {Locks, LockTerms}; up to 8 locks: 19 reads, 17 writes and 125.1 us measured, and a proof of 1,425 bytes.
        let n = crate::MAX_CLEANUP as u64;
        Weight::from_parts(380_000_000, 8_000)
            .saturating_add(T::DbWeight::get().reads_writes(3 + 2 * n, 1 + 2 * n))
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
    fn sale_v2() -> Weight {
        Weight::from_parts(1_000_000, 0)
    }
    fn complete_v2() -> Weight {
        Weight::from_parts(1_000_000, 0)
    }
    fn register_v2() -> Weight {
        Weight::from_parts(1_000_000, 0)
    }
    fn sale_v3() -> Weight {
        Weight::from_parts(1_000_000, 0)
    }
    fn cancel_v2() -> Weight {
        Weight::from_parts(1_000_000, 0)
    }
    fn transfer() -> Weight {
        Weight::from_parts(1_000_000, 0)
    }
    fn reassign() -> Weight {
        Weight::from_parts(1_000_000, 0)
    }
    fn cleanup() -> Weight {
        Weight::from_parts(1_000_000, 0)
    }
}
