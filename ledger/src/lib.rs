//! State/Ledger — a bounded-storage pattern to protect the state (D22).
//!
//! **Basis (D21/D38):** no economic balance and no supply — the accounts
//! here are only the standard `frame_system::Account<AccountId>` (nonce/providers).
//! The architecture is token-ready: adding a balance later means adding a new pallet that consumes
//! the same `AccountId` (from `madar-identity`) without modifying this pallet or anything
//! in consensus/P2P.
//!
//! **D22 (protection against state bloat from the start):** since there are no fees / economic storage
//! deposit (D17/D21), an economic cost cannot be relied on to deter
//! state growth. Instead: explicit limits **at the type level itself**
//! (`BoundedVec`/`Get<u32>`) — no account can store more than
//! `MaxItemsPerAccount` items, and no item larger than `MaxItemSize` bytes, whatever
//! happens — this is enforced by the type (a compile-time bound), not only by a runtime check
//! that could be bypassed by mistake. This is the pattern any future storage pallet
//! in MADAR must follow (Admission/Sybil and others).
//!
//! The actual values of `MaxItemsPerAccount`/`MaxItemSize` are set when wiring into
//! a real runtime — this pallet provides the mechanism, not the final numbers (the same
//! logic as D19/D22: numbers are reviewed before the public testnet with actual measurement; no
//! new placeholder here because this pallet itself is not enabled in any
//! production runtime — there is no real config except in the tests).

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

extern crate alloc;

pub use pallet::*;

// `dev_mode`: this pallet has not undergone actual benchmarking (outside the scope of
// this phase) — we avoid a misleading fixed (deprecated) weight instead of claiming an unmeasured
// number, and defer the real values to the hardening/benchmark phase (matching the same D19/D22
// logic: no numbers without measured evidence).
#[frame_support::pallet(dev_mode)]
pub mod pallet {
    use alloc::vec::Vec;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// Maximum number of items per account — an explicit fixed limit (D22), no unbounded growth.
        #[pallet::constant]
        type MaxItemsPerAccount: Get<u32>;
        /// Maximum size of each item in bytes.
        #[pallet::constant]
        type MaxItemSize: Get<u32>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// The account's items — bounded by type (`BoundedVec` inside `BoundedVec`); the limits
    /// defined in `Config` cannot be exceeded whatever goes wrong in the call logic.
    #[pallet::storage]
    pub type ItemsOf<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        BoundedVec<BoundedVec<u8, T::MaxItemSize>, T::MaxItemsPerAccount>,
        ValueQuery,
    >;

    #[pallet::error]
    pub enum Error<T> {
        /// `MaxItemsPerAccount` exceeded for this account.
        TooManyItems,
        /// `MaxItemSize` exceeded for this item.
        ItemTooLarge,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Store a new item for the signing account — fails explicitly (no silence, no bypass)
        /// when either limit is exceeded.
        #[pallet::call_index(0)]
        pub fn store_item(origin: OriginFor<T>, item: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            let bounded_item: BoundedVec<u8, T::MaxItemSize> =
                item.try_into().map_err(|_| Error::<T>::ItemTooLarge)?;

            ItemsOf::<T>::try_mutate(&who, |items| {
                items
                    .try_push(bounded_item)
                    .map_err(|_| Error::<T>::TooManyItems)
            })?;

            Ok(())
        }
    }
}
