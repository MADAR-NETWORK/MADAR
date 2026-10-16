//! Madar Names — an easy name such as `ahmad.madar` bound to its owner's wallet instead of the long address.
//!
//! **Who owns the name:** the wallet that signed the fixed registration message (EVM `personal_sign` or Solana
//! `signMessage`) — the runtime verifies the signature itself with the same functions as Madar Stamp, so nobody
//! (not even the MADAR service) can claim a name for someone else's wallet.
//!
//! **Who submits:** approved "registrar" accounts only (added by the 2-of-3 upgrade committee). The registrar decides
//! **when** the name is registered and for how long (after payment off chain), and the signature decides **for whom**.
//!
//! **Term:** until `expires` (milliseconds, UTC). After that there is a 30-day grace period during which the name cannot be
//! registered to anyone but its owner; then it is released. Renewal extends the term and does not change the owner.
//!
//! **Reserved:** a list managed by the committee (well-known marks, offensive words, MADAR names) that cannot be registered.
//!
//! **Revoke (emergency):** the 2-of-3 committee only, for proven fraud, with a written reason that stays public on chain.
//!
//! **Safe sale (resale):** no middleman holds money or a name. The seller signs an offer (price, receiving wallet,
//! sale terms), and the buyer signs an acceptance at the same price. When "Buy" is pressed the name is locked for the buyer
//! for at most 60 minutes, during which the seller cannot cancel the offer or sell to someone else. The buyer pays the seller
//! directly (and the fee to MADAR), then the registrar completes the transfer once the payment arrives. If it does not arrive
//! within the window the lock simply lapses with no action needed. Every offer is bound to a number (nonce) that increases with every owner change or cancellation, so an old signature cannot be reused.
//!
//! **Payment proof on chain (spec 8):** `lock_sale_v2` records in the lock and in the `SaleLockedV2` event the exact expected amount
//! (micro units, 6 decimals) and the payment network (rail), and `complete_sale_v2` moves the name only with the payment reference
//! (`<chain>:<tx hash>`) from the lock's network, and emits `SaleCompletedV2` with all of it; so anyone can match every completed sale with
//! the payment chain. One reference cannot complete two sales. Since spec 9: the two old calls `lock_sale` (6) and `complete_sale` (7)
//! are removed (they were disabled since spec 8); their indices are never reused, and storage is unchanged. The safe sale is v2 only.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

extern crate alloc;

pub mod weights;

use alloc::vec::Vec;
pub use madar_stamp::{verify_proof, Wallet, WalletProof};
pub use pallet::*;
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

/// Maximum name length (without `.madar`).
pub const MAX_NAME: u32 = 32;
/// Grace period after the term ends: 30 days in milliseconds.
pub const GRACE_MS: u64 = 30 * 24 * 3600 * 1000;

/// A name record.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, TypeInfo, MaxEncodedLen)]
pub struct NameRecord<AccountId> {
    /// The owning wallet as proved by the signature.
    pub owner: Wallet,
    /// Time of the first registration for this owner (milliseconds, UTC).
    pub registered: u64,
    /// End of the paid term (milliseconds, UTC).
    pub expires: u64,
    pub registrar: AccountId,
}

/// Longest time a name can be locked during a sale: 60 minutes (nothing stays pending longer than an hour).
pub const MAX_LOCK_MS: u64 = 60 * 60 * 1000;
/// Maximum length of the seller's receiving address (EVM is 42 characters, Solana up to 44).
pub const MAX_PAY_TO: u32 = 64;

/// An active sale lock: the name is held for this buyer until `until`.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, TypeInfo, MaxEncodedLen)]
pub struct SaleLock {
    pub buyer: Wallet,
    pub until: u64,
    /// The price in US cents, as signed by both parties.
    pub price_cents: u64,
    pub pay_to: frame_support::BoundedVec<u8, frame_support::traits::ConstU32<MAX_PAY_TO>>,
}

/// Maximum length of the payment reference `<chain>:<tx hash>`.
pub const MAX_PAYMENT_REF: u32 = 160;
/// Number of known payment networks (the same order as the registrar service's rail list):
/// 0 solana_usdc, 1 solana_usdt, 2 base_usdc, 3 arbitrum_usdc, 4 arbitrum_usdt.
pub const RAILS: u8 = 5;
/// Micro units per cent (stablecoins with 6 decimals).
pub const MICRO_PER_CENT: u64 = 10_000;
/// The exact amount = the signed price + a small increment that identifies the payment (less than 0.10 dollars).
pub const MAX_UNIQUE_MICRO: u64 = 100_000;

pub type PaymentRef =
    frame_support::BoundedVec<u8, frame_support::traits::ConstU32<MAX_PAYMENT_REF>>;

/// The payment terms recorded with a v2 lock — separate storage keyed by the name, so no migration of v1 locks existing at upgrade time.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, TypeInfo, MaxEncodedLen)]
pub struct SaleTerms {
    /// 0 solana_usdc, 1 solana_usdt, 2 base_usdc, 3 arbitrum_usdc, 4 arbitrum_usdt.
    pub rail: u8,
    /// The exact amount the buyer pays the seller (micro units, 6 decimals).
    pub pay_amount: u64,
}

/// The payment chain of every rail, as written at the start of the payment reference.
pub fn rail_chain(rail: u8) -> Option<&'static [u8]> {
    match rail {
        0 | 1 => Some(b"solana"),
        2 => Some(b"base"),
        3 | 4 => Some(b"arbitrum"),
        _ => None,
    }
}

/// Does the network fit the seller's receiving address? EVM addresses start with `0x`, the others are Solana.
pub fn rail_fits_pay_to(rail: u8, pay_to: &[u8]) -> bool {
    let evm = pay_to.starts_with(b"0x");
    match rail {
        0 | 1 => !evm,
        2..=4 => evm,
        _ => false,
    }
}

/// Is the exact amount within [price, price + 0.10 dollars)? The registrar cannot record an amount lower than what both parties signed.
pub fn amount_fits_price(pay_amount: u64, price_cents: u64) -> bool {
    match price_cents.checked_mul(MICRO_PER_CENT) {
        Some(base) => pay_amount >= base && pay_amount - base < MAX_UNIQUE_MICRO,
        None => false,
    }
}

const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// A valid payment reference for the lock's network? `base:0x<64 lowercase hex>`, `arbitrum:0x<64 lowercase hex>`, `solana:<base58 signature, 32 to 88 characters>`.
/// Lowercase is mandatory for EVM so the same reference cannot repeat in another form.
pub fn valid_payment_ref(rail: u8, r: &[u8]) -> bool {
    let Some(chain) = rail_chain(rail) else {
        return false;
    };
    let Some(rest) = r.strip_prefix(chain).and_then(|x| x.strip_prefix(b":")) else {
        return false;
    };
    if chain == b"solana" {
        (32..=88).contains(&rest.len()) && rest.iter().all(|c| BASE58.contains(c))
    } else {
        rest.len() == 66
            && rest.starts_with(b"0x")
            && rest[2..]
                .iter()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
    }
}

fn push_u64(m: &mut Vec<u8>, v: u64) {
    let mut d = [0u8; 20];
    let mut i = d.len();
    let mut v = v;
    loop {
        i -= 1;
        d[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    m.extend_from_slice(&d[i..]);
}

fn push_usd(m: &mut Vec<u8>, cents: u64) {
    push_u64(m, cents / 100);
    m.push(b'.');
    m.push(b'0' + ((cents % 100) / 10) as u8);
    m.push(b'0' + (cents % 10) as u8);
}

/// The seller's offer message.
pub fn sale_message(
    name: &[u8],
    nonce: u32,
    price_cents: u64,
    pay_to: &[u8],
    offer_until: u64,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(200);
    m.extend_from_slice(b"MADAR Names: I offer ");
    m.extend_from_slice(name);
    m.extend_from_slice(b".madar for ");
    push_usd(&mut m, price_cents);
    m.extend_from_slice(b" USD, paid to ");
    m.extend_from_slice(pay_to);
    m.extend_from_slice(b", under the MADAR Names sale terms v1. Offer ");
    push_u64(&mut m, nonce as u64);
    m.extend_from_slice(b", valid until ");
    push_u64(&mut m, offer_until);
    m.push(b'.');
    m
}

/// The buyer's acceptance message (at the same price, so the price cannot be swapped on the buyer).
pub fn buy_message(name: &[u8], nonce: u32, price_cents: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(200);
    m.extend_from_slice(b"MADAR Names: I buy ");
    m.extend_from_slice(name);
    m.extend_from_slice(b".madar for ");
    push_usd(&mut m, price_cents);
    m.extend_from_slice(b" USD plus the MADAR fee, under the MADAR Names sale terms v1. Offer ");
    push_u64(&mut m, nonce as u64);
    m.extend_from_slice(b". The name comes to this wallet.");
    m
}

/// The seller's message cancelling their offer.
pub fn cancel_message(name: &[u8], nonce: u32) -> Vec<u8> {
    let mut m = Vec::with_capacity(100);
    m.extend_from_slice(b"MADAR Names: cancel my sale offer for ");
    m.extend_from_slice(name);
    m.extend_from_slice(b".madar. Offer ");
    push_u64(&mut m, nonce as u64);
    m.push(b'.');
    m
}

/// Is the name valid? `a-z`, `0-9` and `-`, 3 to 32 characters, not starting or ending with a hyphen.
pub fn valid_name(name: &[u8]) -> bool {
    (3..=MAX_NAME as usize).contains(&name.len())
        && name
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && name[0] != b'-'
        && name[name.len() - 1] != b'-'
}

/// The message a wallet signs to register the name to itself (moves no funds).
pub fn register_message(name: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(80 + name.len());
    m.extend_from_slice(b"MADAR Names: register ");
    m.extend_from_slice(name);
    m.extend_from_slice(b".madar to this wallet. No funds move.");
    m
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use crate::weights::WeightInfo as _;
    use frame_support::{pallet_prelude::*, traits::UnixTime};
    use frame_system::pallet_prelude::*;

    pub type NameOf = BoundedVec<u8, ConstU32<MAX_NAME>>;

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        /// Registrars and the reserved list — in the runtime: the 2-of-3 upgrade committee.
        type AdminOrigin: EnsureOrigin<Self::RuntimeOrigin>;
        type Time: UnixTime;
        #[pallet::constant]
        type MaxRegistrars: Get<u32>;
        /// Longest term that can be paid in advance (milliseconds) — protection against a registrar mistake.
        #[pallet::constant]
        type MaxTermMs: Get<u64>;
        type WeightInfo: crate::weights::WeightInfo;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    pub type Names<T: Config> =
        StorageMap<_, Blake2_128Concat, NameOf, NameRecord<T::AccountId>, OptionQuery>;

    #[pallet::storage]
    pub type Reserved<T: Config> = StorageMap<_, Blake2_128Concat, NameOf, (), OptionQuery>;

    /// The current offer number for each name — increases with every owner change or offer cancellation.
    #[pallet::storage]
    pub type SaleNonce<T: Config> = StorageMap<_, Blake2_128Concat, NameOf, u32, ValueQuery>;

    /// Active sale locks (an expired lock has no effect even if it is still stored).
    #[pallet::storage]
    pub type Locks<T: Config> = StorageMap<_, Blake2_128Concat, NameOf, SaleLock, OptionQuery>;

    /// (spec 8) Payment terms of a v2 lock (the exact amount and the network) next to `Locks`. Absent = a v1 lock.
    #[pallet::storage]
    pub type LockTerms<T: Config> = StorageMap<_, Blake2_128Concat, NameOf, SaleTerms, OptionQuery>;

    /// (spec 8) Used payment references: blake2_256(reference) → the name. One payment cannot complete two sales.
    #[pallet::storage]
    pub type UsedPaymentRefs<T: Config> =
        StorageMap<_, Blake2_128Concat, [u8; 32], NameOf, OptionQuery>;

    #[pallet::storage]
    pub type Registrars<T: Config> =
        StorageValue<_, BoundedVec<T::AccountId, T::MaxRegistrars>, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        Registered {
            name: NameOf,
            owner: Wallet,
            expires: u64,
        },
        Renewed {
            name: NameOf,
            expires: u64,
        },
        ReservedSet {
            name: NameOf,
            reserved: bool,
        },
        /// The name was revoked by committee decision for proven fraud — the reason is public text on chain.
        Revoked {
            name: NameOf,
            owner: Wallet,
            reason: BoundedVec<u8, ConstU32<256>>,
        },
        /// The name was locked for a buyer until `until`, waiting for their payment.
        SaleLocked {
            name: NameOf,
            buyer: Wallet,
            price_cents: u64,
            until: u64,
        },
        /// The name moved to the buyer after the payment arrived (the term is unchanged).
        Sold {
            name: NameOf,
            from: Wallet,
            to: Wallet,
            price_cents: u64,
        },
        /// The owner cancelled the sale offers for this name.
        OfferCancelled {
            name: NameOf,
        },
        RegistrarAdded {
            who: T::AccountId,
        },
        RegistrarRemoved {
            who: T::AccountId,
        },
        /// (spec 8) The name was locked for a buyer until `until`, with the seller's wallet, the exact expected amount (micro units) and the payment network.
        SaleLockedV2 {
            name: NameOf,
            buyer: Wallet,
            price_cents: u64,
            until: u64,
            pay_to: BoundedVec<u8, ConstU32<MAX_PAY_TO>>,
            rail: u8,
            amount: u64,
        },
        /// (spec 8) The name moved after a payment anyone can verify: `payment_ref` = `<chain>:<tx hash>`.
        SaleCompletedV2 {
            name: NameOf,
            from: Wallet,
            to: Wallet,
            price_cents: u64,
            pay_to: BoundedVec<u8, ConstU32<MAX_PAY_TO>>,
            rail: u8,
            amount: u64,
            payment_ref: PaymentRef,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        NotRegistrar,
        InvalidName,
        NameReserved,
        /// The name belongs to another owner and has not been released yet (term + 30-day grace).
        NameTaken,
        NotRegistered,
        /// The wallet signature does not match the registration message.
        InvalidProof,
        /// The end of the term must be in the future, later than the current one when renewing, and within the maximum.
        BadExpiry,
        AlreadyRegistrar,
        /// Revoking needs a written reason.
        ReasonRequired,
        TooManyRegistrars,
        /// The offer is not from the current owner, has expired, or its number changed.
        BadOffer,
        /// The name is currently locked for another buyer.
        SaleLocked,
        /// There is no active sale lock for this name.
        NoSaleLock,
        /// The lock end must be in the future and within 60 minutes.
        BadLock,
        /// The price must be greater than zero.
        BadPrice,
        /// Unknown payment network, or one that does not fit the seller's receiving address (EVM or Solana).
        BadRail,
        /// The exact amount must be between the signed price and the price + 0.10 dollars.
        BadAmount,
        /// The payment reference is not a valid `<chain>:<tx hash>` for the lock's network.
        BadPaymentRef,
        /// The payment reference was used for an earlier sale.
        PaymentRefUsed,
        /// A v2 lock completes only with the payment reference (`complete_sale_v2`).
        PaymentRefRequired,
        /// `complete_sale_v2` needs a v2 lock that holds the amount and the network.
        NotV2Lock,
        /// (spec 8) Re-registering a name for the same owner cannot shorten its paid term.
        ExpiryShortened,
        /// (spec 8) The old `lock_sale`/`complete_sale` were disabled, and removed in spec 9. The error stays so the indices
        /// of the errors after it do not change.
        V1SaleRemoved,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Registers the name to the signer's wallet until `expires`. The same owner can register again (treated as an extension).
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::register())]
        pub fn register(
            origin: OriginFor<T>,
            name: NameOf,
            proof: WalletProof,
            expires: u64,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(Self::is_registrar(&who), Error::<T>::NotRegistrar);
            ensure!(valid_name(&name), Error::<T>::InvalidName);
            ensure!(
                !Reserved::<T>::contains_key(&name),
                Error::<T>::NameReserved
            );
            let now = T::Time::now().as_millis() as u64;
            ensure!(
                expires > now && expires <= now.saturating_add(T::MaxTermMs::get()),
                Error::<T>::BadExpiry
            );
            let owner =
                verify_proof(&proof, &register_message(&name)).ok_or(Error::<T>::InvalidProof)?;
            let registered = match Names::<T>::get(&name) {
                // Same owner: extension only. The registrar cannot shorten a paid term and then take the name after it ends (security 2026-10-12).
                Some(r) if r.owner == owner => {
                    ensure!(expires >= r.expires, Error::<T>::ExpiryShortened);
                    r.registered
                }
                Some(r) if r.expires.saturating_add(GRACE_MS) > now => {
                    return Err(Error::<T>::NameTaken.into())
                }
                _ => {
                    Self::new_owner(&name);
                    now
                }
            };
            Names::<T>::insert(
                &name,
                NameRecord {
                    owner: owner.clone(),
                    registered,
                    expires,
                    registrar: who,
                },
            );
            Self::deposit_event(Event::Registered {
                name,
                owner,
                expires,
            });
            Ok(())
        }

        /// Extends the term of a registered name (the owner does not change).
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::renew())]
        pub fn renew(origin: OriginFor<T>, name: NameOf, expires: u64) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(Self::is_registrar(&who), Error::<T>::NotRegistrar);
            let now = T::Time::now().as_millis() as u64;
            Names::<T>::try_mutate(&name, |r| {
                let r = r.as_mut().ok_or(Error::<T>::NotRegistered)?;
                // After the grace period the name no longer belongs to its owner: it must be registered again with a signature.
                ensure!(
                    r.expires.saturating_add(GRACE_MS) > now,
                    Error::<T>::NotRegistered
                );
                ensure!(
                    expires > r.expires && expires <= now.saturating_add(T::MaxTermMs::get()),
                    Error::<T>::BadExpiry
                );
                r.expires = expires;
                Ok::<_, DispatchError>(())
            })?;
            Self::deposit_event(Event::Renewed { name, expires });
            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::admin())]
        pub fn add_registrar(origin: OriginFor<T>, who: T::AccountId) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            Registrars::<T>::try_mutate(|s| {
                ensure!(!s.contains(&who), Error::<T>::AlreadyRegistrar);
                s.try_push(who.clone())
                    .map_err(|_| Error::<T>::TooManyRegistrars)?;
                Ok::<_, DispatchError>(())
            })?;
            Self::deposit_event(Event::RegistrarAdded { who });
            Ok(())
        }

        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::admin())]
        pub fn remove_registrar(origin: OriginFor<T>, who: T::AccountId) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            Registrars::<T>::try_mutate(|s| {
                let i = s
                    .iter()
                    .position(|x| x == &who)
                    .ok_or(Error::<T>::NotRegistrar)?;
                s.remove(i);
                Ok::<_, DispatchError>(())
            })?;
            Self::deposit_event(Event::RegistrarRemoved { who });
            Ok(())
        }

        /// Adds a name to the reserved list or removes it. Does not touch a name that is already registered.
        #[pallet::call_index(4)]
        #[pallet::weight(T::WeightInfo::admin())]
        pub fn set_reserved(origin: OriginFor<T>, name: NameOf, reserved: bool) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            ensure!(valid_name(&name), Error::<T>::InvalidName);
            if reserved {
                Reserved::<T>::insert(&name, ());
            } else {
                Reserved::<T>::remove(&name);
            }
            Self::deposit_event(Event::ReservedSet { name, reserved });
            Ok(())
        }

        /// Emergency tool: revokes a registered name for proven fraud (2-of-3 committee only). The reason is recorded publicly,
        /// and the name is added to the reserved list so it cannot be registered again without a new committee decision.
        #[pallet::call_index(5)]
        #[pallet::weight(T::WeightInfo::revoke())]
        pub fn revoke(
            origin: OriginFor<T>,
            name: NameOf,
            reason: BoundedVec<u8, ConstU32<256>>,
        ) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            ensure!(!reason.is_empty(), Error::<T>::ReasonRequired);
            let r = Names::<T>::take(&name).ok_or(Error::<T>::NotRegistered)?;
            Reserved::<T>::insert(&name, ());
            Self::new_owner(&name);
            Self::deposit_event(Event::Revoked {
                name,
                owner: r.owner,
                reason,
            });
            Ok(())
        }

        /// The owner cancels their offers for this name (with their signature). Not possible during an active sale lock.
        #[pallet::call_index(8)]
        #[pallet::weight(T::WeightInfo::register())]
        pub fn cancel_offer(
            origin: OriginFor<T>,
            name: NameOf,
            owner_proof: WalletProof,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(Self::is_registrar(&who), Error::<T>::NotRegistrar);
            let now = T::Time::now().as_millis() as u64;
            let r = Names::<T>::get(&name).ok_or(Error::<T>::NotRegistered)?;
            ensure!(!Self::locked(&name, now), Error::<T>::SaleLocked);
            let nonce = SaleNonce::<T>::get(&name);
            let owner = verify_proof(&owner_proof, &cancel_message(&name, nonce))
                .ok_or(Error::<T>::InvalidProof)?;
            ensure!(owner == r.owner, Error::<T>::BadOffer);
            SaleNonce::<T>::insert(&name, nonce.wrapping_add(1));
            Locks::<T>::remove(&name);
            LockTerms::<T>::remove(&name);
            Self::deposit_event(Event::OfferCancelled { name });
            Ok(())
        }

        /// (spec 8) Like `lock_sale` with the exact amount the buyer will pay the seller (`pay_amount`, micro units with 6 decimals)
        /// and the payment network (`rail`: 0 solana_usdc, 1 solana_usdt, 2 base_usdc, 3 arbitrum_usdc, 4 arbitrum_usdt).
        /// The amount is within [signed price, price + 0.10), and the network fits the receiving address; both are in the lock and in `SaleLockedV2`.
        #[pallet::call_index(9)]
        #[pallet::weight(T::WeightInfo::sale_v2())]
        #[allow(clippy::too_many_arguments)]
        pub fn lock_sale_v2(
            origin: OriginFor<T>,
            name: NameOf,
            seller_proof: WalletProof,
            price_cents: u64,
            pay_to: BoundedVec<u8, ConstU32<MAX_PAY_TO>>,
            offer_until: u64,
            buyer_proof: WalletProof,
            lock_until: u64,
            pay_amount: u64,
            rail: u8,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(Self::is_registrar(&who), Error::<T>::NotRegistrar);
            ensure!(
                rail < RAILS && rail_fits_pay_to(rail, &pay_to),
                Error::<T>::BadRail
            );
            ensure!(
                amount_fits_price(pay_amount, price_cents),
                Error::<T>::BadAmount
            );
            let buyer = Self::do_lock(
                &who,
                &name,
                seller_proof,
                price_cents,
                &pay_to,
                offer_until,
                buyer_proof,
                lock_until,
            )?;
            Locks::<T>::insert(
                &name,
                SaleLock {
                    buyer: buyer.clone(),
                    until: lock_until,
                    price_cents,
                    pay_to: pay_to.clone(),
                },
            );
            LockTerms::<T>::insert(&name, SaleTerms { rail, pay_amount });
            Self::deposit_event(Event::SaleLockedV2 {
                name,
                buyer,
                price_cents,
                until: lock_until,
                pay_to,
                rail,
                amount: pay_amount,
            });
            Ok(())
        }

        /// (spec 8) Completes a v2 lock sale with the payment reference `<chain>:<tx hash>` (like `base:0x…` or `solana:<signature>`) from the lock's
        /// network. The reference is stored so it cannot complete another sale, and `SaleCompletedV2` is emitted with the amount, the network and the reference.
        #[pallet::call_index(10)]
        #[pallet::weight(T::WeightInfo::complete_v2())]
        pub fn complete_sale_v2(
            origin: OriginFor<T>,
            name: NameOf,
            payment_ref: PaymentRef,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(Self::is_registrar(&who), Error::<T>::NotRegistrar);
            let now = T::Time::now().as_millis() as u64;
            let lock = Locks::<T>::get(&name)
                .filter(|l| l.until >= now)
                .ok_or(Error::<T>::NoSaleLock)?;
            let terms = LockTerms::<T>::get(&name).ok_or(Error::<T>::NotV2Lock)?;
            ensure!(
                valid_payment_ref(terms.rail, &payment_ref),
                Error::<T>::BadPaymentRef
            );
            let ref_key = sp_io::hashing::blake2_256(&payment_ref);
            ensure!(
                !UsedPaymentRefs::<T>::contains_key(ref_key),
                Error::<T>::PaymentRefUsed
            );
            let from = Self::move_name(&who, &name, &lock, now)?;
            UsedPaymentRefs::<T>::insert(ref_key, name.clone());
            Self::deposit_event(Event::SaleCompletedV2 {
                name,
                from,
                to: lock.buyer,
                price_cents: lock.price_cents,
                pay_to: lock.pay_to,
                rail: terms.rail,
                amount: terms.pay_amount,
                payment_ref,
            });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        pub fn is_registrar(who: &T::AccountId) -> bool {
            Registrars::<T>::get().contains(who)
        }

        /// Is the name locked for a buyer right now? An expired lock has no effect.
        pub fn locked(name: &NameOf, now: u64) -> bool {
            Locks::<T>::get(name).is_some_and(|l| l.until >= now)
        }

        /// A new owner: all previous offers and locks lapse.
        fn new_owner(name: &NameOf) {
            SaleNonce::<T>::mutate(name, |n| *n = n.wrapping_add(1));
            Locks::<T>::remove(name);
            LockTerms::<T>::remove(name);
        }

        /// Lock checks shared by v1 and v2: the registrar, the price, the name is active, the window, the current owner's offer and the buyer's acceptance.
        #[allow(clippy::too_many_arguments)]
        fn do_lock(
            who: &T::AccountId,
            name: &NameOf,
            seller_proof: WalletProof,
            price_cents: u64,
            pay_to: &[u8],
            offer_until: u64,
            buyer_proof: WalletProof,
            lock_until: u64,
        ) -> Result<Wallet, DispatchError> {
            ensure!(Self::is_registrar(who), Error::<T>::NotRegistrar);
            ensure!(price_cents > 0, Error::<T>::BadPrice);
            let now = T::Time::now().as_millis() as u64;
            let r = Names::<T>::get(name).ok_or(Error::<T>::NotRegistered)?;
            ensure!(r.expires > now, Error::<T>::NotRegistered);
            ensure!(offer_until >= now, Error::<T>::BadOffer);
            ensure!(
                lock_until > now && lock_until <= now.saturating_add(MAX_LOCK_MS),
                Error::<T>::BadLock
            );
            ensure!(!Self::locked(name, now), Error::<T>::SaleLocked);
            let nonce = SaleNonce::<T>::get(name);
            let seller = verify_proof(
                &seller_proof,
                &sale_message(name, nonce, price_cents, pay_to, offer_until),
            )
            .ok_or(Error::<T>::InvalidProof)?;
            ensure!(seller == r.owner, Error::<T>::BadOffer);
            let buyer = verify_proof(&buyer_proof, &buy_message(name, nonce, price_cents))
                .ok_or(Error::<T>::InvalidProof)?;
            ensure!(buyer != r.owner, Error::<T>::BadOffer);
            Ok(buyer)
        }

        /// Moves the name to the buyer it was locked for (the term is unchanged) and drops every offer and lock. Returns the previous owner.
        fn move_name(
            who: &T::AccountId,
            name: &NameOf,
            lock: &SaleLock,
            now: u64,
        ) -> Result<Wallet, DispatchError> {
            let from = Names::<T>::try_mutate(name, |r| {
                let r = r.as_mut().ok_or(Error::<T>::NotRegistered)?;
                let from = core::mem::replace(&mut r.owner, lock.buyer.clone());
                r.registered = now;
                r.registrar = who.clone();
                Ok::<_, DispatchError>(from)
            })?;
            Self::new_owner(name);
            Ok(from)
        }
    }
}

#[cfg(test)]
mod tests;

// Benchmarks only. At the end of the file so no line above moves (the default wasm embeds panic line numbers).
#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarking;
