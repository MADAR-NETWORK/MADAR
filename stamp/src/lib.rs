//! Madar Stamp — permanent timestamps for file fingerprints (SHA-256), "first one wins".
//!
//! **What is stored:** the file fingerprint only (32 bytes), never the file or any of its content. Optionally,
//! the fingerprint of the registrant's name (not the name itself — the network is public and permanent, and a name is personal data).
//!
//! **No duplicates:** a registered fingerprint is never registered again; the first registration is the permanent reference,
//! so nobody can register the same file with a later date and then claim precedence.
//!
//! **Binding the registrant to their wallet (verified by the runtime itself):** each registration may carry
//! the owner's wallet signature over a fixed message containing the fingerprint and the name fingerprint — either EVM
//! (`personal_sign`/EIP-191, e.g. MetaMask) or Solana (`signMessage`, Ed25519, e.g. Phantom).
//! The pallet rejects any signature that does not match the declared address, so the "signing wallet" in the record is proven
//! mathematically, not by trusting the Madar service. A later "I am the registrant" proof = a new signature with the same wallet
//! (off-chain, on the verification page).
//!
//! **Who submits:** approved "stamper" accounts only — added and removed by the upgrade committee
//! (2-of-3) via `AdminOrigin`. This is the spam control on a fee-less network (D17): no random account
//! can fill the storage. A batch is processed entry by entry: a duplicate or a wrong signature
//! is skipped with an event and does not fail the rest of the batch.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

extern crate alloc;

pub mod weights;

pub use pallet::*;

use alloc::vec::Vec;
use parity_scale_codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

/// A SHA-256 fingerprint of a file (or of a name).
pub type Fingerprint = [u8; 32];

/// The registrant's wallet as proven by the signature.
#[derive(
    Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo, MaxEncodedLen,
)]
pub enum Wallet {
    /// An EVM address (20 bytes) — MetaMask and others.
    Evm([u8; 20]),
    /// A Solana public key (Ed25519, 32 bytes) — Phantom and others.
    Solana([u8; 32]),
}

/// The wallet signature over [`signed_message`].
#[derive(
    Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo, MaxEncodedLen,
)]
pub enum WalletProof {
    /// `personal_sign` (EIP-191): r‖s‖v, with `v` = 0/1 or 27/28.
    Evm {
        address: [u8; 20],
        signature: [u8; 65],
    },
    /// `signMessage`: a raw Ed25519 signature over the message bytes.
    Solana {
        public: [u8; 32],
        signature: [u8; 64],
    },
}

/// One registration request inside a batch.
#[derive(
    Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo, MaxEncodedLen,
)]
pub struct Entry {
    pub fingerprint: Fingerprint,
    /// The fingerprint of the registrant's name as entered (optional). The name itself is printed on the receipt only.
    pub name_hash: Option<Fingerprint>,
    /// The wallet signature (optional; without it the registration proves existence only, not the owner).
    pub proof: Option<WalletProof>,
}

/// The permanent record of a fingerprint.
#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug, TypeInfo, MaxEncodedLen)]
pub struct Record<AccountId, BlockNumber> {
    pub block: BlockNumber,
    /// Block time (milliseconds since 1970, UTC).
    pub moment: u64,
    pub stamper: AccountId,
    pub wallet: Option<Wallet>,
    pub name_hash: Option<Fingerprint>,
}

fn hex_into(out: &mut Vec<u8>, bytes: &[u8]) {
    const H: &[u8; 16] = b"0123456789abcdef";
    for b in bytes {
        out.push(H[(b >> 4) as usize]);
        out.push(H[(b & 15) as usize]);
    }
}

/// The message signed by the wallet — a fixed ASCII text the user sees in the signing window.
/// Any change to it breaks all future signatures, so it is part of the network protocol.
pub fn signed_message(fingerprint: &Fingerprint, name_hash: &Option<Fingerprint>) -> Vec<u8> {
    let mut m = Vec::with_capacity(200);
    m.extend_from_slice(
        b"MADAR Stamp: sign to register this file fingerprint. No funds move.\nfingerprint: ",
    );
    hex_into(&mut m, fingerprint);
    m.extend_from_slice(b"\nname: ");
    match name_hash {
        Some(h) => hex_into(&mut m, h),
        None => m.extend_from_slice(b"none"),
    }
    m
}

/// Verifies the wallet signature and returns the proven wallet, or `None` if it does not match.
pub fn verify_proof(proof: &WalletProof, message: &[u8]) -> Option<Wallet> {
    match proof {
        WalletProof::Evm { address, signature } => {
            let mut prefixed = Vec::with_capacity(32 + message.len());
            prefixed.extend_from_slice(b"\x19Ethereum Signed Message:\n");
            let mut len = Vec::new();
            let mut n = message.len();
            loop {
                len.push(b'0' + (n % 10) as u8);
                n /= 10;
                if n == 0 {
                    break;
                }
            }
            len.reverse();
            prefixed.extend_from_slice(&len);
            prefixed.extend_from_slice(message);
            let digest = sp_io::hashing::keccak_256(&prefixed);
            let mut sig = *signature;
            if sig[64] >= 27 {
                sig[64] -= 27;
            }
            if sig[64] > 1 {
                return None;
            }
            let public = sp_io::crypto::secp256k1_ecdsa_recover(&sig, &digest).ok()?;
            let hash = sp_io::hashing::keccak_256(&public);
            (hash[12..] == address[..]).then_some(Wallet::Evm(*address))
        }
        WalletProof::Solana { public, signature } => {
            let sig = sp_core::ed25519::Signature::from_raw(*signature);
            let pk = sp_core::ed25519::Public::from_raw(*public);
            sp_io::crypto::ed25519_verify(&sig, message, &pk).then_some(Wallet::Solana(*public))
        }
    }
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use crate::weights::WeightInfo as _;
    use frame_support::{pallet_prelude::*, traits::UnixTime};
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config<RuntimeEvent: From<Event<Self>>> {
        /// Adding/removing stampers — in the runtime: the 2-of-3 upgrade committee.
        type AdminOrigin: EnsureOrigin<Self::RuntimeOrigin>;
        /// Block time (`pallet_timestamp` in the runtime).
        type Time: UnixTime;
        /// The maximum number of entries in one batch.
        #[pallet::constant]
        type MaxBatch: Get<u32>;
        /// The maximum number of approved stamper accounts.
        #[pallet::constant]
        type MaxStampers: Get<u32>;
        type WeightInfo: crate::weights::WeightInfo;
    }

    /// 1 = the first stamper was seeded (a one-time runtime migration; not repeated in later upgrades).
    pub const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);

    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
    pub struct Pallet<T>(_);

    /// Fingerprint → its permanent record. No deletion or modification by any call.
    #[pallet::storage]
    pub type Stamps<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        Fingerprint,
        Record<T::AccountId, BlockNumberFor<T>>,
        OptionQuery,
    >;

    /// The approved stamper accounts.
    #[pallet::storage]
    pub type Stampers<T: Config> =
        StorageValue<_, BoundedVec<T::AccountId, T::MaxStampers>, ValueQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A new fingerprint was registered.
        Stamped {
            fingerprint: Fingerprint,
            wallet: Option<Wallet>,
        },
        /// The fingerprint was already registered — nothing changed (the first one stays the reference).
        AlreadyStamped {
            fingerprint: Fingerprint,
        },
        /// The wallet signature does not match — the fingerprint was not registered.
        InvalidProof {
            fingerprint: Fingerprint,
        },
        StamperAdded {
            who: T::AccountId,
        },
        StamperRemoved {
            who: T::AccountId,
        },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// The sender is not an approved stamper account.
        NotStamper,
        /// An empty batch.
        EmptyBatch,
        AlreadyStamper,
        TooManyStampers,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Registers a batch of fingerprints. Duplicates and wrong signatures are skipped with an event; the rest are registered.
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::stamp(entries.len() as u32))]
        pub fn stamp(
            origin: OriginFor<T>,
            entries: BoundedVec<Entry, T::MaxBatch>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(Self::is_stamper(&who), Error::<T>::NotStamper);
            ensure!(!entries.is_empty(), Error::<T>::EmptyBatch);
            let block = frame_system::Pallet::<T>::block_number();
            let moment = T::Time::now().as_millis() as u64;
            for e in entries.into_iter() {
                if Stamps::<T>::contains_key(e.fingerprint) {
                    Self::deposit_event(Event::AlreadyStamped {
                        fingerprint: e.fingerprint,
                    });
                    continue;
                }
                let wallet = match &e.proof {
                    None => None,
                    Some(p) => match verify_proof(p, &signed_message(&e.fingerprint, &e.name_hash))
                    {
                        Some(w) => Some(w),
                        None => {
                            Self::deposit_event(Event::InvalidProof {
                                fingerprint: e.fingerprint,
                            });
                            continue;
                        }
                    },
                };
                Stamps::<T>::insert(
                    e.fingerprint,
                    Record {
                        block,
                        moment,
                        stamper: who.clone(),
                        wallet: wallet.clone(),
                        name_hash: e.name_hash,
                    },
                );
                Self::deposit_event(Event::Stamped {
                    fingerprint: e.fingerprint,
                    wallet,
                });
            }
            Ok(())
        }

        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::set_stamper())]
        pub fn add_stamper(origin: OriginFor<T>, who: T::AccountId) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            Stampers::<T>::try_mutate(|s| {
                ensure!(!s.contains(&who), Error::<T>::AlreadyStamper);
                s.try_push(who.clone())
                    .map_err(|_| Error::<T>::TooManyStampers)?;
                Ok::<_, DispatchError>(())
            })?;
            Self::deposit_event(Event::StamperAdded { who });
            Ok(())
        }

        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::set_stamper())]
        pub fn remove_stamper(origin: OriginFor<T>, who: T::AccountId) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            Stampers::<T>::try_mutate(|s| {
                let i = s
                    .iter()
                    .position(|x| x == &who)
                    .ok_or(Error::<T>::NotStamper)?;
                s.remove(i);
                Ok::<_, DispatchError>(())
            })?;
            Self::deposit_event(Event::StamperRemoved { who });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// Is the account an approved stamper? (Used by the runtime's account-creation policy.)
        pub fn is_stamper(who: &T::AccountId) -> bool {
            Stampers::<T>::get().contains(who)
        }
    }
}

#[cfg(test)]
mod tests;
