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

/// (spec 9) A registration request with a v2 message: like [`Entry`] with the signature deadline (`valid_until`, UTC milliseconds). Without a signature it has no effect.
#[derive(
    Encode, Decode, DecodeWithMemTracking, Clone, PartialEq, Eq, Debug, TypeInfo, MaxEncodedLen,
)]
pub struct EntryV2 {
    pub fingerprint: Fingerprint,
    pub name_hash: Option<Fingerprint>,
    pub proof: Option<WalletProof>,
    pub valid_until: u64,
}

/// (spec 9) The maximum deadline for signing a v2 stamp: one day.
pub const MAX_STAMP_PROOF_MS: u64 = 24 * 3600 * 1000;

/// Lowercase hex.
pub fn hex_into(out: &mut Vec<u8>, bytes: &[u8]) {
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

/// (spec 9) The tail of every v2 message (Madar Stamp and Madar Names): `\nnetwork: 0x<hash of block 0>\nvalid until: <ms UTC>`.
/// Binds the signature to this network only and to a deadline. No off-chain message writes it.
pub fn network_tail(m: &mut Vec<u8>, network: &[u8], valid_until: u64) {
    m.extend_from_slice(b"\nnetwork: 0x");
    hex_into(m, network);
    m.extend_from_slice(b"\nvalid until: ");
    let mut d = [0u8; 20];
    let mut i = d.len();
    let mut v = valid_until;
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

/// (spec 9) v2 message: the v1 text + the network and deadline tail.
pub fn signed_message_v2(
    fingerprint: &Fingerprint,
    name_hash: &Option<Fingerprint>,
    network: &[u8],
    valid_until: u64,
) -> Vec<u8> {
    let mut m = signed_message(fingerprint, name_hash);
    network_tail(&mut m, network, valid_until);
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

/// (spec 9, independent review #2) How long v1 messages are accepted after the spec 9 upgrade: 72 hours from the upgrade time, then refused automatically without any
/// committee decision. The same value for Madar Stamp and Madar Names.
pub const LEGACY_SUNSET_MS: u64 = 72 * 3600 * 1000;
/// (spec 9) The maximum extension of the v1 deadline in one committee decision: 7 days past the current deadline (shortening without limit).
pub const MAX_LEGACY_EXTENSION_MS: u64 = 7 * 24 * 3600 * 1000;

/// (spec 9) May the committee set the v1 deadline to `new` when the current deadline is `current`? Shortening, or extension by up to 7 days only.
pub fn legacy_change_allowed(current: u64, new: u64) -> bool {
    new <= current.saturating_add(MAX_LEGACY_EXTENSION_MS)
}

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use crate::weights::WeightInfo as _;
    use frame_support::sp_runtime::traits::Zero;
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
    /// 2 (spec 9) = the v1 message deadline (`LegacyAcceptedUntil`) was set to the upgrade time + 72 hours, once.
    pub const STORAGE_VERSION: StorageVersion = StorageVersion::new(2);

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

    /// (spec 9, independent review #2) The old `stamp` call (a v1 message with no network and no deadline) is accepted only before this time (UTC
    /// milliseconds). The spec 9 migration sets it once to the upgrade time + 72 hours, so v1 stops on its own without a committee decision. A new chain
    /// (Genesis) starts at 0: v1 is refused from the start. The committee can shorten it, or extend it by up to 7 days per decision.
    #[pallet::storage]
    pub type LegacyAcceptedUntil<T: Config> = StorageValue<_, u64, ValueQuery>;

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
        /// (spec 9) The v2 signature deadline has passed or is more than a day away — the stamp was not recorded.
        ProofExpired {
            fingerprint: Fingerprint,
        },
        /// (spec 9) The deadline of the old `stamp` call was set (by the migration or by a committee decision).
        LegacyAcceptedUntilSet {
            until: u64,
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
        /// (spec 9) The deadline of the old `stamp` call has passed: use `stamp_v2`.
        LegacyMessagesOff,
        /// (spec 9) An extension of more than 7 days past the current deadline in one decision.
        LegacyExtensionTooLong,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        /// spec 9: 1 -> 2 once: the v1 deadline = the upgrade time (the last block's timestamp) + 72 hours.
        fn on_runtime_upgrade() -> Weight {
            if Pallet::<T>::on_chain_storage_version() < STORAGE_VERSION {
                let until = (T::Time::now().as_millis() as u64).saturating_add(LEGACY_SUNSET_MS);
                LegacyAcceptedUntil::<T>::put(until);
                STORAGE_VERSION.put::<Pallet<T>>();
                Self::deposit_event(Event::LegacyAcceptedUntilSet { until });
                T::DbWeight::get().reads_writes(2, 4)
            } else {
                T::DbWeight::get().reads(1)
            }
        }
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
            ensure!(Self::legacy_open(moment), Error::<T>::LegacyMessagesOff);
            for e in entries.into_iter() {
                Self::stamp_one(
                    &who,
                    block,
                    moment,
                    e.fingerprint,
                    e.name_hash,
                    e.proof
                        .as_ref()
                        .map(|p| (p, signed_message(&e.fingerprint, &e.name_hash))),
                );
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

        /// (spec 9) Like `stamp` with a v2 message: the signature is bound to this network and valid until `valid_until` (up to one day from now).
        /// An expired signature, or one more than a day away, is skipped with a `ProofExpired` event, and the rest are recorded.
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::stamp_v2(entries.len() as u32))]
        pub fn stamp_v2(
            origin: OriginFor<T>,
            entries: BoundedVec<EntryV2, T::MaxBatch>,
        ) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(Self::is_stamper(&who), Error::<T>::NotStamper);
            ensure!(!entries.is_empty(), Error::<T>::EmptyBatch);
            let block = frame_system::Pallet::<T>::block_number();
            let moment = T::Time::now().as_millis() as u64;
            let network = frame_system::Pallet::<T>::block_hash(BlockNumberFor::<T>::zero());
            for e in entries.into_iter() {
                if e.proof.is_some()
                    && !(e.valid_until >= moment
                        && e.valid_until <= moment.saturating_add(MAX_STAMP_PROOF_MS))
                {
                    if !Stamps::<T>::contains_key(e.fingerprint) {
                        Self::deposit_event(Event::ProofExpired {
                            fingerprint: e.fingerprint,
                        });
                        continue;
                    }
                }
                let msg = e.proof.as_ref().map(|p| {
                    (
                        p,
                        signed_message_v2(
                            &e.fingerprint,
                            &e.name_hash,
                            network.as_ref(),
                            e.valid_until,
                        ),
                    )
                });
                Self::stamp_one(&who, block, moment, e.fingerprint, e.name_hash, msg);
            }
            Ok(())
        }

        /// (spec 9) 2-of-3 committee only: the deadline of the old `stamp` call. Shortening without limit (0 = stop immediately), or extension by up to 7 days
        /// past the current deadline per decision — so v1 cannot be reopened without end by a single decision.
        #[pallet::call_index(4)]
        #[pallet::weight(T::WeightInfo::set_stamper())]
        pub fn set_legacy_accepted_until(origin: OriginFor<T>, until: u64) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            ensure!(
                legacy_change_allowed(LegacyAcceptedUntil::<T>::get(), until),
                Error::<T>::LegacyExtensionTooLong
            );
            LegacyAcceptedUntil::<T>::put(until);
            Self::deposit_event(Event::LegacyAcceptedUntilSet { until });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// One entry: a duplicate is skipped with an event, a wrong signature is skipped with an event, and the rest are recorded (the first one wins).
        fn stamp_one(
            who: &T::AccountId,
            block: BlockNumberFor<T>,
            moment: u64,
            fingerprint: Fingerprint,
            name_hash: Option<Fingerprint>,
            proof: Option<(&WalletProof, Vec<u8>)>,
        ) {
            if Stamps::<T>::contains_key(fingerprint) {
                Self::deposit_event(Event::AlreadyStamped { fingerprint });
                return;
            }
            let wallet = match proof {
                None => None,
                Some((p, msg)) => match verify_proof(p, &msg) {
                    Some(w) => Some(w),
                    None => {
                        Self::deposit_event(Event::InvalidProof { fingerprint });
                        return;
                    }
                },
            };
            Stamps::<T>::insert(
                fingerprint,
                Record {
                    block,
                    moment,
                    stamper: who.clone(),
                    wallet: wallet.clone(),
                    name_hash,
                },
            );
            Self::deposit_event(Event::Stamped {
                fingerprint,
                wallet,
            });
        }

        /// (spec 9) Are v1 messages still accepted at time `now` (milliseconds)?
        pub fn legacy_open(now: u64) -> bool {
            now < LegacyAcceptedUntil::<T>::get()
        }

        /// Is the account an approved stamper? (Used by the runtime's account-creation policy.)
        pub fn is_stamper(who: &T::AccountId) -> bool {
            Stampers::<T>::get().contains(who)
        }
    }
}

#[cfg(test)]
mod tests;

// Benchmarks only. At the end of the file so no line above moves (the default wasm embeds panic line numbers).
#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarking;
