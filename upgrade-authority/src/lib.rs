//! Runtime upgrade authority — a Root gate through a 2-of-3 committee (D43, §13).
//!
//! **Decision (2026-09-18):** no `pallet_sudo`, no single key, no emergency
//! bypass path. Any call that requires `Root` (most importantly `system.set_code` to upgrade
//! the runtime itself) goes **exclusively** through [`Pallet::dispatch_as_root`], locked
//! by `T::ApprovedOrigin` — in the actual runtime: `EnsureProportionAtLeast`
//! on a committee (`pallet_collective`) of 3 members with a threshold of 2 (§2/§3 of
//! the design document).
//!
//! **Security separation from daily operation:** the committee accounts here are a key space
//! **completely independent** of the BABE/GRANDPA (consensus) keys and the release-signing
//! keys (D35/D43, Ed25519 off-chain) — no overlap, no sharing.
//! The failure/compromise of a single operational node **grants no** upgrade authority at all.
//!
//! **Revocation/replacement without breaking 2-of-3:** committee membership itself is managed through
//! `pallet_collective::set_members`, locked by the **same** `T::ApprovedOrigin`
//! (`SetMembersOrigin` in the `pallet_collective` configuration of the runtime) — any
//! replacement of a lost/compromised member needs **the approval of two other members of the original three**,
//! exactly like a runtime upgrade; no easier path and no external authority. This matches the
//! D35 SOP for release keys
//! in principle, but it is a completely separate key space as stated above.
//!
//! **Later upgrade path to community governance (without rebuilding):** `T::ApprovedOrigin`
//! is a config parameter that can be fully rewired at any later runtime upgrade —
//! replacing it with an origin derived from `pallet_democracy` / a broader community vote only requires
//! changing the type definition in `consensus/src/lib.rs` at that same upgrade
//! (which itself goes through this 2-of-3 mechanism) — **no change to this
//! pallet itself is required at all** for that transition.
//!
//! **Weight:** the `dispatch_as_root` declaration = the wrapper weight (`WeightInfo`) +
//! the inner call's weight and class (the same pattern as `pallet_sudo`), and the actual weight of the inner
//! call is carried in the result. The wrapper weight is a conservative upper bound (not a FRAME benchmark)
//! and affects no security check here — every threshold/membership check is strict regardless of it.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

extern crate alloc;

pub mod weights;

pub use pallet::*;

/// The upgrade-committee interface as seen by this pallet (implemented by the runtime on top of `pallet_collective`).
pub trait CommitteeControl<AccountId> {
    /// The current membership.
    fn members() -> alloc::vec::Vec<AccountId>;
    /// Replace the membership with a **sorted** list.
    fn replace(sorted_new: &[AccountId]);
}

#[frame_support::pallet]
pub mod pallet {
    use crate::weights::WeightInfo as _;
    use crate::CommitteeControl as _;
    use alloc::boxed::Box;
    use alloc::vec::Vec;
    use frame_support::{
        dispatch::{extract_actual_weight, GetDispatchInfo, PostDispatchInfo},
        pallet_prelude::*,
        traits::UnfilteredDispatchable,
    };
    use frame_system::pallet_prelude::*;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// Any call that can be dispatched through this pallet (including
        /// `system.set_code`) — actually executed with origin = `Root`
        /// **only after** successfully passing `ApprovedOrigin` below, never before.
        type RuntimeCall: Parameter
            + UnfilteredDispatchable<RuntimeOrigin = Self::RuntimeOrigin>
            + GetDispatchInfo;

        /// The actual approval condition — in the runtime: a 2-of-3 threshold on an independent
        /// `pallet_collective` committee. **This is the only security control of this
        /// entire pallet** — no other path, no exception.
        type ApprovedOrigin: EnsureOrigin<Self::RuntimeOrigin>;

        /// The wrapper weight (the inner call is accounted in the call declaration).
        type WeightInfo: crate::weights::WeightInfo;

        /// The committee itself (reading and replacing its membership) — wired by the runtime to the upgrade committee.
        type Committee: crate::CommitteeControl<Self::AccountId>;

        /// The fixed committee size (3): `2-of-3` makes no sense if the number changes. The only allowed replacement
        /// keeps the size exactly equal to this number.
        #[pallet::constant]
        type CommitteeSize: Get<u32>;

        /// The maximum number of open upgrade-committee proposals (`pallet_collective::MaxProposals`) — replacing the membership
        /// walks every proposal to clean the votes of departing members, so its cost scales with it.
        #[pallet::constant]
        type MaxCommitteeProposals: Get<u32>;
    }

    #[pallet::error]
    pub enum Error<T> {
        /// The number of new members does not equal `CommitteeSize` exactly.
        WrongCommitteeSize,
        /// A duplicated member.
        DuplicateMember,
    }

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        fn integrity_test() {
            assert!(
                T::CommitteeSize::get() >= 3,
                "a 2-of-N committee needs at least 3 members"
            );
        }
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A call was executed with Root origin after passing the committee approval (2-of-3).
        RootCallDispatched { result: DispatchResult },
        /// The committee membership was replaced with 2-of-3 approval while keeping the size fixed.
        CommitteeMembersReplaced,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Executes `call` with `Root` origin **only** if it passes `T::ApprovedOrigin`
        /// (a 2-of-3 threshold in the actual runtime). No other check, no bypass
        /// path — the very same pattern as `pallet_sudo::sudo` (a primitive already tested
        /// across the ecosystem), replacing the check of a single stored key
        /// with a committee-threshold check.
        #[pallet::call_index(0)]
        #[pallet::weight({
            let dispatch_info = call.get_dispatch_info();
            (
                T::WeightInfo::dispatch_as_root().saturating_add(dispatch_info.call_weight),
                dispatch_info.class,
            )
        })]
        pub fn dispatch_as_root(
            origin: OriginFor<T>,
            call: Box<<T as Config>::RuntimeCall>,
        ) -> DispatchResultWithPostInfo {
            T::ApprovedOrigin::ensure_origin(origin)?;

            let dispatch_info = call.get_dispatch_info();
            let res = call.dispatch_bypass_filter(frame_system::RawOrigin::Root.into());
            // The actual weight of the inner call is carried as it is (e.g. `set_code` returns
            // "everything left in the block" on purpose to prevent transactions after it), not swallowed.
            let inner_weight = extract_actual_weight(&res, &dispatch_info);
            Self::deposit_event(Event::RootCallDispatched {
                result: res.map(|_| ()).map_err(|e| e.error),
            });

            Ok(PostDispatchInfo {
                actual_weight: Some(T::WeightInfo::dispatch_as_root().saturating_add(inner_weight)),
                pays_fee: Pays::Yes,
            })
        }

        /// **The only way to change the committee membership** (`pallet_collective::set_members` is disabled in
        /// the runtime): `ApprovedOrigin` approval (2-of-3) **and** a new size = exactly `CommitteeSize`
        /// **and** no duplicates — so the committee can neither be reduced to 0/1/2 nor expanded in a way that weakens the ratio.
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::set_committee_members(T::MaxCommitteeProposals::get()))]
        pub fn set_committee_members(
            origin: OriginFor<T>,
            new_members: Vec<T::AccountId>,
        ) -> DispatchResult {
            T::ApprovedOrigin::ensure_origin(origin)?;
            ensure!(
                new_members.len() as u32 == T::CommitteeSize::get(),
                Error::<T>::WrongCommitteeSize
            );
            let mut sorted = new_members;
            sorted.sort();
            ensure!(
                sorted.windows(2).all(|w| w[0] != w[1]),
                Error::<T>::DuplicateMember
            );
            T::Committee::replace(&sorted);
            Self::deposit_event(Event::CommitteeMembersReplaced);
            Ok(())
        }
    }
}
