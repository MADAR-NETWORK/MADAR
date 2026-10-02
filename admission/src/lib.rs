//! Admission/Sybil resistance — a memory-hard computational puzzle (§2.9, D6, D26–D28).
//!
//! **Formula (§2.9):** a `nonce` satisfies `Argon2id(pubkey || epoch_seed || nonce)`
//! with a number of leading zero bits ≥ `DifficultyLeadingZeroBits` — a real memory-hard
//! function (D26: specifically Argon2id), not plain Blake2-256 over a simple input.
//!
//! **Cryptographic binding (§2.9):** the solution consumes `pubkey` (the signing origin),
//! `epoch_seed` (actual BABE randomness, below) and `nonce` together as one input —
//! a solution cannot be moved from one identity to another (Argon2id of a different input = a completely different output),
//! nor reused for another epoch (same reason: `epoch_seed` is part of the input).
//!
//! **The seed (§2.9 — "unpredictable, derived from verifiable final state (VRF)"):**
//! `T::EpochRandomness` — in the actual runtime it is
//! `pallet_babe::RandomnessFromOneEpochAgo` (real BABE VRF randomness, from
//! a full past epoch, **not randomness invented here**) — the first actual use of
//! `protocol::ADMISSION_PUZZLE_DOMAIN` (§2.7, Protocol phase) as the subject.
//!
//! **Weight (D6 — flat):** there is no weight field in this pallet at all — every accepted
//! validator is implicitly treated with equal weight (enforced by the **absence** of any
//! differentiable weight field, not by extra logic). `SessionManager` returns lists of accounts only, never
//! weights.
//!
//! **`SessionManager` (§2.9 — "feeds BABE/GRANDPA the validator list
//! and weights... through the standard `SessionManager` interface"):** this pallet
//! actually implements `pallet_session::SessionManager<AccountId>` — **replacing**
//! the `SessionManager = ()` reserved in the Consensus phase (§11.2 there), exactly
//! as documented: "without rebuilding BABE/GRANDPA".
//!
//! **Equivocation (implemented):** a valid GRANDPA/BABE proof together with a session-key ownership proof calls
//! `Pallet::ban` (a permanent ban) through `BanOnOffence` in the runtime; `ban_key` (Root) remains an administrative entry point.
//!
//! **All difficulty/cap numbers and Argon2 parameters below are non-final placeholders
//! (D26/D27/D28)** — settled by actual benchmarking/security testing before the public
//! testnet, as documented for similar numbers in earlier phases (D19/D22/D24).

//!
//! **Membership lifecycle (reviews #4/#5/#7):**
//! - **Joining = a lottery:** a correct solution does not make the account a validator immediately; it enters a limited
//!   candidate set (`MaxCandidatesPerRound`) whose content is not affected by transaction order (when
//!   full, the worst is replaced **by the Argon2 output itself**, not by a cheap key from the identity). The set is closed at the epoch boundary and
//!   the winners are drawn after `LOTTERY_DELAY_ROTATIONS` (=2) rotations with randomness built from VRFs written **after** the closing (the BABE seed + an internal per-block VRF accumulator, and only with enough fresh entropy)
//!   (an immediate draw with randomness known during candidacy was grindable: the attacker generates identities at no cost and submits
//!   only the lowest key). The order is `H(randomness‖account)` among those holding session keys at the draw. **Precision of the guarantee:** the randomness comes from
//!   `RandomnessFromOneEpochAgo` (a VRF over a whole epoch, not determined by a single block producer); the runtime
//!   does not see finality, so it is not claimed to be derived from finalized state.
//! - **Renewal:** a current member submits a new puzzle and its validity is extended by `MembershipTermSessions`;
//!   its accounting is completely separate from the new-identity cap (it does not compete with them).
//! - **Validity:** after the term ends a `RenewalGraceSessions` grace period begins (a warning event at every
//!   rotation), then the membership is removed at the epoch boundary. No removal ever empties the set (a liveness guarantee).
//! - **Exit/ban** are also executed at the epoch boundary, with the same no-emptying guarantee.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

extern crate alloc;

pub mod weights;

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use crate::weights::WeightInfo as _;
    use alloc::vec::Vec;
    use argon2::{Algorithm, Argon2, Params, Version};
    use frame_support::{
        dispatch::{DispatchClass, DispatchErrorWithPostInfo, PostDispatchInfo},
        pallet_prelude::*,
        traits::{Contains, Randomness},
    };
    use frame_system::pallet_prelude::*;

    /// Domain separating the lottery randomness from the puzzle randomness.
    pub const LOTTERY_DOMAIN: &[u8] = b"madar/admission-lottery/v1";
    /// Domain of the entropy accumulator (the VRF of every block).
    pub const ENTROPY_DOMAIN: &[u8] = b"madar/admission-entropy/v1";

    /// The number of rotations between closing the candidacy and the draw (a minimum). When round `s` closes (rotation k), `R(s+2)` is built
    /// entirely from the VRFs of epoch `s+1` written after the closing ⇒ the draw happens at rotation k+2 at the earliest.
    pub const LOTTERY_DELAY_ROTATIONS: u32 = 2;

    /// The maximum number of closed sets awaiting the draw (memory bound). No set is ever dropped; overflow restricts new candidacy.
    pub const MAX_PENDING_POOLS: usize = 4;

    /// A candidate: the account + the Argon2id output of its solution (bound to the account, the round and the nonce). **The output is the ordering key**.
    pub type Candidate<T> = (<T as frame_system::Config>::AccountId, [u8; 32]);
    pub type Pool<T> = BoundedVec<Candidate<T>, <T as Config>::MaxCandidatesPerRound>;

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

        /// BABE randomness for an epoch (`RandomnessFromOneEpochAgo`) — one of the two inputs of the draw seed.
        type EpochRandomness: Randomness<Self::Hash, BlockNumberFor<Self>>;

        /// A block VRF (`pallet_babe::ParentBlockRandomness`): accumulated inside MADAR in every block, so the fairness
        /// of the draw does not depend on a BABE epoch containing primary slots (`deposit_randomness` records only those).
        type BlockRandomness: Randomness<Option<Self::Hash>, BlockNumberFor<Self>>;

        /// The minimum number of fresh VRFs (after the round closes) that must enter the accumulator before the draw. Without them the draw is postponed.
        #[pallet::constant]
        type MinFreshEntropyBlocks: Get<u32>;

        /// The number of leading zero bits required in the Argon2id output — placeholder (D26).
        #[pallet::constant]
        type DifficultyLeadingZeroBits: Get<u32>;

        /// The maximum number of new winners per round (epoch) — placeholder (D27).
        #[pallet::constant]
        type AdmissionCapPerRound: Get<u32>;

        /// The candidate set size per round (≥ the winner cap).
        #[pallet::constant]
        type MaxCandidatesPerRound: Get<u32>;

        /// The overall maximum number of validators accepted at once.
        #[pallet::constant]
        type MaxValidators: Get<u32>;

        /// The membership term in sessions (epochs) — a non-final placeholder.
        #[pallet::constant]
        type MembershipTermSessions: Get<u32>;

        /// The grace period after the term ends, before removal (sessions) — placeholder.
        #[pallet::constant]
        type RenewalGraceSessions: Get<u32>;

        /// Does the account have registered session keys? (A winner without keys is not accepted.)
        type HasSessionKeys: Contains<Self::AccountId>;

        /// **Resistance to identity duplication (Sybil through one operator, D47):** the party that
        /// approves an "operator" and sets its vote cap — it must be independent governance
        /// (a multi-party committee); relying on a name typed by the operator itself
        /// is **not** accepted. In the actual runtime: the same 2-of-3 committee (D44/D45).
        type OperatorApprovalOrigin: EnsureOrigin<Self::RuntimeOrigin>;

        /// The origin of the two temporary administrative calls `ban_key` and `dev_only_force_set_validators`.
        /// In the actual runtime it is `EnsureNever` (closing N1):
        /// no origin reaches them, not even Root through the committee's `dispatch_as_root`. The production ban remains
        /// through the equivocation mechanism (`Pallet::ban`) alone.
        type AdminOrigin: EnsureOrigin<Self::RuntimeOrigin>;

        /// The absolute maximum number of votes (live validators at once)
        /// for any single operator — a second line of defense that governance cannot exceed by mistake
        /// whatever it approves. A non-final placeholder (the same pattern as D26/D27/D28), settled
        /// by an actual policy decision before the public testnet.
        #[pallet::constant]
        type MaxVotesPerOperator: Get<u32>;

        /// Argon2id parameters — placeholder (D26), awaiting actual benchmarking.
        #[pallet::constant]
        type ArgonMemoryCostKib: Get<u32>;
        #[pallet::constant]
        type ArgonTimeCost: Get<u32>;

        /// Weights of the calls and hooks — Argon2 computed from the parameters above, and storage from the set sizes.
        type WeightInfo: crate::weights::WeightInfo;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    #[pallet::hooks]
    impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
        /// Accumulates the previous block's VRF (if present and not already accumulated) into an internal hash chain.
        fn on_initialize(_now: BlockNumberFor<T>) -> Weight {
            Self::mix_parent_vrf();
            T::WeightInfo::on_initialize()
        }

        fn integrity_test() {
            assert!(
                Params::new(
                    T::ArgonMemoryCostKib::get(),
                    T::ArgonTimeCost::get(),
                    1,
                    Some(32)
                )
                .is_ok(),
                "Argon2 parameters from Config must be valid"
            );
            assert!(T::MaxCandidatesPerRound::get() >= T::AdmissionCapPerRound::get());
            assert!(T::MembershipTermSessions::get() > 0);
        }
    }

    /// The current validator set — accounts only, **with no stored weight** (D6).
    #[pallet::storage]
    pub type Validators<T: Config> =
        StorageValue<_, BoundedVec<T::AccountId, T::MaxValidators>, ValueQuery>;

    /// The last session (exclusive) of a member's validity — extended by renewal.
    #[pallet::storage]
    pub type MembershipExpiry<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, u32, OptionQuery>;

    /// The current session number (updated from `start_session`).
    #[pallet::storage]
    pub type CurrentSession<T: Config> = StorageValue<_, u32, ValueQuery>;

    /// The current candidacy round: (the puzzle seed, the candidates with the Argon2 output of each). Cleared completely at every rotation.
    #[pallet::storage]
    pub type Round<T: Config> = StorageValue<_, (T::Hash, Pool<T>), OptionQuery>;

    /// Sets that were **closed** and await the draw: `(closing rotation, entropy counter at closing, candidates)`.
    #[pallet::storage]
    pub type Pending<T: Config> = StorageValue<
        _,
        BoundedVec<(u32, u64, Pool<T>), ConstU32<{ MAX_PENDING_POOLS as u32 }>>,
        ValueQuery,
    >;

    /// A hash chain of every block's VRF since the network started (never reset; any fresh VRF changes its value completely).
    #[pallet::storage]
    pub type EntropyAccumulator<T: Config> = StorageValue<_, [u8; 32], ValueQuery>;

    /// The number of accumulated VRFs.
    #[pallet::storage]
    pub type EntropyCount<T: Config> = StorageValue<_, u64, ValueQuery>;

    /// The last accumulated VRF (to avoid counting it twice if the new block wrote no VRF).
    #[pallet::storage]
    pub type EntropyLast<T: Config> = StorageValue<_, T::Hash, OptionQuery>;

    /// A permanent ban (§2.9: the result of equivocation).
    #[pallet::storage]
    pub type BannedKeys<T: Config> = StorageMap<_, Blake2_128Concat, T::AccountId, (), OptionQuery>;

    /// A registered voluntary exit (current members only) — executed at the epoch boundary.
    #[pallet::storage]
    pub type PendingVoluntaryExit<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, (), OptionQuery>;

    /// **D47 — approved operators:** operator account → the maximum number of votes
    /// (live validators) allowed to it at once. Insertion/modification exclusively
    /// through `T::OperatorApprovalOrigin` (independent governance) — the system never relies
    /// on any name the operator types itself as proof of identity.
    #[pallet::storage]
    pub type ApprovedOperators<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, u32, OptionQuery>;

    /// **D47** — any node (a candidate/potential validator account) bound to an approved
    /// operator. Set exclusively through `vouch_node` (signed by the operator itself) — a node
    /// with no bound operator here **can never actually become a validator, however many lotteries
    /// it wins** (see the filtering in `new_session` below).
    #[pallet::storage]
    pub type NodeOperator<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, T::AccountId, OptionQuery>;

    /// **D47** — the reverse list of [`NodeOperator`]: every node vouched for by a given
    /// operator, bounded by `MaxVotesPerOperator` (no vouching
    /// beyond the operator's own cap — prevents unbounded storage growth and makes
    /// `revoke_operator_approval` a bounded-cost operation, not dependent on scanning
    /// every operator in the network).
    #[pallet::storage]
    pub type OperatorNodes<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        BoundedVec<T::AccountId, T::MaxVotesPerOperator>,
        ValueQuery,
    >;

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A correct solution entered this round's candidate set.
        CandidateAccepted { who: T::AccountId },
        /// Won the lottery and became a validator.
        Admitted {
            who: T::AccountId,
            valid_until_session: u32,
        },
        /// A membership was renewed.
        Renewed {
            who: T::AccountId,
            valid_until_session: u32,
        },
        /// The term ended and the grace period began: must renew before `removal_session`.
        MembershipInGrace {
            who: T::AccountId,
            removal_session: u32,
        },
        /// The membership was removed for not renewing.
        MembershipExpired { who: T::AccountId },
        /// A voluntary exit was executed.
        Exited { who: T::AccountId },
        /// Removals were postponed because they would have emptied the set (network liveness).
        RemovalsDeferredToKeepLiveness,
        /// Won the lottery but the validator set is full (`MaxValidators`).
        NotAdmittedSetFull { who: T::AccountId },
        /// A draw was postponed because of insufficient fresh entropy after the closing.
        DrawDeferredForEntropy { fresh_blocks: u64 },
        /// **D47** — a new operator approved (or its vote cap changed) through governance.
        OperatorApproved {
            operator: T::AccountId,
            max_votes: u32,
        },
        /// **D47** — lowering an operator's cap below its current live vote count evicted
        /// the excess immediately from this pallet's record (`Validators`). **Precise, not
        /// exaggerated:** the actual removal from BABE/GRANDPA authority follows two
        /// session rotations as usual, not this event itself.
        OperatorCapLoweredEvictedExcess {
            operator: T::AccountId,
            evicted: u32,
        },
        /// **D47** — an operator's approval was fully revoked; all its bound nodes were removed immediately
        /// from this pallet's record (`Validators`/candidates, without waiting for the
        /// epoch boundary). **Precise, not exaggerated:** the actual removal from
        /// BABE/GRANDPA authority follows two session rotations, see `OperatorCapLoweredEvictedExcess`.
        OperatorApprovalRevoked {
            operator: T::AccountId,
            evicted_nodes: u32,
        },
        /// **D47** — a node was bound to an approved operator (signed by the operator itself).
        NodeVouched {
            operator: T::AccountId,
            node: T::AccountId,
        },
        /// **D47** — a node's binding to its operator was removed (at the operator's own request) and it was evicted from
        /// this pallet's record immediately; its removal from actual BABE/GRANDPA authority
        /// follows two session rotations as usual.
        NodeVouchRevoked {
            operator: T::AccountId,
            node: T::AccountId,
        },
        /// **D47** — won the lottery but no approved operator is bound to it — does not become a validator.
        NotAdmittedNoOperator { who: T::AccountId },
        /// **D47** — won the lottery and is bound to an approved operator, but that operator's
        /// vote cap is full now — does not become a validator until a slot frees up or the cap is raised.
        NotAdmittedOperatorCapReached {
            who: T::AccountId,
            operator: T::AccountId,
        },
        /// **B12:** the last live voter was proven to have cheated: it was banned (no renewal and no return) but stays a voter until a replacement is accepted, to protect the network.
        /// (Added at the end of the list on purpose so the indices of earlier events do not change.)
        LastValidatorBannedButKept { who: T::AccountId },
    }

    #[pallet::error]
    pub enum Error<T> {
        /// The key is permanently banned (an earlier equivocation).
        KeyPermanentlyBanned,
        /// The solution does not meet the difficulty condition.
        SolutionDoesNotMeetDifficulty,
        /// The account is already a candidate in this round.
        AlreadyAdmittedThisRound,
        /// The set is full and this solution's output is not better than the worst in it (needs more work).
        AdmissionCapReached,
        /// The overall maximum number of validators would be exceeded.
        TooManyValidators,
        /// The member has already renewed for this term.
        AlreadyRenewed,
        /// Voluntary exit is for current members only.
        NotAValidator,
        /// The draw queue is full of accepted sets awaiting entropy/delay; new candidacy is restricted until a slot frees up.
        CandidacyBacklogFull,
        /// **D47** — the requested vote cap exceeds `MaxVotesPerOperator` (the absolute limit).
        MaxVotesExceedsAbsoluteLimit,
        /// **D47** — this account is not currently an approved operator.
        OperatorNotApproved,
        /// **D47** — this node is already bound to another operator (one operator per node only).
        NodeAlreadyVouched,
        /// **D47** — the operator has reached its approved vote cap; no additional node can be vouched for.
        OperatorAtVouchCapacity,
        /// **D47** — this node is not currently vouched for by any operator.
        NodeNotVouched,
        /// **D47** — only the operator that vouched for this node can withdraw its vouch.
        NotTheVouchingOperator,
        /// **D50** — executing this eviction (a new cap / approval revocation / vouch withdrawal) would empty
        /// the validator set completely — explicitly rejected; provide a live replacement
        /// first (another operator or another node) before retrying.
        EvictionWouldEmptyTheValidatorSet,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Submit a puzzle solution — **one path with two outcomes depending on the account's state:** a current member => immediate renewal (no round
        /// cap); a non-member => candidacy. **A candidate's rank in the set = the Argon2id output itself** (smaller is better):
        /// improving the rank requires an Argon2 evaluation per attempt (nonce), and its output is bound to the account and the round — identities
        /// cannot be ground with a cheap key and then spend the work only on the best one.
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::submit_admission_solution())]
        pub fn submit_admission_solution(
            origin: OriginFor<T>,
            nonce: u64,
        ) -> DispatchResultWithPostInfo {
            let who = ensure_signed(origin)?;

            // Cheap checks first (reads only) **before** the expensive Argon2, refunding to their actual weight (a conservative upper bound).
            let early_reject = |error: Error<T>| -> DispatchErrorWithPostInfo {
                DispatchErrorWithPostInfo {
                    post_info: PostDispatchInfo {
                        actual_weight: Some(T::WeightInfo::submit_admission_rejected_early()),
                        pays_fee: Pays::Yes,
                    },
                    error: error.into(),
                }
            };

            if BannedKeys::<T>::contains_key(&who) {
                return Err(early_reject(Error::<T>::KeyPermanentlyBanned));
            }

            let (round_seed, _since) =
                T::EpochRandomness::random(madar_protocol::ADMISSION_PUZZLE_DOMAIN);
            let session = CurrentSession::<T>::get();

            if Validators::<T>::get().contains(&who) {
                let valid_until = session.saturating_add(T::MembershipTermSessions::get());
                if MembershipExpiry::<T>::get(&who).unwrap_or(0) >= valid_until {
                    return Err(early_reject(Error::<T>::AlreadyRenewed));
                }
                ensure!(
                    Self::solution_meets_difficulty(&who, &round_seed, nonce),
                    Error::<T>::SolutionDoesNotMeetDifficulty
                );
                MembershipExpiry::<T>::insert(&who, valid_until);
                Self::deposit_event(Event::Renewed {
                    who,
                    valid_until_session: valid_until,
                });
                return Ok(().into());
            }

            let mut candidates: Pool<T> = match Round::<T>::get() {
                Some((seed, candidates)) if seed == round_seed => candidates,
                // An older round that has not closed yet because the draw queue is full: we do not replace it (accepted candidacies would be lost) nor open
                // a new commitment on top of it. Candidacy is restricted until a slot frees up (no silent deletion).
                Some((_, old)) if !old.is_empty() => {
                    return Err(early_reject(Error::<T>::CandidacyBacklogFull));
                }
                _ => Default::default(),
            };
            if candidates.iter().any(|(c, _)| c == &who) {
                return Err(early_reject(Error::<T>::AlreadyAdmittedThisRound));
            }

            // Argon2 once: the validity of the solution and the ordering key from the same output.
            let output = Self::compute_puzzle_output(&who, &round_seed, nonce);
            ensure!(
                leading_zero_bits(&output) >= T::DifficultyLeadingZeroBits::get(),
                Error::<T>::SolutionDoesNotMeetDifficulty
            );

            if candidates.is_full() {
                let (worst_index, worst_output) = candidates
                    .iter()
                    .enumerate()
                    .map(|(i, (_, out))| (i, *out))
                    .max_by_key(|(_, out)| *out)
                    .expect("a full pool is non-empty");
                ensure!(output < worst_output, Error::<T>::AdmissionCapReached);
                candidates[worst_index] = (who.clone(), output);
            } else {
                candidates
                    .try_push((who.clone(), output))
                    .map_err(|_| Error::<T>::AdmissionCapReached)?;
            }
            Round::<T>::put((round_seed, candidates));
            Self::deposit_event(Event::CandidateAccepted { who });
            Ok(().into())
        }

        /// Voluntary exit (§2.9) — for current members only, executed at the epoch boundary (`new_session`).
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::voluntary_exit())]
        pub fn voluntary_exit(origin: OriginFor<T>) -> DispatchResult {
            let who = ensure_signed(origin)?;
            ensure!(
                Validators::<T>::get().contains(&who),
                Error::<T>::NotAValidator
            );
            PendingVoluntaryExit::<T>::insert(&who, ());
            Ok(())
        }

        /// Permanently ban a key (§2.9: the result of equivocation) — temporary administrative, `T::AdminOrigin` only
        /// (`EnsureNever` in the actual runtime). The equivocation mechanism calls `Pallet::ban` directly, not this.
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::ban_key())]
        pub fn ban_key(origin: OriginFor<T>, offender: T::AccountId) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            Self::ban(&offender);
            Ok(())
        }

        /// **Dev-only (D25)** — directly sets the initial validator set, outside the puzzle.
        /// `T::AdminOrigin` only (`EnsureNever` in the actual runtime).
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::dev_only_force_set_validators(validators.len() as u32))]
        pub fn dev_only_force_set_validators(
            origin: OriginFor<T>,
            validators: Vec<T::AccountId>,
        ) -> DispatchResult {
            T::AdminOrigin::ensure_origin(origin)?;
            let bounded: BoundedVec<T::AccountId, T::MaxValidators> = validators
                .try_into()
                .map_err(|_| Error::<T>::TooManyValidators)?;
            Self::set_validators_with_fresh_terms(bounded);
            Ok(())
        }

        /// **D47** — approve an operator (or change its vote cap), exclusively through independent
        /// governance (`T::OperatorApprovalOrigin`). No name typed by the operator
        /// itself is accepted as proof — the account itself is the approved identity, and the approving
        /// party is governance, not the operator.
        ///
        /// **Lowering the cap below the current live vote count takes effect immediately in
        /// this pallet's own storage** — the operator is not left with actual votes
        /// exceeding its new cap while waiting for a future vacancy; the excess over the cap
        /// is evicted in the same call. **No immunity for the operator's own seat (D50):**
        /// if it occupies a seat directly (genesis / `dev_only_force_set_validators`,
        /// entirely outside the vouching system), it counts as a priority within the same new cap —
        /// a cap of 0 evicts it too, not only its vouched nodes. **Liveness guard:** if
        /// the resulting eviction would empty the validator set completely, the whole
        /// operation is rejected (`EvictionWouldEmptyTheValidatorSet`) — no new cap
        /// is recorded and no eviction happens; no fake success while a vote remains active.
        /// **Precise note (no absolute "immediate" claim) on success:** the eviction
        /// is immediate in `Validators` (this pallet's record) only; the real actual authority
        /// in BABE/GRANDPA (block production / finality) only ends
        /// after two full session rotations — exactly as proven by
        /// `consensus/tests/operator_revocation_authority_timing.rs` (the same
        /// one-rotation-delayed `pallet_session` mechanism that voluntary exit
        /// and bans are already subject to, not a new exception).
        #[pallet::call_index(4)]
        #[pallet::weight(T::WeightInfo::approve_operator())]
        pub fn approve_operator(
            origin: OriginFor<T>,
            operator: T::AccountId,
            max_votes: u32,
        ) -> DispatchResult {
            T::OperatorApprovalOrigin::ensure_origin(origin)?;
            ensure!(
                max_votes <= T::MaxVotesPerOperator::get(),
                Error::<T>::MaxVotesExceedsAbsoluteLimit
            );

            // **D50 — no absolute immunity for the operator's own seat:** if it actually occupies
            // a seat (genesis or `dev_only_force_set_validators`,
            // dev-only), it counts as a priority within its own new cap — not outside it.
            // A cap of 0 means evicting its seat too, not only its vouched nodes. Order:
            // its own seat is kept first as long as the cap allows (it uses one vote),
            // then its live vouched nodes in deterministic order; anything beyond that is evicted,
            // starting with the vouched nodes, and finally its own seat if needed.
            let validators = Validators::<T>::get();
            let self_occupies_a_seat = validators.contains(&operator);
            let mut live_vouched: Vec<T::AccountId> = validators
                .iter()
                .filter(|v| {
                    *v != &operator && NodeOperator::<T>::get(v).as_ref() == Some(&operator)
                })
                .cloned()
                .collect();
            live_vouched.sort();

            let mut keep_budget = max_votes;
            let mut to_evict: Vec<T::AccountId> = Vec::new();
            let evict_self = if self_occupies_a_seat {
                if keep_budget > 0 {
                    keep_budget -= 1;
                    false
                } else {
                    true
                }
            } else {
                false
            };
            for node in live_vouched {
                if keep_budget > 0 {
                    keep_budget -= 1;
                } else {
                    to_evict.push(node);
                }
            }
            if evict_self {
                to_evict.push(operator.clone());
            }

            // **Liveness guard (D50):** if evicting all of the above would empty the
            // validator set completely, the whole operation is clearly rejected — no
            // change is executed (neither the cap nor the eviction), we show no fake success
            // while a vote remains active, and we never silently empty the network.
            ensure!(
                !Self::would_empty_the_live_validator_set(&to_evict),
                Error::<T>::EvictionWouldEmptyTheValidatorSet
            );

            for node in &to_evict {
                NodeOperator::<T>::remove(node);
                OperatorNodes::<T>::mutate(&operator, |nodes| nodes.retain(|n| n != node));
                Self::remove_from_all_pools(node);
            }
            if !to_evict.is_empty() {
                Self::deposit_event(Event::OperatorCapLoweredEvictedExcess {
                    operator: operator.clone(),
                    evicted: to_evict.len() as u32,
                });
            }

            ApprovedOperators::<T>::insert(&operator, max_votes);
            Self::deposit_event(Event::OperatorApproved {
                operator,
                max_votes,
            });
            Ok(())
        }

        /// **D47/D50** — fully revoke an operator's approval: it is removed from governance immediately,
        /// and every vote it controls — its vouched nodes **and its own seat if any** (D50:
        /// no immunity; genesis / `dev_only_force_set_validators` are not exempt) —
        /// is evicted immediately from this pallet's record (`Validators`) and the candidates, without
        /// waiting for the epoch boundary/renewal. **Liveness guard:** if these are all
        /// the remaining live votes in the network, the whole operation is rejected
        /// (`EvictionWouldEmptyTheValidatorSet`) — no approval is revoked and nothing
        /// is evicted; provide a live replacement first. **Precise on success:** this is immediate
        /// in the Admission storage itself only; the actual removal from block-production /
        /// finality authority (BABE/GRANDPA) follows two session rotations, exactly
        /// like voluntary exit and bans — see
        /// `consensus/tests/operator_revocation_authority_timing.rs`.
        #[pallet::call_index(5)]
        #[pallet::weight(T::WeightInfo::revoke_operator_approval())]
        pub fn revoke_operator_approval(
            origin: OriginFor<T>,
            operator: T::AccountId,
        ) -> DispatchResult {
            T::OperatorApprovalOrigin::ensure_origin(origin)?;
            ensure!(
                ApprovedOperators::<T>::contains_key(&operator),
                Error::<T>::OperatorNotApproved
            );

            // **D50 — no immunity for the operator's own seat here either:** fully revoking the approval
            // must evict its own seat (if any, genesis or dev-only)
            // exactly as it evicts its vouched nodes — "revoking the right to vote" means every vote
            // it controls, not only the vouched nodes.
            let nodes = OperatorNodes::<T>::get(&operator);
            let mut to_evict: Vec<T::AccountId> = nodes.into_inner();
            let self_occupies_a_seat = Validators::<T>::get().contains(&operator);
            if self_occupies_a_seat {
                to_evict.push(operator.clone());
            }

            // **Liveness guard (D50):** if these are all the remaining live votes in
            // the network, the whole operation is rejected — no approval revoked, nothing evicted.
            ensure!(
                !Self::would_empty_the_live_validator_set(&to_evict),
                Error::<T>::EvictionWouldEmptyTheValidatorSet
            );

            ApprovedOperators::<T>::remove(&operator);
            OperatorNodes::<T>::remove(&operator);
            for node in &to_evict {
                NodeOperator::<T>::remove(node);
                Self::remove_from_all_pools(node);
            }
            Self::deposit_event(Event::OperatorApprovalRevoked {
                operator,
                evicted_nodes: to_evict.len() as u32,
            });
            Ok(())
        }

        /// **D47** — the operator vouches (signing with its own approved account) for one
        /// node as its follower. One node = one operator only, and bounded by the currently approved
        /// operator cap — this is the control of "no automatic vote for every node".
        #[pallet::call_index(6)]
        #[pallet::weight(T::WeightInfo::vouch_node())]
        pub fn vouch_node(origin: OriginFor<T>, node: T::AccountId) -> DispatchResult {
            let operator = ensure_signed(origin)?;
            let max_votes =
                ApprovedOperators::<T>::get(&operator).ok_or(Error::<T>::OperatorNotApproved)?;
            ensure!(
                NodeOperator::<T>::get(&node).is_none(),
                Error::<T>::NodeAlreadyVouched
            );
            // **D48/D49:** the operator account itself may already occupy a seat directly
            // (genesis or `dev_only_force_set_validators`, dev-only, without any
            // vouching) — it counts as one vote used from its cap before allowing
            // any additional node to be vouched for; otherwise the operator would actually exceed its cap without any
            // extra vote going through `vouch_node` (exactly the reported gap).
            let self_occupies_a_seat = Validators::<T>::get().contains(&operator);
            let reserved =
                (self_occupies_a_seat as u32) + OperatorNodes::<T>::get(&operator).len() as u32;
            ensure!(reserved < max_votes, Error::<T>::OperatorAtVouchCapacity);
            let mut nodes = OperatorNodes::<T>::get(&operator);
            nodes
                .try_push(node.clone())
                .map_err(|_| Error::<T>::OperatorAtVouchCapacity)?;
            OperatorNodes::<T>::insert(&operator, nodes);
            NodeOperator::<T>::insert(&node, operator.clone());
            Self::deposit_event(Event::NodeVouched { operator, node });
            Ok(())
        }

        /// **D47/D50** — the operator that vouched for a node withdraws its vouch (voluntarily, e.g.
        /// when stopping it). **Liveness guard:** if this node is the last live vote in
        /// the whole network, the removal is explicitly rejected. On success: the node is evicted
        /// immediately from this pallet's record (`Validators`)/candidates — but its actual
        /// authority in BABE/GRANDPA (if it had any) only ends after two
        /// session rotations, as usual.
        #[pallet::call_index(7)]
        #[pallet::weight(T::WeightInfo::revoke_vouch())]
        pub fn revoke_vouch(origin: OriginFor<T>, node: T::AccountId) -> DispatchResult {
            let caller = ensure_signed(origin)?;
            let operator = NodeOperator::<T>::get(&node).ok_or(Error::<T>::NodeNotVouched)?;
            ensure!(caller == operator, Error::<T>::NotTheVouchingOperator);
            // **Liveness guard (D50):** if this node is the last live vote in the whole
            // network, the removal is explicitly rejected instead of silently emptying the network.
            ensure!(
                !Self::would_empty_the_live_validator_set(core::slice::from_ref(&node)),
                Error::<T>::EvictionWouldEmptyTheValidatorSet
            );
            NodeOperator::<T>::remove(&node);
            OperatorNodes::<T>::mutate(&operator, |nodes| nodes.retain(|n| n != &node));
            Self::remove_from_all_pools(&node);
            Self::deposit_event(Event::NodeVouchRevoked { operator, node });
            Ok(())
        }
    }

    impl<T: Config> Pallet<T> {
        /// Accumulates the **previous** block's VRF (if present and not already accumulated). Idempotent through `EntropyLast`, so it is called from
        /// both `on_initialize` and `new_session` with no double counting and no dependency on hook order: in the runtime
        /// `Session` precedes `Admission` in `on_initialize`, so if the round closed before the previous block's VRF was accumulated,
        /// that VRF (produced before the closing) would enter the "fresh" count. So it is force-accumulated before recording the closing counter.
        fn mix_parent_vrf() {
            if let (Some(vrf), _) = T::BlockRandomness::random(ENTROPY_DOMAIN) {
                if EntropyLast::<T>::get() != Some(vrf) {
                    let mut input = EntropyAccumulator::<T>::get().to_vec();
                    input.extend_from_slice(vrf.as_ref());
                    EntropyAccumulator::<T>::put(<frame_support::sp_runtime::traits::BlakeTwo256 as frame_support::sp_runtime::traits::Hash>::hash(&input).0);
                    EntropyCount::<T>::mutate(|c| *c = c.saturating_add(1));
                    EntropyLast::<T>::put(vrf);
                }
            }
        }

        /// A deterministic ordering key (for the selection members after the draw only — with randomness that comes after the commitment).
        fn draw_key(seed: &[u8], who: &T::AccountId) -> [u8; 32] {
            let mut input = seed.to_vec();
            input.extend_from_slice(&who.encode());
            <frame_support::sp_runtime::traits::BlakeTwo256 as frame_support::sp_runtime::traits::Hash>::hash(&input).0
        }

        /// Draw seed = H(BABE randomness ‖ per-block VRF accumulator): one fresh VRF unknown to the candidates is enough.
        fn draw_seed() -> [u8; 32] {
            let (babe, _) = T::EpochRandomness::random(LOTTERY_DOMAIN);
            let mut input = LOTTERY_DOMAIN.to_vec();
            input.extend_from_slice(babe.as_ref());
            input.extend_from_slice(&EntropyAccumulator::<T>::get());
            <frame_support::sp_runtime::traits::BlakeTwo256 as frame_support::sp_runtime::traits::Hash>::hash(&input).0
        }

        fn set_validators_with_fresh_terms(validators: BoundedVec<T::AccountId, T::MaxValidators>) {
            let valid_until =
                CurrentSession::<T>::get().saturating_add(T::MembershipTermSessions::get());
            for old in Validators::<T>::get() {
                if !validators.contains(&old) {
                    MembershipExpiry::<T>::remove(&old);
                }
            }
            for v in validators.iter() {
                MembershipExpiry::<T>::insert(v, valid_until);
            }
            Validators::<T>::put(validators);
        }

        /// Immediately and permanently ban a key: it is removed from the members and the candidates, and its exit/validity is cancelled.
        /// (The single enforcement point — `ban_key` and the equivocation mechanism both call it.)
        pub fn ban(offender: &T::AccountId) {
            BannedKeys::<T>::insert(offender, ());
            // **B12 — owner decision (2026-09-28): the last live voter stays even if proven to have cheated.** Evicting it immediately would empty `Validators` before
            // `new_session`, so the liveness guard there would not work (it requires a non-empty previous set) and an empty set would come out ⇒ a permanent halt
            // with no recovery (nobody produces a block that adds a replacement). Therefore: the ban is recorded (no renewal and never a return), and it is removed from all
            // rounds/sets, but it stays the only voter until a replacement is accepted — then `new_session` removes it automatically (a banned
            // account does not count as "staying"). The event shows the state immediately to alert the operator.
            if Self::would_empty_the_live_validator_set(core::slice::from_ref(offender)) {
                Self::remove_from_candidate_pools(offender);
                Self::deposit_event(Event::LastValidatorBannedButKept {
                    who: offender.clone(),
                });
                return;
            }
            Self::remove_from_all_pools(offender);
        }

        /// Remove from the open round and from the closed sets awaiting the draw only (without touching `Validators`).
        fn remove_from_candidate_pools(who: &T::AccountId) {
            Round::<T>::mutate(|round| {
                if let Some((_, candidates)) = round {
                    candidates.retain(|(c, _)| c != who);
                }
            });
            Pending::<T>::mutate(|pending| {
                for (_, _, candidates) in pending.iter_mut() {
                    candidates.retain(|(c, _)| c != who);
                }
            });
        }

        /// Immediately remove an account from everything that may grant it a vote: the current
        /// validators, membership validity, a pending voluntary exit, the open
        /// round, and every closed set awaiting the draw. **Does not touch `BannedKeys`**
        /// (those are permanent; this is merely an eviction) — used by `ban` (permanent) and by revoking
        /// an operator approval/vouch (D47, not necessarily permanent).
        fn remove_from_all_pools(who: &T::AccountId) {
            Validators::<T>::mutate(|validators| validators.retain(|v| v != who));
            MembershipExpiry::<T>::remove(who);
            PendingVoluntaryExit::<T>::remove(who);
            Round::<T>::mutate(|round| {
                if let Some((_, candidates)) = round {
                    candidates.retain(|(c, _)| c != who);
                }
            });
            Pending::<T>::mutate(|pending| {
                for (_, _, candidates) in pending.iter_mut() {
                    candidates.retain(|(c, _)| c != who);
                }
            });
        }

        /// **D50** — would evicting every account in `evict` from the current `Validators`
        /// empty it completely while it is not empty now? An explicit liveness guard for every
        /// immediate removal through a direct administrative call (it does not wait for `new_session`, which
        /// has its own separate guarantee for the regular lottery path).
        fn would_empty_the_live_validator_set(evict: &[T::AccountId]) -> bool {
            let current = Validators::<T>::get();
            !current.is_empty() && current.iter().all(|v| evict.contains(v))
        }

        /// The actual puzzle check: Argon2id(pubkey || round_seed || nonce) has ≥
        /// `DifficultyLeadingZeroBits` leading zero bits.
        pub fn solution_meets_difficulty(
            who: &T::AccountId,
            round_seed: &T::Hash,
            nonce: u64,
        ) -> bool {
            let output = Self::compute_puzzle_output(who, round_seed, nonce);
            leading_zero_bits(&output) >= T::DifficultyLeadingZeroBits::get()
        }

        /// Computes the Argon2id output of the puzzle — a public helper (also used by the tests).
        pub fn compute_puzzle_output(
            who: &T::AccountId,
            round_seed: &T::Hash,
            nonce: u64,
        ) -> [u8; 32] {
            let mut input = who.encode();
            input.extend_from_slice(round_seed.as_ref());
            input.extend_from_slice(&nonce.to_le_bytes());

            // Salt: Argon2 requires at least 8 bytes — the first 16 bytes of the round_seed encoding
            // (public and fixed for the round; the real binding to the round comes from round_seed being part of the input).
            let salt = round_seed.encode();

            let params = Params::new(
                T::ArgonMemoryCostKib::get(),
                T::ArgonTimeCost::get(),
                1,
                Some(32),
            )
            .expect("Argon2 params from Config must be valid — checked in integrity_test");

            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut output = [0u8; 32];
            argon2
                .hash_password_into(&input, &salt[..salt.len().min(16).max(8)], &mut output)
                .expect("Argon2id hashing with valid fixed-size inputs must never fail");
            output
        }

        /// The current validator list (for tests/external use).
        pub fn validators() -> Vec<T::AccountId> {
            Validators::<T>::get().into_inner()
        }

        /// Is the account a candidate in the open round or in a closed set awaiting the draw? (Read-only; used by `MembershipApi`.)
        pub fn is_candidate(who: &T::AccountId) -> bool {
            Round::<T>::get().map_or(false, |(_, c)| c.iter().any(|(a, _)| a == who))
                || Pending::<T>::get()
                    .iter()
                    .any(|(_, _, c)| c.iter().any(|(a, _)| a == who))
        }

        /// The candidates of the current round.
        pub fn candidates() -> Vec<T::AccountId> {
            Round::<T>::get()
                .map(|(_, c)| c.into_iter().map(|(a, _)| a).collect())
                .unwrap_or_default()
        }

        /// A member's exit/expiry at rotation `index` (without modifying any storage).
        fn is_leaving(who: &T::AccountId, index: u32) -> bool {
            if PendingVoluntaryExit::<T>::contains_key(who) {
                return true;
            }
            let removal = MembershipExpiry::<T>::get(who)
                .map(|expiry| expiry.saturating_add(T::RenewalGraceSessions::get()));
            matches!(removal, Some(r) if index >= r)
        }
    }

    fn leading_zero_bits(bytes: &[u8]) -> u32 {
        let mut count = 0u32;
        for byte in bytes {
            if *byte == 0 {
                count += 8;
                continue;
            }
            count += byte.leading_zeros();
            break;
        }
        count
    }

    impl<T: Config> pallet_session::SessionManager<T::AccountId> for Pallet<T> {
        fn new_session(new_index: sp_staking::SessionIndex) -> Option<Vec<T::AccountId>> {
            // This hook runs inside `Session::on_initialize` with no declared weight: we register its upper-bound weight explicitly
            // (mandatory) so it is not hidden from the block budget.
            frame_system::Pallet::<T>::register_extra_weight_unchecked(
                T::WeightInfo::new_session(),
                DispatchClass::Mandatory,
            );

            let previous = Validators::<T>::get().into_inner();
            let previous_set: alloc::collections::BTreeSet<T::AccountId> =
                previous.iter().cloned().collect();

            // 1) Who leaves now (voluntary exit, or the term + grace ended)? — no writes yet.
            // A banned account does not count as staying (B12): if it stayed because it was the last voter, it leaves at the first rotation where a replacement exists; if there is no
            // replacement, the liveness guard below keeps it.
            let staying: Vec<T::AccountId> = previous
                .iter()
                .filter(|v| !Self::is_leaving(v, new_index) && !BannedKeys::<T>::contains_key(*v))
                .cloned()
                .collect();

            // 2) The open round closes now; and sets whose delay has passed **and that have enough
            //    fresh entropy** are drawn (otherwise the draw is postponed — we never draw with a predictable seed).
            // Every VRF produced before this block is accumulated now (before recording the closing counter): whatever is accumulated after that was produced in the
            // closing block or later.
            Self::mix_parent_vrf();
            let entropy_now = EntropyCount::<T>::get();
            let min_fresh = T::MinFreshEntropyBlocks::get() as u64;
            let (ready, still_waiting): (Vec<_>, Vec<_>) = Pending::<T>::get()
                .into_inner()
                .into_iter()
                .partition(|(closed_at, count_at_close, _)| {
                    new_index >= closed_at.saturating_add(LOTTERY_DELAY_ROTATIONS)
                        && entropy_now.saturating_sub(*count_at_close) >= min_fresh
                });
            if let Some((_, count_at_close, _)) = still_waiting.iter().find(|(closed_at, _, _)| {
                new_index >= closed_at.saturating_add(LOTTERY_DELAY_ROTATIONS)
            }) {
                Self::deposit_event(Event::DrawDeferredForEntropy {
                    fresh_blocks: entropy_now.saturating_sub(*count_at_close),
                });
            }
            let mut still_waiting = still_waiting;
            // The open round closes **after** releasing what was drawn, and only if there is room: an accepted set is never dropped. When
            // the queue is full the round stays open (and new candidacy is restricted in `submit`) until a slot frees up.
            if let Some((_, closed)) = Round::<T>::get() {
                if closed.is_empty() {
                    Round::<T>::kill();
                } else if still_waiting.len() < MAX_PENDING_POOLS {
                    Round::<T>::kill();
                    still_waiting.push((new_index, entropy_now, closed));
                }
            }
            Pending::<T>::put(BoundedVec::truncate_from(still_waiting));

            let mut winners: Vec<T::AccountId> = Vec::new();
            for (_, _, candidates) in ready {
                let seed = Self::draw_seed();
                let mut eligible: Vec<([u8; 32], T::AccountId)> = candidates
                    .into_iter()
                    .map(|(c, _)| c)
                    .filter(|c| {
                        !BannedKeys::<T>::contains_key(c)
                            && !previous_set.contains(c)
                            && !winners.contains(c)
                            && T::HasSessionKeys::contains(c)
                    })
                    .map(|c| (Self::draw_key(&seed, &c), c))
                    .collect();
                eligible.sort();
                winners.extend(
                    eligible
                        .into_iter()
                        .take(T::AdmissionCapPerRound::get() as usize)
                        .map(|(_, c)| c),
                );
            }

            // **D47/D49 — vote cap per operator:** we first count how many live validators
            // currently (from `staying`, unaffected by this rotation) are attributed to each
            // operator, then we never let any new winner exceed its operator's approved cap.
            // A winner with no vouching operator at all **does not become a validator however much it wins**.
            //
            // **Attribution of each `v` is exclusive (no double counting):** if it is vouched for by an operator
            // (`NodeOperator::get(v)`), it is attributed to that operator — even if the operator
            // vouched for itself (`op == v`), it stays a single entry. **Otherwise**, if
            // `v` itself is an account approved as an operator (`ApprovedOperators`) although
            // nobody vouched for it — the case of a dev-only seat (genesis or
            // `dev_only_force_set_validators`) whose owner was later approved as an operator —
            // it is attributed to itself: its direct seat uses a vote from its own cap, so it
            // cannot vouch for an extra node beyond that actual cap (the gap
            // found by the consensus test in D48 and fixed here).
            let mut operator_live_counts: alloc::collections::BTreeMap<T::AccountId, u32> =
                Default::default();
            for v in &staying {
                let effective_operator = match NodeOperator::<T>::get(v) {
                    Some(op) => Some(op),
                    None if ApprovedOperators::<T>::contains_key(v) => Some(v.clone()),
                    None => None,
                };
                if let Some(op) = effective_operator {
                    *operator_live_counts.entry(op).or_insert(0) += 1;
                }
            }

            let mut next = staying.clone();
            let mut admitted = Vec::new();
            for w in winners {
                if (next.len() as u32) >= T::MaxValidators::get() {
                    // Won the lottery but the validator set is full: no acceptance and no silent deletion — an explicit event.
                    Self::deposit_event(Event::NotAdmittedSetFull { who: w });
                    continue;
                }
                let Some(operator) = NodeOperator::<T>::get(&w) else {
                    // No approved operator vouches for this node — no automatic vote just for winning the lottery.
                    Self::deposit_event(Event::NotAdmittedNoOperator { who: w });
                    continue;
                };
                let approved_max = ApprovedOperators::<T>::get(&operator).unwrap_or(0);
                let current = *operator_live_counts.get(&operator).unwrap_or(&0);
                if current >= approved_max {
                    Self::deposit_event(Event::NotAdmittedOperatorCapReached { who: w, operator });
                    continue;
                }
                operator_live_counts.insert(operator, current + 1);
                next.push(w.clone());
                admitted.push(w);
            }

            // 3) Liveness guarantee: never empty a set that was non-empty.
            if next.is_empty() && !previous.is_empty() {
                Self::deposit_event(Event::RemovalsDeferredToKeepLiveness);
                return Some(previous);
            }

            // 4) Actual application.
            let grace = T::RenewalGraceSessions::get();
            let next_set: alloc::collections::BTreeSet<T::AccountId> =
                next.iter().cloned().collect();
            for v in previous.iter().filter(|v| !next_set.contains(*v)) {
                let exited = PendingVoluntaryExit::<T>::take(v).is_some();
                MembershipExpiry::<T>::remove(v);
                Self::deposit_event(if exited {
                    Event::Exited { who: v.clone() }
                } else {
                    Event::MembershipExpired { who: v.clone() }
                });
            }
            for v in &staying {
                if let Some(expiry) = MembershipExpiry::<T>::get(v) {
                    if new_index >= expiry {
                        Self::deposit_event(Event::MembershipInGrace {
                            who: v.clone(),
                            removal_session: expiry.saturating_add(grace),
                        });
                    }
                }
            }
            let valid_until = new_index.saturating_add(T::MembershipTermSessions::get());
            for w in admitted {
                MembershipExpiry::<T>::insert(&w, valid_until);
                Self::deposit_event(Event::Admitted {
                    who: w,
                    valid_until_session: valid_until,
                });
            }
            if let Ok(bounded) = BoundedVec::try_from(next.clone()) {
                Validators::<T>::put(bounded);
            }
            Some(next)
        }

        /// **Actual finding:** `pallet_session::GenesisConfig::build` calls this function first,
        /// and if it returns `Some(...)` it overrides the `keys` in genesis itself — hence the explicit `None`.
        fn new_session_genesis(_new_index: sp_staking::SessionIndex) -> Option<Vec<T::AccountId>> {
            None
        }

        fn start_session(start_index: sp_staking::SessionIndex) {
            CurrentSession::<T>::put(start_index);
        }
        fn end_session(_end_index: sp_staking::SessionIndex) {}
    }

    /// History (`pallet_session::historical`) needs a full identity for each validator; there is no stake here, so it is `()`.
    impl<T: Config> pallet_session::historical::SessionManager<T::AccountId, ()> for Pallet<T> {
        fn new_session(new_index: sp_staking::SessionIndex) -> Option<Vec<(T::AccountId, ())>> {
            <Self as pallet_session::SessionManager<T::AccountId>>::new_session(new_index)
                .map(|set| set.into_iter().map(|v| (v, ())).collect())
        }
        fn new_session_genesis(
            _new_index: sp_staking::SessionIndex,
        ) -> Option<Vec<(T::AccountId, ())>> {
            None
        }
        fn start_session(start_index: sp_staking::SessionIndex) {
            <Self as pallet_session::SessionManager<T::AccountId>>::start_session(start_index)
        }
        fn end_session(end_index: sp_staking::SessionIndex) {
            <Self as pallet_session::SessionManager<T::AccountId>>::end_session(end_index)
        }
    }

    #[pallet::genesis_config]
    #[derive(frame_support::DefaultNoBound)]
    pub struct GenesisConfig<T: Config> {
        /// **Dev-only (D25)** — synchronized with `pallet_session::GenesisConfig::keys`.
        pub validators: Vec<T::AccountId>,
    }

    #[pallet::genesis_build]
    impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
        fn build(&self) {
            if let Ok(bounded) = BoundedVec::try_from(self.validators.clone()) {
                Pallet::<T>::set_validators_with_fresh_terms(bounded);
            }
        }
    }
}
