//! Consensus — BABE (block production) + GRANDPA (finality), with no internal modification
//! to either of them (§2: "no internal modification to BABE or GRANDPA except for a compelling security reason
//! that needs my approval"). Everything here is **wiring** of standard pallets as they are.
//!
//! **D8/§2.4 (actually applied here for the first time):** BABE = sr25519, GRANDPA =
//! ed25519 — this is not a choice but a property of each algorithm in Substrate itself
//! (`sp_consensus_babe::AuthorityId` = `sr25519::Public`,
//! `sp_consensus_grandpa::AuthorityId` = `ed25519::Public`).
//!
//! **`SessionKeys` (deferred from the Identity/Cryptography phase, §11.2 there):**
//! defined here now because this is the first phase with an actual consumer for them (`pallet_babe`/
//! `pallet_grandpa`/`pallet_session` together) — defining them in an earlier phase without a
//! real runtime would have been code without a consumer (half-finished).
//!
//! **Updated in the Admission/Sybil phase (D26–D28):** `SessionManager` is now
//! actually `madar_admission::Pallet<Runtime>` — `()` **was replaced** exactly as
//! originally documented: "replaceable... without rebuilding the Byzantine voting layer"
//! (§2.9) — not a single line of BABE/GRANDPA themselves changed here to allow this replacement.
//!
//! **Equivocation (implemented, review #6):** GRANDPA/BABE proofs are accepted as unsigned transactions together with a
//! session-key ownership proof from `pallet_session::historical`, and end through `BanOnOffence` in a permanent ban of the identity
//! (`madar_admission::Pallet::ban`). No monetary slashing (no stake). Tested: `tests/equivocation.rs`.
//!
//! **D25 (strict):** any genesis with a validator set here is for internal dev/testnet
//! purposes only (this library's tests) — it is **forbidden** to use it as the basis of any public
//! network before Admission/Sybil is ready (§11 below, and D25 itself).
//!
//! **`pallet-balances` (D42 — SDK upgrade to `polkadot-stable2606-2`):**
//! `pallet_session::Config` in this SDK release now requires a real `Currency`
//! (`fungible::Mutate` + `fungible::hold::Mutate`) and a `KeyDeposit` when
//! registering session keys — an unavoidable SDK requirement, not an architectural
//! choice of ours. **`KeyDeposit = ()` (always zero)** — any hold requested for
//! registering a key is always zero-valued and always accepted regardless of the account's
//! balance. **No genesis endowment for any account** (`balances: vec![]`) — nobody
//! actually holds any real balance anywhere. This **does not violate D21/D38**
//! ("no token/economy for now, but the architecture stays token-ready"): the pallet
//! exists now as mandatory infrastructure imposed by the SDK itself, not as an economic decision — no
//! fees (D17 still stands), no distribution, no supply, no path through which
//! any account obtains real value. See the internal design document
//! (attempt 4) for the full details and the reason for this decision (a security upgrade to fix critical
//! wasmtime vulnerabilities, not an independent economic decision).
//!
//! **Runtime upgrade authority — a 2-of-3 committee (D43/governance, §13):** no
//! `pallet_sudo`, no single key holds `Root`. `UpgradeCommittee`
//! (`pallet_collective::Instance1`, 3 members) + `madar_upgrade_authority`
//! are the only path for any call that requires `Root` (most importantly
//! `System::set_code` to upgrade the runtime itself) — it requires the approval of two members out
//! of three (`EnsureProportionAtLeast<AccountId, Instance1, 2, 3>`) through
//! the standard (unmodified) `pallet_collective::propose`/`vote`/`close`,
//! then `UpgradeAuthority::dispatch_as_root`. **Exactly the same threshold governs
//! the committee membership itself** (`SetMembersOrigin`) — replacing a lost/compromised member
//! needs the approval of two other members; no easier path, no backup sudo, no kill
//! switch. The committee members (genesis currently dev/testnet only, D25) are a key space
//! **completely independent** of BABE/GRANDPA and the release-signing keys (D35/D43) —
//! no overlap. See `madar-upgrade-authority` (the full module comment) and
//! the internal design document for the full decision.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

extern crate alloc;

mod genesis_config_presets;
pub mod membership_api;
/// B1: SDK pallet weights = the larger of the SDK weight and the floor measured on MADAR (2× execution + MADAR's DbWeight).
pub mod sdk_weights;

pub use madar_admission;
pub use madar_names;
pub use madar_stamp;
pub use pallet_babe;
pub use pallet_grandpa;
pub use pallet_session;
pub use pallet_timestamp;

use alloc::vec::Vec;
use frame_support::{
    construct_runtime, derive_impl, parameter_types,
    traits::{ConstU128, ConstU16, ConstU32, ConstU64, VariantCountOf},
    weights::Weight,
};
use pallet_collective::EnsureProportionAtLeast;
use sp_runtime::{generic, impl_opaque_keys, traits::ConvertInto};

/// The `pallet_collective` instance used for the runtime upgrade committee — only one
/// instance for now (`Instance1`); no other committees yet.
pub type UpgradeCommitteeInstance = pallet_collective::Instance1;

/// The actual approval threshold: **exactly 2 of 3** (D43) — governs both the delegation of
/// `Root` (`madar_upgrade_authority`) and the committee membership itself
/// (`SetMembersOrigin`). A regular config type, fully replaceable at any
/// later runtime upgrade (e.g. an origin derived from broader community governance) without any
/// structural change here now — no extra complexity (`EitherOfDiverse` / disabled alternative
/// paths) is needed to achieve that flexibility; replacing one type alias is enough at that time.
pub type UpgradeApprovedOrigin = EnsureProportionAtLeast<AccountId, UpgradeCommitteeInstance, 2, 3>;

/// The numeric balance type of `pallet-balances` — a data structure only (D42), no supply
/// and no real distribution (see the module comment above). `u128` is standard across the whole
/// Substrate ecosystem, not an economic decision in itself.
pub type Balance = u128;
/// A purely technical value (no economic meaning here, because no account is funded with any balance in Genesis, `balances: vec![]`): prevents
/// Dust Accounts in `pallet-balances` itself. Reviewed together with the economic decisions, not before.
pub const EXISTENTIAL_DEPOSIT: Balance = 500;

/// Account/signature identity — reuses `madar-identity` (Identity phase)
/// verbatim, not a parallel definition. The first actual consumer of this type in a real runtime.
pub type Signature = madar_identity::Signature;
pub type AccountId = madar_identity::AccountId;
/// The destination address in a signed transaction — the standard `MultiAddress` (no named/indexed
/// lookup yet, `()` — matches the default `AccountIdLookup` in
/// `SolochainDefaultConfig`).
pub type Address = sp_runtime::MultiAddress<AccountId, ()>;
/// The block number — `u32` (enough for decades at Slot=8s; not an economic decision).
pub type BlockNumber = u32;
/// The nonce type as in `SolochainDefaultConfig` (no independent decision here).
pub type Nonce = <Runtime as frame_system::Config>::Nonce;
pub type Header = generic::Header<BlockNumber, sp_runtime::traits::BlakeTwo256>;

/// The transaction envelope — reuses `madar-transactions::SignedExtra` (Transactions
/// phase) verbatim: no fees (D17), mortal only (D18).
pub type SignedExtra = madar_transactions::SignedExtra<Runtime, OnboardingPolicy>;
pub type UncheckedExtrinsic =
    generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;
/// The actual block, for the first time in this project — replaces the `MockBlock` used in
/// the tests of each earlier phase separately.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;

/// Opaque types — used by `node/` (client/network/RPC) without knowing the details of
/// the actual transaction (SignedExtra/Signature), so network sync keeps working even
/// across future upgrades of the transaction structure itself.
pub mod opaque {
    use super::BlockNumber;
    use sp_runtime::{generic, traits::BlakeTwo256};

    pub use sp_runtime::OpaqueExtrinsic as UncheckedExtrinsic;

    pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
    pub type Block = generic::Block<Header, UncheckedExtrinsic>;
}

/// The standard execution engine — no custom execution logic (`frame_executive` as is). The only spec 9 migration: the Admission storage version
/// (0 → 1, no data change). The two one-time seeding migrations (`SeedFirstStamper` spec 6, `SeedNames` spec 7) were removed in spec 9:
/// they ran on the live network (spec 6 then 7, and it was then on 8) and had become no-ops because of
/// their markers; the two markers stay in storage with no effect.
pub type Executive = frame_executive::Executive<
    Runtime,
    Block,
    frame_system::ChainContext<Runtime>,
    Runtime,
    AllPalletsWithSystem,
    madar_admission::migrations::V0ToV1<Runtime>,
>;

/// The first account of the "Madar Stamp" service (D55) — seeded as a registrar for the stamp (spec 6) and for names (spec 7). Its secret is encrypted outside the repository
/// (`stamper.enc`); replacing/removing it is a 2-of-3 committee decision. Reference only (the Runtime no longer uses it after the seeding migrations were removed).
/// SS58: eYg3neSEXwFuJGQQR5NxiSdGsFgewSN2B8Bg4oVVxrn7bD1GE
pub const FIRST_STAMPER: [u8; 32] = [
    0xc4, 0x0a, 0x6c, 0xf4, 0x87, 0xbe, 0x89, 0xad, 0x2c, 0xbe, 0x5e, 0x9c, 0x39, 0xc8, 0xf3, 0xad,
    0x24, 0x06, 0xe3, 0x61, 0x12, 0xe1, 0x30, 0x53, 0xab, 0x8e, 0x82, 0x50, 0x58, 0xd7, 0x7b, 0x48,
];

construct_runtime!(
    pub enum Runtime {
        System: frame_system,
        Timestamp: pallet_timestamp,
        Authorship: pallet_authorship,
        Babe: pallet_babe,
        Grandpa: pallet_grandpa,
        Balances: pallet_balances,
        Session: pallet_session,
        Historical: pallet_session::historical,
        Admission: madar_admission,
        UpgradeCommittee: pallet_collective::<Instance1>,
        UpgradeAuthority: madar_upgrade_authority,
        Stamp: madar_stamp,
        Names: madar_names,
    }
);

/// **Account lifecycle without an economy (review issue #1):** there is no balance and no existential
/// deposit in this runtime (D17/D21), and the standard `CheckNonce` rejects any account without
/// a reference (`providers`/`sufficients`). Without this, a new user could not submit an
/// Admission solution and an upgrade-committee member could not start a proposal/vote. [`madar_transactions::
/// CheckNonceOrOnboard`] grants the account its first reference **only at its first accepted transaction** and exclusively
/// for these paths:
/// - `Admission::submit_admission_solution` (submitting the onboarding/renewal puzzle);
/// - `UpgradeCommittee::{propose, vote, close}` **if the sender is actually a member**
///   of the committee (its membership is decided by the same 2-of-3, no weaker path).
/// Any other call from an account without a reference is rejected as before (`Payment`). No centralization and no
/// back door: the policy is fixed in the code and only changes through a runtime upgrade via the committee.
pub struct OnboardingPolicy;

impl madar_transactions::AccountCreationPolicy<AccountId, RuntimeCall> for OnboardingPolicy {
    fn may_create_account(who: &AccountId, call: &RuntimeCall) -> bool {
        match call {
            // spec 9: only a vouched node (D47/B2) may create its account with its first solution. Before, ANY fresh key was
            // accepted into the pool here, failed cheaply at dispatch (`NodeNotVouched`), left no account and no nonce, and
            // so could be signed for free from endless new keys (and replayed) to fill block space.
            // (a current member renewing is accepted too: it has an account already, this only guards an odd founding seat)
            RuntimeCall::Admission(madar_admission::Call::submit_admission_solution { .. }) => {
                // spec 9 (independent review #5): O(1) reads only — `MembershipExpiry` is kept for exactly the members (set
                // on admission/genesis, removed with the seat), so the pool check no longer decodes the whole member list
                // for every fresh key.
                madar_admission::NodeOperator::<Runtime>::contains_key(who)
                    || madar_admission::MembershipExpiry::<Runtime>::contains_key(who)
            }
            // B2 (spec 9): a candidate must be vouched before it applies, so an approved operator that has no account yet
            // must be able to create it with its first vouch (only operators the 2-of-3 committee approved).
            RuntimeCall::Admission(madar_admission::Call::vouch_node { .. }) => {
                madar_admission::ApprovedOperators::<Runtime>::contains_key(who)
            }
            RuntimeCall::UpgradeCommittee(
                pallet_collective::Call::propose { .. }
                | pallet_collective::Call::vote { .. }
                | pallet_collective::Call::close { .. },
            ) => pallet_collective::Pallet::<Runtime, UpgradeCommitteeInstance>::is_member(who),
            // Madar Stamp: the approved stamper account (by 2-of-3 committee decision) is created at its first batch.
            RuntimeCall::Stamp(
                madar_stamp::Call::stamp { .. } | madar_stamp::Call::stamp_v2 { .. },
            ) => madar_stamp::Pallet::<Runtime>::is_stamper(who),
            // Madar Names: the approved registrar account only (spec 9: the v2 calls and transfer under the same condition).
            RuntimeCall::Names(
                madar_names::Call::register { .. }
                | madar_names::Call::renew { .. }
                | madar_names::Call::cancel_offer { .. }
                | madar_names::Call::lock_sale_v2 { .. }
                | madar_names::Call::complete_sale_v2 { .. }
                | madar_names::Call::register_v2 { .. }
                | madar_names::Call::lock_sale_v3 { .. }
                | madar_names::Call::cancel_offer_v2 { .. }
                | madar_names::Call::transfer { .. },
            ) => madar_names::Pallet::<Runtime>::is_registrar(who),
            _ => false,
        }
    }
}

/// D11/D12 (locked in advance, Protocol phase): Slot = 8 seconds, Epoch = 900 slots.
pub const SLOT_DURATION_MILLIS: u64 = 8_000;
/// **Production:** 900 slots (D12). The `fast-test-runtime` feature (isolated live tests only, not enabled
/// by default and never part of any production build) shortens the epoch to 12 slots to cover several rotations in minutes.
#[cfg(not(feature = "fast-test-runtime"))]
pub const EPOCH_DURATION_IN_SLOTS: u64 = 900;
#[cfg(feature = "fast-test-runtime")]
pub const EPOCH_DURATION_IN_SLOTS: u64 = 12;

/// Half the slot duration — the standard minimum timestamp difference between two
/// consecutive blocks (a common Substrate pattern), not an economic or security number.
pub const MINIMUM_TIMESTAMP_PERIOD_MILLIS: u64 = SLOT_DURATION_MILLIS / 2;

parameter_types! {
    /// **The single version source** (`VERSION` below): wired into `frame_system`
    /// itself so that `CheckSpecVersion`/`CheckTxVersion` and the `set_code` check
    /// (version name/number) match what `Core::version()` announces to clients. Without this
    /// wiring `SolochainDefaultConfig` left `Version = ()` (spec=0,
    /// an empty name) while the runtime announced spec=1.
    pub const RuntimeVersionSource: sp_version::RuntimeVersion = VERSION;
}

#[derive_impl(frame_system::config_preludes::SolochainDefaultConfig)]
impl frame_system::Config for Runtime {
    type Block = Block;
    type Version = RuntimeVersionSource;
    // The actual block limits (review issue #3): without them the runtime used the default values
    // of `SolochainDefaultConfig` while `madar_blocks` (and its tested limits) was not wired in.
    type BlockWeights = madar_blocks::MadarBlockWeights;
    type BlockLength = madar_blocks::MadarBlockLength;
    // The storage read/write cost enters the weight accounting (it was `()` = zero).
    type DbWeight = frame_support::weights::constants::RocksDbWeight;
    // Required now (D42) because `pallet_balances::Config::AccountStore = System`
    // requires `frame_system::Config::AccountData = AccountData<Balance>` —
    // purely standard wiring, not an economic decision (no account actually has a balance in genesis).
    type AccountData = pallet_balances::AccountData<Balance>;
    /// B5: the MADAR address prefix = 85 (`madar_protocol::SS58_PREFIX`); it was the default 42.
    type SS58Prefix = ConstU16<85>;
    /// B1 (2026-10-15): measured weights (see `sdk_weights`).
    type SystemWeightInfo = sdk_weights::SystemWeights;
}

impl pallet_timestamp::Config for Runtime {
    type Moment = u64;
    /// BABE itself needs a notification when the timestamp is set (`OnTimestampSet`) —
    /// pallet_babe provides it ready-made (`impl OnTimestampSet for Pallet<T>`).
    type OnTimestampSet = Babe;
    type MinimumPeriod = ConstU64<MINIMUM_TIMESTAMP_PERIOD_MILLIS>;
    type WeightInfo = sdk_weights::TimestampWeights;
}

impl pallet_babe::Config for Runtime {
    type EpochDuration = ConstU64<EPOCH_DURATION_IN_SLOTS>;
    type ExpectedBlockTime = ConstU64<SLOT_DURATION_MILLIS>;
    // `ExternalTrigger`: we rely on `pallet_session` to trigger the epoch change
    // (the standard wiring when a session pallet exists) — no custom internal trigger.
    type EpochChangeTrigger = pallet_babe::ExternalTrigger;
    // spec 9: an account banned by an Equivocation proof is disabled in BABE **immediately** (its block is rejected), not after two rotations — through
    // the standard `pallet_session` and `MadarDisablingStrategy` (the last one is never disabled, and never more than a third). See `BanOnOffence`.
    type DisabledValidators = Session;
    type WeightInfo = sdk_weights::BabeWeights;
    type MaxAuthorities = ConstU32<1_000>;
    type MaxNominators = ConstU32<0>; // no nomination (no stake, D5/D21).
    type KeyOwnerProof = <Historical as frame_support::traits::KeyOwnerProofSystem<(
        sp_core::crypto::KeyTypeId,
        sp_consensus_babe::AuthorityId,
    )>>::Proof;
    type EquivocationReportSystem = VerifiedBabeReports<
        pallet_babe::EquivocationReportSystem<
            Runtime,
            BanOnOffence,
            Historical,
            EquivocationReportLongevity,
        >,
    >;
}

impl pallet_grandpa::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = sdk_weights::GrandpaWeights;
    type MaxAuthorities = ConstU32<1_000>;
    type MaxNominators = ConstU32<0>;
    // The set-id→session history is kept for the membership term (84 epochs): required so an old equivocation proof is accepted.
    type MaxSetIdSessionEntries = ConstU64<{ MEMBERSHIP_TERM_SESSIONS as u64 }>;
    type KeyOwnerProof = <Historical as frame_support::traits::KeyOwnerProofSystem<(
        sp_core::crypto::KeyTypeId,
        sp_consensus_grandpa::AuthorityId,
    )>>::Proof;
    type EquivocationReportSystem = VerifiedGrandpaReports<
        pallet_grandpa::EquivocationReportSystem<
            Runtime,
            BanOnOffence,
            Historical,
            EquivocationReportLongevity,
        >,
    >;
}

/// **D42** — mandatory infrastructure imposed by `pallet_session::Config::Currency`
/// (see the module comment above). No genesis endowment, no fees, no supply.
impl pallet_balances::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeHoldReason = RuntimeHoldReason;
    type RuntimeFreezeReason = RuntimeFreezeReason;
    type WeightInfo = sdk_weights::BalancesWeights;
    type Balance = Balance;
    type DustRemoval = ();
    type ExistentialDeposit = ConstU128<EXISTENTIAL_DEPOSIT>;
    type AccountStore = System;
    type ReserveIdentifier = [u8; 8];
    type FreezeIdentifier = RuntimeFreezeReason;
    type MaxLocks = ConstU32<50>;
    type MaxReserves = ();
    type MaxFreezes = VariantCountOf<RuntimeFreezeReason>;
    type DoneSlashHandler = ();
}

impl_opaque_keys! {
    /// BABE=sr25519 (D8) via `babe`, GRANDPA=ed25519 (D8) via `grandpa` —
    /// the two types are completely separate by the type itself (the Rust type system); they cannot
    /// be mixed by simple composition (an extra generalization of the spirit of INV-7 at the level of the whole
    /// key bundle, not only the single account as in the corrected IDN-1).
    pub struct SessionKeys {
        pub babe: Babe,
        pub grandpa: Grandpa,
    }
}

impl pallet_session::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type ValidatorId = <Runtime as frame_system::Config>::AccountId;
    type ValidatorIdOf = ConvertInto;
    // `Babe` implements `ShouldEndSession`/`EstimateNextSessionRotation` itself
    // (standard, unmodified code) — this is the official standard wiring between BABE
    // and Session, not custom logic.
    type ShouldEndSession = Babe;
    type NextSessionRotation = Babe;
    /// `()` was replaced by the actual Admission (§2.9) — see the module comment above.
    type SessionManager =
        pallet_session::historical::NoteHistoricalRoot<Runtime, MadarSessionManager>;
    type SessionHandler = (Babe, Grandpa);
    type Keys = SessionKeys;
    // spec 9: the only trigger for disabling is a proven Equivocation (`BanOnOffence`); the decision is in `MadarDisablingStrategy`.
    type DisablingStrategy = MadarDisablingStrategy;
    /// spec 9 (B1): `set_keys`/`purge_keys` weights measured on Madar (they were `()`).
    type WeightInfo = sdk_weights::SessionWeights;
    // **D42** — required now by `pallet_session::Config` (SDK upgrade to
    // stable2606-2). `KeyDeposit = ()` (always zero) means the hold required
    // when registering a session key is always accepted regardless of the account's balance — no
    // actual economic effect. See the module comment above (D42) for the full details.
    type Currency = Balances;
    type KeyDeposit = ();
}

/// The runtime version — the first actual version (spec version 1), no production assumption.
/// The actual spec_version = 9, and `transaction_version` = 2 because calls were removed (Admission 2 and 3, and the v1 sale calls in names). (B2: no candidacy and no draw entry without a vouch from an approved operator, and the operator's account is created with its first vouch; and removal of the two old v1 sale calls; before that 8 for the payment proof in safe sale: lock_sale_v2/complete_sale_v2, with the names security fixes of 2026-10-12 in the same upgrade; before that 7 for Madar Names, 6 for D55 Madar Stamp, 5 for D54 `AdmissionCapPerRound` 5→2, 4 for closing N1, and 3 for the ban_key weight in B1). The `upgrade-fixture` feature makes it 10.
#[cfg(not(feature = "upgrade-fixture"))]
#[sp_version::runtime_version]
pub const VERSION: sp_version::RuntimeVersion = sp_version::RuntimeVersion {
    spec_name: alloc::borrow::Cow::Borrowed("madar"),
    impl_name: alloc::borrow::Cow::Borrowed("madar-node"),
    authoring_version: 1,
    spec_version: 9,
    impl_version: 1,
    apis: RUNTIME_API_VERSIONS,
    // spec 9: 1 → 2 — calls were removed (Admission `ban_key`=2 and `dev_only_force_set_validators`=3, and names v1), so a transaction
    // signed for them before the upgrade does not decode after it. The committee tool still serves a spec ≤ 8 chain with tx 1 to pass the upgrade itself.
    transaction_version: 2,
    // Renamed from `state_version` to `system_version` in the SDK itself
    // (D40/D41 — SDK upgrade) — no semantic change.
    system_version: 1,
};
#[cfg(feature = "upgrade-fixture")]
#[sp_version::runtime_version]
pub const VERSION: sp_version::RuntimeVersion = sp_version::RuntimeVersion {
    spec_name: alloc::borrow::Cow::Borrowed("madar"),
    impl_name: alloc::borrow::Cow::Borrowed("madar-node"),
    authoring_version: 1,
    spec_version: 10,
    impl_version: 1,
    apis: RUNTIME_API_VERSIONS,
    // spec 9: 1 → 2 — calls were removed (Admission `ban_key`=2 and `dev_only_force_set_validators`=3, and names v1), so a transaction
    // signed for them before the upgrade does not decode after it. The committee tool still serves a spec ≤ 8 chain with tx 1 to pass the upgrade itself.
    transaction_version: 2,
    // Renamed from `state_version` to `system_version` in the SDK itself
    // (D40/D41 — SDK upgrade) — no semantic change.
    system_version: 1,
};

sp_api::impl_runtime_apis! {
    impl sp_api::Core<Block> for Runtime {
        fn version() -> sp_version::RuntimeVersion {
            VERSION
        }

        fn execute_block(block: <Block as sp_runtime::traits::Block>::LazyBlock) {
            Executive::execute_block(block);
        }

        fn initialize_block(header: &<Block as sp_runtime::traits::Block>::Header) -> sp_runtime::ExtrinsicInclusionMode {
            Executive::initialize_block(header)
        }
    }

    impl sp_api::Metadata<Block> for Runtime {
        fn metadata() -> sp_core::OpaqueMetadata {
            sp_core::OpaqueMetadata::new(Runtime::metadata().into())
        }

        fn metadata_at_version(version: u32) -> Option<sp_core::OpaqueMetadata> {
            Runtime::metadata_at_version(version)
        }

        fn metadata_versions() -> Vec<u32> {
            Runtime::metadata_versions()
        }
    }

    impl sp_block_builder::BlockBuilder<Block> for Runtime {
        fn apply_extrinsic(extrinsic: <Block as sp_runtime::traits::Block>::Extrinsic) -> sp_runtime::ApplyExtrinsicResult {
            Executive::apply_extrinsic(extrinsic)
        }

        fn finalize_block() -> <Block as sp_runtime::traits::Block>::Header {
            Executive::finalize_block()
        }

        fn inherent_extrinsics(data: sp_inherents::InherentData) -> Vec<<Block as sp_runtime::traits::Block>::Extrinsic> {
            data.create_extrinsics()
        }

        fn check_inherents(
            block: <Block as sp_runtime::traits::Block>::LazyBlock,
            data: sp_inherents::InherentData,
        ) -> sp_inherents::CheckInherentsResult {
            data.check_extrinsics(&block)
        }
    }

    impl sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block> for Runtime {
        fn validate_transaction(
            source: sp_runtime::transaction_validity::TransactionSource,
            tx: <Block as sp_runtime::traits::Block>::Extrinsic,
            block_hash: <Block as sp_runtime::traits::Block>::Hash,
        ) -> sp_runtime::transaction_validity::TransactionValidity {
            Executive::validate_transaction(source, tx, block_hash)
        }
    }

    impl sp_offchain::OffchainWorkerApi<Block> for Runtime {
        fn offchain_worker(header: &<Block as sp_runtime::traits::Block>::Header) {
            Executive::offchain_worker(header)
        }
    }

    impl sp_consensus_babe::BabeApi<Block> for Runtime {
        fn configuration() -> sp_consensus_babe::BabeConfiguration {
            let epoch_config = Babe::epoch_config().unwrap_or(sp_consensus_babe::BabeEpochConfiguration {
                c: (1, 4),
                allowed_slots: sp_consensus_babe::AllowedSlots::PrimaryAndSecondaryVRFSlots,
            });
            sp_consensus_babe::BabeConfiguration {
                slot_duration: Babe::slot_duration(),
                epoch_length: EPOCH_DURATION_IN_SLOTS,
                c: epoch_config.c,
                authorities: Babe::authorities().to_vec(),
                randomness: Babe::randomness(),
                allowed_slots: epoch_config.allowed_slots,
            }
        }

        fn current_epoch_start() -> sp_consensus_babe::Slot {
            Babe::current_epoch_start()
        }

        fn current_epoch() -> sp_consensus_babe::Epoch {
            Babe::current_epoch()
        }

        fn next_epoch() -> sp_consensus_babe::Epoch {
            Babe::next_epoch()
        }

        /// Session-key ownership proof from history (`pallet_session::historical`) — required to report a
        /// BABE equivocation, and it leads to `BanOnOffence`.
        fn generate_key_ownership_proof(
            _slot: sp_consensus_babe::Slot,
            authority_id: sp_consensus_babe::AuthorityId,
        ) -> Option<sp_consensus_babe::OpaqueKeyOwnershipProof> {
            use frame_support::traits::KeyOwnerProofSystem;
            use parity_scale_codec::Encode;
            Historical::prove((sp_consensus_babe::KEY_TYPE, authority_id))
                .map(|p| p.encode())
                .map(sp_consensus_babe::OpaqueKeyOwnershipProof::new)
        }

        fn submit_report_equivocation_unsigned_extrinsic(
            equivocation_proof: sp_consensus_babe::EquivocationProof<<Block as sp_runtime::traits::Block>::Header>,
            key_owner_proof: sp_consensus_babe::OpaqueKeyOwnershipProof,
        ) -> Option<()> {
            let key_owner_proof = key_owner_proof.decode()?;
            Babe::submit_unsigned_equivocation_report(equivocation_proof, key_owner_proof)
        }
    }

    impl sp_consensus_grandpa::GrandpaApi<Block> for Runtime {
        fn grandpa_authorities() -> sp_consensus_grandpa::AuthorityList {
            Grandpa::grandpa_authorities()
        }

        fn current_set_id() -> sp_consensus_grandpa::SetId {
            Grandpa::current_set_id()
        }

        /// Reporting a GRANDPA equivocation — leads to `BanOnOffence` (a permanent ban of the identity).
        fn submit_report_equivocation_unsigned_extrinsic(
            equivocation_proof: sp_consensus_grandpa::EquivocationProof<
                <Block as sp_runtime::traits::Block>::Hash,
                sp_runtime::traits::NumberFor<Block>,
            >,
            key_owner_proof: sp_consensus_grandpa::OpaqueKeyOwnershipProof,
        ) -> Option<()> {
            let key_owner_proof = key_owner_proof.decode()?;
            Grandpa::submit_unsigned_equivocation_report(equivocation_proof, key_owner_proof)
        }

        fn generate_key_ownership_proof(
            _set_id: sp_consensus_grandpa::SetId,
            authority_id: sp_consensus_grandpa::AuthorityId,
        ) -> Option<sp_consensus_grandpa::OpaqueKeyOwnershipProof> {
            use frame_support::traits::KeyOwnerProofSystem;
            use parity_scale_codec::Encode;
            Historical::prove((sp_consensus_grandpa::KEY_TYPE, authority_id))
                .map(|p| p.encode())
                .map(sp_consensus_grandpa::OpaqueKeyOwnershipProof::new)
        }
    }

    impl sp_session::SessionKeys<Block> for Runtime {
        fn generate_session_keys(owner: Vec<u8>, seed: Option<Vec<u8>>) -> sp_session::OpaqueGeneratedSessionKeys {
            SessionKeys::generate(&owner, seed).into()
        }

        fn decode_session_keys(
            encoded: Vec<u8>,
        ) -> Option<Vec<(Vec<u8>, sp_core::crypto::KeyTypeId)>> {
            SessionKeys::decode_into_raw_public_keys(&encoded)
        }
    }

    impl madar_admission_api::MembershipApi<Block> for Runtime {
        fn membership_status(who: sp_core::crypto::AccountId32) -> madar_admission_api::MembershipStatusV1 {
            membership_api::status(&who)
        }

        fn admission_params() -> madar_admission_api::AdmissionParamsV1 {
            membership_api::params()
        }

        fn puzzle_challenge() -> madar_admission_api::PuzzleChallengeV1 {
            membership_api::challenge()
        }
    }
    #[cfg(feature = "runtime-benchmarks")] impl frame_benchmarking::Benchmark<Block> for Runtime { fn benchmark_metadata(extra: bool) -> (Vec<frame_benchmarking::BenchmarkList>, Vec<frame_support::traits::StorageInfo>) { benchmarks::metadata(extra) } fn dispatch_benchmark(config: frame_benchmarking::BenchmarkConfig) -> Result<Vec<frame_benchmarking::BenchmarkBatch>, alloc::string::String> { benchmarks::dispatch(config) } } // B1 benchmarks only; one line on purpose, see the note at the end of this file.
    impl frame_system_rpc_runtime_api::AccountNonceApi<Block, AccountId, <Runtime as frame_system::Config>::Nonce> for Runtime {
        fn account_nonce(account: AccountId) -> <Runtime as frame_system::Config>::Nonce {
            System::account_nonce(account)
        }
    }

    impl sp_genesis_builder::GenesisBuilder<Block> for Runtime {
        fn build_state(config: Vec<u8>) -> sp_genesis_builder::Result {
            frame_support::genesis_builder_helper::build_state::<RuntimeGenesisConfig>(config)
        }

        fn get_preset(id: &Option<sp_genesis_builder::PresetId>) -> Option<Vec<u8>> {
            frame_support::genesis_builder_helper::get_preset::<RuntimeGenesisConfig>(
                id,
                genesis_config_presets::get_preset,
            )
        }

        fn preset_names() -> Vec<sp_genesis_builder::PresetId> {
            genesis_config_presets::preset_names()
        }
    }
}

impl madar_admission::Config for Runtime {
    // Membership term 84 Epochs (~7 days at Epoch=2h) + grace 12 Epochs (~1 day) — placeholders (D27/D28) until ARM64 measurement.
    type MembershipTermSessions = ConstU32<MEMBERSHIP_TERM_SESSIONS>;
    type RenewalGraceSessions = ConstU32<RENEWAL_GRACE_SESSIONS>;
    type MaxCandidatesPerRound = ConstU32<64>;
    type HasSessionKeys = HasRegisteredSessionKeys;
    // `RandomnessFromOneEpochAgo`: real BABE VRF randomness from a full past
    // epoch (§2.9: "unpredictable, derived from verifiable final state") — not
    // invented randomness.
    type EpochRandomness = pallet_babe::RandomnessFromOneEpochAgo<Runtime>;
    type BlockRandomness = pallet_babe::ParentBlockRandomness<Runtime>;
    // The minimum fresh VRFs before the draw: 16 blocks (production) — 4 in the isolated live build.
    type MinFreshEntropyBlocks = ConstU32<MIN_FRESH_ENTROPY_BLOCKS>;
    // 13 bits — owner decision 2026-09-28 (final; see `PUZZLE_DIFFICULTY_BITS`).
    type DifficultyLeadingZeroBits = ConstU32<PUZZLE_DIFFICULTY_BITS>;
    // D54 — owner decision (2026-09-23): at most 2 winners **per rotation** (all pools drawn in it together since spec 9).
    // spec 9: the value is in storage and is changed by the 2-of-3 committee (`set_admission_cap_per_round`) within 0..=16 — the hard limit 16
    // (`MaxCandidatesPerRound` 64 ≥ 16). Raising it to 3 and then 5 stays an explicit owner decision (D54); the committee is the execution tool.
    type DefaultAdmissionCapPerRound = ConstU32<2>;
    type AdmissionCapPerRoundLimit = ConstU32<16>;
    type MaxValidators = ConstU32<1_000>;
    // D47 — resistance to identity duplication through one operator: the same 2-of-3 committee (D44/D45)
    // is the only party able to approve an operator or revoke its approval. The system never relies
    // on any name the operator types itself.
    type OperatorApprovalOrigin = UpgradeApprovedOrigin;
    // N1 then spec 9: `ban_key` and `dev_only_force_set_validators` were removed from the Pallet (their indices 2 and 3 are never reused).
    // Banning only through Equivocation (`BanOnOffence` → `Admission::ban`). Tested: `tests/admin_calls_closed.rs`.
    // D52 — **final decision approved by the founder (2026-09-23):**
    // exactly one vote per operator, regardless of the source of its seat (a vouch or a
    // founding genesis/dev-only seat) — including the founding node itself if it belongs to it.
    // Justified by actual GRANDPA safety: no blocking vote can be tolerated from any single party unless
    // it holds less than 1/3 of the total weight; a cap of 1 guarantees that whatever the actual network size
    // at launch (see the internal design document,
    // §"Phase 1 scope", for the full analysis). Raising it later (if needed as the network grows)
    // a new explicit policy decision, not a silent change. spec 9: the value is in storage and is changed by the 2-of-3 committee
    // (`set_max_votes_per_operator`) within 1..=4 — the hard limit 4 that no governance can exceed.
    type DefaultMaxVotesPerOperator = ConstU32<1>;
    type MaxVotesPerOperatorLimit = ConstU32<4>;
    // Placeholder (D26) — the Argon2id values are frozen after ARM64 measurement (D23, B2 §4 proposal 2).
    type ArgonMemoryCostKib = ConstU32<19_456>;
    type ArgonTimeCost = ConstU32<2>;
    // The real Argon2 cost is derived from the two parameters above (see `madar_admission::weights`).
    type WeightInfo = madar_admission::weights::ArgonMeteredWeight<Runtime>;
}

parameter_types! {
    /// A technical maximum (half the block weight, 1 s of 2 s) for any call the committee decides —
    /// it does not restrict the kind of call itself, only a defensive execution cap (the measured `set_code` ≈ 220 ms).
    /// **The proof size (proof_size) is no longer 0:** after accounting the inner call's weight in
    /// `dispatch_as_root`, any Root proposal (such as `set_code`) has a proof weight > 0, and
    /// a cap of 0 would reject every proposal with `WrongProposalWeight`.
    pub UpgradeCommitteeMaxProposalWeight: Weight = Weight::from_parts(1_000_000_000_000, 4 * 1024 * 1024);
}

/// The runtime upgrade committee — 3 members, a 2-of-3 threshold (D43). `pallet_collective`
/// is not modified at all; the wiring here is the only security control. See the
/// module comment at the top of the file for the full details.
impl pallet_collective::Config<UpgradeCommitteeInstance> for Runtime {
    type RuntimeOrigin = RuntimeOrigin;
    type Proposal = RuntimeCall;
    type RuntimeEvent = RuntimeEvent;
    /// A minimum voting window before an early close is possible with the default values
    /// (abstention → `false` via `PrimeDefaultVote` with no prime set, safe
    /// by default) — one Epoch (900 blocks ≈ 2 hours), reviewed together with the committee's
    /// operating policy.
    /// **It does not affect the essential security control:** `UpgradeApprovedOrigin`
    /// re-checks the actual vote ratio (`Members(yes, total)`) at
    /// execution regardless of this value or of the threshold chosen by the proposal's
    /// submitter.
    type MotionDuration = ConstU32<900>;
    type MaxProposals = ConstU32<16>;
    type MaxMembers = ConstU32<3>;
    type DefaultVote = pallet_collective::PrimeDefaultVote;
    type WeightInfo = sdk_weights::CollectiveWeights;
    /// **Direct `set_members` is completely disabled:** it accepted any membership size (`MaxMembers` is not enforced
    /// on it), weakening 2-of-3. The membership now changes only through
    /// `madar_upgrade_authority::set_committee_members` (2-of-3 **and** exactly size 3, no duplicates).
    type SetMembersOrigin = CommitteeSetMembersOrigin;
    type MaxProposalWeight = UpgradeCommitteeMaxProposalWeight;
    /// Cancelling a proposal without cost — the same 2-of-3 threshold, no easier path (no reason
    /// to allow cancellation with a weaker origin than the approval itself).
    type DisapproveOrigin = UpgradeApprovedOrigin;
    /// "Killing" a malicious proposal (with a possible cost through `Consideration`) — the same
    /// threshold too, for the same reason.
    type KillOrigin = UpgradeApprovedOrigin;
    /// No cost/deposit for storing proposals (D17: no fees at all in this
    /// runtime; `()` means no cost, exactly matching).
    type Consideration = ();
}

/// The `Root` gate through the committee (D43) — there is no `pallet_sudo` in this runtime
/// at all. See `madar_upgrade_authority` (the full module comment there)
/// and the internal design document.
impl madar_upgrade_authority::Config for Runtime {
    type RuntimeCall = RuntimeCall;
    /// **The only security control for every Root call through this pallet** —
    /// a 2-of-3 threshold on `UpgradeCommittee`, without exception.
    type ApprovedOrigin = UpgradeApprovedOrigin;
    type WeightInfo = madar_upgrade_authority::weights::ConservativeWeight<Runtime>;
    type Committee = UpgradeCommitteeControl;
    type CommitteeSize = ConstU32<3>;
    type MaxCommitteeProposals = ConstU32<16>;
}

/// Madar Stamp (D55): permanent timestamps for file fingerprints, "first one wins", and the wallet signature is verified by
/// the runtime. Stampers are added/removed by the same upgrade committee (2-of-3) — no single key.
impl madar_stamp::Config for Runtime {
    type AdminOrigin = UpgradeApprovedOrigin;
    type Time = Timestamp;
    type MaxBatch = ConstU32<50>;
    type MaxStampers = ConstU32<4>;
    type WeightInfo = madar_stamp::weights::ConservativeWeight<Runtime>;
}

// Madar Names (spec 7; payment proof in safe sale spec 8): a yearly name bound to its owner's wallet by its signature, verified by the Runtime. The registrars,
// the reserved list and withdrawal for proven fraud are decided by the upgrade committee itself (2-of-3).
parameter_types! {
    /// Longest term that can be paid in advance: 10 years.
    pub const NamesMaxTermMs: u64 = 10 * 366 * 24 * 3600 * 1000;
}
impl madar_names::Config for Runtime {
    type AdminOrigin = UpgradeApprovedOrigin;
    type Time = Timestamp;
    type MaxRegistrars = ConstU32<4>;
    type MaxTermMs = NamesMaxTermMs;
    type WeightInfo = madar_names::weights::ConservativeWeight<Runtime>;
}

/// An Admission candidate is not accepted at the lottery unless it actually registered session keys
/// (`pallet_session::NextKeys`) — so no seat is wasted on an account without BABE/GRANDPA keys.
pub struct HasRegisteredSessionKeys;
impl frame_support::traits::Contains<AccountId> for HasRegisteredSessionKeys {
    fn contains(who: &AccountId) -> bool {
        pallet_session::NextKeys::<Runtime>::contains_key(who)
    }
}

/// The upgrade committee as seen by `madar_upgrade_authority`. `pallet_collective::set_members` is disabled
/// (`SetMembersOrigin = EnsureNever`), so this is the only way to change the membership, and it enforces the size.
pub struct UpgradeCommitteeControl;
impl madar_upgrade_authority::CommitteeControl<AccountId> for UpgradeCommitteeControl {
    fn members() -> Vec<AccountId> {
        pallet_collective::Members::<Runtime, UpgradeCommitteeInstance>::get()
    }
    fn replace(sorted_new: &[AccountId]) {
        use frame_support::traits::ChangeMembers;
        let old = pallet_collective::Members::<Runtime, UpgradeCommitteeInstance>::get();
        pallet_collective::Pallet::<Runtime, UpgradeCommitteeInstance>::set_members_sorted(
            sorted_new, &old,
        );
    }
}

/// The membership term (epochs) — a single source for the membership term and GRANDPA's set-id history.
#[cfg(not(feature = "fast-test-runtime"))]
pub const MEMBERSHIP_TERM_SESSIONS: u32 = 84;
#[cfg(all(feature = "fast-test-runtime", not(feature = "upgrade-fixture")))]
pub const MEMBERSHIP_TERM_SESSIONS: u32 = 4;
/// The test upgrade build changes the constant on purpose (5) to prove that clients follow the chain parameters through `MembershipApi` without rebuilding.
#[cfg(all(feature = "fast-test-runtime", feature = "upgrade-fixture"))]
pub const MEMBERSHIP_TERM_SESSIONS: u32 = 5;
/// Renewal grace (epochs) — the same isolation.
#[cfg(not(feature = "fast-test-runtime"))]
pub const RENEWAL_GRACE_SESSIONS: u32 = 12;
#[cfg(feature = "fast-test-runtime")]
pub const RENEWAL_GRACE_SESSIONS: u32 = 2;
/// Puzzle difficulty (bits) — the same isolation (the Argon2 cost of every verification stays real).
/// **B2 — owner decision 2026-09-28:** the target is ~5 minutes on average on a regular computer. Actually measured: 14 ms/attempt on an i7-12700KF
/// (~35 ms on a regular computer ~2.5× slower) ⇒ 13 bits = 8192 attempts ≈ 4.8 minutes (regular) and ≈ 1.9 minutes (fast). The distribution is geometric:
/// the average is as stated, and sometimes several times that. Final, and on the live network since spec 6.
#[cfg(not(feature = "fast-test-runtime"))]
pub const PUZZLE_DIFFICULTY_BITS: u32 = 13;
#[cfg(feature = "fast-test-runtime")]
pub const PUZZLE_DIFFICULTY_BITS: u32 = 6;
/// The accepted age of an equivocation proof (slots) ~ the membership term.
pub type EquivocationReportLongevity =
    ConstU64<{ MEMBERSHIP_TERM_SESSIONS as u64 * EPOCH_DURATION_IN_SLOTS }>;

impl pallet_authorship::Config for Runtime {
    type FindAuthor = pallet_session::FindAccountFromAuthorIndex<Self, Babe>;
    type EventHandler = ();
}

/// No stake and no economic identity: the full identity of a validator is `()`.
pub struct UnitIdentification;
impl sp_runtime::traits::Convert<AccountId, Option<()>> for UnitIdentification {
    fn convert(_: AccountId) -> Option<()> {
        Some(())
    }
}

impl pallet_session::historical::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type FullIdentification = ();
    type FullIdentificationOf = UnitIdentification;
}

/// **Equivocation enforcement:** any offence (double vote/block) proven by GRANDPA or BABE with a valid session-key
/// ownership proof ends in a permanent ban of the offender's identity (`Admission::ban`): removal from the members and candidates
/// and no re-admission. No monetary slashing (no stake, D21); the only penalty is losing the identity.
pub struct BanOnOffence;

/// Penalty for a proven offence: permanent ban (`Admission::ban`, with the B12 rule for the last one), then (spec 9) immediate disabling in BABE within the limits of
/// `MadarDisablingStrategy` — its blocks are rejected from this block on. GRANDPA has no disabling in the SDK: it leaves the GRANDPA set through the
/// usual rotation (two rotations) as before. Its weight is counted in the weight of the Equivocation report (`sdk_weights::EQUIVOCATION_EXTRA`).
pub fn ban_and_disable(offender: &AccountId) {
    Admission::ban(offender);
    Session::report_offence(
        offender.clone(),
        sp_staking::offence::OffenceSeverity(sp_runtime::Perbill::one()),
    );
}
impl<O> sp_staking::offence::ReportOffence<AccountId, (AccountId, ()), O> for BanOnOffence
where
    O: sp_staking::offence::Offence<(AccountId, ())>,
{
    fn report_offence(
        _reporters: Vec<AccountId>,
        offence: O,
    ) -> Result<(), sp_staking::offence::OffenceError> {
        for (offender, _) in offence.offenders() {
            ban_and_disable(&offender);
        }
        Ok(())
    }

    /// Already reported = all offenders are actually banned: duplicates are rejected in the pool (`Stale`) and at execution
    /// (`DuplicateOffenceReport`) instead of being re-included in every block.
    fn is_known_offence(offenders: &[(AccountId, ())], _time_slot: &O::TimeSlot) -> bool {
        !offenders.is_empty()
            && offenders
                .iter()
                .all(|(who, _)| madar_admission::BannedKeys::<Runtime>::contains_key(who))
    }
}

/// **spec 9 — the banned validator is disabled immediately in BABE (`pallet_session::DisabledValidators`).** Before this, a proven offender stayed a fully
/// valid block producer until it left the session set after two rotations (up to ~4 hours). The decision:
/// - the offender is outside the active set, or already disabled ⇒ nothing.
/// - **Byzantine limit:** disabled validators never exceed `floor((n-1)/3)` of the active set (the same as the standard `UpToLimitDisablingStrategy`,
///   without "re-enabling" others: all our offences are a permanent ban of the same severity). With 1–3 voters nobody is disabled.
/// - **B12 (the last voters):** not disabled unless at least one block producer would remain in the active set that is **not disabled,
///   still in Admission and not banned** — so the kept banned validator (`LastValidatorBannedButKept`) is never disabled, and nobody is disabled
///   in favour of departing members only.
/// Disabling does not touch GRANDPA (it has no disabling in the SDK; the client ignores `OnDisabled`), so it does not reduce the number of finality voters.
pub struct MadarDisablingStrategy;
impl pallet_session::disabling::DisablingStrategy<Runtime> for MadarDisablingStrategy {
    fn decision(
        offender: &AccountId,
        _severity: sp_staking::offence::OffenceSeverity,
        currently_disabled: &Vec<(u32, sp_staking::offence::OffenceSeverity)>,
    ) -> pallet_session::disabling::DisablingDecision {
        let active = pallet_session::Validators::<Runtime>::get();
        // sets, so the scan stays O(n log n) even when most of a 1000-member active set has already left Admission
        let staying: alloc::collections::BTreeSet<AccountId> =
            madar_admission::Validators::<Runtime>::get()
                .into_iter()
                .collect();
        madar_disabling_decision(offender, currently_disabled, &active, &staying)
    }
}

/// The decision of [`MadarDisablingStrategy`] with the active set and the Admission members passed in, so
/// [`MadarSessionManager::start_session`] builds them once for all banned keys (spec 9, independent review #7).
fn madar_disabling_decision(
    offender: &AccountId,
    currently_disabled: &[(u32, sp_staking::offence::OffenceSeverity)],
    active: &[AccountId],
    staying: &alloc::collections::BTreeSet<AccountId>,
) -> pallet_session::disabling::DisablingDecision {
    {
        let none = pallet_session::disabling::DisablingDecision {
            disable: None,
            reenable: None,
        };
        let Some(idx) = active.iter().position(|v| v == offender).map(|i| i as u32) else {
            return none;
        };
        if currently_disabled.iter().any(|(i, _)| *i == idx) {
            return none;
        }
        if currently_disabled.len()
            >= pallet_session::disabling::UpToLimitDisablingStrategy::<3>::disable_limit(
                active.len(),
            )
        {
            return none;
        }
        let disabled: alloc::collections::BTreeSet<u32> =
            currently_disabled.iter().map(|(i, _)| *i).collect();
        let another_author_stays = active.iter().enumerate().any(|(i, v)| {
            i as u32 != idx
                && !disabled.contains(&(i as u32))
                && staying.contains(v)
                && !madar_admission::BannedKeys::<Runtime>::contains_key(v)
        });
        if !another_author_stays {
            return none;
        }
        pallet_session::disabling::DisablingDecision {
            disable: Some(idx),
            reenable: None,
        }
    }
}

/// The actual `SessionManager`: Admission as is, then (spec 9) at the start of each session any banned validator still in the active set is
/// disabled again. `pallet_session` clears the disabled list at every rotation in which the set changes, and a banned validator stays in the active set
/// for one rotation after the ban (it was in the queued set); without this it would be a fully valid block producer again in that rotation.
/// Only those who left the Admission record are checked (a banned validator is removed from it immediately, except the kept last one, which is never disabled).
pub struct MadarSessionManager;
impl pallet_session::SessionManager<AccountId> for MadarSessionManager {
    fn new_session(new_index: u32) -> Option<Vec<AccountId>> {
        <Admission as pallet_session::SessionManager<AccountId>>::new_session(new_index)
    }
    fn new_session_genesis(new_index: u32) -> Option<Vec<AccountId>> {
        <Admission as pallet_session::SessionManager<AccountId>>::new_session_genesis(new_index)
    }
    fn start_session(start_index: u32) {
        <Admission as pallet_session::SessionManager<AccountId>>::start_session(start_index);
        // spec 9 (independent review #7): the active set and the Admission members are built once here, not again for
        // every banned key (`madar_disabling_decision` takes them); the effect equals `Session::report_offence`.
        let staying: alloc::collections::BTreeSet<AccountId> =
            madar_admission::Validators::<Runtime>::get()
                .into_iter()
                .collect();
        let active = pallet_session::Validators::<Runtime>::get();
        let severity = sp_staking::offence::OffenceSeverity(sp_runtime::Perbill::one());
        for v in active.iter() {
            if !staying.contains(v) && madar_admission::BannedKeys::<Runtime>::contains_key(v) {
                let disabled = pallet_session::DisabledValidators::<Runtime>::get();
                if let Some(idx) = madar_disabling_decision(v, &disabled, &active, &staying).disable
                {
                    Session::disable_index_with_severity(idx, severity);
                }
            }
        }
    }
    fn end_session(end_index: u32) {
        <Admission as pallet_session::SessionManager<AccountId>>::end_session(end_index)
    }
}
impl pallet_session::historical::SessionManager<AccountId, ()> for MadarSessionManager {
    fn new_session(new_index: u32) -> Option<Vec<(AccountId, ())>> {
        <Self as pallet_session::SessionManager<AccountId>>::new_session(new_index)
            .map(|s| s.into_iter().map(|v| (v, ())).collect())
    }
    fn new_session_genesis(new_index: u32) -> Option<Vec<(AccountId, ())>> {
        <Self as pallet_session::SessionManager<AccountId>>::new_session_genesis(new_index)
            .map(|s| s.into_iter().map(|v| (v, ())).collect())
    }
    fn start_session(start_index: u32) {
        <Self as pallet_session::SessionManager<AccountId>>::start_session(start_index)
    }
    fn end_session(end_index: u32) {
        <Self as pallet_session::SessionManager<AccountId>>::end_session(end_index)
    }
}

impl<C> frame_system::offchain::CreateTransactionBase<C> for Runtime
where
    RuntimeCall: From<C>,
{
    type Extrinsic = UncheckedExtrinsic;
    type RuntimeCall = RuntimeCall;
}

impl<C> frame_system::offchain::CreateBare<C> for Runtime
where
    RuntimeCall: From<C>,
{
    fn create_bare(call: Self::RuntimeCall) -> Self::Extrinsic {
        generic::UncheckedExtrinsic::new_bare(call)
    }
}

/// **Pre-checking an equivocation proof before it enters the pool** (not only at execution). The standard `check_evidence`
/// verifies the key-ownership proof and non-duplication but does **not** verify the validity of the conflicting signatures; so an
/// invalid report was included in every block and then failed (found live: 44 failed inclusions). Here it is rejected early (`BadProof`).
/// It does not change BABE/GRANDPA: a wrapper over the standard `EquivocationReportSystem`.
pub struct VerifiedBabeReports<Inner>(core::marker::PhantomData<Inner>);

type BabeEvidence = (
    sp_consensus_babe::EquivocationProof<Header>,
    <Runtime as pallet_babe::Config>::KeyOwnerProof,
);

impl<Inner> sp_staking::offence::OffenceReportSystem<Option<AccountId>, BabeEvidence>
    for VerifiedBabeReports<Inner>
where
    Inner: sp_staking::offence::OffenceReportSystem<Option<AccountId>, BabeEvidence>,
{
    type Longevity = Inner::Longevity;

    fn publish_evidence(evidence: BabeEvidence) -> Result<(), ()> {
        Inner::publish_evidence(evidence)
    }

    fn check_evidence(
        evidence: BabeEvidence,
    ) -> Result<(), sp_runtime::transaction_validity::TransactionValidityError> {
        if !sp_consensus_babe::check_equivocation_proof(evidence.0.clone()) {
            return Err(sp_runtime::transaction_validity::InvalidTransaction::BadProof.into());
        }
        Inner::check_evidence(evidence)
    }

    fn process_evidence(
        reporter: Option<AccountId>,
        evidence: BabeEvidence,
    ) -> Result<(), sp_runtime::DispatchError> {
        Inner::process_evidence(reporter, evidence)
    }
}

/// The same idea for GRANDPA (verifying the two conflicting signatures before the pool).
pub struct VerifiedGrandpaReports<Inner>(core::marker::PhantomData<Inner>);

type GrandpaEvidence = (
    sp_consensus_grandpa::EquivocationProof<<Runtime as frame_system::Config>::Hash, BlockNumber>,
    <Runtime as pallet_grandpa::Config>::KeyOwnerProof,
);

impl<Inner> sp_staking::offence::OffenceReportSystem<Option<AccountId>, GrandpaEvidence>
    for VerifiedGrandpaReports<Inner>
where
    Inner: sp_staking::offence::OffenceReportSystem<Option<AccountId>, GrandpaEvidence>,
{
    type Longevity = Inner::Longevity;

    fn publish_evidence(evidence: GrandpaEvidence) -> Result<(), ()> {
        Inner::publish_evidence(evidence)
    }

    fn check_evidence(
        evidence: GrandpaEvidence,
    ) -> Result<(), sp_runtime::transaction_validity::TransactionValidityError> {
        if !sp_consensus_grandpa::check_equivocation_proof(evidence.0.clone()) {
            return Err(sp_runtime::transaction_validity::InvalidTransaction::BadProof.into());
        }
        Inner::check_evidence(evidence)
    }

    fn process_evidence(
        reporter: Option<AccountId>,
        evidence: GrandpaEvidence,
    ) -> Result<(), sp_runtime::DispatchError> {
        Inner::process_evidence(reporter, evidence)
    }
}

/// The minimum number of fresh VRFs (after the candidacy closes) before the lottery draw — production 16 blocks; the isolated live build 4.
#[cfg(not(feature = "fast-test-runtime"))]
pub const MIN_FRESH_ENTROPY_BLOCKS: u32 = 16;
#[cfg(feature = "fast-test-runtime")]
pub const MIN_FRESH_ENTROPY_BLOCKS: u32 = 4;

// ---------------------------------------------------------------------------------------------------------------------
// B1 benchmarks (feature `runtime-benchmarks`, never in a production build). Everything is kept at the end of the file,
// and the `Benchmark` runtime API impl above sits on one line, on purpose: the runtime wasm embeds source line numbers
// (panic locations), so moving any line above would change the default wasm. With the feature off nothing here exists
// and the default runtime is byte-identical (B1-2026-10-15).
// ---------------------------------------------------------------------------------------------------------------------

/// Wiring for `madar-node benchmark` (benchmarked pallets, helpers, the session-transition benchmark).
#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarks;

/// `pallet_collective::SetMembersOrigin` of the upgrade committee: `EnsureNever` in every real build (membership changes
/// only through `UpgradeAuthority::set_committee_members`, see the collective config above).
#[cfg(not(feature = "runtime-benchmarks"))]
pub type CommitteeSetMembersOrigin = frame_system::EnsureNever<()>;
/// Benchmark builds only: the SDK `pallet_collective` benchmarks seed members through `set_members(Root)`.
#[cfg(feature = "runtime-benchmarks")]
pub type CommitteeSetMembersOrigin = frame_system::EnsureRoot<AccountId>;
