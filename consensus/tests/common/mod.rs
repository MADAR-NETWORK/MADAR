//! Shared test utilities — Genesis with a Validator set that is **local, for testing
//! purposes only** (D25: this must not be used as the basis for any public network before
//! Admission/Sybil).

#![allow(dead_code)] // shared helpers: each test file uses a subset of them

use madar_consensus::Runtime;
use sp_core::{ed25519, sr25519, Pair};
use sp_runtime::BuildStorage;

/// A test Dev account: a BABE (sr25519) + GRANDPA (ed25519) key derived from
/// the same numeric seed, and a matching account identifier (`madar_identity::AccountId`
/// derived from the BABE key — a purely testing choice, not a production identity decision).
pub struct DevValidator {
    pub seed: u8,
    pub account: sp_runtime::AccountId32,
    pub babe: sp_consensus_babe::AuthorityId,
    pub grandpa: sp_consensus_grandpa::AuthorityId,
}

pub fn dev_validator(seed_byte: u8) -> DevValidator {
    let babe_pair = sr25519::Pair::from_seed(&[seed_byte; 32]);
    let grandpa_pair = ed25519::Pair::from_seed(&[seed_byte; 32]);
    DevValidator {
        seed: seed_byte,
        account: sp_runtime::AccountId32::from(babe_pair.public().0),
        babe: babe_pair.public().into(),
        grandpa: grandpa_pair.public().into(),
    }
}

/// Test Runtime upgrade committee accounts (D43) — fixed Seeds completely separate
/// from any Seed used for Validators in any other test, to avoid any overlap.
/// **Purely for testing** — unrelated to any actual production committee (matches D25).
pub fn dev_committee_accounts() -> [sp_runtime::AccountId32; 3] {
    [201u8, 202u8, 203u8]
        .map(|seed| sp_runtime::AccountId32::from(sr25519::Pair::from_seed(&[seed; 32]).public().0))
}

pub fn new_test_ext(validators: &[DevValidator]) -> sp_io::TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("frame_system genesis storage must build");

    // Important technical note: we do not set `authorities` here directly — when using
    // `pallet_session` together, BABE/GRANDPA authority initialization happens automatically via
    // `SessionHandler::on_genesis_session` (called from the Genesis of
    // `pallet_session` below), and setting them here as well causes an actual Panic
    // ("Authorities are already initialized!") — discovered by actually running it.
    pallet_babe::GenesisConfig::<Runtime> {
        authorities: vec![],
        epoch_config: sp_consensus_babe::BabeEpochConfiguration {
            c: (1, 4),
            allowed_slots: sp_consensus_babe::AllowedSlots::PrimaryAndSecondaryVRFSlots,
        },
        ..Default::default()
    }
    .assimilate_storage(&mut storage)
    .expect("pallet_babe genesis storage must build");

    pallet_grandpa::GenesisConfig::<Runtime> {
        authorities: vec![],
        ..Default::default()
    }
    .assimilate_storage(&mut storage)
    .expect("pallet_grandpa genesis storage must build");

    // D42: mandatory infrastructure imposed by `pallet_session::Config::Currency` —
    // with no Endowment at all, matching `genesis_config_presets.rs` exactly.
    pallet_balances::GenesisConfig::<Runtime> {
        balances: vec![],
        ..Default::default()
    }
    .assimilate_storage(&mut storage)
    .expect("pallet_balances genesis storage must build");

    pallet_session::GenesisConfig::<Runtime> {
        keys: validators
            .iter()
            .map(|v| {
                (
                    v.account.clone(),
                    v.account.clone(),
                    madar_consensus::SessionKeys {
                        babe: v.babe.clone(),
                        grandpa: v.grandpa.clone(),
                    },
                )
            })
            .collect(),
        ..Default::default()
    }
    .assimilate_storage(&mut storage)
    .expect("pallet_session genesis storage must build");

    // Sync the private accounting of `madar_admission` (Validators) with the same
    // Genesis set — see the `new_session_genesis` comment in `madar_admission` for why
    // this sync is needed separately from `pallet_session::GenesisConfig::keys`.
    madar_admission::GenesisConfig::<Runtime> {
        validators: validators.iter().map(|v| v.account.clone()).collect(),
    }
    .assimilate_storage(&mut storage)
    .expect("madar_admission genesis storage must build");

    // D43: Runtime upgrade committee — 3 fixed test accounts (see
    // `dev_committee_accounts`), completely separate from the consensus Validators.
    pallet_collective::GenesisConfig::<Runtime, madar_consensus::UpgradeCommitteeInstance> {
        members: dev_committee_accounts().to_vec(),
        ..Default::default()
    }
    .assimilate_storage(&mut storage)
    .expect("pallet_collective (UpgradeCommittee) genesis storage must build");

    sp_io::TestExternalities::new(storage)
}
