//! Genesis presets — `dev`/`local_testnet` only (D25, strict: any validator
//! set here is purely internal dev/testnet, and it is **forbidden** to use it as the basis of any
//! public network before Admission/Sybil is actually ready).
//!
//! Matches the pattern of `consensus/tests/common/mod.rs` exactly (the same fields, the same logic of
//! not setting `authorities` directly in Babe/Grandpa — `pallet_session` is the single source
//! of truth through `SessionHandler::on_genesis_session`, avoiding the
//! "Authorities are already initialized!" panic actually found in the Consensus phase).
//! No `Sudo` here. `Balances` exists now (D42 — mandatory infrastructure imposed by
//! `pallet_session::Config::Currency`) but **with no endowment at all**
//! (`balances: vec![]`) — nobody holds any real balance (D21/D38 still
//! stand: no token/economy for now).
//!
//! **Runtime upgrade committee (D43/D45):** the three committee members below are
//! the **real** upgrade-committee accounts (D45 — the three keys were created with
//! `committee-tools/madar-committee-keygen` on an air-gapped machine, each
//! key on a separate encrypted USB medium; the `.enc` files were never moved into this repository
//! — the values here are derived only from the public `account_id_hex` of each
//! `.pub` file). This is **completely separate** from the consensus validators (Alice/Bob)
//! below, which stay explicitly dev-only (D25) until Admission/Sybil is ready.

use crate::{AccountId, RuntimeGenesisConfig, SessionKeys};
use alloc::{vec, vec::Vec};
use frame_support::build_struct_json_patch;
use serde_json::Value;
use sp_genesis_builder::{self, PresetId};
use sp_keyring::{Ed25519Keyring, Sr25519Keyring};

/// One dev account: an address (AccountId from the BABE/sr25519 key) + two session keys.
fn dev_validator(sr25519: Sr25519Keyring, ed25519: Ed25519Keyring) -> (AccountId, SessionKeys) {
    (
        sr25519.to_account_id(),
        SessionKeys {
            babe: sr25519.public().into(),
            grandpa: ed25519.public().into(),
        },
    )
}

/// The real runtime upgrade committee members (D45) — 3 independent accounts, each
/// matching a key on a separate encrypted USB medium. The values here are
/// only the public `account_id_hex` from each `.pub` file — unrelated to any
/// secret phrase or private key.
fn upgrade_committee_members() -> Vec<AccountId> {
    vec![
        AccountId::from([
            0xbe, 0xf8, 0x50, 0x3c, 0xbf, 0x6c, 0xfe, 0xcd, 0x34, 0x5a, 0xdd, 0x42, 0x70, 0x8f,
            0x1b, 0x75, 0x89, 0x11, 0xac, 0xfc, 0x79, 0xc6, 0x1a, 0x30, 0xf9, 0x09, 0xba, 0x41,
            0xbe, 0xb9, 0xcf, 0x45,
        ]),
        AccountId::from([
            0xce, 0x46, 0x19, 0x57, 0x7b, 0xfc, 0x76, 0x7f, 0xe3, 0x85, 0xe3, 0x47, 0xc2, 0x43,
            0xc0, 0xd8, 0xff, 0xa4, 0x95, 0xf1, 0x21, 0x84, 0x9f, 0x5c, 0x2b, 0x92, 0x30, 0xa6,
            0x56, 0x8a, 0x59, 0x25,
        ]),
        AccountId::from([
            0xf0, 0x27, 0x36, 0xa1, 0xad, 0xc6, 0xa7, 0x43, 0x1c, 0x45, 0x82, 0x70, 0x91, 0x39,
            0xcd, 0x4e, 0x63, 0x7f, 0x3f, 0x34, 0x76, 0x71, 0x8d, 0x9c, 0xee, 0xe0, 0x48, 0xf3,
            0x31, 0x2a, 0x0b, 0x7c,
        ]),
    ]
}

fn testnet_genesis(validators: Vec<(AccountId, SessionKeys)>, committee: Vec<AccountId>) -> Value {
    build_struct_json_patch!(RuntimeGenesisConfig {
        babe: pallet_babe::GenesisConfig {
            authorities: vec![],
            epoch_config: sp_consensus_babe::BabeEpochConfiguration {
                c: (1, 4),
                allowed_slots: sp_consensus_babe::AllowedSlots::PrimaryAndSecondaryVRFSlots,
            },
        },
        grandpa: pallet_grandpa::GenesisConfig {
            authorities: vec![]
        },
        balances: pallet_balances::GenesisConfig { balances: vec![] },
        session: pallet_session::GenesisConfig {
            keys: validators
                .iter()
                .map(|(account, keys)| (account.clone(), account.clone(), keys.clone()))
                .collect::<Vec<_>>(),
        },
        admission: madar_admission::GenesisConfig {
            validators: validators
                .iter()
                .map(|(account, _)| account.clone())
                .collect::<Vec<_>>(),
        },
        upgrade_committee: pallet_collective::GenesisConfig {
            members: committee,
            ..Default::default()
        },
    })
}

/// One dev node (Alice) — for a single `--dev` run only.
pub fn development_config_genesis() -> Value {
    testnet_genesis(
        vec![dev_validator(Sr25519Keyring::Alice, Ed25519Keyring::Alice)],
        upgrade_committee_members(),
    )
}

/// A local multi-node network (Alice + Bob) — for actually testing multi-node P2P.
#[cfg(not(feature = "fast-test-runtime"))]
pub fn local_config_genesis() -> Value {
    testnet_genesis(
        vec![
            dev_validator(Sr25519Keyring::Alice, Ed25519Keyring::Alice),
            dev_validator(Sr25519Keyring::Bob, Ed25519Keyring::Bob),
        ],
        upgrade_committee_members(),
    )
}

/// **Isolated live tests only (`fast-test-runtime`, never built for production):** 3 validators (Alice/Bob/Charlie)
/// and a test upgrade committee with public dev keys (Dave/Eve/Ferdie) — unrelated to the real D45 committee and
/// to any production key. Replaces the `local_testnet` preset in that build only.
#[cfg(feature = "fast-test-runtime")]
pub fn local_config_genesis() -> Value {
    testnet_genesis(
        vec![
            dev_validator(Sr25519Keyring::Alice, Ed25519Keyring::Alice),
            dev_validator(Sr25519Keyring::Bob, Ed25519Keyring::Bob),
            dev_validator(Sr25519Keyring::Charlie, Ed25519Keyring::Charlie),
        ],
        vec![
            Sr25519Keyring::Dave.to_account_id(),
            Sr25519Keyring::Eve.to_account_id(),
            Sr25519Keyring::Ferdie.to_account_id(),
        ],
    )
}

/// Per `sp_genesis_builder::GenesisBuilder::get_preset` (§2.10) — dev/local only.
pub fn get_preset(id: &PresetId) -> Option<Vec<u8>> {
    let patch = match id.as_ref() {
        sp_genesis_builder::DEV_RUNTIME_PRESET => development_config_genesis(),
        sp_genesis_builder::LOCAL_TESTNET_RUNTIME_PRESET => local_config_genesis(),
        _ => return None,
    };
    Some(
        serde_json::to_string(&patch)
            .expect("serialization to json is expected to work. qed.")
            .into_bytes(),
    )
}

pub fn preset_names() -> Vec<PresetId> {
    vec![
        PresetId::from(sp_genesis_builder::DEV_RUNTIME_PRESET),
        PresetId::from(sp_genesis_builder::LOCAL_TESTNET_RUNTIME_PRESET),
    ]
}
