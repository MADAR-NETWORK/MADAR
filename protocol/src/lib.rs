//! MADAR Network — Protocol crate.
//!
//! The scope of this library is limited to the "Protocol" phase per
//! the design document (§2.12):
//! chain ID, network prefix, genesis fields, and the single domain-separation tag.
//!
//! No runtime, no consensus, no P2P, no admission logic here — those are later phases.
//! No custom cryptography: everything cryptographic is consumed directly from `sp-core`/`sp-runtime`.
//!
//! **`no_std` (a decision implemented in the P2P networking phase — explicitly deferred since
//! the Protocol phase, see `rust-toolchain.toml` and the comment that used to be in
//! `chain_spec.rs`):** required to actually build `madar-consensus::Runtime` as WASM
//! (`substrate-wasm-builder` compiles the runtime for the `wasm32-unknown-unknown` target,
//! which has no `std`). No change to any behavior or protocol constant — a pure
//! compilation-compatibility change.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod chain_spec;
pub mod domains;

pub use chain_spec::{chain_id, GenesisFields, SS58_PREFIX, SS58_PREFIX_DEV};
pub use domains::ADMISSION_PUZZLE_DOMAIN;
