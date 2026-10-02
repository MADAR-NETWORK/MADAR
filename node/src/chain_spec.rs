//! ChainSpec definitions — Dev/Local only (D25: no public network before the actual
//! Admission/Sybil readiness). The first real use of the `madar_protocol::chain_spec` constants
//! (Chain ID/SS58 Prefix) in a real node (§2.1/§2.5).

use madar_consensus::WASM_BINARY;
use sc_service::{ChainType, Properties};

pub type ChainSpec = sc_service::GenericChainSpec;

fn dev_properties() -> Properties {
    let mut properties = Properties::new();
    properties.insert(
        "ss58Format".into(),
        madar_protocol::chain_spec::SS58_PREFIX_DEV.into(),
    );
    properties
}

pub fn development_chain_spec() -> Result<ChainSpec, String> {
    Ok(ChainSpec::builder(
        WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?,
        None,
    )
    .with_name("MADAR Development")
    .with_id("dev")
    .with_protocol_id(madar_protocol::chain_spec::chain_id::DEV)
    .with_chain_type(ChainType::Development)
    .with_properties(dev_properties())
    .with_genesis_config_preset_name(sp_genesis_builder::DEV_RUNTIME_PRESET)
    .build())
}

pub fn local_chain_spec() -> Result<ChainSpec, String> {
    Ok(ChainSpec::builder(
        WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?,
        None,
    )
    .with_name("MADAR Local Testnet")
    .with_id("local_testnet")
    .with_protocol_id(madar_protocol::chain_spec::chain_id::TESTNET)
    .with_chain_type(ChainType::Local)
    .with_properties(dev_properties())
    .with_genesis_config_preset_name(sp_genesis_builder::LOCAL_TESTNET_RUNTIME_PRESET)
    .build())
}
