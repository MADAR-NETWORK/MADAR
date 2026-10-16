//! `madar-node benchmark` helpers (only with the `runtime-benchmarks` feature): extrinsic builder and inherent data for
//! `benchmark overhead`. Uses the real MADAR transaction envelope (mortal era, nonce/onboarding, no fees).

use crate::service::FullClient;
use madar_consensus::{Address, RuntimeCall, SignedExtra, UncheckedExtrinsic, VERSION};
use sc_cli::Result;
use sc_client_api::BlockBackend;
use sp_core::{Encode, Pair as _};
use sp_inherents::{InherentData, InherentDataProvider};
use sp_keyring::Sr25519Keyring;
use sp_runtime::{
    generic::{Era, SignedPayload},
    OpaqueExtrinsic, SaturatedConversion,
};
use std::{sync::Arc, time::Duration};

/// `System::remark` (empty) signed by Alice (a dev-genesis validator, so the account already exists).
pub struct RemarkBuilder {
    client: Arc<FullClient>,
}

impl RemarkBuilder {
    pub fn new(client: Arc<FullClient>) -> Self {
        Self { client }
    }
}

impl frame_benchmarking_cli::ExtrinsicBuilder for RemarkBuilder {
    fn pallet(&self) -> &str {
        "system"
    }

    fn extrinsic(&self) -> &str {
        "remark"
    }

    fn build(&self, nonce: u32) -> std::result::Result<OpaqueExtrinsic, &'static str> {
        let call = RuntimeCall::System(frame_system::Call::remark { remark: vec![] });
        let xt = create_benchmark_extrinsic(
            self.client.as_ref(),
            Sr25519Keyring::Alice.pair(),
            call,
            nonce,
        );
        Ok(xt.into())
    }
}

/// Signs `call` with the runtime's own `SignedExtra` (same envelope as `join`/`committee`).
pub fn create_benchmark_extrinsic(
    client: &FullClient,
    sender: sp_core::sr25519::Pair,
    call: RuntimeCall,
    nonce: u32,
) -> UncheckedExtrinsic {
    let genesis_hash = client
        .block_hash(0)
        .ok()
        .flatten()
        .expect("genesis block exists");
    let best_hash = client.chain_info().best_hash;
    let best_block: u64 = client.chain_info().best_number.saturated_into();
    let era = Era::mortal(128, best_block);
    let extra: SignedExtra = (
        frame_system::CheckSpecVersion::new(),
        frame_system::CheckTxVersion::new(),
        frame_system::CheckGenesis::new(),
        madar_transactions::CheckMortalOnly::from(era),
        madar_transactions::CheckNonceOrOnboard::from(nonce),
        frame_system::CheckWeight::new(),
    );
    let implicit = (
        VERSION.spec_version,
        VERSION.transaction_version,
        genesis_hash,
        best_hash,
        (),
        (),
    );
    let payload = SignedPayload::from_raw(call.clone(), extra.clone(), implicit);
    let signature = payload.using_encoded(|e| sender.sign(e));
    let who = madar_consensus::AccountId::from(sender.public());
    UncheckedExtrinsic::new_signed(call, Address::Id(who), signature.into(), extra)
}

/// Inherent data for `benchmark overhead`: timestamp 0 (slot 0, matching BABE's slot at genesis).
pub fn inherent_benchmark_data() -> Result<InherentData> {
    let mut inherent_data = InherentData::new();
    let timestamp = sp_timestamp::InherentDataProvider::new(Duration::from_millis(0).into());
    futures::executor::block_on(timestamp.provide_inherent_data(&mut inherent_data))
        .map_err(|e| format!("creating inherent data: {e:?}"))?;
    Ok(inherent_data)
}
