//! RPC extensions specific to this node — only the standard `system` for now (no Fees
//! after D17, so no `pallet-transaction-payment` RPC).

use std::sync::Arc;

use jsonrpsee::RpcModule;
use madar_consensus::{opaque::Block, AccountId, Nonce};
use sc_transaction_pool_api::TransactionPool;
use sp_api::ProvideRuntimeApi;
use sp_block_builder::BlockBuilder;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};

/// Full node dependencies for the RPC APIs.
pub struct FullDeps<C, P> {
    /// The Client instance.
    pub client: Arc<C>,
    /// The Transaction pool instance.
    pub pool: Arc<P>,
}

/// Builds all full RPC extensions.
pub fn create_full<C, P>(
    deps: FullDeps<C, P>,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
    C: ProvideRuntimeApi<Block>,
    C: HeaderBackend<Block> + HeaderMetadata<Block, Error = BlockChainError> + 'static,
    C: Send + Sync + 'static,
    C::Api: substrate_frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>,
    C::Api: BlockBuilder<Block>,
    P: TransactionPool + 'static,
{
    use substrate_frame_rpc_system::{System, SystemApiServer};

    let mut module = RpcModule::new(());
    let FullDeps { client, pool } = deps;

    module.merge(System::new(client, pool).into_rpc())?;

    Ok(module)
}
