//! Builds the signed transaction (the actual Runtime envelope: Mortal only, Nonce/Onboarding) and submits it. Signing happens locally; the secret never leaves this module.

use super::account::Account;
use super::rpc::Transport;
use madar_consensus::{Address, RuntimeCall, SignedExtra, UncheckedExtrinsic, VERSION};
use parity_scale_codec::Encode;
use serde_json::json;
use sp_core::{crypto::Ss58Codec, H256};
use sp_runtime::generic::{Era, SignedPayload};

/// Transaction lifetime in blocks (Mortal). 128 (< `BlockHashCount` = 256) guarantees a validity window of ≥ ~64 blocks regardless of the block's phase within the period.
const ERA_PERIOD: u64 = 128;

pub fn build_signed(
    t: &dyn Transport,
    account: &Account,
    call: RuntimeCall,
) -> Result<Vec<u8>, String> {
    let nonce = next_nonce(t, &account.id())?;
    let p = fetch_params(t, ERA_PERIOD)?;
    Ok(sign_with(&p, account, call, nonce))
}

/// The next sequence number (nonce) of an account (read from the node).
pub fn next_nonce(t: &dyn Transport, who: &madar_consensus::AccountId) -> Result<u32, String> {
    Ok(
        t.call("system_accountNextIndex", json!([who.to_ss58check()]))?
            .as_u64()
            .ok_or("Invalid nonce from the node")? as u32,
    )
}

/// Everything needed to sign a transaction **offline**: fetched once from the node (online), then used to sign without a network (upgrade committee).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TxParams {
    pub genesis: H256,
    pub birth_hash: H256,
    /// The block from which validity was computed (the parent of the best block).
    pub current: u64,
    pub period: u64,
    /// The network version **as it is on chain** at fetch time (0 in old files = this tool's version). Signing uses the chain's version, not the tool's: a tool built
    /// for a newer version still signs correctly before the upgrade, and an older tool does not break after it (automatic renewal in particular).
    #[serde(default)]
    pub spec_version: u32,
    #[serde(default)]
    pub transaction_version: u32,
}

impl TxParams {
    pub fn era(&self) -> Era {
        Era::mortal(self.period, self.current)
    }
    /// The last block at which the transaction is accepted (after that it is rejected as expired).
    pub fn expires_at(&self) -> u64 {
        self.era().death(self.current)
    }
}

pub fn fetch_params(t: &dyn Transport, period: u64) -> Result<TxParams, String> {
    let header = t.call("chain_getHeader", json!([]))?;
    let best = u64::from_str_radix(
        header
            .get("number")
            .and_then(|n| n.as_str())
            .ok_or("Invalid block header")?
            .trim_start_matches("0x"),
        16,
    )
    .map_err(|_| "Invalid block number")?;
    let hash_at = |n: u64| -> Result<H256, String> {
        t.call("chain_getBlockHash", json!([n]))?
            .as_str()
            .ok_or("Missing block hash")?
            .parse()
            .map_err(|_| "Invalid block hash".to_string())
    };
    let genesis = hash_at(0)?;
    // The birth is derived from the **parent block**, not from the best block itself: the Runtime stores only the hash of block N-1 while verifying on top of N, otherwise the transaction is rejected
    // with `AncientBirthBlock` (seen especially in the first ~64 blocks or when the block is on a period boundary).
    let current = best.saturating_sub(1);
    let era = Era::mortal(period, current);
    let birth_hash = hash_at(era.birth(current))?;
    let v = t.call("state_getRuntimeVersion", json!([]))?;
    let spec_version = v
        .get("specVersion")
        .and_then(|s| s.as_u64())
        .ok_or("Invalid network version")? as u32;
    let transaction_version = v
        .get("transactionVersion")
        .and_then(|s| s.as_u64())
        .ok_or("Invalid network version")? as u32;
    // The transaction structure itself follows transaction_version: if it changed, this tool may encode incorrectly — we do not sign.
    if transaction_version != VERSION.transaction_version {
        return Err(format!(
            "The network's transaction structure has changed (tx {transaction_version} ≠ {}) — update madar-node before signing anything.",
            VERSION.transaction_version
        ));
    }
    Ok(TxParams {
        genesis,
        birth_hash,
        current,
        period,
        spec_version,
        transaction_version,
    })
}

/// Pure signing with no network at all: the same envelope the Runtime verifies (Mortal only, Nonce/Onboarding).
pub fn sign_with(p: &TxParams, account: &Account, call: RuntimeCall, nonce: u32) -> Vec<u8> {
    let who = account.id();
    let era = p.era();
    let extra: SignedExtra = (
        frame_system::CheckSpecVersion::new(),
        frame_system::CheckTxVersion::new(),
        frame_system::CheckGenesis::new(),
        madar_transactions::CheckMortalOnly::from(era),
        madar_transactions::CheckNonceOrOnboard::from(nonce),
        frame_system::CheckWeight::new(),
    );
    let spec = if p.spec_version == 0 {
        VERSION.spec_version
    } else {
        p.spec_version
    };
    let txv = if p.transaction_version == 0 {
        VERSION.transaction_version
    } else {
        p.transaction_version
    };
    let implicit = (spec, txv, p.genesis, p.birth_hash, (), ());
    let payload = SignedPayload::from_raw(call.clone(), extra.clone(), implicit);
    let signature = account.sign(&payload.encode());
    UncheckedExtrinsic::new_signed(call, Address::Id(who), signature.into(), extra).encode()
}

/// Submits an already-signed transaction (such as a committee signature made offline) as is.
pub fn submit_raw(t: &dyn Transport, xt: &[u8]) -> Result<String, String> {
    Ok(t.call(
        "author_submitExtrinsic",
        json!([format!("0x{}", hex::encode(xt))]),
    )?
    .as_str()
    .unwrap_or_default()
    .to_string())
}

/// A freshly started/syncing node's transaction pool may still be on a block older than its announced head: the transaction is then temporarily rejected with `AncientBirthBlock`. We rebuild
/// it with a new head after a short delay instead of failing the user (we retry only for this specific error; any other is shown as is).
const TRANSIENT_RETRIES: usize = 6;
const TRANSIENT_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

fn is_transient(e: &str) -> bool {
    e.contains("ancient birth block")
}

/// Submits the transaction and returns its hash. A pool rejection (e.g. an invalid puzzle/expired round) shows up as a text error.
pub fn submit(t: &dyn Transport, account: &Account, call: RuntimeCall) -> Result<String, String> {
    let mut last = String::new();
    for attempt in 0..TRANSIENT_RETRIES {
        if attempt > 0 {
            eprintln!("The node's transaction pool has not caught up with the chain head yet — retrying ({attempt}/{})…", TRANSIENT_RETRIES - 1);
            std::thread::sleep(TRANSIENT_WAIT);
        }
        let xt = build_signed(t, account, call.clone())?;
        match t.call(
            "author_submitExtrinsic",
            json!([format!("0x{}", hex::encode(xt))]),
        ) {
            Ok(r) => return Ok(r.as_str().unwrap_or_default().to_string()),
            Err(e) if is_transient(&e) => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The birth (as the Runtime computes it for `current`) is never the best block itself nor newer than its parent, and stays within the `BlockHashCount` window.
    #[test]
    fn only_the_stale_pool_error_is_retried() {
        assert!(is_transient(
            "Invalid Transaction: Transaction has an ancient birth block"
        ));
        assert!(!is_transient(
            "Invalid Transaction: Transaction has a bad signature"
        ));
        assert!(!is_transient("Custom error: 5"));
    }

    #[test]
    fn the_birth_block_is_always_an_already_stored_ancestor_and_the_window_stays_open() {
        for best in [0u64, 1, 2, 5, 63, 64, 65, 127, 128, 129, 1000, 4096] {
            let current = best.saturating_sub(1);
            let era = Era::mortal(ERA_PERIOD, current);
            let birth = era.birth(current);
            assert!(
                birth <= current,
                "best {best}: birth {birth} must be <= parent {current}"
            );
            assert!(
                current - birth < 256,
                "birth hash must still be stored (BlockHashCount)"
            );
            let (birth_c, death) = (birth, era.death(current));
            assert!(
                death > best + 30 || best < 3,
                "best {best}: the era must stay valid for a while (death {death}, birth {birth_c})"
            );
        }
    }
}
