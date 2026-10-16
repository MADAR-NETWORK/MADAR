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
    ensure_call_fits(&p, &call)?;
    Ok(sign_with(&p, account, call, nonce))
}

/// The last spec with `transaction_version` = 1. spec 9 raised it to 2 because calls were removed (Admission 2 and 3, and names v1); an old
/// transaction for them does not decode after the upgrade.
pub const LAST_SPEC_WITH_TX_V1: u32 = 8;
/// `transaction_version` of a spec ≤ 8 chain.
pub const LEGACY_TX_VERSION: u32 = 1;

/// Does this tool serve a chain with this version? Its current version (tx 2, spec ≥ 9), **or** a spec ≤ 8 chain with tx 1: the committee signs the spec 9
/// upgrade itself while the chain is still on 8, and operators renew their membership before the upgrade. On the old chain only calls whose
/// encoding did not change are signed (`encodes_the_same_on_spec8`).
pub fn tx_version_supported(spec: u32, txv: u32) -> bool {
    txv == VERSION.transaction_version || is_legacy(spec, txv)
}

/// A chain before spec 9 (tx 1)?
pub fn is_legacy(spec: u32, txv: u32) -> bool {
    txv == LEGACY_TX_VERSION && spec <= LAST_SPEC_WITH_TX_V1
}

/// The calls whose **encoding and meaning did not change** from spec 8 to spec 9 (same Pallet index, call and fields) — only these are signed
/// for a spec 8 chain. Everything else (including the two new calls that set the Admission parameters, and names and stamp) is explicitly refused there.
pub fn encodes_the_same_on_spec8(call: &RuntimeCall) -> bool {
    use madar_consensus::{
        madar_admission::Call as A, madar_names::Call as N, pallet_grandpa, pallet_session,
    };
    match call {
        RuntimeCall::Admission(
            A::submit_admission_solution { .. }
            | A::voluntary_exit {}
            | A::approve_operator { .. }
            | A::revoke_operator_approval { .. }
            | A::vouch_node { .. }
            | A::revoke_vouch { .. },
        ) => true,
        RuntimeCall::Session(
            pallet_session::Call::set_keys { .. } | pallet_session::Call::purge_keys {},
        ) => true,
        RuntimeCall::Names(N::set_reserved { .. }) => true,
        RuntimeCall::UpgradeAuthority(madar_upgrade_authority::Call::dispatch_as_root { call }) => {
            matches!(
                &**call,
                RuntimeCall::System(frame_system::Call::authorize_upgrade { .. })
                    | RuntimeCall::Grandpa(pallet_grandpa::Call::note_stalled { .. })
            )
        }
        RuntimeCall::UpgradeCommittee(pallet_collective::Call::propose { proposal, .. }) => {
            encodes_the_same_on_spec8(proposal)
        }
        RuntimeCall::UpgradeCommittee(
            pallet_collective::Call::vote { .. } | pallet_collective::Call::close { .. },
        ) => true,
        _ => false,
    }
}

/// Refuses to sign a call that does not fit the chain version (a spec 9 call on a spec 8 chain).
pub fn ensure_call_fits(p: &TxParams, call: &RuntimeCall) -> Result<(), String> {
    if is_legacy(p.spec_version, p.transaction_version) && !encodes_the_same_on_spec8(call) {
        return Err(format!(
            "The network is still on version {} and this action needs version 9 — wait for the network upgrade and try again.",
            p.spec_version
        ));
    }
    Ok(())
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
    // The transaction format itself follows transaction_version: if it changed, this tool may encode wrongly — we do not sign (except the known spec ≤ 8 chain).
    if !tx_version_supported(spec_version, transaction_version) {
        return Err(format!(
            "The network's transaction format (spec {spec_version}, tx {transaction_version}) does not fit this tool (tx {}) — update madar-node before any signing.",
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

    /// spec 9 (tx 2): the tool serves its own tx version and a spec ≤ 8 chain (tx 1) — never a spec 9 chain with tx 1
    /// or an unknown tx version.
    #[test]
    fn the_supported_chain_versions_are_exactly_current_and_spec8_legacy() {
        assert_eq!(VERSION.transaction_version, 2);
        assert!(tx_version_supported(
            VERSION.spec_version,
            VERSION.transaction_version
        ));
        assert!(
            tx_version_supported(8, 1),
            "the chain the spec 9 upgrade is signed on"
        );
        assert!(tx_version_supported(7, 1));
        assert!(!tx_version_supported(9, 1));
        assert!(!tx_version_supported(VERSION.spec_version, 3));
        assert!(is_legacy(8, 1) && !is_legacy(9, 2));
    }

    /// On a spec 8 chain only calls whose encoding did not change are signed; the new spec 9 calls are refused.
    #[test]
    fn a_spec8_chain_gets_only_calls_that_encode_the_same() {
        use madar_consensus::madar_admission;
        let op = madar_consensus::AccountId::from([9u8; 32]);
        let approve = RuntimeCall::Admission(madar_admission::Call::approve_operator {
            operator: op.clone(),
            max_votes: 1,
        });
        let upgrade =
            RuntimeCall::UpgradeAuthority(madar_upgrade_authority::Call::dispatch_as_root {
                call: Box::new(RuntimeCall::System(frame_system::Call::authorize_upgrade {
                    code_hash: H256::repeat_byte(1),
                })),
            });
        let set_cap =
            RuntimeCall::Admission(madar_admission::Call::set_admission_cap_per_round { cap: 3 });
        let set_votes =
            RuntimeCall::Admission(madar_admission::Call::set_max_votes_per_operator { votes: 2 });
        let propose = |c: &RuntimeCall| {
            RuntimeCall::UpgradeCommittee(pallet_collective::Call::propose {
                threshold: 2,
                proposal: Box::new(c.clone()),
                length_bound: 100,
            })
        };
        for ok in [&approve, &upgrade, &propose(&approve), &propose(&upgrade)] {
            assert!(encodes_the_same_on_spec8(ok), "{ok:?}");
        }
        for new in [
            &set_cap,
            &set_votes,
            &propose(&set_cap),
            &propose(&set_votes),
        ] {
            assert!(!encodes_the_same_on_spec8(new), "{new:?}");
        }
        // the encodings the spec 8 chain expects (pallet 8 = Admission; approve_operator = 4, unchanged)
        assert_eq!(&approve.encode()[..2], &[8, 4]);
        let legacy = TxParams {
            genesis: H256::zero(),
            birth_hash: H256::zero(),
            current: 1,
            period: 128,
            spec_version: 8,
            transaction_version: 1,
        };
        assert!(ensure_call_fits(&legacy, &approve).is_ok());
        assert!(ensure_call_fits(&legacy, &set_cap)
            .unwrap_err()
            .contains("version 9"));
        let current = TxParams {
            spec_version: VERSION.spec_version,
            transaction_version: VERSION.transaction_version,
            ..legacy
        };
        assert!(ensure_call_fits(&current, &set_cap).is_ok());
    }

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
