//! Upgrade-committee approvals (2 of 3) signed **offline** (`madar-node committee …`):
//!
//! 1. `prepare` (online): reads from the node everything needed for signing — genesis, validity window, committee members and their nonces, the next
//!    proposal index — and writes a **request file** that contains no secrets.
//! 2. `sign` (**refuses to run while the machine is connected to the internet**): decrypts a committee member's key (a `.enc` file in `madar-keystore` format) in memory only, signs
//!    its two transactions and adds them to the request file. First member: propose + vote. Second: vote + close (execute). Neither the key nor the passphrase is written to disk.
//! 3. `submit` (online): sends the four transactions in order, waits for each to be included, then verifies the decision's effect on chain.
//!
//! Supported decisions: `approve-operator` (approve an operator with a vote cap), `names-reserve` (reserve a name in Madar Names or release it,
//! `Names::set_reserved`), `recover-finality` (recover stalled finality: `Grandpa::note_stalled`) and `upgrade-runtime` (network upgrade): the committee approves only the **hash** of the WASM file
//! (`System::authorize_upgrade` via `UpgradeAuthority::dispatch_as_root`), so the signature stays small with no large file; then `submit` sends the file itself
//! (`apply_authorized_upgrade`, unsigned) and the chain accepts it only if its hash matches and its version is newer. Transactions are Mortal (window ~256 blocks ≈ 40 minutes): signing
//! and submitting must both happen within it, otherwise `prepare` must be rerun.

use crate::join::account::{self, Account};
use crate::join::rpc::{HttpRpc, Transport};
use crate::join::tx::{self, TxParams};
use madar_consensus::{
    madar_admission, madar_names, AccountId, Runtime, RuntimeCall, UpgradeCommitteeInstance,
    VERSION,
};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sp_core::{crypto::Ss58Codec, H256};
use sp_runtime::traits::{BlakeTwo256, Hash};
use std::io::Read;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// Validity window in blocks (the maximum allowed by `BlockHashCount` = 256). At one block every ~8–10 seconds ≈ 35–40 minutes.
pub const ERA_PERIOD: u64 = 256;
/// Committee threshold (2 of 3, D44).
pub const THRESHOLD: u32 = 2;
/// Addresses probed to answer "is this machine online?" before decrypting any key: public DNS + the MADAR network gateways.
const PROBES: &[&str] = &[
    "1.1.1.1:443",
    "8.8.8.8:53",
    "188.241.241.253:30333",
    "188.241.241.234:30333",
];
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);
/// Finality recovery is prepared only if finality lags the best block by at least this much (~15 minutes): forcing is an emergency tool, not for a passing delay.
pub const MIN_STALL_BLOCKS: u64 = 100;
/// The default wait in blocks after the session starts before the forced set takes effect.
pub const RECOVER_DELAY: u32 = 50;

#[derive(Debug, Clone, clap::Subcommand)]
pub enum CommitteeCmd {
    /// (online) Prepare an approval request: writes a request file with no secrets.
    Prepare(PrepareArgs),
    /// (online) Prepare a network-upgrade request from a WASM file: only its hash is approved.
    PrepareUpgrade(PrepareUpgradeArgs),
    /// (online) Prepare a request to reserve a name in Madar Names or release it (`--reserved false` = release).
    PrepareNamesReserve(PrepareNamesReserveArgs),
    /// (online) Prepare a request to recover stalled finality: at the start of the next session the current voter set is forced on GRANDPA.
    PrepareRecoverFinality(PrepareRecoverFinalityArgs),
    /// (offline) A committee member signs the request. Refuses to run while the machine is online.
    Sign(SignArgs),
    /// (online) Submit a request signed by two members to the network in order, and verify the result.
    Submit(SubmitArgs),
    /// Show the status of a request file (no network).
    Show(ShowArgs),
}

#[derive(Debug, Clone, clap::Args)]
pub struct PrepareArgs {
    #[arg(long, default_value = "127.0.0.1:9944")]
    pub rpc: String,
    /// The operator account to approve (SS58 or 0x…).
    #[arg(long)]
    pub operator: String,
    /// Operator vote cap (D52: 1).
    #[arg(long, default_value_t = 1)]
    pub max_votes: u32,
    /// Output request file (JSON).
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Debug, Clone, clap::Args)]
pub struct PrepareUpgradeArgs {
    #[arg(long, default_value = "127.0.0.1:9944")]
    pub rpc: String,
    /// The new Runtime file (`madar_consensus.compact.compressed.wasm`). It stays in place: `submit` reads it and verifies its hash.
    #[arg(long)]
    pub wasm: PathBuf,
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Debug, Clone, clap::Args)]
pub struct PrepareNamesReserveArgs {
    #[arg(long, default_value = "127.0.0.1:9944")]
    pub rpc: String,
    /// The name (like `madar` or `madar.madar`).
    #[arg(long)]
    pub name: String,
    /// true = reserve the name, false = release it (so it can be registered).
    #[arg(long, action = clap::ArgAction::Set)]
    pub reserved: bool,
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Debug, Clone, clap::Args)]
pub struct PrepareRecoverFinalityArgs {
    #[arg(long, default_value = "127.0.0.1:9944")]
    pub rpc: String,
    /// Accounts of the permanently dead voters (SS58, one or more). The tool refuses while any of them is in the next session's set:
    /// forcing takes the next session's set as it is, so if a dead voter stays in it the stall repeats.
    #[arg(long, required = true, num_args = 1..)]
    pub dead: Vec<String>,
    /// Number of blocks after the next session starts before the forced set takes effect.
    #[arg(long, default_value_t = RECOVER_DELAY)]
    pub delay: u32,
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Debug, Clone, clap::Args)]
pub struct SignArgs {
    #[arg(long)]
    pub request: PathBuf,
    /// The committee member's key file (`.enc`). Without it, with `--stdin-json`, the key is read from stdin.
    #[arg(long)]
    pub key_file: Option<PathBuf>,
    #[arg(long)]
    pub passphrase_file: Option<PathBuf>,
    /// Reads one JSON line from stdin: {"key_hex": "…", "passphrase": "…"} (for the dashboard; nothing is written to disk).
    #[arg(long)]
    pub stdin_json: bool,
    /// Testing only: allow signing while the machine is online.
    #[arg(long, hide = true)]
    pub allow_online: bool,
}

#[derive(Debug, Clone, clap::Args)]
pub struct SubmitArgs {
    #[arg(long, default_value = "127.0.0.1:9944")]
    pub rpc: String,
    #[arg(long)]
    pub request: PathBuf,
    /// Maximum wait for each transaction to be included (seconds).
    #[arg(long, default_value_t = 180)]
    pub wait_secs: u64,
}

#[derive(Debug, Clone, clap::Args)]
pub struct ShowArgs {
    #[arg(long)]
    pub request: PathBuf,
    #[arg(long)]
    pub json: bool,
}

/// A signed transaction ready to submit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedTx {
    /// propose | vote | close
    pub kind: String,
    pub signer: String,
    pub nonce: u32,
    pub hex: String,
    #[serde(default)]
    pub submitted: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    pub version: u32,
    pub action: String,
    pub description: String,
    #[serde(default)]
    pub operator: String,
    #[serde(default)]
    pub max_votes: u32,
    /// For `upgrade-runtime` requests only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade: Option<UpgradeInfo>,
    /// For `names-reserve` requests only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub names_reserve: Option<NamesReserveInfo>,
    /// For `recover-finality` requests only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recover: Option<RecoverInfo>,
    /// The call the committee will execute (SCALE-encoded).
    pub call_hex: String,
    pub proposal_hash: H256,
    pub proposal_index: u32,
    pub spec_version: u32,
    pub transaction_version: u32,
    pub params: TxParams,
    pub expires_at_block: u64,
    /// Committee members (SS58) and each one's nonce at preparation time.
    pub members: Vec<(String, u32)>,
    #[serde(default)]
    pub signed: Vec<SignedTx>,
    #[serde(default)]
    pub done: bool,
}

/// Network-upgrade details: what the members approve (hash and version) and where the file is.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpgradeInfo {
    pub code_file: String,
    /// blake2-256 of the file bytes exactly as they will be sent (this is what members approve, comparing it with the published build hash).
    pub code_hash: H256,
    pub code_size: u64,
    pub from_spec: u32,
    pub to_spec: u32,
}

/// Finality recovery: the voters the preparer declared dead, and the voter set id at preparation (to tell that the forcing happened).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoverInfo {
    pub dead: Vec<String>,
    pub set_id: u64,
}

/// Reserve or release a name: the name without `.madar`, and the requested state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NamesReserveInfo {
    pub name: String,
    pub reserved: bool,
}

impl Request {
    pub fn signers(&self) -> Vec<String> {
        let mut s: Vec<String> = Vec::new();
        for t in &self.signed {
            if !s.contains(&t.signer) {
                s.push(t.signer.clone());
            }
        }
        s
    }
    pub fn complete(&self) -> bool {
        self.signers().len() as u32 >= THRESHOLD
    }
    fn call(&self) -> Result<RuntimeCall, String> {
        let bytes = hex::decode(self.call_hex.trim_start_matches("0x"))
            .map_err(|_| "Request file is corrupted (call_hex)")?;
        RuntimeCall::decode(&mut &bytes[..])
            .map_err(|_| "Request file does not match this network version (call)".to_string())
    }
}

pub fn run(cmd: CommitteeCmd) -> Result<(), String> {
    match cmd {
        CommitteeCmd::Prepare(a) => prepare(a),
        CommitteeCmd::PrepareUpgrade(a) => prepare_upgrade(a),
        CommitteeCmd::PrepareNamesReserve(a) => prepare_names_reserve(a),
        CommitteeCmd::PrepareRecoverFinality(a) => prepare_recover_finality(a),
        CommitteeCmd::Sign(a) => sign(a),
        CommitteeCmd::Submit(a) => submit(a),
        CommitteeCmd::Show(a) => show(a),
    }
}

// ------------------------------------------------------------------ calls

fn approve_operator_call(operator: &AccountId, max_votes: u32) -> RuntimeCall {
    RuntimeCall::Admission(madar_admission::Call::approve_operator {
        operator: operator.clone(),
        max_votes,
    })
}

fn authorize_upgrade_call(code_hash: H256) -> RuntimeCall {
    RuntimeCall::UpgradeAuthority(madar_upgrade_authority::Call::dispatch_as_root {
        call: Box::new(RuntimeCall::System(frame_system::Call::authorize_upgrade {
            code_hash,
        })),
    })
}

fn names_reserve_call(name: madar_names::NameOf, reserved: bool) -> RuntimeCall {
    RuntimeCall::Names(madar_names::Call::set_reserved { name, reserved })
}

/// The text a member sees for a decision to reserve/release a name.
pub fn names_reserve_summary(name: &str, reserved: bool) -> String {
    if reserved {
        format!("Reserve the name {name}.madar")
    } else {
        format!("Release the name {name}.madar")
    }
}

fn recover_finality_call(delay: u32, best_finalized: u32) -> RuntimeCall {
    RuntimeCall::UpgradeAuthority(madar_upgrade_authority::Call::dispatch_as_root {
        call: Box::new(RuntimeCall::Grandpa(pallet_grandpa::Call::note_stalled {
            delay,
            best_finalized_block_number: best_finalized,
        })),
    })
}

pub fn recover_finality_summary(delay: u32, best_finalized: u32) -> String {
    format!(
        "Recover finality stalled at block #{best_finalized}: force the current voter set at the start of the next session after {delay} blocks"
    )
}

/// What the decision will actually execute, read from the encoded call itself (not from the description text in the file). `None` = a call
/// the tool does not know, so it is never signed.
pub fn call_summary(call: &RuntimeCall) -> Option<String> {
    match call {
        RuntimeCall::Names(madar_names::Call::set_reserved { name, reserved }) => Some(
            names_reserve_summary(std::str::from_utf8(name).ok()?, *reserved),
        ),
        RuntimeCall::Admission(madar_admission::Call::approve_operator {
            operator,
            max_votes,
        }) => Some(format!(
            "Approve operator {} with a cap of {max_votes} vote(s)",
            operator.to_ss58check()
        )),
        RuntimeCall::UpgradeAuthority(madar_upgrade_authority::Call::dispatch_as_root { call }) => {
            match &**call {
                RuntimeCall::System(frame_system::Call::authorize_upgrade { code_hash }) => Some(
                    format!("Approve the network upgrade to the file with hash {code_hash:?}"),
                ),
                RuntimeCall::Grandpa(pallet_grandpa::Call::note_stalled {
                    delay,
                    best_finalized_block_number,
                }) => Some(recover_finality_summary(
                    *delay,
                    *best_finalized_block_number,
                )),
                _ => None,
            }
        }
        _ => None,
    }
}

fn propose(call: &RuntimeCall) -> RuntimeCall {
    RuntimeCall::UpgradeCommittee(pallet_collective::Call::propose {
        threshold: THRESHOLD,
        proposal: Box::new(call.clone()),
        length_bound: call.encoded_size() as u32,
    })
}

fn vote(hash: H256, index: u32) -> RuntimeCall {
    RuntimeCall::UpgradeCommittee(pallet_collective::Call::vote {
        proposal: hash,
        index,
        approve: true,
    })
}

fn close(call: &RuntimeCall, index: u32) -> RuntimeCall {
    RuntimeCall::UpgradeCommittee(pallet_collective::Call::close {
        proposal_hash: BlakeTwo256::hash_of(call),
        index,
        proposal_weight_bound: frame_support::dispatch::GetDispatchInfo::get_dispatch_info(call)
            .call_weight,
        length_bound: call.encoded_size() as u32,
    })
}

// ------------------------------------------------------------------ storage reads

fn storage<T: Decode>(t: &dyn Transport, key: Vec<u8>) -> Result<Option<T>, String> {
    let raw = t.call(
        "state_getStorage",
        json!([format!("0x{}", hex::encode(key))]),
    )?;
    match raw.as_str() {
        None => Ok(None),
        Some(h) => {
            let b =
                hex::decode(h.trim_start_matches("0x")).map_err(|_| "Invalid storage response")?;
            T::decode(&mut &b[..]).map(Some).map_err(|_| {
                "Could not decode a storage value (different network version?)".to_string()
            })
        }
    }
}

fn members(t: &dyn Transport) -> Result<Vec<AccountId>, String> {
    Ok(storage(
        t,
        pallet_collective::Members::<Runtime, UpgradeCommitteeInstance>::hashed_key().to_vec(),
    )?
    .unwrap_or_default())
}

fn proposal_count(t: &dyn Transport) -> Result<u32, String> {
    Ok(storage(
        t,
        pallet_collective::ProposalCount::<Runtime, UpgradeCommitteeInstance>::hashed_key()
            .to_vec(),
    )?
    .unwrap_or(0))
}

fn approved_votes(t: &dyn Transport, operator: &AccountId) -> Result<Option<u32>, String> {
    storage(
        t,
        madar_admission::ApprovedOperators::<Runtime>::hashed_key_for(operator),
    )
}

/// Is the name in the on-chain reserved list of Madar Names?
fn name_reserved(t: &dyn Transport, name: &madar_names::NameOf) -> Result<bool, String> {
    let key = madar_names::Reserved::<Runtime>::hashed_key_for(name);
    Ok(t.call(
        "state_getStorage",
        json!([format!("0x{}", hex::encode(key))]),
    )?
    .as_str()
    .is_some())
}

/// Is this request's own proposal (same hash and same index) already on chain? This happens when the first member's proposal reached the network but was not
/// recorded in the file (interrupted after sending and before saving) — so the proposal count changed because of it, not because of another proposal.
fn own_proposal_on_chain(t: &dyn Transport, r: &Request) -> Result<bool, String> {
    // The first field of `Votes` is the proposal index (decoding the first field is enough; the other fields are private).
    let index: Option<u32> = storage(
        t,
        pallet_collective::Voting::<Runtime, UpgradeCommitteeInstance>::hashed_key_for(
            r.proposal_hash,
        ),
    )?;
    Ok(index == Some(r.proposal_index))
}

fn header_number(v: &serde_json::Value) -> Result<u64, String> {
    u64::from_str_radix(
        v.get("number")
            .and_then(|n| n.as_str())
            .ok_or("Invalid block header")?
            .trim_start_matches("0x"),
        16,
    )
    .map_err(|_| "Invalid block number".into())
}

fn finalized_block(t: &dyn Transport) -> Result<u64, String> {
    let hash = t.call("chain_getFinalizedHead", json!([]))?;
    header_number(&t.call("chain_getHeader", json!([hash]))?)
}

/// `Grandpa::Stalled` present = the recovery decision reached the chain and is waiting for the next session to start.
fn grandpa_stalled(t: &dyn Transport) -> Result<Option<(u32, u32)>, String> {
    storage(t, pallet_grandpa::Stalled::<Runtime>::hashed_key().to_vec())
}

/// Accounts of the next session's set (`Session::QueuedKeys`) — exactly what is forced on GRANDPA at the start of the session.
fn queued_validators(t: &dyn Transport) -> Result<Vec<AccountId>, String> {
    let mut key = sp_crypto_hashing::twox_128(b"Session").to_vec();
    key.extend(sp_crypto_hashing::twox_128(b"QueuedKeys"));
    let keys: Vec<(AccountId, madar_consensus::SessionKeys)> = storage(t, key)?.unwrap_or_default();
    Ok(keys.into_iter().map(|(a, _)| a).collect())
}

fn grandpa_set_id(t: &dyn Transport) -> Result<u64, String> {
    Ok(storage(
        t,
        pallet_grandpa::CurrentSetId::<Runtime>::hashed_key().to_vec(),
    )?
    .unwrap_or(0))
}

fn best_block(t: &dyn Transport) -> Result<u64, String> {
    let header = t.call("chain_getHeader", json!([]))?;
    u64::from_str_radix(
        header
            .get("number")
            .and_then(|n| n.as_str())
            .ok_or("Invalid block header")?
            .trim_start_matches("0x"),
        16,
    )
    .map_err(|_| "Invalid block number".into())
}

fn chain_version(t: &dyn Transport) -> Result<(u32, u32), String> {
    let v = t.call("state_getRuntimeVersion", json!([]))?;
    let spec = v.get("specVersion").and_then(|s| s.as_u64()).unwrap_or(0) as u32;
    let txv = v
        .get("transactionVersion")
        .and_then(|s| s.as_u64())
        .unwrap_or(0) as u32;
    Ok((spec, txv))
}

/// The tool serves the current network version or older ones (before an upgrade the tool is built from the new code), provided the transaction format is the same.
fn compatible(spec: u32, txv: u32) -> bool {
    spec <= VERSION.spec_version && txv == VERSION.transaction_version
}

/// Returns the chain version if the tool is compatible with it.
fn check_runtime(t: &dyn Transport) -> Result<u32, String> {
    let (spec, txv) = chain_version(t)?;
    if !compatible(spec, txv) {
        return Err(format!(
            "Network version (spec {spec}, tx {txv}) is not compatible with this tool (spec {}, tx {}) — update madar-node before signing anything.",
            VERSION.spec_version, VERSION.transaction_version
        ));
    }
    Ok(spec)
}

/// `System::AuthorizedUpgrade` (internal frame_system storage): (approved hash, version check).
fn authorized_upgrade(t: &dyn Transport) -> Result<Option<(H256, bool)>, String> {
    let mut key = sp_crypto_hashing::twox_128(b"System").to_vec();
    key.extend(sp_crypto_hashing::twox_128(b"AuthorizedUpgrade"));
    storage(t, key)
}

/// Runtime version of a WASM file (compressed or not) without executing it.
pub fn wasm_version(code: &[u8]) -> Result<sp_version::RuntimeVersion, String> {
    let blob = sc_executor_common::runtime_blob::RuntimeBlob::uncompress_if_needed(code)
        .map_err(|e| format!("Invalid WASM file: {e}"))?;
    sc_executor::read_embedded_version(&blob)
        .map_err(|e| format!("Could not read the WASM version: {e}"))?
        .ok_or_else(|| "WASM file has no embedded version — not a MADAR Runtime.".into())
}

// ------------------------------------------------------------------ prepare

pub fn prepare_request(
    t: &dyn Transport,
    operator: &AccountId,
    max_votes: u32,
) -> Result<Request, String> {
    let spec = check_runtime(t)?;
    if let Some(v) = approved_votes(t, operator)? {
        if v == max_votes {
            return Err(format!(
                "Operator {} is already approved with cap {v} — no request needed.",
                operator.to_ss58check()
            ));
        }
    }
    let members = members(t)?;
    if members.len() < THRESHOLD as usize {
        return Err("The on-chain upgrade committee has fewer than two members — a 2-of-3 decision cannot pass.".into());
    }
    let mut with_nonces = Vec::new();
    for m in &members {
        with_nonces.push((m.to_ss58check(), tx::next_nonce(t, m)?));
    }
    let call = approve_operator_call(operator, max_votes);
    let params = tx::fetch_params(t, ERA_PERIOD)?;
    Ok(Request {
        version: 1,
        action: "approve-operator".into(),
        description: format!(
            "Approve operator {} with a cap of {max_votes} vote(s)",
            operator.to_ss58check()
        ),
        operator: operator.to_ss58check(),
        max_votes,
        upgrade: None,
        names_reserve: None,
        recover: None,
        call_hex: format!("0x{}", hex::encode(call.encode())),
        proposal_hash: BlakeTwo256::hash_of(&call),
        proposal_index: proposal_count(t)?,
        spec_version: spec,
        transaction_version: VERSION.transaction_version,
        expires_at_block: params.expires_at(),
        params,
        members: with_nonces,
        signed: vec![],
        done: false,
    })
}

/// Network-upgrade request: verifies the file is a MADAR Runtime newer than the chain's, and approves its hash.
pub fn prepare_upgrade_request(
    t: &dyn Transport,
    code: &[u8],
    code_file: &str,
) -> Result<Request, String> {
    let spec = check_runtime(t)?;
    let v = wasm_version(code)?;
    if v.spec_name != VERSION.spec_name {
        return Err(format!(
            "The file is for another network (spec_name \"{}\" ≠ \"{}\").",
            v.spec_name, VERSION.spec_name
        ));
    }
    if v.spec_version <= spec {
        return Err(format!("File version ({}) is not newer than the network's ({spec}) — the chain would reject it.", v.spec_version));
    }
    if v.transaction_version != VERSION.transaction_version {
        return Err("The file changes the transaction format — it needs a committee tool built specifically for it.".into());
    }
    let members = members(t)?;
    if members.len() < THRESHOLD as usize {
        return Err("The on-chain upgrade committee has fewer than two members — a 2-of-3 decision cannot pass.".into());
    }
    let mut with_nonces = Vec::new();
    for m in &members {
        with_nonces.push((m.to_ss58check(), tx::next_nonce(t, m)?));
    }
    let code_hash = H256(sp_crypto_hashing::blake2_256(code));
    let call = authorize_upgrade_call(code_hash);
    let params = tx::fetch_params(t, ERA_PERIOD)?;
    Ok(Request {
        version: 1,
        action: "upgrade-runtime".into(),
        description: format!(
            "Upgrade the network from version {spec} to {} — file hash {code_hash:?}",
            v.spec_version
        ),
        operator: String::new(),
        max_votes: 0,
        upgrade: Some(UpgradeInfo {
            code_file: code_file.to_string(),
            code_hash,
            code_size: code.len() as u64,
            from_spec: spec,
            to_spec: v.spec_version,
        }),
        names_reserve: None,
        recover: None,
        call_hex: format!("0x{}", hex::encode(call.encode())),
        proposal_hash: BlakeTwo256::hash_of(&call),
        proposal_index: proposal_count(t)?,
        spec_version: spec,
        transaction_version: VERSION.transaction_version,
        expires_at_block: params.expires_at(),
        params,
        members: with_nonces,
        signed: vec![],
        done: false,
    })
}

/// Request to reserve or release a name (`Names::set_reserved`, the 2-of-3 committee gate).
pub fn prepare_names_reserve_request(
    t: &dyn Transport,
    name: &str,
    reserved: bool,
) -> Result<Request, String> {
    let spec = check_runtime(t)?;
    let name = crate::names::parse_name(name)?;
    let plain = String::from_utf8(name.to_vec()).map_err(|_| "Invalid name".to_string())?;
    if name_reserved(t, &name)? == reserved {
        return Err(if reserved {
            format!("The name {plain}.madar is already reserved — no request needed.")
        } else {
            format!("The name {plain}.madar is already not reserved — no request needed.")
        });
    }
    let members = members(t)?;
    if members.len() < THRESHOLD as usize {
        return Err("The on-chain upgrade committee has fewer than two members — a 2-of-3 decision cannot pass.".into());
    }
    let mut with_nonces = Vec::new();
    for m in &members {
        with_nonces.push((m.to_ss58check(), tx::next_nonce(t, m)?));
    }
    let call = names_reserve_call(name, reserved);
    let params = tx::fetch_params(t, ERA_PERIOD)?;
    Ok(Request {
        version: 1,
        action: "names-reserve".into(),
        description: names_reserve_summary(&plain, reserved),
        operator: String::new(),
        max_votes: 0,
        upgrade: None,
        names_reserve: Some(NamesReserveInfo {
            name: plain,
            reserved,
        }),
        recover: None,
        call_hex: format!("0x{}", hex::encode(call.encode())),
        proposal_hash: BlakeTwo256::hash_of(&call),
        proposal_index: proposal_count(t)?,
        spec_version: spec,
        transaction_version: VERSION.transaction_version,
        expires_at_block: params.expires_at(),
        params,
        members: with_nonces,
        signed: vec![],
        done: false,
    })
}

/// Finality recovery request: refuses if finality is working (lag below `MIN_STALL_BLOCKS`), and pins the last finalized block as the node sees it.
pub fn prepare_recover_finality_request(
    t: &dyn Transport,
    dead: &[AccountId],
    delay: u32,
) -> Result<Request, String> {
    let spec = check_runtime(t)?;
    let best = best_block(t)?;
    let fin = finalized_block(t)?;
    if best < fin + MIN_STALL_BLOCKS {
        return Err(format!(
            "Finality is not stalled: best block #{best} and last finalized block #{fin} (the gap is below {MIN_STALL_BLOCKS}). No recovery needed."
        ));
    }
    if grandpa_stalled(t)?.is_some() {
        return Err("An earlier recovery decision is waiting for the next session to start — no new request needed.".into());
    }
    if !(1..=1000).contains(&delay) {
        return Err("--delay must be between 1 and 1000 blocks.".into());
    }
    if dead.is_empty() {
        return Err("Name the dead voters with --dead.".into());
    }
    let queued = queued_validators(t)?;
    if queued.is_empty() {
        return Err("Could not read the next session's set.".into());
    }
    if let Some(d) = dead.iter().find(|d| queued.contains(d)) {
        return Err(format!(
            "Voter {} is still in the next session's set — forcing would take it along and the stall would repeat. Wait until its membership ends and it leaves, then prepare again.",
            d.to_ss58check()
        ));
    }
    let fin = u32::try_from(fin).map_err(|_| "Block number too large".to_string())?;
    let members = members(t)?;
    if members.len() < THRESHOLD as usize {
        return Err("The on-chain upgrade committee has fewer than two members — a 2-of-3 decision cannot pass.".into());
    }
    let mut with_nonces = Vec::new();
    for m in &members {
        with_nonces.push((m.to_ss58check(), tx::next_nonce(t, m)?));
    }
    let call = recover_finality_call(delay, fin);
    let params = tx::fetch_params(t, ERA_PERIOD)?;
    Ok(Request {
        version: 1,
        action: "recover-finality".into(),
        description: recover_finality_summary(delay, fin),
        operator: String::new(),
        max_votes: 0,
        upgrade: None,
        names_reserve: None,
        recover: Some(RecoverInfo {
            dead: dead.iter().map(|d| d.to_ss58check()).collect(),
            set_id: grandpa_set_id(t)?,
        }),
        call_hex: format!("0x{}", hex::encode(call.encode())),
        proposal_hash: BlakeTwo256::hash_of(&call),
        proposal_index: proposal_count(t)?,
        spec_version: spec,
        transaction_version: VERSION.transaction_version,
        expires_at_block: params.expires_at(),
        params,
        members: with_nonces,
        signed: vec![],
        done: false,
    })
}

fn prepare_recover_finality(a: PrepareRecoverFinalityArgs) -> Result<(), String> {
    let t = HttpRpc::new(&a.rpc);
    let mut dead = Vec::new();
    for d in &a.dead {
        dead.push(account::parse_address(d)?);
    }
    let r = prepare_recover_finality_request(&t, &dead, a.delay)?;
    write_request(&a.out, &r)?;
    println!("Request prepared: {}", r.description);
    println!("  File: {}", a.out.display());
    println!(
        "  Valid until block #{} (sign and submit before then).",
        r.expires_at_block
    );
    println!("Next step: disconnect from the internet, then: madar-node committee sign --request {} --key-file <member-key.enc>", a.out.display());
    Ok(())
}

/// What to do after a name release is executed.
fn names_follow_up(n: &NamesReserveInfo) -> Option<String> {
    (!n.reserved).then(|| {
        format!(
            "Next step: register the name {}.madar to its wallet with that wallet's signature (through the registration service).",
            n.name
        )
    })
}

fn prepare_names_reserve(a: PrepareNamesReserveArgs) -> Result<(), String> {
    let t = HttpRpc::new(&a.rpc);
    let r = prepare_names_reserve_request(&t, &a.name, a.reserved)?;
    write_request(&a.out, &r)?;
    println!("Request prepared: {}", r.description);
    println!("  File: {}", a.out.display());
    println!(
        "  Valid until block #{} (sign and submit before then).",
        r.expires_at_block
    );
    println!(
        "Next step: disconnect from the internet, then: madar-node committee sign --request {} --key-file <member-key.enc>",
        a.out.display()
    );
    Ok(())
}

fn prepare_upgrade(a: PrepareUpgradeArgs) -> Result<(), String> {
    let t = HttpRpc::new(&a.rpc);
    let code =
        std::fs::read(&a.wasm).map_err(|e| format!("Could not read {}: {e}", a.wasm.display()))?;
    let abs = std::fs::canonicalize(&a.wasm).map_err(|e| e.to_string())?;
    let r = prepare_upgrade_request(&t, &code, &abs.to_string_lossy())?;
    write_request(&a.out, &r)?;
    println!("Request prepared: {}", r.description);
    println!("  File: {}", a.out.display());
    println!(
        "  Valid until block #{} (sign and submit before then).",
        r.expires_at_block
    );
    Ok(())
}

fn prepare(a: PrepareArgs) -> Result<(), String> {
    let t = HttpRpc::new(&a.rpc);
    let operator = account::parse_address(&a.operator)?;
    let r = prepare_request(&t, &operator, a.max_votes)?;
    write_request(&a.out, &r)?;
    println!("Request prepared: {}", r.description);
    println!("  File: {}", a.out.display());
    println!(
        "  Valid until block #{} (sign and submit before then).",
        r.expires_at_block
    );
    println!("Next step: disconnect from the internet, then: madar-node committee sign --request {} --key-file <member-key.enc>", a.out.display());
    Ok(())
}

// ------------------------------------------------------------------ sign (offline)

/// Can this machine reach any external address? (Used to refuse signing while online.)
pub fn is_online() -> bool {
    PROBES
        .iter()
        .filter_map(|a| a.parse::<SocketAddr>().ok())
        .any(|a| TcpStream::connect_timeout(&a, PROBE_TIMEOUT).is_ok())
}

/// Signs this member's part of the request (no network). Returns a description of what was added.
pub fn sign_request(r: &mut Request, acct: &Account) -> Result<String, String> {
    if r.done {
        return Err("This request has already been executed.".into());
    }
    if !compatible(r.spec_version, r.transaction_version) || r.params.spec_version != r.spec_version
    {
        return Err("The request was prepared for a different network version than this tool — prepare it again.".into());
    }
    let who = acct.id().to_ss58check();
    let nonce = r.members.iter().find(|(m, _)| *m == who).map(|(_, n)| *n).ok_or_else(|| {
        format!("The key ({who}) is not a member of the upgrade committee recorded in this request — will not sign.")
    })?;
    if r.signers().contains(&who) {
        return Err(
            "This member has already signed the request — another member is required.".into(),
        );
    }
    if r.complete() {
        return Err(
            "The request already has all signatures (2 of 3) — no third signature is needed."
                .into(),
        );
    }
    let call = r.call()?;
    if BlakeTwo256::hash_of(&call) != r.proposal_hash {
        return Err("Request file is corrupted (the proposal hash does not match its contents) — will not sign.".into());
    }
    let summary = call_summary(&call)
        .ok_or("The request holds a decision this tool does not know — will not sign.")?;
    if let Some(n) = &r.names_reserve {
        // The description the member sees must match what will actually be executed.
        let expected = names_reserve_summary(&n.name, n.reserved);
        if r.action != "names-reserve" || summary != expected || r.description != expected {
            return Err("Request file is corrupted (the name-reserve description does not match its contents) — will not sign.".into());
        }
    } else if r.action == "names-reserve" || matches!(call, RuntimeCall::Names(_)) {
        return Err(
            "Request file is corrupted (a names decision without its details) — will not sign."
                .into(),
        );
    }
    let is_recover = matches!(&call, RuntimeCall::UpgradeAuthority(madar_upgrade_authority::Call::dispatch_as_root { call })
        if matches!(&**call, RuntimeCall::Grandpa(_)));
    if (r.action == "recover-finality") != is_recover || (is_recover && r.description != summary) {
        return Err("Request file is corrupted (the finality-recovery description does not match its contents) — will not sign.".into());
    }
    let first = r.signed.is_empty();
    let (a_call, a_kind, b_call, b_kind) = if first {
        (
            propose(&call),
            "propose",
            vote(r.proposal_hash, r.proposal_index),
            "vote",
        )
    } else {
        (
            vote(r.proposal_hash, r.proposal_index),
            "vote",
            close(&call, r.proposal_index),
            "close",
        )
    };
    for (i, (c, kind)) in [(a_call, a_kind), (b_call, b_kind)].into_iter().enumerate() {
        let n = nonce + i as u32;
        let xt = tx::sign_with(&r.params, acct, c, n);
        r.signed.push(SignedTx {
            kind: kind.into(),
            signer: who.clone(),
            nonce: n,
            hex: format!("0x{}", hex::encode(xt)),
            submitted: false,
        });
    }
    Ok(if first {
        format!("Signature 1 of 2 on \"{summary}\" ({who}): propose + vote")
    } else {
        format!("Signature 2 of 2 on \"{summary}\" ({who}): vote + execute")
    })
}

#[derive(Deserialize)]
struct StdinKey {
    key_hex: String,
    passphrase: String,
}

fn sign(a: SignArgs) -> Result<(), String> {
    if !a.allow_online && is_online() {
        return Err("This machine is connected to the internet — disconnect it first. No committee key will be decrypted while online.".into());
    }
    let mut r = read_request(&a.request)?;
    let acct = if a.stdin_json {
        let mut raw = Zeroizing::new(String::new());
        std::io::stdin()
            .read_to_string(&mut raw)
            .map_err(|e| e.to_string())?;
        let k: StdinKey = serde_json::from_str(&raw).map_err(|_| "Invalid stdin input")?;
        let key_hex = Zeroizing::new(k.key_hex);
        let pass = Zeroizing::new(k.passphrase);
        let bytes = Zeroizing::new(hex::decode(key_hex.trim()).map_err(|_| "Invalid key file")?);
        Account::from_encrypted(&bytes, &pass)?
    } else {
        let f = a
            .key_file
            .as_ref()
            .ok_or("Specify --key-file or --stdin-json")?;
        let pass = account::read_passphrase(a.passphrase_file.as_deref(), false)?;
        Account::load(f, &pass)?
    };
    let msg = sign_request(&mut r, &acct)?;
    drop(acct);
    write_request(&a.request, &r)?;
    println!("{msg}");
    if r.complete() {
        println!("Signing complete. Remove the USB drives, reconnect to the internet, then: madar-node committee submit --request {}", a.request.display());
    } else {
        println!("Next: a second member signs (with their own USB drive) using the same command.");
    }
    Ok(())
}

// ------------------------------------------------------------------ submit

/// The nonce **included in a block** (from `System::Account` storage), not from the pool — `system_accountNextIndex` also counts pending
/// transactions, so relying on it would send the second member's vote before the proposal actually exists on chain.
fn onchain_nonce(t: &dyn Transport, who: &AccountId) -> Result<u32, String> {
    // The first field of `AccountInfo` is the nonce (decoding the first field is enough).
    let n: Option<madar_consensus::Nonce> =
        storage(t, frame_system::Account::<Runtime>::hashed_key_for(who))?;
    Ok(n.map(|n| n as u32).unwrap_or(0))
}

fn wait_nonce(
    t: &dyn Transport,
    who: &AccountId,
    above: u32,
    wait: Duration,
) -> Result<(), String> {
    let start = Instant::now();
    loop {
        if onchain_nonce(t, who)? > above {
            return Ok(());
        }
        if start.elapsed() > wait {
            return Err("The transaction was not included in the expected time — check the node connection, then rerun `submit` (it resumes where it stopped).".into());
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

pub fn submit_request(
    t: &dyn Transport,
    r: &mut Request,
    wait: Duration,
    mut save: impl FnMut(&Request),
) -> Result<String, String> {
    if r.done {
        return Ok("The request has already been executed.".into());
    }
    if !r.complete() {
        return Err(format!(
            "The request needs two signatures, but has only {}.",
            r.signers().len()
        ));
    }
    if let Some(u) = r.upgrade.clone() {
        if chain_version(t)?.0 >= u.to_spec {
            r.done = true;
            save(r);
            return Ok(format!(
                "✅ The network is already on version {}.",
                u.to_spec
            ));
        }
    }
    if let Some(n) = r.names_reserve.clone() {
        if r.signed.iter().all(|s| !s.submitted)
            && name_reserved(t, &crate::names::parse_name(&n.name)?)? == n.reserved
        {
            return Err(format!(
                "{} — the chain is already in that state, nothing was sent.",
                r.description
            ));
        }
    }
    check_runtime(t)?;
    let best = best_block(t)?;
    if best >= r.expires_at_block {
        return Err(format!("The request has expired (current block #{best} ≥ #{}) — prepare a new request and sign it.", r.expires_at_block));
    }
    if r.signed.iter().all(|s| !s.submitted)
        && proposal_count(t)? != r.proposal_index
        && !own_proposal_on_chain(t, r)?
    {
        return Err("Another committee proposal was submitted since preparation, so the proposal index changed — prepare a new request.".into());
    }
    // Order: first member's proposal, its vote, the second member's vote, the second member's close.
    let order = ["propose", "vote", "vote", "close"];
    let mut seq: Vec<usize> = Vec::new();
    let first_signer = r
        .signed
        .first()
        .map(|s| s.signer.clone())
        .unwrap_or_default();
    for (i, kind) in order.iter().enumerate() {
        let want_first = i < 2;
        let idx = r
            .signed
            .iter()
            .position(|s| {
                s.kind == *kind
                    && (s.signer == first_signer) == want_first
                    && !seq.contains(&r.signed.iter().position(|x| x == s).unwrap())
            })
            .ok_or("Request file is missing transactions")?;
        seq.push(idx);
    }
    for idx in seq {
        if r.signed[idx].submitted {
            continue;
        }
        let s = r.signed[idx].clone();
        let who = account::parse_address(&s.signer)?;
        let xt = hex::decode(s.hex.trim_start_matches("0x"))
            .map_err(|_| "Corrupted transaction in the request file")?;
        let current = onchain_nonce(t, &who)?;
        if current > s.nonce {
            // Already sent earlier (restart after an interruption).
        } else {
            tx::submit_raw(t, &xt).map_err(|e| {
                format!("The network rejected \"{}\" from {}: {e}", s.kind, s.signer)
            })?;
            wait_nonce(t, &who, s.nonce, wait)?;
        }
        r.signed[idx].submitted = true;
        save(r);
    }
    if let Some(u) = r.upgrade.clone() {
        return apply_upgrade(t, r, &u, wait, save);
    }
    if let Some(n) = r.names_reserve.clone() {
        let name = crate::names::parse_name(&n.name)?;
        let now = name_reserved(t, &name)?;
        if now != n.reserved {
            return Err(format!(
                "The four transactions were sent but the name's reservation did not change on chain (reserved now: {}). Check the chain events.",
                if now { "yes" } else { "no" }
            ));
        }
        r.done = true;
        save(r);
        let done = format!("✅ Committee decision executed: {}", r.description);
        // A caller showing only the last line sees the result; the next step comes before it.
        return Ok(match names_follow_up(&n) {
            Some(f) => format!("{f}\n{done}"),
            None => done,
        });
    }
    if r.action == "recover-finality" {
        let before = r.recover.as_ref().map(|i| i.set_id).unwrap_or(u64::MAX);
        if grandpa_stalled(t)?.is_none() && grandpa_set_id(t)? <= before {
            return Err("The four transactions were sent but the recovery decision did not appear on chain. Check the chain events.".into());
        }
        r.done = true;
        save(r);
        return Ok(format!(
            "Next: at the start of the next session the voter set id changes (now {}) and finality resumes. Do not repeat the decision; if it is late, check the set id.\n✅ Committee decision executed: {}",
            grandpa_set_id(t)?,
            r.description
        ));
    }
    let operator = account::parse_address(&r.operator)?;
    match approved_votes(t, &operator)? {
        Some(v) if v == r.max_votes => {
            r.done = true;
            save(r);
            Ok(format!("✅ Committee decision executed: {}", r.description))
        },
        other => Err(format!(
            "The four transactions were sent but the approval did not appear on chain (current value: {other:?}). Check the events in the dashboard."
        )),
    }
}

/// After the committee decision: sends the approved Runtime file (unsigned; the chain verifies the hash and version) and waits for the network version to change.
fn apply_upgrade(
    t: &dyn Transport,
    r: &mut Request,
    u: &UpgradeInfo,
    wait: Duration,
    mut save: impl FnMut(&Request),
) -> Result<String, String> {
    match authorized_upgrade(t)? {
        Some((h, _)) if h == u.code_hash => {},
        other => {
            return Err(format!(
                "The four transactions were sent but the upgrade authorization did not appear on chain (currently authorized: {:?}). Check the events in the dashboard.",
                other.map(|(h, _)| h)
            ))
        },
    }
    let code = std::fs::read(&u.code_file)
        .map_err(|e| format!("Could not read the upgrade file {}: {e}", u.code_file))?;
    if H256(sp_crypto_hashing::blake2_256(&code)) != u.code_hash {
        return Err(
            "The upgrade file changed after it was approved (hash mismatch) — will not send it."
                .into(),
        );
    }
    let xt = madar_consensus::UncheckedExtrinsic::new_bare(RuntimeCall::System(
        frame_system::Call::apply_authorized_upgrade { code },
    ));
    tx::submit_raw(t, &xt.encode())
        .map_err(|e| format!("The network rejected the upgrade file: {e}"))?;
    let start = Instant::now();
    while chain_version(t)?.0 < u.to_spec {
        if start.elapsed() > wait {
            return Err("The upgrade file was sent but the network version has not changed yet — rerun `submit` in a few minutes (it resumes where it stopped).".into());
        }
        std::thread::sleep(Duration::from_secs(3));
    }
    r.done = true;
    save(r);
    Ok(format!(
        "✅ Committee decision executed: the network is now on version {}.",
        u.to_spec
    ))
}

fn submit(a: SubmitArgs) -> Result<(), String> {
    if !is_online() {
        return Err(
            "This machine is not connected to the internet — reconnect first, then submit.".into(),
        );
    }
    let t = HttpRpc::new(&a.rpc);
    let mut r = read_request(&a.request)?;
    let path = a.request.clone();
    let msg = submit_request(&t, &mut r, Duration::from_secs(a.wait_secs), |r| {
        let _ = write_request(&path, r);
    })?;
    println!("{msg}");
    Ok(())
}

fn show(a: ShowArgs) -> Result<(), String> {
    let r = read_request(&a.request)?;
    if a.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&r).map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    println!("{}", r.description);
    match r.call().ok().and_then(|c| call_summary(&c)) {
        Some(s) => println!("What will actually be executed (from the request contents): {s}"),
        None => println!("Warning: this tool does not know the request contents — do not sign it."),
    }
    if let Some(n) = &r.names_reserve {
        if let Some(f) = names_follow_up(n) {
            println!("After execution — {f}");
        }
    }
    if let Some(i) = &r.recover {
        println!(
            "Dead voters according to the preparer: {}",
            i.dead.join(", ")
        );
    }
    if let Some(u) = &r.upgrade {
        println!("Upgrade file: {} ({} bytes)", u.code_file, u.code_size);
    }
    println!(
        "Signatures: {} of {THRESHOLD} ({})",
        r.signers().len().min(THRESHOLD as usize),
        r.signers().join(", ")
    );
    println!("Valid until block #{}", r.expires_at_block);
    println!("Executed: {}", if r.done { "yes" } else { "no" });
    Ok(())
}

// ------------------------------------------------------------------ files

pub fn read_request(p: &Path) -> Result<Request, String> {
    let text =
        std::fs::read_to_string(p).map_err(|e| format!("Could not read {}: {e}", p.display()))?;
    serde_json::from_str(&text)
        .map_err(|_| "Request file is corrupted or not a committee request file.".into())
}

pub fn write_request(p: &Path, r: &Request) -> Result<(), String> {
    let tmp = p.with_extension("tmp");
    std::fs::write(
        &tmp,
        serde_json::to_string_pretty(r).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, p).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp_core::{sr25519, Pair};

    fn acct(seed: u8) -> Account {
        Account::from_pair_for_tests(sr25519::Pair::from_seed(&[seed; 32]))
    }

    fn request(members: &[&Account]) -> Request {
        let op = AccountId::from([9u8; 32]);
        let call = approve_operator_call(&op, 1);
        Request {
            version: 1,
            action: "approve-operator".into(),
            description: "test".into(),
            operator: op.to_ss58check(),
            max_votes: 1,
            upgrade: None,
            names_reserve: None,
            recover: None,
            call_hex: format!("0x{}", hex::encode(call.encode())),
            proposal_hash: BlakeTwo256::hash_of(&call),
            proposal_index: 7,
            spec_version: VERSION.spec_version,
            transaction_version: VERSION.transaction_version,
            params: TxParams {
                genesis: H256::repeat_byte(1),
                birth_hash: H256::repeat_byte(2),
                current: 1000,
                period: ERA_PERIOD,
                spec_version: VERSION.spec_version,
                transaction_version: VERSION.transaction_version,
            },
            expires_at_block: 1256,
            members: members
                .iter()
                .enumerate()
                .map(|(i, a)| (a.id().to_ss58check(), i as u32 * 10))
                .collect(),
            signed: vec![],
            done: false,
        }
    }

    #[test]
    fn two_members_sign_propose_vote_then_vote_close_with_their_own_nonces() {
        let (a, b, c) = (acct(1), acct(2), acct(3));
        let mut r = request(&[&a, &b, &c]);
        assert!(sign_request(&mut r, &b).unwrap().contains("1 of 2"));
        assert!(
            sign_request(&mut r, &b).is_err(),
            "the same member cannot sign twice"
        );
        assert!(sign_request(&mut r, &c).unwrap().contains("2 of 2"));
        assert!(r.complete());
        assert!(sign_request(&mut r, &a).is_err(), "no third signature");
        let kinds: Vec<(&str, u32)> = r
            .signed
            .iter()
            .map(|s| (s.kind.as_str(), s.nonce))
            .collect();
        assert_eq!(
            kinds,
            vec![("propose", 10), ("vote", 11), ("vote", 20), ("close", 21)]
        );
        // The transactions decode as well-formed Runtime extrinsics, signed by the correct member.
        for s in &r.signed {
            let bytes = hex::decode(s.hex.trim_start_matches("0x")).unwrap();
            let xt = madar_consensus::UncheckedExtrinsic::decode(&mut &bytes[..])
                .expect("decodes as a runtime extrinsic");
            let signer = match &xt.preamble {
                sp_runtime::generic::Preamble::Signed(madar_consensus::Address::Id(who), _, _) => {
                    who.to_ss58check()
                }
                _ => panic!("must be signed"),
            };
            assert_eq!(signer, s.signer);
        }
    }

    #[test]
    fn a_non_member_or_a_tampered_request_is_refused() {
        let (a, b, outsider) = (acct(1), acct(2), acct(5));
        let mut r = request(&[&a, &b]);
        assert!(sign_request(&mut r, &outsider)
            .unwrap_err()
            .contains("is not a member"));
        let mut t = r.clone();
        t.proposal_hash = H256::repeat_byte(7);
        assert!(sign_request(&mut t, &a).unwrap_err().contains("corrupted"));
        assert!(r.signed.is_empty(), "nothing is added on refusal");
    }

    #[test]
    fn the_close_call_executes_exactly_the_proposed_call() {
        let op = AccountId::from([9u8; 32]);
        let call = approve_operator_call(&op, 1);
        match close(&call, 3) {
            RuntimeCall::UpgradeCommittee(pallet_collective::Call::close {
                proposal_hash,
                index,
                length_bound,
                ..
            }) => {
                assert_eq!(proposal_hash, BlakeTwo256::hash_of(&call));
                assert_eq!(index, 3);
                assert_eq!(length_bound, call.encoded_size() as u32);
            }
            _ => panic!("close"),
        }
    }

    #[test]
    fn the_upgrade_proposal_only_authorizes_a_hash_through_the_root_gate() {
        let h = H256::repeat_byte(4);
        match authorize_upgrade_call(h) {
            RuntimeCall::UpgradeAuthority(madar_upgrade_authority::Call::dispatch_as_root {
                call,
            }) => {
                assert!(
                    matches!(*call, RuntimeCall::System(frame_system::Call::authorize_upgrade { code_hash }) if code_hash == h)
                );
            }
            _ => panic!("must go through UpgradeAuthority"),
        }
        assert!(
            authorize_upgrade_call(h).encoded_size() < 100,
            "the signed proposal stays tiny: no WASM inside"
        );
    }

    #[test]
    fn the_tool_serves_the_current_or_an_older_chain_but_never_a_newer_one() {
        assert!(compatible(
            VERSION.spec_version,
            VERSION.transaction_version
        ));
        assert!(compatible(
            VERSION.spec_version - 1,
            VERSION.transaction_version
        ));
        assert!(!compatible(
            VERSION.spec_version + 1,
            VERSION.transaction_version
        ));
        assert!(!compatible(
            VERSION.spec_version,
            VERSION.transaction_version + 1
        ));
    }

    #[test]
    fn a_request_prepared_for_an_older_chain_is_signed_with_the_chains_version() {
        use sp_runtime::traits::Verify;
        let (a, b) = (acct(1), acct(2));
        let mut r = request(&[&a, &b]);
        r.spec_version = VERSION.spec_version - 1;
        r.params.spec_version = VERSION.spec_version - 1;
        sign_request(&mut r, &a).unwrap();
        let bytes = hex::decode(r.signed[0].hex.trim_start_matches("0x")).unwrap();
        let xt = madar_consensus::UncheckedExtrinsic::decode(&mut &bytes[..]).unwrap();
        let (sig, extra) = match &xt.preamble {
            sp_runtime::generic::Preamble::Signed(_, s, e) => (s.clone(), e.clone()),
            _ => panic!("signed"),
        };
        // The payload verifies with the chain's version; with the tool's version it does not.
        let payload = |spec: u32| {
            sp_runtime::generic::SignedPayload::from_raw(
                xt.function.clone(),
                extra.clone(),
                (
                    spec,
                    VERSION.transaction_version,
                    r.params.genesis,
                    r.params.birth_hash,
                    (),
                    (),
                ),
            )
            .encode()
        };
        assert!(sig.verify(&payload(VERSION.spec_version - 1)[..], &a.id()));
        assert!(!sig.verify(&payload(VERSION.spec_version)[..], &a.id()));
        let mut stale = request(&[&a, &b]);
        stale.params.spec_version = VERSION.spec_version - 1;
        assert!(
            sign_request(&mut stale, &a).is_err(),
            "request and params versions must agree"
        );
    }

    fn names_request(members: &[&Account], name: &str, reserved: bool) -> Request {
        let mut r = request(members);
        let call = names_reserve_call(crate::names::parse_name(name).unwrap(), reserved);
        r.action = "names-reserve".into();
        r.description = names_reserve_summary(name, reserved);
        r.operator = String::new();
        r.max_votes = 0;
        r.names_reserve = Some(NamesReserveInfo {
            name: name.into(),
            reserved,
        });
        r.call_hex = format!("0x{}", hex::encode(call.encode()));
        r.proposal_hash = BlakeTwo256::hash_of(&call);
        r
    }

    #[test]
    fn the_names_reserve_call_matches_the_spec_8_runtime_indexes() {
        // Names = index 12 in construct_runtime, and `set_reserved` = call_index 4; then the name (BoundedVec) then bool.
        let call = names_reserve_call(crate::names::parse_name("madar").unwrap(), false);
        let mut want = vec![12u8, 4, 5 << 2];
        want.extend_from_slice(b"madar");
        want.push(0);
        assert_eq!(call.encode(), want);
        assert_eq!(
            names_reserve_call(crate::names::parse_name("madar.madar").unwrap(), true)
                .encode()
                .last(),
            Some(&1)
        );
    }

    #[test]
    fn members_see_and_sign_exactly_the_names_decision() {
        let (a, b, c) = (acct(1), acct(2), acct(3));
        let mut r = names_request(&[&a, &b, &c], "madar", false);
        assert_eq!(r.description, "Release the name madar.madar");
        assert_eq!(
            call_summary(&r.call().unwrap()).unwrap(),
            "Release the name madar.madar"
        );
        assert_eq!(
            names_reserve_summary("abc", true),
            "Reserve the name abc.madar"
        );
        assert!(sign_request(&mut r, &acct(5))
            .unwrap_err()
            .contains("is not a member"));
        let m1 = sign_request(&mut r, &a).unwrap();
        assert!(
            m1.contains("1 of 2") && m1.contains("Release the name madar.madar"),
            "{m1}"
        );
        assert!(!r.complete(), "one signature is not enough");
        let m2 = sign_request(&mut r, &b).unwrap();
        assert!(
            m2.contains("2 of 2") && m2.contains("Release the name madar.madar"),
            "{m2}"
        );
        assert!(r.complete());
        let kinds: Vec<&str> = r.signed.iter().map(|s| s.kind.as_str()).collect();
        assert_eq!(kinds, vec!["propose", "vote", "vote", "close"]);
    }

    #[test]
    fn a_names_request_whose_text_does_not_match_its_call_is_refused() {
        let (a, b) = (acct(1), acct(2));
        // The description says "reserve" and the call says "release".
        let mut lie = names_request(&[&a, &b], "madar", false);
        lie.description = names_reserve_summary("madar", true);
        assert!(sign_request(&mut lie, &a)
            .unwrap_err()
            .contains("does not match"));
        // The request details name a different name than the call.
        let mut other = names_request(&[&a, &b], "madar", false);
        other.names_reserve = Some(NamesReserveInfo {
            name: "admin".into(),
            reserved: false,
        });
        other.description = names_reserve_summary("admin", false);
        assert!(sign_request(&mut other, &a)
            .unwrap_err()
            .contains("does not match"));
        // A names decision hidden in a request that looks like an operator approval.
        let mut hidden = names_request(&[&a, &b], "madar", false);
        hidden.names_reserve = None;
        hidden.action = "approve-operator".into();
        assert!(sign_request(&mut hidden, &a)
            .unwrap_err()
            .contains("corrupted"));
        assert!(lie.signed.is_empty() && other.signed.is_empty() && hidden.signed.is_empty());
    }

    #[test]
    fn a_call_the_tool_cannot_describe_is_never_signed() {
        let (a, b) = (acct(1), acct(2));
        let mut r = request(&[&a, &b]);
        let call = RuntimeCall::System(frame_system::Call::remark {
            remark: vec![1, 2, 3],
        });
        r.call_hex = format!("0x{}", hex::encode(call.encode()));
        r.proposal_hash = BlakeTwo256::hash_of(&call);
        assert!(sign_request(&mut r, &a)
            .unwrap_err()
            .contains("does not know"));
    }

    fn recover_request(members: &[&Account], delay: u32, fin: u32) -> Request {
        let mut r = request(members);
        let call = recover_finality_call(delay, fin);
        r.action = "recover-finality".into();
        r.description = recover_finality_summary(delay, fin);
        r.operator = String::new();
        r.max_votes = 0;
        r.call_hex = format!("0x{}", hex::encode(call.encode()));
        r.proposal_hash = BlakeTwo256::hash_of(&call);
        r
    }

    #[test]
    fn the_recovery_call_notes_the_stall_through_the_root_gate() {
        match recover_finality_call(10, 4) {
            RuntimeCall::UpgradeAuthority(madar_upgrade_authority::Call::dispatch_as_root {
                call,
            }) => match *call {
                RuntimeCall::Grandpa(pallet_grandpa::Call::note_stalled {
                    delay,
                    best_finalized_block_number,
                }) => {
                    assert_eq!((delay, best_finalized_block_number), (10, 4))
                }
                other => panic!("unexpected inner call {other:?}"),
            },
            other => panic!("unexpected call {other:?}"),
        }
    }

    #[test]
    fn members_sign_exactly_the_recovery_decision_and_a_mismatch_is_refused() {
        let (a, b) = (acct(1), acct(2));
        let mut r = recover_request(&[&a, &b], 10, 4);
        assert_eq!(call_summary(&r.call().unwrap()).unwrap(), r.description);
        assert!(
            r.description.contains("#4") && r.description.contains("10 blocks"),
            "{}",
            r.description
        );
        assert!(sign_request(&mut r, &a).unwrap().contains("1 of 2"));
        assert!(sign_request(&mut r, &b).unwrap().contains("2 of 2"));
        // the text says block 4, the call says 900
        let mut lie = recover_request(&[&a, &b], 10, 900);
        lie.description = recover_finality_summary(10, 4);
        assert!(sign_request(&mut lie, &a)
            .unwrap_err()
            .contains("does not match"));
        // a recovery call hidden in a request that looks like an operator approval
        let mut hidden = recover_request(&[&a, &b], 10, 4);
        hidden.action = "approve-operator".into();
        assert!(sign_request(&mut hidden, &a)
            .unwrap_err()
            .contains("does not match"));
        // and the reverse: a "recover-finality" label on another call
        let mut label = request(&[&a, &b]);
        label.action = "recover-finality".into();
        assert!(sign_request(&mut label, &a)
            .unwrap_err()
            .contains("does not match"));
        assert!(lie.signed.is_empty() && hidden.signed.is_empty() && label.signed.is_empty());
    }

    struct Chain {
        best: u64,
        fin: u64,
    }
    impl Transport for Chain {
        fn call(
            &self,
            method: &str,
            _params: serde_json::Value,
        ) -> Result<serde_json::Value, String> {
            Ok(match method {
                "state_getRuntimeVersion" => {
                    json!({"specVersion": VERSION.spec_version, "transactionVersion": VERSION.transaction_version})
                }
                "chain_getFinalizedHead" => json!("0xfin"),
                "state_getStorage" => {
                    let mut key = sp_crypto_hashing::twox_128(b"Session").to_vec();
                    key.extend(sp_crypto_hashing::twox_128(b"QueuedKeys"));
                    if _params == json!([format!("0x{}", hex::encode(key))]) {
                        let k = madar_consensus::SessionKeys {
                            babe: sp_core::sr25519::Public::from_raw([0; 32]).into(),
                            grandpa: sp_core::ed25519::Public::from_raw([0; 32]).into(),
                        };
                        json!(format!(
                            "0x{}",
                            hex::encode(vec![(AccountId::from([1u8; 32]), k)].encode())
                        ))
                    } else {
                        serde_json::Value::Null
                    }
                }
                "chain_getHeader" => {
                    json!({"number": format!("0x{:x}", if _params == json!(["0xfin"]) { self.fin } else { self.best })})
                }
                other => return Err(format!("not mocked: {other}")),
            })
        }
    }

    #[test]
    fn recovery_is_refused_while_finality_still_runs() {
        let dead = [AccountId::from([2u8; 32])];
        let e = prepare_recover_finality_request(
            &Chain {
                best: 150,
                fin: 100,
            },
            &dead,
            50,
        )
        .unwrap_err();
        assert!(e.contains("is not stalled"), "{e}");
        let e = prepare_recover_finality_request(
            &Chain {
                best: 199,
                fin: 100,
            },
            &dead,
            50,
        )
        .unwrap_err();
        assert!(e.contains("is not stalled"), "{e}");
    }

    #[test]
    fn recovery_waits_until_the_dead_voters_left_the_next_sessions_set() {
        // account [1;32] is still queued for the next session: forcing now would take it along
        let e = prepare_recover_finality_request(
            &Chain {
                best: 400,
                fin: 100,
            },
            &[AccountId::from([1u8; 32])],
            50,
        )
        .unwrap_err();
        assert!(e.contains("is still in the next session's set"), "{e}");
        let e = prepare_recover_finality_request(
            &Chain {
                best: 400,
                fin: 100,
            },
            &[],
            50,
        )
        .unwrap_err();
        assert!(e.contains("--dead"), "{e}");
    }

    #[test]
    fn the_request_file_round_trips() {
        let a = acct(1);
        let r = request(&[&a]);
        assert!(
            !serde_json::to_string(&r).unwrap().contains("names_reserve"),
            "old kinds keep their file format"
        );
        let n = names_request(&[&a], "madar", false);
        let pn =
            std::env::temp_dir().join(format!("madar-committee-n-{}.json", std::process::id()));
        write_request(&pn, &n).unwrap();
        assert_eq!(read_request(&pn).unwrap(), n);
        let _ = std::fs::remove_file(pn);
        let p = std::env::temp_dir().join(format!("madar-committee-{}.json", std::process::id()));
        write_request(&p, &r).unwrap();
        assert_eq!(read_request(&p).unwrap(), r);
        let _ = std::fs::remove_file(p);
    }
}
