//! Upgrade-committee approvals (2 of 3) signed **offline** (`madar-node committee …`):
//!
//! 1. `prepare` (online): reads from the node everything needed for signing — genesis, validity window, committee members and their nonces, the next
//!    proposal index — and writes a **request file** that contains no secrets.
//! 2. `sign` (**refuses to run while the machine is connected to the internet**): decrypts a committee member's key (a `.enc` file in `madar-keystore` format) in memory only, signs
//!    its two transactions and adds them to the request file. First member: propose + vote. Second: vote + close (execute). Neither the key nor the passphrase is written to disk.
//! 3. `submit` (online): sends the four transactions in order, waits for each to be included, then verifies the decision's effect on chain.
//!
//! Supported decisions: `approve-operator` (approve an operator with a vote cap) and `upgrade-runtime` (network upgrade): the committee approves only the **hash** of the WASM file
//! (`System::authorize_upgrade` via `UpgradeAuthority::dispatch_as_root`), so the signature stays small with no large file; then `submit` sends the file itself
//! (`apply_authorized_upgrade`, unsigned) and the chain accepts it only if its hash matches and its version is newer. Transactions are Mortal (window ~256 blocks ≈ 40 minutes): signing
//! and submitting must both happen within it, otherwise `prepare` must be rerun.

use crate::join::account::{self, Account};
use crate::join::rpc::{HttpRpc, Transport};
use crate::join::tx::{self, TxParams};
use madar_consensus::{
    madar_admission, AccountId, Runtime, RuntimeCall, UpgradeCommitteeInstance, VERSION,
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
    "103.254.60.222:30333",
];
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

#[derive(Debug, Clone, clap::Subcommand)]
pub enum CommitteeCmd {
    /// (online) Prepare an approval request: writes a request file with no secrets.
    Prepare(PrepareArgs),
    /// (online) Prepare a network-upgrade request from a WASM file: only its hash is approved.
    PrepareUpgrade(PrepareUpgradeArgs),
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
        format!("Signature 1 of 2 ({who}): propose + vote")
    } else {
        format!("Signature 2 of 2 ({who}): vote + execute")
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
    check_runtime(t)?;
    let best = best_block(t)?;
    if best >= r.expires_at_block {
        return Err(format!("The request has expired (current block #{best} ≥ #{}) — prepare a new request and sign it.", r.expires_at_block));
    }
    if r.signed.iter().all(|s| !s.submitted) && proposal_count(t)? != r.proposal_index {
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

    #[test]
    fn the_request_file_round_trips() {
        let a = acct(1);
        let r = request(&[&a]);
        let p = std::env::temp_dir().join(format!("madar-committee-{}.json", std::process::id()));
        write_request(&p, &r).unwrap();
        assert_eq!(read_request(&p).unwrap(), r);
        let _ = std::fs::remove_file(p);
    }
}
