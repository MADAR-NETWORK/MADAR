//! "MADAR Stamp" tool for the server service (`madar-node stamp …`): submit a batch of fingerprints with the registrar account, and read a stamp record.
//! Output is JSON on a single line for the service program to read. No secrets are printed; the passphrase comes from a file or stdin.

use crate::join::{
    account::{self, Account},
    rpc::{HttpRpc, Transport},
    tx,
};
use madar_consensus::{madar_stamp, AccountId, RuntimeCall};
use madar_stamp::{Entry, Record, Wallet, WalletProof};
use parity_scale_codec::Decode;
use serde_json::{json, Value};
use sp_core::crypto::Ss58Codec;
use std::io::Read;
use std::path::PathBuf;

#[derive(Debug, Clone, clap::Subcommand)]
pub enum StampCmd {
    /// Submits a batch of fingerprints (JSON from a file or stdin) with the approved registrar account, and prints the transaction hash.
    Submit(SubmitArgs),
    /// Reads a stamp record from the chain (read-only) and prints it as JSON, or {"found":false}.
    Lookup(LookupArgs),
    /// "I am the registrant": verifies that a new signature over the challenge message comes from the same wallet registered for the stamp. Read-only.
    Prove(ProveArgs),
    /// Prints the storage prefix of all records (`Stamp.Stamps`) — for the service's daily backup. No network.
    Prefix,
}

#[derive(Debug, Clone, clap::Args)]
pub struct ProveArgs {
    #[arg(long, default_value = "127.0.0.1:9944")]
    pub rpc: String,
    #[arg(long)]
    pub fingerprint: String,
    /// The challenge message as signed by the wallet (hex of its bytes).
    #[arg(long)]
    pub message_hex: String,
    /// The signature in the same format as the batch: {"evm":{…}} or {"solana":{…}}.
    #[arg(long)]
    pub proof: String,
}

#[derive(Debug, Clone, clap::Args)]
pub struct SubmitArgs {
    #[arg(long, default_value = "127.0.0.1:9944")]
    pub rpc: String,
    /// The encrypted registrar account (.enc).
    #[arg(long)]
    pub account_file: PathBuf,
    #[arg(long)]
    pub passphrase_file: Option<PathBuf>,
    /// Reads the passphrase from the first line of stdin (the batch must then come from --batch).
    #[arg(long)]
    pub passphrase_stdin: bool,
    /// Batch file: [{"fingerprint":"hex","name_hash":"hex"|null,"proof":null|{"evm":{"address":"0x…","signature":"0x…"}}|{"solana":{"public":"hex","signature":"hex"}}}]
    /// Without it, the batch is read from stdin.
    #[arg(long)]
    pub batch: Option<PathBuf>,
    /// (spec 9) Sends `stamp_v2`: every signature contains "valid_until" (inside proof or in the entry itself). Automatic if a v2 signature is present.
    #[arg(long)]
    pub v2: bool,
}

#[derive(Debug, Clone, clap::Args)]
pub struct LookupArgs {
    #[arg(long, default_value = "127.0.0.1:9944")]
    pub rpc: String,
    /// SHA-256 fingerprint (64 hex characters, with or without 0x).
    #[arg(long)]
    pub fingerprint: String,
}

pub fn run(cmd: StampCmd) -> Result<(), String> {
    match cmd {
        StampCmd::Submit(a) => submit(a),
        StampCmd::Lookup(a) => lookup(a),
        StampCmd::Prove(a) => prove(a),
        StampCmd::Prefix => {
            use frame_support::storage::StoragePrefixedMap;
            let p = madar_stamp::Stamps::<madar_consensus::Runtime>::final_prefix();
            println!("{}", json!({ "prefix": format!("0x{}", hex::encode(p)) }));
            Ok(())
        }
    }
}

fn bytes<const N: usize>(v: &Value, what: &str) -> Result<[u8; N], String> {
    let s = v
        .as_str()
        .ok_or_else(|| format!("{what}: hex string required"))?;
    let raw =
        hex::decode(s.trim_start_matches("0x")).map_err(|_| format!("{what}: invalid hex"))?;
    raw.try_into()
        .map_err(|_| format!("{what}: length must be {N} bytes"))
}

pub fn parse_entries(v: &Value) -> Result<Vec<Entry>, String> {
    let arr = v.as_array().ok_or("The batch must be a JSON array")?;
    arr.iter()
        .map(|e| {
            let fingerprint = bytes::<32>(&e["fingerprint"], "fingerprint")?;
            let name_hash = match &e["name_hash"] {
                Value::Null => None,
                x => Some(bytes::<32>(x, "name_hash")?),
            };
            let proof = match &e["proof"] {
                Value::Null => None,
                p if !p["evm"].is_null() => Some(WalletProof::Evm {
                    address: bytes::<20>(&p["evm"]["address"], "evm.address")?,
                    signature: bytes::<65>(&p["evm"]["signature"], "evm.signature")?,
                }),
                p if !p["solana"].is_null() => Some(WalletProof::Solana {
                    public: bytes::<32>(&p["solana"]["public"], "solana.public")?,
                    signature: bytes::<64>(&p["solana"]["signature"], "solana.signature")?,
                }),
                _ => return Err("proof: evm or solana".into()),
            };
            Ok(Entry {
                fingerprint,
                name_hash,
                proof,
            })
        })
        .collect()
}

/// (spec 9) The signature deadline of a v2 entry: `valid_until` in the entry or inside proof; None = a v1 entry (or unsigned).
fn entry_until(e: &Value) -> Result<Option<u64>, String> {
    let v = if e["valid_until"].is_null() {
        &e["proof"]["valid_until"]
    } else {
        &e["valid_until"]
    };
    match v {
        Value::Null => Ok(None),
        x => x
            .as_u64()
            .map(Some)
            .ok_or_else(|| "valid_until: a number (UTC milliseconds)".to_string()),
    }
}

/// The batch as a call: `stamp` (v1) or `stamp_v2`. v1 and v2 signatures are not mixed in one batch; an unsigned entry fits both.
pub fn batch_call(v: &Value, force_v2: bool) -> Result<RuntimeCall, String> {
    let entries = parse_entries(v)?;
    if entries.is_empty() {
        return Err("The batch is empty".into());
    }
    let arr = v.as_array().ok_or("The batch must be a JSON array")?;
    let untils = arr.iter().map(entry_until).collect::<Result<Vec<_>, _>>()?;
    let any_v2 = untils.iter().any(Option::is_some);
    if !(force_v2 || any_v2) {
        let bounded = entries
            .try_into()
            .map_err(|_| "The batch exceeds the allowed limit (50) or is empty".to_string())?;
        return Ok(RuntimeCall::Stamp(madar_stamp::Call::stamp {
            entries: bounded,
        }));
    }
    let mut v2 = Vec::with_capacity(entries.len());
    for (e, until) in entries.into_iter().zip(untils) {
        if e.proof.is_some() && until.is_none() {
            return Err("A v2 batch contains a v1 signature (without valid_until): send it in a separate batch".into());
        }
        v2.push(madar_stamp::EntryV2 {
            fingerprint: e.fingerprint,
            name_hash: e.name_hash,
            proof: e.proof,
            valid_until: until.unwrap_or(0),
        });
    }
    let bounded = v2
        .try_into()
        .map_err(|_| "The batch exceeds the allowed limit (50) or is empty".to_string())?;
    Ok(RuntimeCall::Stamp(madar_stamp::Call::stamp_v2 {
        entries: bounded,
    }))
}

fn submit(a: SubmitArgs) -> Result<(), String> {
    let mut stdin = String::new();
    let pass = if a.passphrase_stdin {
        std::io::stdin()
            .read_line(&mut stdin)
            .map_err(|e| e.to_string())?;
        zeroize::Zeroizing::new(stdin.trim_end_matches(['\r', '\n']).to_string())
    } else {
        account::read_passphrase(a.passphrase_file.as_deref(), false)?
    };
    let raw = match &a.batch {
        Some(p) => {
            std::fs::read_to_string(p).map_err(|e| format!("Could not read the batch: {e}"))?
        }
        None if a.passphrase_stdin => {
            return Err("--batch must be given with --passphrase-stdin".into())
        }
        None => {
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .map_err(|e| e.to_string())?;
            s
        }
    };
    let call = batch_call(
        &serde_json::from_str(&raw).map_err(|e| format!("Invalid JSON: {e}"))?,
        a.v2,
    )?;
    let acct: Account = Account::load(&a.account_file, &pass)?;
    let t = HttpRpc::new(&a.rpc);
    let hash = tx::submit(&t, &acct, call)?;
    println!(
        "{}",
        json!({ "tx": hash, "stamper": acct.id().to_ss58check() })
    );
    Ok(())
}

fn read_record(rpc: &str, fingerprint: &str) -> Result<Option<Record<AccountId, u32>>, String> {
    let fp = bytes::<32>(&Value::String(fingerprint.to_string()), "fingerprint")?;
    let key = madar_stamp::Stamps::<madar_consensus::Runtime>::hashed_key_for(fp);
    let t = HttpRpc::new(rpc);
    let v = t.call(
        "state_getStorage",
        json!([format!("0x{}", hex::encode(key))]),
    )?;
    let Some(s) = v.as_str() else { return Ok(None) };
    let raw = hex::decode(s.trim_start_matches("0x")).map_err(|_| "Invalid storage")?;
    Record::<AccountId, u32>::decode(&mut &raw[..])
        .map(Some)
        .map_err(|_| "Could not decode the stamp record".to_string())
}

fn prove(a: ProveArgs) -> Result<(), String> {
    let Some(r) = read_record(&a.rpc, &a.fingerprint)? else {
        println!("{}", json!({ "ok": false, "reason": "not_found" }));
        return Ok(());
    };
    let Some(registered) = r.wallet else {
        println!("{}", json!({ "ok": false, "reason": "no_wallet" }));
        return Ok(());
    };
    let message =
        hex::decode(a.message_hex.trim_start_matches("0x")).map_err(|_| "Invalid message_hex")?;
    let proof_json: Value = serde_json::from_str(&a.proof).map_err(|e| format!("proof: {e}"))?;
    let entry = parse_entries(
        &json!([{ "fingerprint": a.fingerprint, "name_hash": null, "proof": proof_json }]),
    )?;
    let Some(proof) = entry.into_iter().next().and_then(|e| e.proof) else {
        return Err("proof required".into());
    };
    let ok = madar_stamp::verify_proof(&proof, &message).is_some_and(|w| w == registered);
    println!(
        "{}",
        json!({ "ok": ok, "reason": if ok { "match" } else { "mismatch" } })
    );
    Ok(())
}

fn lookup(a: LookupArgs) -> Result<(), String> {
    let Some(r) = read_record(&a.rpc, &a.fingerprint)? else {
        println!("{}", json!({ "found": false }));
        return Ok(());
    };
    let wallet = match r.wallet {
        None => Value::Null,
        Some(Wallet::Evm(a)) => {
            json!({ "kind": "evm", "address": format!("0x{}", hex::encode(a)) })
        }
        Some(Wallet::Solana(p)) => json!({ "kind": "solana", "public": hex::encode(p) }),
    };
    println!(
        "{}",
        json!({
            "found": true,
            "block": r.block,
            "moment": r.moment,
            "stamper": r.stamper.to_ss58check(),
            "wallet": wallet,
            "name_hash": r.name_hash.map(hex::encode),
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_proof_kinds_and_rejects_bad_lengths() {
        let v = json!([
            { "fingerprint": "ab".repeat(32), "name_hash": null, "proof": null },
            { "fingerprint": format!("0x{}", "01".repeat(32)), "name_hash": "02".repeat(32),
              "proof": { "evm": { "address": format!("0x{}", "03".repeat(20)), "signature": "04".repeat(65) } } },
            { "fingerprint": "05".repeat(32), "name_hash": null,
              "proof": { "solana": { "public": "06".repeat(32), "signature": "07".repeat(64) } } },
        ]);
        let e = parse_entries(&v).unwrap();
        assert_eq!(e.len(), 3);
        assert!(matches!(e[1].proof, Some(WalletProof::Evm { .. })));
        assert!(matches!(e[2].proof, Some(WalletProof::Solana { .. })));
        assert!(
            parse_entries(&json!([{ "fingerprint": "ab", "name_hash": null, "proof": null }]))
                .is_err()
        );
    }

    #[test]
    fn v2_batches_go_to_stamp_v2_and_never_mix_with_v1_signatures() {
        let evm = |until: Option<u64>| {
            let mut p = json!({ "evm": { "address": format!("0x{}", "03".repeat(20)), "signature": "04".repeat(65) } });
            if let Some(u) = until {
                p["valid_until"] = json!(u);
            }
            p
        };
        let plain = json!({ "fingerprint": "01".repeat(32), "name_hash": null, "proof": null });
        let v1 = json!({ "fingerprint": "02".repeat(32), "name_hash": null, "proof": evm(None) });
        let v2 =
            json!({ "fingerprint": "03".repeat(32), "name_hash": null, "proof": evm(Some(77)) });
        let top = json!({ "fingerprint": "04".repeat(32), "name_hash": null, "proof": evm(None), "valid_until": 78 });
        assert!(matches!(
            batch_call(&json!([plain.clone(), v1.clone()]), false).unwrap(),
            RuntimeCall::Stamp(madar_stamp::Call::stamp { .. })
        ));
        match batch_call(&json!([plain.clone(), v2.clone(), top]), false).unwrap() {
            RuntimeCall::Stamp(madar_stamp::Call::stamp_v2 { entries }) => {
                assert_eq!(
                    entries.iter().map(|e| e.valid_until).collect::<Vec<_>>(),
                    vec![0, 77, 78]
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            batch_call(&json!([plain.clone()]), true).unwrap(),
            RuntimeCall::Stamp(madar_stamp::Call::stamp_v2 { .. })
        ));
        assert!(
            batch_call(&json!([v1.clone(), v2]), false).is_err(),
            "v1 and v2 signatures in one batch"
        );
        assert!(batch_call(&json!([v1]), true).is_err());
        assert!(batch_call(&json!([]), true).is_err());
    }

    /// Backup prefix = twox128("Stamp") ++ twox128("Stamps") — follows the pallet name in the Runtime.
    #[test]
    fn backup_prefix_is_pallet_and_storage_names() {
        use frame_support::storage::StoragePrefixedMap;
        let mut want =
            <frame_support::Twox128 as frame_support::StorageHasher>::hash(b"Stamp").to_vec();
        want.extend(<frame_support::Twox128 as frame_support::StorageHasher>::hash(b"Stamps"));
        assert_eq!(
            madar_stamp::Stamps::<madar_consensus::Runtime>::final_prefix().to_vec(),
            want
        );
    }
}
