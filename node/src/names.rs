//! The "Madar Names" tool for the server service (`madar-node names …`): register and renew a name with the registrar account, and read a name's record.
//! Output is single-line JSON for the service program to read. Secrets are never printed; the passphrase comes from a file or stdin.

use crate::join::{
    account::{self, Account},
    rpc::{HttpRpc, Transport},
    tx,
};
use madar_consensus::{madar_names, AccountId, RuntimeCall};
use madar_names::{NameOf, NameRecord, Wallet, WalletProof};
use parity_scale_codec::Decode;
use serde_json::{json, Value};
use sp_core::crypto::Ss58Codec;
use std::path::PathBuf;

#[derive(Debug, Clone, clap::Subcommand)]
pub enum NamesCmd {
    /// Registers a name for a wallet that proved itself by signing the registration message, until `--expires` (milliseconds, UTC).
    Register(WriteArgs),
    /// Extends a registered name's term until `--expires` (the owner does not change).
    Renew(WriteArgs),
    /// Reads a name's record from the chain (read only) and prints it as JSON, or {"found":false}.
    Lookup(LookupArgs),
    /// Checks offline that the wallet signature is valid for this name's registration message — before taking any payment.
    CheckProof(CheckProofArgs),
    /// Safe sale: prints the exact text of the offer/buy/cancel message, and with `--proof` checks it offline and prints the signing wallet.
    SaleMessage(SaleMessageArgs),
    /// Safe sale: locks the name for the buyer (60 minutes at most) with the seller's offer and the buyer's acceptance.
    LockSale(LockSaleArgs),
    /// Safe sale: moves the name to the buyer it is locked for, after the payment arrives.
    CompleteSale(NameWriteArgs),
    /// Safe sale: cancels the owner's offers for this name with the owner's signature (`--proof`).
    CancelOffer(NameWriteArgs),
}

#[derive(Debug, Clone, clap::Args)]
pub struct AuthArgs {
    #[arg(long, default_value = "127.0.0.1:9944")]
    pub rpc: String,
    #[arg(long)]
    pub account_file: PathBuf,
    #[arg(long)]
    pub passphrase_file: Option<PathBuf>,
    #[arg(long)]
    pub passphrase_stdin: bool,
}

#[derive(Debug, Clone, clap::Args)]
pub struct SaleMessageArgs {
    /// offer | buy | cancel
    #[arg(long)]
    pub kind: String,
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    pub nonce: u32,
    #[arg(long, default_value_t = 0)]
    pub price_cents: u64,
    #[arg(long, default_value = "")]
    pub pay_to: String,
    #[arg(long, default_value_t = 0)]
    pub offer_until: u64,
    #[arg(long)]
    pub proof: Option<String>,
}

#[derive(Debug, Clone, clap::Args)]
pub struct LockSaleArgs {
    #[command(flatten)]
    pub auth: AuthArgs,
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    pub seller_proof: String,
    #[arg(long)]
    pub price_cents: u64,
    #[arg(long)]
    pub pay_to: String,
    #[arg(long)]
    pub offer_until: u64,
    #[arg(long)]
    pub buyer_proof: String,
    #[arg(long)]
    pub lock_until: u64,
}

#[derive(Debug, Clone, clap::Args)]
pub struct NameWriteArgs {
    #[command(flatten)]
    pub auth: AuthArgs,
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    pub proof: Option<String>,
}

#[derive(Debug, Clone, clap::Args)]
pub struct CheckProofArgs {
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    pub proof: String,
}

#[derive(Debug, Clone, clap::Args)]
pub struct WriteArgs {
    #[arg(long, default_value = "127.0.0.1:9944")]
    pub rpc: String,
    #[arg(long)]
    pub account_file: PathBuf,
    #[arg(long)]
    pub passphrase_file: Option<PathBuf>,
    /// Reads the passphrase from the first line of stdin.
    #[arg(long)]
    pub passphrase_stdin: bool,
    #[arg(long)]
    pub name: String,
    /// End of the term (milliseconds since 1970, UTC).
    #[arg(long)]
    pub expires: u64,
    /// Registration only: {"evm":{"address":"0x…","signature":"0x…"}} or {"solana":{"public":"hex","signature":"hex"}}
    #[arg(long)]
    pub proof: Option<String>,
}

#[derive(Debug, Clone, clap::Args)]
pub struct LookupArgs {
    #[arg(long, default_value = "127.0.0.1:9944")]
    pub rpc: String,
    #[arg(long)]
    pub name: String,
}

pub fn run(cmd: NamesCmd) -> Result<(), String> {
    match cmd {
        NamesCmd::Register(a) => write(a, true),
        NamesCmd::Renew(a) => write(a, false),
        NamesCmd::Lookup(a) => lookup(a),
        NamesCmd::SaleMessage(a) => {
            let name = parse_name(&a.name)?;
            let msg = match a.kind.as_str() {
                "offer" => madar_names::sale_message(
                    &name,
                    a.nonce,
                    a.price_cents,
                    a.pay_to.as_bytes(),
                    a.offer_until,
                ),
                "buy" => madar_names::buy_message(&name, a.nonce, a.price_cents),
                "cancel" => madar_names::cancel_message(&name, a.nonce),
                _ => return Err("--kind: offer, buy or cancel".into()),
            };
            let text =
                String::from_utf8(msg.clone()).map_err(|_| "message is not text".to_string())?;
            match a.proof {
                None => println!("{}", json!({ "message": text })),
                Some(raw) => {
                    let proof = parse_proof(
                        &serde_json::from_str(&raw).map_err(|e| format!("proof: {e}"))?,
                    )?;
                    match madar_names::verify_proof(&proof, &msg) {
                        Some(w) => println!(
                            "{}",
                            json!({ "message": text, "ok": true, "wallet": wallet_json(&w) })
                        ),
                        None => println!("{}", json!({ "message": text, "ok": false })),
                    }
                }
            }
            Ok(())
        }
        NamesCmd::LockSale(a) => {
            let proof = |raw: &str| {
                parse_proof(&serde_json::from_str(raw).map_err(|e| format!("proof: {e}"))?)
            };
            let call = RuntimeCall::Names(madar_names::Call::lock_sale {
                name: parse_name(&a.name)?,
                seller_proof: proof(&a.seller_proof)?,
                price_cents: a.price_cents,
                pay_to: a
                    .pay_to
                    .as_bytes()
                    .to_vec()
                    .try_into()
                    .map_err(|_| "pay-to is too long".to_string())?,
                offer_until: a.offer_until,
                buyer_proof: proof(&a.buyer_proof)?,
                lock_until: a.lock_until,
            });
            submit(&a.auth, call)
        }
        NamesCmd::CompleteSale(a) => submit(
            &a.auth,
            RuntimeCall::Names(madar_names::Call::complete_sale {
                name: parse_name(&a.name)?,
            }),
        ),
        NamesCmd::CancelOffer(a) => {
            let raw = a.proof.as_deref().ok_or("--proof is required to cancel")?;
            let owner_proof =
                parse_proof(&serde_json::from_str(raw).map_err(|e| format!("proof: {e}"))?)?;
            submit(
                &a.auth,
                RuntimeCall::Names(madar_names::Call::cancel_offer {
                    name: parse_name(&a.name)?,
                    owner_proof,
                }),
            )
        }
        NamesCmd::CheckProof(a) => {
            let name = parse_name(&a.name)?;
            let proof =
                parse_proof(&serde_json::from_str(&a.proof).map_err(|e| format!("proof: {e}"))?)?;
            match madar_names::verify_proof(&proof, &madar_names::register_message(&name)) {
                Some(w) => println!("{}", json!({ "ok": true, "owner": wallet_json(&w) })),
                None => println!("{}", json!({ "ok": false })),
            }
            Ok(())
        }
    }
}

fn bytes<const N: usize>(v: &Value, what: &str) -> Result<[u8; N], String> {
    let s = v
        .as_str()
        .ok_or_else(|| format!("{what}: a hex string is required"))?;
    let raw =
        hex::decode(s.trim_start_matches("0x")).map_err(|_| format!("{what}: invalid hex"))?;
    raw.try_into()
        .map_err(|_| format!("{what}: length must be {N} bytes"))
}

pub fn parse_proof(v: &Value) -> Result<WalletProof, String> {
    if !v["evm"].is_null() {
        return Ok(WalletProof::Evm {
            address: bytes::<20>(&v["evm"]["address"], "evm.address")?,
            signature: bytes::<65>(&v["evm"]["signature"], "evm.signature")?,
        });
    }
    if !v["solana"].is_null() {
        return Ok(WalletProof::Solana {
            public: bytes::<32>(&v["solana"]["public"], "solana.public")?,
            signature: bytes::<64>(&v["solana"]["signature"], "solana.signature")?,
        });
    }
    Err("proof: evm or solana".into())
}

pub fn parse_name(s: &str) -> Result<NameOf, String> {
    let s = s.trim().trim_end_matches(".madar");
    if !madar_names::valid_name(s.as_bytes()) {
        return Err("invalid name: a-z, 0-9 and -, 3 to 32 characters, not starting or ending with a hyphen".into());
    }
    NameOf::try_from(s.as_bytes().to_vec()).map_err(|_| "name is too long".to_string())
}

fn write(a: WriteArgs, register: bool) -> Result<(), String> {
    let name = parse_name(&a.name)?;
    let call = if register {
        let raw = a
            .proof
            .as_deref()
            .ok_or("--proof is required to register")?;
        let proof = parse_proof(&serde_json::from_str(raw).map_err(|e| format!("proof: {e}"))?)?;
        RuntimeCall::Names(madar_names::Call::register {
            name,
            proof,
            expires: a.expires,
        })
    } else {
        RuntimeCall::Names(madar_names::Call::renew {
            name,
            expires: a.expires,
        })
    };
    let pass = if a.passphrase_stdin {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        zeroize::Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_string())
    } else {
        account::read_passphrase(a.passphrase_file.as_deref(), false)?
    };
    let acct: Account = Account::load(&a.account_file, &pass)?;
    let t = HttpRpc::new(&a.rpc);
    let hash = tx::submit(&t, &acct, call)?;
    println!(
        "{}",
        json!({ "tx": hash, "registrar": acct.id().to_ss58check() })
    );
    Ok(())
}

fn submit(a: &AuthArgs, call: RuntimeCall) -> Result<(), String> {
    let pass = if a.passphrase_stdin {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        zeroize::Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_string())
    } else {
        account::read_passphrase(a.passphrase_file.as_deref(), false)?
    };
    let acct: Account = Account::load(&a.account_file, &pass)?;
    let t = HttpRpc::new(&a.rpc);
    let hash = tx::submit(&t, &acct, call)?;
    println!(
        "{}",
        json!({ "tx": hash, "registrar": acct.id().to_ss58check() })
    );
    Ok(())
}

pub fn wallet_json(w: &Wallet) -> Value {
    match w {
        Wallet::Evm(a) => json!({ "kind": "evm", "address": format!("0x{}", hex::encode(a)) }),
        Wallet::Solana(p) => json!({ "kind": "solana", "public": hex::encode(p) }),
    }
}

fn lookup(a: LookupArgs) -> Result<(), String> {
    let name = parse_name(&a.name)?;
    let t = HttpRpc::new(&a.rpc);
    let key = madar_names::Names::<madar_consensus::Runtime>::hashed_key_for(&name);
    let v = t.call(
        "state_getStorage",
        json!([format!("0x{}", hex::encode(key))]),
    )?;
    let reserved_key = madar_names::Reserved::<madar_consensus::Runtime>::hashed_key_for(&name);
    let reserved = !t
        .call(
            "state_getStorage",
            json!([format!("0x{}", hex::encode(reserved_key))]),
        )?
        .is_null();
    let nonce_key = madar_names::SaleNonce::<madar_consensus::Runtime>::hashed_key_for(&name);
    let nonce = match t
        .call(
            "state_getStorage",
            json!([format!("0x{}", hex::encode(nonce_key))]),
        )?
        .as_str()
    {
        Some(h) => u32::decode(
            &mut &hex::decode(h.trim_start_matches("0x")).map_err(|_| "invalid storage")?[..],
        )
        .unwrap_or(0),
        None => 0,
    };
    let lock_key = madar_names::Locks::<madar_consensus::Runtime>::hashed_key_for(&name);
    let lock = match t
        .call(
            "state_getStorage",
            json!([format!("0x{}", hex::encode(lock_key))]),
        )?
        .as_str()
    {
        Some(h) => {
            let raw = hex::decode(h.trim_start_matches("0x")).map_err(|_| "invalid storage")?;
            let l = madar_names::SaleLock::decode(&mut &raw[..])
                .map_err(|_| "could not decode the sale lock".to_string())?;
            json!({ "buyer": wallet_json(&l.buyer), "until": l.until, "price_cents": l.price_cents, "pay_to": String::from_utf8_lossy(&l.pay_to) })
        }
        None => Value::Null,
    };
    let Some(s) = v.as_str() else {
        println!(
            "{}",
            json!({ "found": false, "reserved": reserved, "nonce": nonce })
        );
        return Ok(());
    };
    let raw = hex::decode(s.trim_start_matches("0x")).map_err(|_| "invalid storage")?;
    let r = NameRecord::<AccountId>::decode(&mut &raw[..])
        .map_err(|_| "could not decode the name record".to_string())?;
    println!(
        "{}",
        json!({ "found": true, "reserved": reserved, "owner": wallet_json(&r.owner), "registered": r.registered, "expires": r.expires, "registrar": r.registrar.to_ss58check(), "nonce": nonce, "lock": lock })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_a_real_solana_signature_offline() {
        use sp_core::{ed25519, Pair};
        let pair = ed25519::Pair::from_seed(&[4; 32]);
        let msg = madar_names::register_message(b"nova");
        let proof = json!({ "solana": { "public": hex::encode(pair.public().0), "signature": hex::encode(pair.sign(&msg).0) } });
        let p = parse_proof(&proof).unwrap();
        assert!(madar_names::verify_proof(&p, &madar_names::register_message(b"nova")).is_some());
        assert!(madar_names::verify_proof(&p, &madar_names::register_message(b"novas")).is_none());
    }

    #[test]
    fn sale_messages_match_the_runtime_and_verify_offline() {
        use sp_core::{ed25519, Pair};
        let pair = ed25519::Pair::from_seed(&[4; 32]);
        let msg = madar_names::buy_message(b"nova", 2, 1_999);
        let proof = json!({ "solana": { "public": hex::encode(pair.public().0), "signature": hex::encode(pair.sign(&msg).0) } });
        let p = parse_proof(&proof).unwrap();
        assert!(
            madar_names::verify_proof(&p, &madar_names::buy_message(b"nova", 2, 1_999)).is_some()
        );
        assert!(
            madar_names::verify_proof(&p, &madar_names::buy_message(b"nova", 3, 1_999)).is_none(),
            "another offer number"
        );
        assert!(
            madar_names::verify_proof(&p, &madar_names::buy_message(b"nova", 2, 999)).is_none(),
            "another price"
        );
    }

    #[test]
    fn parses_names_and_proofs() {
        assert_eq!(
            parse_name("ahmad.madar").unwrap().into_inner(),
            b"ahmad".to_vec()
        );
        assert!(
            parse_name("Ahmad").is_err()
                && parse_name("ab").is_err()
                && parse_name("-ab-").is_err()
        );
        let evm = json!({ "evm": { "address": format!("0x{}", "03".repeat(20)), "signature": "04".repeat(65) } });
        assert!(matches!(parse_proof(&evm), Ok(WalletProof::Evm { .. })));
        let sol = json!({ "solana": { "public": "06".repeat(32), "signature": "07".repeat(64) } });
        assert!(matches!(parse_proof(&sol), Ok(WalletProof::Solana { .. })));
        assert!(parse_proof(&json!({ "evm": { "address": "0x01", "signature": "02" } })).is_err());
    }

    /// Storage keys follow the pallet's name in the runtime: twox128("Names") ++ twox128("Names") ++ blake2_128concat(name).
    #[test]
    fn storage_key_layout() {
        let name = parse_name("ahmad").unwrap();
        let k = madar_names::Names::<madar_consensus::Runtime>::hashed_key_for(&name);
        let mut want =
            <frame_support::Twox128 as frame_support::StorageHasher>::hash(b"Names").to_vec();
        want.extend(<frame_support::Twox128 as frame_support::StorageHasher>::hash(b"Names"));
        assert_eq!(&k[..32], &want[..]);
    }
}
