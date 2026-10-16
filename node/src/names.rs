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
    /// With `--pay-amount` and `--rail` (spec 8) it records the exact amount and the payment network on chain (`lock_sale_v2`).
    LockSale(LockSaleArgs),
    /// Safe sale: moves the name to the buyer it is locked for, after the payment arrives.
    /// With `--payment-ref <chain>:<tx hash>` (spec 8) it records the payment reference on chain (`complete_sale_v2`).
    CompleteSale(CompleteSaleArgs),
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
    /// (spec 8) The exact amount the buyer pays the seller, in micro units (6 decimals). Given with `--rail`.
    #[arg(long)]
    pub pay_amount: Option<u64>,
    /// (spec 8) Payment network: solana_usdc | solana_usdt | base_usdc | arbitrum_usdc | arbitrum_usdt (or 0..4). Given with `--pay-amount`.
    #[arg(long)]
    pub rail: Option<String>,
}

#[derive(Debug, Clone, clap::Args)]
pub struct CompleteSaleArgs {
    #[command(flatten)]
    pub auth: AuthArgs,
    #[arg(long)]
    pub name: String,
    /// Payment reference (required since spec 9): `base:0x<hash>`, `arbitrum:0x<hash>` or `solana:<signature>`.
    #[arg(long)]
    pub payment_ref: Option<String>,
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
            let call = lock_sale_call(&a)?;
            submit(&a.auth, call)
        }
        NamesCmd::CompleteSale(a) => {
            let call = complete_sale_call(&a.name, a.payment_ref.as_deref())?;
            submit(&a.auth, call)
        }
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

/// Payment networks in the registrar service's rail order (their on-chain number is their position here).
pub const RAIL_NAMES: [&str; 5] = [
    "solana_usdc",
    "solana_usdt",
    "base_usdc",
    "arbitrum_usdc",
    "arbitrum_usdt",
];

pub fn parse_rail(s: &str) -> Result<u8, String> {
    let s = s.trim();
    if let Some(i) = RAIL_NAMES.iter().position(|r| *r == s) {
        return Ok(i as u8);
    }
    match s.parse::<u8>() {
        Ok(n) if n < madar_names::RAILS => Ok(n),
        _ => Err(format!("--rail: one of {}", RAIL_NAMES.join(" | "))),
    }
}

/// `<chain>:<tx hash>` in the chain's format: the EVM hash in lowercase, and the reference is checked before sending.
pub fn parse_payment_ref(s: &str) -> Result<madar_names::PaymentRef, String> {
    let s = s.trim();
    let (chain, rest) = s
        .split_once(':')
        .ok_or("--payment-ref: <chain>:<tx hash>")?;
    let (norm, rail) = match chain {
        "solana" => (s.to_string(), 0u8),
        "base" => (format!("base:{}", rest.to_ascii_lowercase()), 2),
        "arbitrum" => (format!("arbitrum:{}", rest.to_ascii_lowercase()), 3),
        _ => return Err("--payment-ref: the chain is solana, base or arbitrum".into()),
    };
    if !madar_names::valid_payment_ref(rail, norm.as_bytes()) {
        return Err("--payment-ref: the transaction hash is not valid for this chain".into());
    }
    norm.into_bytes()
        .try_into()
        .map_err(|_| "--payment-ref is too long".to_string())
}

pub fn lock_sale_call(a: &LockSaleArgs) -> Result<RuntimeCall, String> {
    let proof =
        |raw: &str| parse_proof(&serde_json::from_str(raw).map_err(|e| format!("proof: {e}"))?);
    let name = parse_name(&a.name)?;
    let seller_proof = proof(&a.seller_proof)?;
    let buyer_proof = proof(&a.buyer_proof)?;
    let pay_to: sp_runtime::BoundedVec<u8, sp_core::ConstU32<{ madar_names::MAX_PAY_TO }>> = a
        .pay_to
        .as_bytes()
        .to_vec()
        .try_into()
        .map_err(|_| "pay-to is too long".to_string())?;
    let (price_cents, offer_until, lock_until) = (a.price_cents, a.offer_until, a.lock_until);
    Ok(RuntimeCall::Names(match (a.pay_amount, a.rail.as_deref()) {
        (None, None) => return Err("--pay-amount and --rail are required: the old sale without an amount and a network was removed from the network (spec 9)".into()),
        (Some(pay_amount), Some(rail)) => {
            let rail = parse_rail(rail)?;
            if !madar_names::amount_fits_price(pay_amount, price_cents) {
                return Err("--pay-amount: from the price to below the price + 0.10 (micro units, 6 decimals)".into());
            }
            if !madar_names::rail_fits_pay_to(rail, &pay_to) {
                return Err("--rail does not fit the --pay-to address (EVM or Solana)".into());
            }
            madar_names::Call::lock_sale_v2 { name, seller_proof, price_cents, pay_to, offer_until, buyer_proof, lock_until, pay_amount, rail }
        },
        _ => return Err("--pay-amount and --rail are given together".into()),
    }))
}

pub fn complete_sale_call(name: &str, payment_ref: Option<&str>) -> Result<RuntimeCall, String> {
    let name = parse_name(name)?;
    let r = payment_ref.ok_or("--payment-ref is required: the old completion without a payment reference was removed from the network (spec 9)")?;
    Ok(RuntimeCall::Names(madar_names::Call::complete_sale_v2 {
        name,
        payment_ref: parse_payment_ref(r)?,
    }))
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
            // (spec 8) the v2 lock terms if present; on a spec 7 chain this storage does not exist so it stays null.
            let terms_key =
                madar_names::LockTerms::<madar_consensus::Runtime>::hashed_key_for(&name);
            let terms = match t
                .call(
                    "state_getStorage",
                    json!([format!("0x{}", hex::encode(terms_key))]),
                )?
                .as_str()
            {
                Some(h) => {
                    let raw =
                        hex::decode(h.trim_start_matches("0x")).map_err(|_| "invalid storage")?;
                    let s = madar_names::SaleTerms::decode(&mut &raw[..])
                        .map_err(|_| "could not decode the payment terms".to_string())?;
                    json!({ "rail": RAIL_NAMES.get(s.rail as usize).copied().unwrap_or("unknown"), "pay_amount": s.pay_amount })
                }
                None => Value::Null,
            };
            json!({ "buyer": wallet_json(&l.buyer), "until": l.until, "price_cents": l.price_cents, "pay_to": String::from_utf8_lossy(&l.pay_to), "terms": terms })
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

    #[derive(clap::Parser)]
    struct Cli {
        #[command(subcommand)]
        cmd: NamesCmd,
    }

    fn cli(args: &[&str]) -> NamesCmd {
        <Cli as clap::Parser>::try_parse_from([&["names"], args].concat())
            .expect("parses")
            .cmd
    }

    const EVM_TX: &str = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn lock_args(extra: &[&str]) -> LockSaleArgs {
        let evm = json!({ "evm": { "address": format!("0x{}", "03".repeat(20)), "signature": "04".repeat(65) } }).to_string();
        let mut a = vec![
            "lock-sale",
            "--account-file",
            "r.enc",
            "--name",
            "ahmad",
            "--seller-proof",
            &evm,
            "--price-cents",
            "2500",
            "--pay-to",
            "0x00000000000000000000000000000000000000aa",
            "--offer-until",
            "9",
            "--buyer-proof",
            &evm,
            "--lock-until",
            "10",
        ];
        a.extend_from_slice(extra);
        match cli(&a) {
            NamesCmd::LockSale(l) => l,
            _ => unreachable!(),
        }
    }

    #[test]
    fn lock_sale_uses_v2_only_with_amount_and_rail() {
        assert!(
            lock_sale_call(&lock_args(&[])).is_err(),
            "the v1 lock without amount and rail is gone (spec 9)"
        );
        match lock_sale_call(&lock_args(&[
            "--pay-amount",
            "25004200",
            "--rail",
            "base_usdc",
        ]))
        .unwrap()
        {
            RuntimeCall::Names(madar_names::Call::lock_sale_v2 {
                pay_amount,
                rail,
                price_cents,
                ..
            }) => assert_eq!((pay_amount, rail, price_cents), (25_004_200, 2, 2_500)),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            lock_sale_call(&lock_args(&["--pay-amount", "25004200", "--rail", "4"])).unwrap(),
            RuntimeCall::Names(madar_names::Call::lock_sale_v2 { rail: 4, .. })
        ));
        assert!(
            lock_sale_call(&lock_args(&["--pay-amount", "25004200"])).is_err(),
            "amount without rail"
        );
        assert!(
            lock_sale_call(&lock_args(&["--rail", "base_usdc"])).is_err(),
            "rail without amount"
        );
        assert!(
            lock_sale_call(&lock_args(&[
                "--pay-amount",
                "24000000",
                "--rail",
                "base_usdc"
            ]))
            .is_err(),
            "below the price"
        );
        assert!(
            lock_sale_call(&lock_args(&[
                "--pay-amount",
                "25004200",
                "--rail",
                "solana_usdc"
            ]))
            .is_err(),
            "Solana rail for an EVM payee"
        );
        assert!(lock_sale_call(&lock_args(&["--pay-amount", "25004200", "--rail", "5"])).is_err());
    }

    #[test]
    fn complete_sale_uses_v2_only_with_a_payment_ref() {
        let NamesCmd::CompleteSale(a) = cli(&[
            "complete-sale",
            "--account-file",
            "r.enc",
            "--name",
            "ahmad",
        ]) else {
            unreachable!()
        };
        assert!(
            complete_sale_call(&a.name, a.payment_ref.as_deref()).is_err(),
            "the v1 completion without a payment ref is gone (spec 9)"
        );
        let r = format!("base:{EVM_TX}");
        let NamesCmd::CompleteSale(a) = cli(&[
            "complete-sale",
            "--account-file",
            "r.enc",
            "--name",
            "ahmad",
            "--payment-ref",
            &r,
        ]) else {
            unreachable!()
        };
        match complete_sale_call(&a.name, a.payment_ref.as_deref()).unwrap() {
            RuntimeCall::Names(madar_names::Call::complete_sale_v2 { payment_ref, .. }) => {
                assert_eq!(
                    payment_ref.into_inner(),
                    format!("base:{}", EVM_TX.to_ascii_lowercase()).into_bytes(),
                    "EVM hash lower-cased"
                )
            }
            other => panic!("{other:?}"),
        }
        let sol = "solana:5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW";
        assert_eq!(
            parse_payment_ref(sol).unwrap().into_inner(),
            sol.as_bytes().to_vec(),
            "Solana signatures keep their case"
        );
        for bad in [
            "base:0x12",
            "ethereum:0xabc",
            "nohash",
            "solana:0OIl",
            &format!("arbitrum:{}", &EVM_TX[2..]),
        ] {
            assert!(parse_payment_ref(bad).is_err(), "{bad}");
        }
        assert_eq!(
            RAIL_NAMES
                .iter()
                .map(|r| parse_rail(r).unwrap())
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4]
        );
        assert!(parse_rail("ethereum_usdc").is_err());
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
