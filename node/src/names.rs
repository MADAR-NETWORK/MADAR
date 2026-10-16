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
    /// A v2 signature (containing `valid_until`, or with `--valid-until`) sends `cancel_offer_v2` (spec 9).
    CancelOffer(NameWriteArgs),
    /// (spec 9) Transfers the name with two signatures: the owner (the transfer message to the new wallet) and the new wallet (the acceptance message).
    Transfer(TransferArgs),
}

#[derive(Debug, Clone, clap::Args)]
pub struct TransferArgs {
    #[command(flatten)]
    pub auth: AuthArgs,
    #[arg(long)]
    pub name: String,
    /// The owner's signature on the transfer message (`sale-message --kind transfer`).
    #[arg(long)]
    pub owner_proof: String,
    /// The new wallet's signature on the acceptance message (`sale-message --kind accept`).
    #[arg(long)]
    pub new_owner_proof: String,
    /// The deadline of both signatures (UTC milliseconds). Without it, it is taken from `valid_until` inside the two signatures.
    #[arg(long)]
    pub valid_until: Option<u64>,
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
    /// offer | buy | cancel | register; and with `--v2` also transfer | accept.
    #[arg(long)]
    pub kind: String,
    /// (spec 9) v2 message: bound to the network (`--genesis` or the hash of block 0 from `--rpc`) and to a deadline.
    #[arg(long)]
    pub v2: bool,
    /// The hash of block 0 (0x + 64 hex). Without it, it is read from `--rpc`.
    #[arg(long)]
    pub genesis: Option<String>,
    #[arg(long, default_value = "127.0.0.1:9944")]
    pub rpc: String,
    /// (v2) Signature deadline: acceptance (buy), cancellation, transfer, transfer acceptance and registration. The offer uses `--offer-until`.
    #[arg(long, default_value_t = 0)]
    pub valid_until: u64,
    /// (v2, transfer) The new wallet: 0x + 40 hex or a Solana key in base58.
    #[arg(long, default_value = "")]
    pub to: String,
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
    /// (spec 8) Payment network: solana_usdc | solana_usdt | base_usdc | arbitrum_usdc | arbitrum_usdt, and since spec 9 also
    /// ethereum_usdc | ethereum_usdt | optimism_usdc | optimism_usdt | polygon_usdc | polygon_usdt | bsc_usdc | bsc_usdt
    /// (or 0..12). Given with `--pay-amount`.
    #[arg(long)]
    pub rail: Option<String>,
    /// (spec 9) The buyer's acceptance deadline (v2). With it, or with `valid_until` inside the buyer's signature, `lock_sale_v3` is sent.
    #[arg(long)]
    pub accept_until: Option<u64>,
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
    /// (spec 9) v2 signature deadline. Without it, it is taken from `valid_until` inside the signature if present.
    #[arg(long)]
    pub valid_until: Option<u64>,
}

#[derive(Debug, Clone, clap::Args)]
pub struct CheckProofArgs {
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    pub proof: String,
    /// (v2) The hash of block 0; without it, it is read from `--rpc` (only for a v2 signature, i.e. one containing `valid_until`).
    #[arg(long)]
    pub genesis: Option<String>,
    #[arg(long, default_value = "127.0.0.1:9944")]
    pub rpc: String,
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
    /// For registration only: {"evm":{"address":"0x…","signature":"0x…"}} or {"solana":{"public":"hex","signature":"hex"}},
    /// and with "valid_until": <ms> inside it (or `--valid-until`) it is a v2 signature and `register_v2` is sent (spec 9).
    #[arg(long)]
    pub proof: Option<String>,
    /// (spec 9) The deadline of the v2 registration signature.
    #[arg(long)]
    pub valid_until: Option<u64>,
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
            let msg = sale_message_text(&a)?;
            let text = String::from_utf8(msg.clone())
                .map_err(|_| "The message is not text".to_string())?;
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
            submit(&a.auth, cancel_call(&a.name, raw, a.valid_until)?)
        }
        NamesCmd::Transfer(a) => submit(&a.auth, transfer_call(&a)?),
        NamesCmd::CheckProof(a) => {
            let name = parse_name(&a.name)?;
            let v: Value = serde_json::from_str(&a.proof).map_err(|e| format!("proof: {e}"))?;
            let proof = parse_proof(&v)?;
            let Some(until) = proof_until(&v)? else {
                match madar_names::verify_proof(&proof, &madar_names::register_message(&name)) {
                    Some(w) => println!("{}", json!({ "ok": true, "owner": wallet_json(&w) })),
                    None => println!("{}", json!({ "ok": false })),
                }
                return Ok(());
            };
            // v2: bound to this network and to its window (the chain checks both again)
            let net = network(&a.rpc, a.genesis.as_deref())?;
            let now = now_ms();
            if until < now || until > now.saturating_add(madar_names::MAX_REGISTER_PROOF_MS) {
                println!(
                    "{}",
                    json!({ "ok": false, "reason": "expired", "valid_until": until })
                );
                return Ok(());
            }
            match madar_names::verify_proof(
                &proof,
                &madar_names::register_message_v2(&name, &net, until),
            ) {
                Some(w) => println!(
                    "{}",
                    json!({ "ok": true, "owner": wallet_json(&w), "v": 2, "valid_until": until })
                ),
                None => println!("{}", json!({ "ok": false })),
            }
            Ok(())
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// (spec 9) `valid_until` inside a v2 signature (`{"evm":…,"valid_until":<ms>}`); None = a v1 signature.
pub fn proof_until(v: &Value) -> Result<Option<u64>, String> {
    match &v["valid_until"] {
        Value::Null => Ok(None),
        x => x
            .as_u64()
            .map(Some)
            .ok_or_else(|| "proof.valid_until: a number (UTC milliseconds)".to_string()),
    }
}

/// The network identity in v2 messages: `--genesis` if given, otherwise the hash of block 0 from the node.
pub fn network(rpc: &str, genesis: Option<&str>) -> Result<Vec<u8>, String> {
    let s = match genesis {
        Some(g) => g.to_string(),
        None => HttpRpc::new(rpc)
            .call("chain_getBlockHash", json!([0]))?
            .as_str()
            .ok_or("No hash for block 0")?
            .to_string(),
    };
    let raw = hex::decode(s.trim().trim_start_matches("0x"))
        .map_err(|_| "--genesis: invalid hex".to_string())?;
    if raw.len() != 32 {
        return Err("--genesis: 32 bytes".into());
    }
    Ok(raw)
}

/// A wallet as its owner writes it: `0x` + 40 hex (EVM) or a Solana key in base58 (32 bytes).
pub fn parse_wallet_text(s: &str) -> Result<Wallet, String> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x") {
        let raw = hex::decode(h).map_err(|_| "--to: invalid hex".to_string())?;
        return raw
            .try_into()
            .map(Wallet::Evm)
            .map_err(|_| "--to: an EVM address of 20 bytes".to_string());
    }
    let raw = madar_names::base58_decode(s.as_bytes()).ok_or("--to: invalid base58")?;
    raw.try_into()
        .map(Wallet::Solana)
        .map_err(|_| "--to: a Solana key of 32 bytes".to_string())
}

/// The text of the message the wallet signs, v1 or v2 (`--v2`), exactly as the Runtime builds it.
pub fn sale_message_text(a: &SaleMessageArgs) -> Result<Vec<u8>, String> {
    let name = parse_name(&a.name)?;
    if !a.v2 {
        return Ok(match a.kind.as_str() {
            "offer" => madar_names::sale_message(
                &name,
                a.nonce,
                a.price_cents,
                a.pay_to.as_bytes(),
                a.offer_until,
            ),
            "buy" => madar_names::buy_message(&name, a.nonce, a.price_cents),
            "cancel" => madar_names::cancel_message(&name, a.nonce),
            "register" => madar_names::register_message(&name),
            _ => {
                return Err(
                    "--kind: offer or buy or cancel or register (and with --v2 also transfer or accept)"
                        .into(),
                )
            }
        });
    }
    let net = network(&a.rpc, a.genesis.as_deref())?;
    let until = a.valid_until;
    Ok(match a.kind.as_str() {
        "offer" => madar_names::sale_message_v2(
            &name,
            a.nonce,
            a.price_cents,
            a.pay_to.as_bytes(),
            a.offer_until,
            &net,
        ),
        "buy" => madar_names::buy_message_v2(
            &name,
            a.nonce,
            a.price_cents,
            a.pay_to.as_bytes(),
            until,
            &net,
        ),
        "cancel" => madar_names::cancel_message_v2(&name, a.nonce, &net, until),
        "register" => madar_names::register_message_v2(&name, &net, until),
        "transfer" => {
            madar_names::transfer_message(&name, a.nonce, &parse_wallet_text(&a.to)?, &net, until)
        }
        "accept" => madar_names::accept_message(&name, a.nonce, &net, until),
        _ => return Err("--kind: offer or buy or cancel or register or transfer or accept".into()),
    })
}

/// Offer cancellation: a v2 signature (a deadline in the signature or `--valid-until`) sends `cancel_offer_v2`, otherwise `cancel_offer`.
pub fn cancel_call(
    name: &str,
    raw_proof: &str,
    valid_until: Option<u64>,
) -> Result<RuntimeCall, String> {
    let v: Value = serde_json::from_str(raw_proof).map_err(|e| format!("proof: {e}"))?;
    let owner_proof = parse_proof(&v)?;
    let name = parse_name(name)?;
    Ok(RuntimeCall::Names(match valid_until.or(proof_until(&v)?) {
        Some(valid_until) => madar_names::Call::cancel_offer_v2 {
            name,
            owner_proof,
            valid_until,
        },
        None => madar_names::Call::cancel_offer { name, owner_proof },
    }))
}

/// Transfer: two v2 signatures with the same deadline.
pub fn transfer_call(a: &TransferArgs) -> Result<RuntimeCall, String> {
    let o: Value = serde_json::from_str(&a.owner_proof).map_err(|e| format!("owner-proof: {e}"))?;
    let n: Value =
        serde_json::from_str(&a.new_owner_proof).map_err(|e| format!("new-owner-proof: {e}"))?;
    let valid_until = match (a.valid_until, proof_until(&o)?, proof_until(&n)?) {
        (Some(u), _, _) => u,
        (None, Some(x), Some(y)) if x == y => x,
        (None, Some(_), Some(_)) => {
            return Err("The two signatures have different deadlines".into())
        }
        _ => {
            return Err(
                "--valid-until is required (or valid_until inside the two signatures)".into(),
            )
        }
    };
    Ok(RuntimeCall::Names(madar_names::Call::transfer {
        name: parse_name(&a.name)?,
        owner_proof: parse_proof(&o)?,
        new_owner_proof: parse_proof(&n)?,
        valid_until,
    }))
}

/// The payment networks in the same order as `Rail::all()` in the off-chain service (their number on chain is their position here; only appended at the end).
pub const RAIL_NAMES: [&str; 13] = [
    "solana_usdc",
    "solana_usdt",
    "base_usdc",
    "arbitrum_usdc",
    "arbitrum_usdt",
    "ethereum_usdc",
    "ethereum_usdt",
    "optimism_usdc",
    "optimism_usdt",
    "polygon_usdc",
    "polygon_usdt",
    "bsc_usdc",
    "bsc_usdt",
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
    let rail = match chain {
        "solana" => 0u8,
        "base" => 2,
        "arbitrum" => 3,
        "ethereum" => 5,
        "optimism" => 7,
        "polygon" => 9,
        "bsc" => 11,
        _ => return Err("--payment-ref: the chain is solana or base or arbitrum or ethereum or optimism or polygon or bsc".into()),
    };
    let norm = if rail == 0 {
        s.to_string()
    } else {
        format!("{chain}:{}", rest.to_ascii_lowercase())
    };
    if !madar_names::valid_payment_ref(rail, norm.as_bytes()) {
        return Err("--payment-ref: the transaction hash is not valid for this chain".into());
    }
    norm.into_bytes()
        .try_into()
        .map_err(|_| "--payment-ref is too long".to_string())
}

pub fn lock_sale_call(a: &LockSaleArgs) -> Result<RuntimeCall, String> {
    let json = |raw: &str| serde_json::from_str::<Value>(raw).map_err(|e| format!("proof: {e}"));
    let (sv, bv) = (json(&a.seller_proof)?, json(&a.buyer_proof)?);
    let name = parse_name(&a.name)?;
    let seller_proof = parse_proof(&sv)?;
    let buyer_proof = parse_proof(&bv)?;
    // spec 9: a v2 acceptance (its window in the proof or --accept-until) goes to lock_sale_v3
    let accept_until = a.accept_until.or(proof_until(&bv)?);
    let pay_to: sp_runtime::BoundedVec<u8, sp_core::ConstU32<{ madar_names::MAX_PAY_TO }>> = a
        .pay_to
        .as_bytes()
        .to_vec()
        .try_into()
        .map_err(|_| "pay-to is too long".to_string())?;
    let (price_cents, offer_until, lock_until) = (a.price_cents, a.offer_until, a.lock_until);
    Ok(RuntimeCall::Names(
        match (a.pay_amount, a.rail.as_deref()) {
            (None, None) => return Err(
                "--pay-amount and --rail are required: the old sale without an amount and a network was removed from the network (spec 9)"
                    .into(),
            ),
            (Some(pay_amount), Some(rail)) => {
                let rail = parse_rail(rail)?;
                if !madar_names::amount_fits_price(pay_amount, price_cents) {
                    return Err(
                        "--pay-amount: between the price and less than the price + 0.10 (micro units, 6 decimals)"
                            .into(),
                    );
                }
                if !madar_names::rail_fits_pay_to(rail, &pay_to) {
                    return Err("--rail does not fit the --pay-to address (EVM or Solana)".into());
                }
                match accept_until {
                    Some(accept_until) => {
                        if !madar_names::valid_pay_to(rail, &pay_to) {
                            return Err("--pay-to: not a valid address for this network".into());
                        }
                        if accept_until > lock_until {
                            return Err("--accept-until is after --lock-until: the acceptance ends before or at the end of the lock".into());
                        }
                        madar_names::Call::lock_sale_v3 {
                            name,
                            seller_proof,
                            price_cents,
                            pay_to,
                            offer_until,
                            buyer_proof,
                            accept_until,
                            lock_until,
                            pay_amount,
                            rail,
                        }
                    }
                    None if rail >= 5 => {
                        return Err("--rail: the new networks (spec 9) only with v2 signatures".into())
                    }
                    None => madar_names::Call::lock_sale_v2 {
                        name,
                        seller_proof,
                        price_cents,
                        pay_to,
                        offer_until,
                        buyer_proof,
                        lock_until,
                        pay_amount,
                        rail,
                    },
                }
            }
            _ => return Err("--pay-amount and --rail are given together".into()),
        },
    ))
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
            .ok_or("--proof is required for registration")?;
        let v: Value = serde_json::from_str(raw).map_err(|e| format!("proof: {e}"))?;
        let proof = parse_proof(&v)?;
        match a.valid_until.or(proof_until(&v)?) {
            Some(valid_until) => RuntimeCall::Names(madar_names::Call::register_v2 {
                name,
                proof,
                expires: a.expires,
                valid_until,
            }),
            None => RuntimeCall::Names(madar_names::Call::register {
                name,
                proof,
                expires: a.expires,
            }),
        }
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
            "tron:0xabc",
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
            (0..13).collect::<Vec<u8>>()
        );
        assert_eq!(parse_rail("ethereum_usdc"), Ok(5));
        assert!(parse_rail("13").is_err() && parse_rail("tron_usdt").is_err());
        // spec 9 chains: lower-cased EVM hashes, each mapped to its own chain
        for chain in ["ethereum", "optimism", "polygon", "bsc"] {
            assert_eq!(
                parse_payment_ref(&format!("{chain}:{EVM_TX}"))
                    .unwrap()
                    .into_inner(),
                format!("{chain}:{}", EVM_TX.to_ascii_lowercase()).into_bytes()
            );
        }
    }

    // ---------------------------------------------------------------- spec 9: v2 messages

    const GEN: &str = "0x4242424242424242424242424242424242424242424242424242424242424242";

    fn msg_args(extra: &[&str]) -> SaleMessageArgs {
        let mut a = vec![
            "sale-message",
            "--name",
            "ahmad",
            "--nonce",
            "3",
            "--v2",
            "--genesis",
            GEN,
        ];
        a.extend_from_slice(extra);
        match cli(&a) {
            NamesCmd::SaleMessage(m) => m,
            _ => unreachable!(),
        }
    }

    #[test]
    fn v2_messages_match_the_runtime_byte_for_byte() {
        let net = [0x42u8; 32];
        let pay = "0x00000000000000000000000000000000000000aa";
        let m = |x: &[&str]| sale_message_text(&msg_args(x)).unwrap();
        assert_eq!(
            m(&[
                "--kind",
                "offer",
                "--price-cents",
                "2500",
                "--pay-to",
                pay,
                "--offer-until",
                "9"
            ]),
            madar_names::sale_message_v2(b"ahmad", 3, 2500, pay.as_bytes(), 9, &net)
        );
        assert_eq!(
            m(&[
                "--kind",
                "buy",
                "--price-cents",
                "2500",
                "--pay-to",
                pay,
                "--valid-until",
                "7"
            ]),
            madar_names::buy_message_v2(b"ahmad", 3, 2500, pay.as_bytes(), 7, &net)
        );
        assert_eq!(
            m(&["--kind", "cancel", "--valid-until", "7"]),
            madar_names::cancel_message_v2(b"ahmad", 3, &net, 7)
        );
        assert_eq!(
            m(&["--kind", "register", "--valid-until", "7"]),
            madar_names::register_message_v2(b"ahmad", &net, 7)
        );
        assert_eq!(
            m(&["--kind", "accept", "--valid-until", "7"]),
            madar_names::accept_message(b"ahmad", 3, &net, 7)
        );
        let sol = "BxMsjB6DM2cZV2vhzPQBETJnBh257ewnvkT61CoZpEMt";
        let w = parse_wallet_text(sol).unwrap();
        assert_eq!(
            m(&["--kind", "transfer", "--to", sol, "--valid-until", "7"]),
            madar_names::transfer_message(b"ahmad", 3, &w, &net, 7)
        );
        assert!(matches!(
            parse_wallet_text("0xB95c91Bb8C58b929d501BD8D0aCcB420F8A7045d"),
            Ok(Wallet::Evm(_))
        ));
        assert!(
            parse_wallet_text("0x1234").is_err()
                && parse_wallet_text("not-base58-0OIl").is_err()
                && parse_wallet_text("1111").is_err()
        );
        assert!(sale_message_text(&msg_args(&[
            "--kind",
            "transfer",
            "--to",
            "",
            "--valid-until",
            "7"
        ]))
        .is_err());
        // without --v2 the old texts, and transfer/accept do not exist there
        let mut a = msg_args(&["--kind", "cancel"]);
        a.v2 = false;
        assert_eq!(
            sale_message_text(&a).unwrap(),
            madar_names::cancel_message(b"ahmad", 3)
        );
        a.kind = "accept".into();
        assert!(sale_message_text(&a).is_err());
        assert!(network("127.0.0.1:1", Some("0x12")).is_err());
    }

    #[test]
    fn v2_proofs_choose_the_v2_calls() {
        use sp_core::{ed25519, Pair};
        let pair = ed25519::Pair::from_seed(&[4; 32]);
        let sig = |m: &[u8]| hex::encode(pair.sign(m).0);
        let net = [0x42u8; 32];
        let until = now_ms() + 3_600_000;
        // register: valid_until inside the proof -> register_v2; check-proof verifies the v2 text offline with --genesis
        let p2 = json!({ "solana": { "public": hex::encode(pair.public().0), "signature": sig(&madar_names::register_message_v2(b"sara", &net, until)) }, "valid_until": until });
        assert_eq!(proof_until(&p2), Ok(Some(until)));
        assert!(proof_until(&json!({ "valid_until": "x" })).is_err());
        let p = parse_proof(&p2).unwrap();
        assert!(madar_names::verify_proof(
            &p,
            &madar_names::register_message_v2(b"sara", &net, until)
        )
        .is_some());
        // cancel
        let raw = p2.to_string();
        assert!(
            matches!(cancel_call("sara", &raw, None).unwrap(), RuntimeCall::Names(madar_names::Call::cancel_offer_v2 { valid_until, .. }) if valid_until == until)
        );
        let v1 = json!({ "solana": { "public": hex::encode(pair.public().0), "signature": "07".repeat(64) } }).to_string();
        assert!(matches!(
            cancel_call("sara", &v1, None).unwrap(),
            RuntimeCall::Names(madar_names::Call::cancel_offer { .. })
        ));
        assert!(matches!(
            cancel_call("sara", &v1, Some(5)).unwrap(),
            RuntimeCall::Names(madar_names::Call::cancel_offer_v2 { valid_until: 5, .. })
        ));
        // transfer: one window for both signatures
        let NamesCmd::Transfer(t) = cli(&[
            "transfer",
            "--account-file",
            "r.enc",
            "--name",
            "sara",
            "--owner-proof",
            &raw,
            "--new-owner-proof",
            &raw,
        ]) else {
            unreachable!()
        };
        assert!(
            matches!(transfer_call(&t).unwrap(), RuntimeCall::Names(madar_names::Call::transfer { valid_until, .. }) if valid_until == until)
        );
        let other = json!({ "solana": { "public": "06".repeat(32), "signature": "07".repeat(64) }, "valid_until": until + 1 }).to_string();
        let NamesCmd::Transfer(t) = cli(&[
            "transfer",
            "--account-file",
            "r.enc",
            "--name",
            "sara",
            "--owner-proof",
            &raw,
            "--new-owner-proof",
            &other,
        ]) else {
            unreachable!()
        };
        assert!(transfer_call(&t).is_err(), "two different windows");
        let NamesCmd::Transfer(t) = cli(&[
            "transfer",
            "--account-file",
            "r.enc",
            "--name",
            "sara",
            "--owner-proof",
            &v1,
            "--new-owner-proof",
            &v1,
        ]) else {
            unreachable!()
        };
        assert!(transfer_call(&t).is_err(), "transfer needs a window");
    }

    #[test]
    fn lock_sale_v3_with_an_acceptance_window() {
        // the window inside the buyer's proof, or --accept-until
        let mut a = lock_args(&[
            "--pay-amount",
            "25004200",
            "--rail",
            "optimism_usdc",
            "--accept-until",
            "10",
        ]);
        match lock_sale_call(&a).unwrap() {
            RuntimeCall::Names(madar_names::Call::lock_sale_v3 {
                accept_until,
                lock_until,
                rail,
                ..
            }) => assert_eq!((accept_until, lock_until, rail), (10, 10, 7)),
            other => panic!("{other:?}"),
        }
        a.accept_until = Some(11);
        assert!(lock_sale_call(&a).is_err(), "acceptance after the lock end");
        let a = lock_args(&["--pay-amount", "25004200", "--rail", "optimism_usdc"]);
        assert!(
            lock_sale_call(&a).is_err(),
            "new rails only with v2 signatures"
        );
        let mut a = lock_args(&[
            "--pay-amount",
            "25004200",
            "--rail",
            "base_usdc",
            "--accept-until",
            "10",
        ]);
        a.pay_to = "0xshort".into();
        assert!(lock_sale_call(&a).is_err(), "v3 needs a real payee address");
        let mut a = lock_args(&["--pay-amount", "25004200", "--rail", "bsc_usdt"]);
        a.buyer_proof = json!({ "evm": { "address": format!("0x{}", "03".repeat(20)), "signature": "04".repeat(65) }, "valid_until": 9 }).to_string();
        assert!(matches!(
            lock_sale_call(&a).unwrap(),
            RuntimeCall::Names(madar_names::Call::lock_sale_v3 {
                accept_until: 9,
                rail: 12,
                ..
            })
        ));
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
