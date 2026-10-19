//! The text interface of the join tool: clap commands, messages, confirmations. All logic lives in the other modules; replacing this interface does not touch the protocol.

use super::account::{self, Account};
use super::chain::Reader;
use super::rpc::{HttpRpc, Transport};
use super::status::{self, JoinStatus};
use super::{backup, puzzle, sessionkeys, tx};
use madar_consensus::{madar_admission, pallet_session, AccountId, RuntimeCall, SessionKeys};
use parity_scale_codec::Decode;
use serde_json::json;
use sp_core::crypto::Ss58Codec;
use std::io::Write;
use std::path::PathBuf;

/// Maximum number of puzzle attempts before giving up (the actual difficulty is far lower; protection against an infinite loop).
const MAX_PUZZLE_ATTEMPTS: u64 = 500_000_000;
/// Re-solve attempts when the round seed changes during solving.
const SEED_RETRIES: usize = 5;

#[derive(Debug, Clone, clap::Subcommand)]
pub enum JoinCmd {
    /// Create a new operator account: a recovery phrase encrypted immediately into a file (never displayed) + a public file. An existing file is never overwritten.
    NewAccount(NewAccountArgs),
    /// Account status: candidacy/membership/renewal/removal, session keys, and the next step. Read-only, no passphrase.
    Status(StatusArgs),
    /// Join (or re-apply): solves the current round's puzzle and submits it. Requires a vouch from an approved operator first (spec 9, B2).
    Apply(TxArgs),
    /// Register session keys: generated inside the local node's Keystore (they never leave it) and registered on chain with a proof of ownership.
    /// With `--keys` (from `gen-keys`): no generation over RPC; the ownership proof is produced locally from the Keystore files, and the safe RPC is enough.
    RegisterKeys(RegisterKeysArgs),
    /// Generate the session keys (BABE + GRANDPA) directly in the node's Keystore **with the node stopped** (refused if it is running), and print only the public
    /// keys (for `register-keys --keys`). Needs no unsafe RPC.
    GenKeys(GenKeysArgs),
    /// An encrypted backup of the operator account with a password you choose (Argon2id), in a file you keep wherever you like.
    Export(ExportArgs),
    /// Restore the operator account from an encrypted backup (`export`) into a new account file with a new passphrase.
    Import(ImportArgs),
    /// Renew membership (extends validity; rejected if too early).
    Renew(TxArgs),
    /// Voluntary exit (takes effect at the next session rotation).
    Exit(TxArgs),
    /// Automatic renewal (for hourly scheduling): renews membership only when the renewal window opens, otherwise does nothing. No prompts.
    AutoRenew(AutoRenewArgs),
    /// (A committee-approved operator) attests a node as its own — a condition for its lottery win to become a vote (D47). An operator running the node itself attests its own account.
    Vouch(VouchArgs),
    /// Rotate session keys when moving to another machine: run on the **new machine** (new keys in its node's Keystore → registration → wait for activation → confirm the old one is no longer an authority).
    /// Safe to rerun after an interruption, and never deletes any key.
    RotateKeys(RotateArgs),
}

#[derive(Debug, Clone, clap::Args)]
pub struct AutoRenewArgs {
    #[arg(long, default_value = "127.0.0.1:9944")]
    pub rpc: String,
    /// The voting node's secret file (JSON containing secretPhrase) — for genesis nodes whose account is their voting key.
    #[arg(long, conflicts_with = "sealed_secret_file")]
    pub secret_file: Option<PathBuf>,
    /// or the same file sealed with Windows protection (DPAPI) via `madar-node secret seal` — unsealed in memory only (Windows).
    #[arg(long, conflicts_with = "account_file")]
    pub sealed_secret_file: Option<PathBuf>,
    /// Or an encrypted operator account (.enc) with --passphrase-file.
    #[arg(long)]
    pub account_file: Option<PathBuf>,
    #[arg(long)]
    pub passphrase_file: Option<PathBuf>,
    /// Renew only when this many sessions or fewer remain before expiry (24 ≈ two days). With the grace period after expiry (12)
    /// that leaves about 3 days during which the machine only needs to run once.
    #[arg(long, default_value_t = 24)]
    pub renew_within: u32,
    /// Reads the account passphrase from stdin (a single line) — for a scheduler that unwraps protected storage (Windows DPAPI) without writing it to disk.
    #[arg(long)]
    pub passphrase_stdin: bool,
    /// If the account is not a member yet (lost the lottery or was removed) and its keys are registered: automatically re-apply in the current round.
    #[arg(long)]
    pub reapply: bool,
}

#[derive(Debug, Clone, clap::Args)]
pub struct VouchArgs {
    #[command(flatten)]
    pub tx: TxArgs,
    /// The account of the node to attest (SS58 or 0x…). Without it: the operator's own account.
    #[arg(long)]
    pub node: Option<String>,
}

#[derive(Debug, Clone, clap::Args)]
pub struct RotateArgs {
    /// RPC of **the new machine's node** (Loopback, running with `--validator --rpc-methods unsafe`).
    #[arg(long, default_value = "127.0.0.1:9944")]
    pub rpc: String,
    #[arg(long)]
    pub account_file: PathBuf,
    #[arg(long)]
    pub passphrase_file: Option<PathBuf>,
    #[arg(long)]
    pub yes: bool,
    /// Do not wait for activation (returns after registration; rerun the command later to follow activation).
    #[arg(long)]
    pub no_wait: bool,
    /// Maximum wait for activation, in seconds.
    #[arg(long, default_value_t = 3600)]
    pub wait_timeout_secs: u64,
}

#[derive(Debug, Clone, clap::Args)]
pub struct NewAccountArgs {
    /// Path of the encrypted account file (`.enc`); a public `.pub` is written next to it.
    #[arg(long)]
    pub out: PathBuf,
    /// A file containing the passphrase (for automation). Without it, it is prompted for with no echo.
    #[arg(long)]
    pub passphrase_file: Option<PathBuf>,
}

#[derive(Debug, Clone, clap::Args)]
pub struct StatusArgs {
    /// The node's RPC address (plain HTTP: host:port).
    #[arg(long, default_value = "127.0.0.1:9944")]
    pub rpc: String,
    /// The account file (the public ID is read from the adjacent `.pub`).
    #[arg(long, conflicts_with = "address")]
    pub account_file: Option<PathBuf>,
    /// Or an SS58 address / Hex ID directly.
    #[arg(long)]
    pub address: Option<String>,
    /// JSON output (for a UI/script).
    #[arg(long)]
    pub json: bool,
    /// Optional: if the neighbouring `.pub` file is missing (a half-created account), the public ID is read by decrypting `.enc` with this passphrase (nothing is signed).
    #[arg(long)]
    pub passphrase_file: Option<PathBuf>,
}

#[derive(Debug, Clone, clap::Args)]
pub struct RegisterKeysArgs {
    #[command(flatten)]
    pub tx: TxArgs,
    /// The public keys from `join gen-keys` (SessionKeys encoding, hex). Without it: the older path (`author_rotateKeysWithOwner`).
    #[arg(long, requires_all = ["base_path", "chain"])]
    pub keys: Option<String>,
    /// The node's data folder (the `--base-path` it runs with), to read the Keystore files and produce the ownership proof.
    #[arg(long)]
    pub base_path: Option<PathBuf>,
    /// The chain spec file the node runs with (`--chain`).
    #[arg(long)]
    pub chain: Option<String>,
}

#[derive(Debug, Clone, clap::Args)]
pub struct GenKeysArgs {
    /// The node's data folder (the same `--base-path`). The node must be stopped.
    #[arg(long)]
    pub base_path: PathBuf,
    /// The chain spec file (the same `--chain`), or dev/local.
    #[arg(long)]
    pub chain: String,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, clap::Args)]
pub struct ExportArgs {
    #[arg(long)]
    pub account_file: PathBuf,
    #[arg(long)]
    pub passphrase_file: Option<PathBuf>,
    /// A file (or a one-time pipe) holding the backup password (at least 12 characters). Without it, it is asked for with no echo and confirmed.
    #[arg(long)]
    pub backup_pass_file: Option<PathBuf>,
    /// The new backup file (an existing file is never replaced).
    #[arg(long)]
    pub out: PathBuf,
}

#[derive(Debug, Clone, clap::Args)]
pub struct ImportArgs {
    /// The backup file (from `join export`).
    #[arg(long = "in")]
    pub input: PathBuf,
    #[arg(long)]
    pub backup_pass_file: Option<PathBuf>,
    /// The new account file (`.enc`; a `.pub` is written next to it). Never replaced.
    #[arg(long)]
    pub out: PathBuf,
    /// The passphrase for the new account file (at least 12 characters).
    #[arg(long)]
    pub passphrase_file: Option<PathBuf>,
}

#[derive(Debug, Clone, clap::Args)]
pub struct TxArgs {
    #[arg(long, default_value = "127.0.0.1:9944")]
    pub rpc: String,
    #[arg(long)]
    pub account_file: PathBuf,
    /// A file containing the passphrase (for automation). Without it, it is prompted for with no echo.
    #[arg(long)]
    pub passphrase_file: Option<PathBuf>,
    /// No confirmation prompt (for automation).
    #[arg(long)]
    pub yes: bool,
}

pub fn run(cmd: JoinCmd) -> Result<(), String> {
    match cmd {
        JoinCmd::NewAccount(a) => new_account(a),
        JoinCmd::Status(a) => show_status(a),
        JoinCmd::Apply(a) => apply(a),
        JoinCmd::RegisterKeys(a) => register_keys(a),
        JoinCmd::Renew(a) => renew(a),
        JoinCmd::Exit(a) => exit(a),
        JoinCmd::RotateKeys(a) => rotate_keys(a),
        JoinCmd::Vouch(a) => vouch(a),
        JoinCmd::AutoRenew(a) => auto_renew(a),
        JoinCmd::GenKeys(a) => gen_keys(a),
        JoinCmd::Export(a) => export(a),
        JoinCmd::Import(a) => import(a),
    }
}

fn gen_keys(a: GenKeysArgs) -> Result<(), String> {
    let g = sessionkeys::gen_keys(&a.base_path, &a.chain)?;
    if a.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&g.to_json()).map_err(|e| e.to_string())?
        );
    } else {
        println!("Session keys were generated in the node's Keystore (only the public keys are shown here):");
        println!(
            "  keys (for register-keys --keys): 0x{}",
            hex::encode(g.encoded())
        );
        println!("  babe: 0x{}", hex::encode(g.babe));
        println!("  grandpa: 0x{}", hex::encode(g.grandpa));
        println!("Next step: start the node with --validator (the safe RPC is enough), then:");
        println!("  madar-node join register-keys --account-file <account file> --keys 0x{} --base-path {} --chain {}", hex::encode(g.encoded()), a.base_path.display(), a.chain);
    }
    Ok(())
}

fn export(a: ExportArgs) -> Result<(), String> {
    if a.out.exists() {
        return Err(format!(
            "{} already exists — it will not be replaced.",
            a.out.display()
        ));
    }
    let pass = account::read_passphrase(a.passphrase_file.as_deref(), false)?;
    let backup_pass =
        account::read_secret_line(a.backup_pass_file.as_deref(), "Backup password: ", true)?;
    let (id, text) = backup::export(&a.account_file, &pass, &backup_pass)?;
    madar_keystore::create_new_secret_file(&a.out, text.as_bytes())
        .map_err(|e| format!("Could not write {}: {e}", a.out.display()))?;
    println!(
        "An encrypted backup of account {} was saved to {}",
        id.to_ss58check(),
        a.out.display()
    );
    println!("It can only be restored with its password; keep the file and the password in two separate places.");
    Ok(())
}

fn import(a: ImportArgs) -> Result<(), String> {
    let meta = std::fs::metadata(&a.input)
        .map_err(|e| format!("Could not read {}: {e}", a.input.display()))?;
    if meta.len() as usize > backup::MAX_BACKUP {
        return Err("The backup file is larger than expected — it is not a MADAR backup.".into());
    }
    let bytes = zeroize::Zeroizing::new(
        std::fs::read(&a.input)
            .map_err(|e| format!("Could not read {}: {e}", a.input.display()))?,
    );
    let backup_pass =
        account::read_secret_line(a.backup_pass_file.as_deref(), "Backup password: ", false)?;
    let pass = account::read_passphrase(a.passphrase_file.as_deref(), true)?;
    let id = backup::import(&bytes, &backup_pass, &a.out, &pass)?;
    println!(
        "Account {} was restored to {}",
        id.to_ss58check(),
        a.out.display()
    );
    println!("Register new session keys for this computer before voting from it (gen-keys, then register-keys --keys).");
    Ok(())
}

fn new_account(a: NewAccountArgs) -> Result<(), String> {
    let pass = account::read_passphrase(a.passphrase_file.as_deref(), true)?;
    let id = Account::create(&a.out, &pass)?;
    println!("Account created.");
    println!("  Address (SS58): {}", id.to_ss58check());
    println!(
        "  Encrypted file (private — back it up somewhere safe and never commit it to Git): {}",
        a.out.display()
    );
    println!("  Public file: {}", account::pub_path(&a.out).display());
    println!("The secret phrase is never displayed; the backup is the encrypted file + the passphrase (store them separately).");
    println!(
        "Next step: start the node, then `madar-node join apply --account-file {}`.",
        a.out.display()
    );
    Ok(())
}

fn who_from(
    account_file: &Option<PathBuf>,
    address: &Option<String>,
    passphrase_file: &Option<PathBuf>,
) -> Result<AccountId, String> {
    match (account_file, address) {
        // A half-created account (`.pub` missing): the ID comes from decrypting `.enc` if the passphrase is given (read only, no signing).
        (Some(f), _) if !account::pub_path(f).exists() && passphrase_file.is_some() => {
            let pass = account::read_passphrase(passphrase_file.as_deref(), false)?;
            Ok(Account::load(f, &pass)?.id())
        }
        (Some(f), _) => account::read_public(f),
        (None, Some(_)) if passphrase_file.is_some() => {
            Err("--passphrase-file is only used with --account-file".into())
        }
        (None, Some(a)) => account::parse_address(a),
        (None, None) => Err("Specify --account-file or --address".into()),
    }
}

fn snapshot(t: &dyn Transport, who: &AccountId) -> Result<JoinStatus, String> {
    let (view, params) = Reader::at_best(t)?.view(who)?;
    Ok(status::interpret(&view, params))
}

fn print_status(who: &AccountId, s: &JoinStatus) {
    println!("Account: {}", who.to_ss58check());
    println!("Status: {}", s.summary);
    println!("Current session: {}", s.current_session);
    if let (Some(e), Some(r)) = (s.expiry_session, s.removal_session) {
        println!(
            "Validity expires at session {e}, and membership is removed at {r} unless renewed."
        );
    }
    println!(
        "Session keys: {}",
        match (s.keys_registered, s.keys_held_by_node) {
            (false, _) => "not registered",
            (true, Some(true)) => "registered and the node owns the private keys ✓",
            (true, Some(false)) => "registered but the node does not own them ✗",
            (true, None) =>
                "registered (could not verify that the node owns them — unsafe RPC disabled?)",
        }
    );
    for w in &s.warnings {
        println!("⚠️  {w}");
    }
    for (i, n) in s.next_steps.iter().enumerate() {
        println!("{} {n}", if i == 0 { "Next step:" } else { "          " });
    }
}

fn show_status(a: StatusArgs) -> Result<(), String> {
    let who = who_from(&a.account_file, &a.address, &a.passphrase_file)?;
    let t = HttpRpc::new(&a.rpc);
    if a.json {
        // The node app (the "Enable voting" button) reads these two fields to know whether to vouch and apply, or wait for committee approval. Read only,
        // at the same block the status was read at; if they cannot be read they are null (the whole command does not fail: dashboards read only "status").
        let r = Reader::at_best(&t)?;
        let (view, params) = r.view(&who)?;
        let s = status::interpret(&view, params);
        let flag = |key: Vec<u8>| -> Option<bool> {
            t.call(
                "state_getStorage",
                json!([format!("0x{}", hex::encode(key)), r.at]),
            )
            .ok()
            .map(|v| !v.is_null())
        };
        let out = json!({
            "account": who.to_ss58check(),
            "status": s,
            "operator_approved": flag(madar_admission::ApprovedOperators::<madar_consensus::Runtime>::hashed_key_for(&who)),
            "vouched": flag(madar_admission::NodeOperator::<madar_consensus::Runtime>::hashed_key_for(&who)),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?
        );
    } else {
        print_status(&who, &snapshot(&t, &who)?);
    }
    Ok(())
}

/// Shared context for submitting commands: transport + state + ID (no key yet).
struct Ctx {
    t: HttpRpc,
    args_yes: bool,
    who: AccountId,
    s: JoinStatus,
}

fn context(rpc: &str, account_file: &PathBuf, yes: bool) -> Result<Ctx, String> {
    let who = account::read_public(account_file)?;
    let t = HttpRpc::new(rpc);
    let s = snapshot(&t, &who)?;
    Ok(Ctx {
        t,
        args_yes: yes,
        who,
        s,
    })
}

fn confirm(ctx: &Ctx, plan: &str) -> Result<(), String> {
    print_status(&ctx.who, &ctx.s);
    println!("\nAbout to: {plan}");
    if ctx.args_yes {
        return Ok(());
    }
    print!("Type yes to continue: ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    if line.trim() == "yes" {
        Ok(())
    } else {
        Err("Cancelled at your request — nothing was submitted.".into())
    }
}

fn load_account(
    file: &PathBuf,
    pass_file: &Option<PathBuf>,
    expect: &AccountId,
) -> Result<Account, String> {
    let pass = account::read_passphrase(pass_file.as_deref(), false)?;
    let acct = Account::load(file, &pass)?;
    if &acct.id() != expect {
        return Err(
            "The encrypted file does not match the adjacent .pub file — refusing to sign.".into(),
        );
    }
    Ok(acct)
}

/// Is `who` vouched for by an approved operator (`Admission::NodeOperator`)? Since B2 (2026-10-14) the chain refuses a
/// candidate without it, before the puzzle is even checked.
fn vouched(t: &HttpRpc, who: &AccountId) -> Result<bool, String> {
    // the key from the pallet itself, so it cannot drift from the storage definition
    let key = madar_admission::NodeOperator::<madar_consensus::Runtime>::hashed_key_for(who);
    let v = t.call(
        "state_getStorage",
        serde_json::json!([format!("0x{}", hex::encode(key))]),
    )?;
    Ok(!v.is_null())
}

fn apply(a: TxArgs) -> Result<(), String> {
    let ctx = context(&a.rpc, &a.account_file, a.yes)?;
    status::gate_apply(&ctx.s)?;
    if !vouched(&ctx.t, &ctx.who)? {
        return Err("No approved operator has vouched for your node yet, and the network refuses candidacy without it. Send your account address to an approved operator to vouch for it (madar-node join vouch), then try again. Nothing was sent.".into());
    }
    confirm(&ctx, "Solve the current round's puzzle (may take minutes depending on difficulty) and submit it. No fees.")?;
    let acct = load_account(&a.account_file, &a.passphrase_file, &ctx.who)?;
    submit_solution(&ctx.t, &acct)?;
    println!(
        "\nAfter inclusion, follow up with: madar-node join status --account-file {} --rpc {}",
        a.account_file.display(),
        a.rpc
    );
    if !ctx.s.keys_registered {
        println!("Then register the keys right away on the Validator node: madar-node join register-keys --account-file {}", a.account_file.display());
    }
    Ok(())
}

fn renew(a: TxArgs) -> Result<(), String> {
    let ctx = context(&a.rpc, &a.account_file, a.yes)?;
    status::gate_renew(&ctx.s)?;
    confirm(
        &ctx,
        "Solve the current round's puzzle and submit it to renew membership.",
    )?;
    let acct = load_account(&a.account_file, &a.passphrase_file, &ctx.who)?;
    submit_solution(&ctx.t, &acct)?;
    println!(
        "\nAfter inclusion, follow up with: madar-node join status --account-file {} --rpc {}",
        a.account_file.display(),
        a.rpc
    );
    Ok(())
}

fn exit(a: TxArgs) -> Result<(), String> {
    let ctx = context(&a.rpc, &a.account_file, a.yes)?;
    status::gate_exit(&ctx.s)?;
    confirm(&ctx, "Register a voluntary exit (takes effect at the next session rotation; your authority ends after two rotations).")?;
    let acct = load_account(&a.account_file, &a.passphrase_file, &ctx.who)?;
    let hash = tx::submit(
        &ctx.t,
        &acct,
        RuntimeCall::Admission(madar_admission::Call::voluntary_exit {}),
    )?;
    println!("Exit request submitted: {hash}");
    Ok(())
}

/// Run from a scheduler (hourly): renews only when the chain allows it, otherwise exits successfully without submitting anything. A real error (not a member/banned/network) = non-zero exit code.
fn auto_renew(a: AutoRenewArgs) -> Result<(), String> {
    let acct = match (&a.secret_file, &a.account_file) {
        _ if a.sealed_secret_file.is_some() => crate::sealed::load_account(
            a.sealed_secret_file
                .as_deref()
                .expect("checked by the guard"),
        )?,
        (Some(s), _) => Account::from_secret_json(s)?,
        (None, Some(f)) => {
            let pass = if a.passphrase_stdin {
                let mut line = zeroize::Zeroizing::new(String::new());
                std::io::stdin()
                    .read_line(&mut line)
                    .map_err(|e| e.to_string())?;
                zeroize::Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_string())
            } else {
                account::read_passphrase(a.passphrase_file.as_deref(), false)?
            };
            let acct = Account::load(f, &pass)?;
            if acct.id() != account::read_public(f)? {
                return Err(
                    "The encrypted file does not match the adjacent .pub file — refusing to sign."
                        .into(),
                );
            }
            acct
        }
        (None, None) => {
            return Err("Give --secret-file or --sealed-secret-file or --account-file".into())
        }
    };
    let t = HttpRpc::new(&a.rpc);
    let who = acct.id();
    let s = snapshot(&t, &who)?;
    let stamp = format!("[{}] {}", s.current_session, who.to_ss58check());
    let remaining = s
        .expiry_session
        .map(|e| e.saturating_sub(s.current_session));
    let due = remaining.map_or(true, |r| r <= a.renew_within);
    match status::gate_renew(&s) {
        Ok(()) if !due => {
            println!(
                "{stamp}: no renewal needed yet ({} sessions left before expiry).",
                remaining.unwrap_or(0)
            );
            Ok(())
        }
        Ok(()) => {
            println!("{stamp}: renewal window is open — renewing now.");
            submit_solution(&t, &acct)?;
            println!("{stamp}: renewal submitted.");
            Ok(())
        }
        Err(_)
            if matches!(
                s.phase,
                status::Phase::Member | status::Phase::MemberInGrace
            ) =>
        {
            println!(
                "{stamp}: no renewal needed yet (expires at session {:?}).",
                s.expiry_session
            );
            Ok(())
        }
        Err(_)
            if a.reapply
                && status::gate_apply(&s).is_ok()
                && s.keys_registered
                && !vouched(&t, &acct.id())? =>
        {
            println!("{stamp}: not a member now and not vouched by an approved operator — not applying until an operator vouches for it (madar-node join vouch).");
            Ok(())
        }
        Err(_) if a.reapply && status::gate_apply(&s).is_ok() && s.keys_registered => {
            println!(
                "{stamp}: not a member now ({}) — re-applying in the current round.",
                s.summary
            );
            submit_solution(&t, &acct)?;
            println!("{stamp}: application submitted.");
            Ok(())
        }
        Err(_) if matches!(s.phase, status::Phase::Candidate) => {
            println!("{stamp}: candidate in a round awaiting the draw — nothing to do now.");
            Ok(())
        }
        Err(e) => Err(format!("{stamp}: {e}")),
    }
}

fn vouch(a: VouchArgs) -> Result<(), String> {
    let who = account::read_public(&a.tx.account_file)?;
    let node = match &a.node {
        Some(n) => account::parse_address(n)?,
        None => who.clone(),
    };
    let t = HttpRpc::new(&a.tx.rpc);
    println!("Operator: {}", who.to_ss58check());
    println!("About to: attest node {} as belonging to this operator (the operator must first be approved by the committee).", node.to_ss58check());
    if !a.tx.yes {
        print!("Type yes to continue: ");
        std::io::stdout().flush().ok();
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| e.to_string())?;
        if line.trim() != "yes" {
            return Err("Cancelled at your request — nothing was submitted.".into());
        }
    }
    let acct = load_account(&a.tx.account_file, &a.tx.passphrase_file, &who)?;
    let hash = tx::submit(
        &t,
        &acct,
        RuntimeCall::Admission(madar_admission::Call::vouch_node { node }),
    )?;
    println!("Attestation submitted: {hash}");
    println!(
        "Follow up: madar-node join status --account-file {}",
        a.tx.account_file.display()
    );
    Ok(())
}

/// Solves and submits; the seed changes every Epoch, so we make sure it did not change during solving and retry if needed.
fn submit_solution(t: &HttpRpc, acct: &Account) -> Result<(), String> {
    // Current network difficulty (read from the chain, so the tool does not break when an upgrade changes it).
    let bits = Reader::at_best(t)?.ensure_puzzle_params_match()?;
    let who = acct.id();
    for attempt in 1..=SEED_RETRIES {
        // The seed comes from `MembershipApi::puzzle_challenge` (the same source the Runtime verifies against) — no off-chain derivation.
        let seed = Reader::at_best(t)?.challenge()?.round_seed;
        eprint!("Solving the puzzle (attempt {attempt}) ");
        let nonce = puzzle::solve(&who, &seed, bits, MAX_PUZZLE_ATTEMPTS, |n| {
            if n % (64 * 64) == 0 {
                eprint!(".");
            }
        })
        .ok_or("No solution found within the maximum number of attempts")?;
        eprintln!(" done.");
        if Reader::at_best(t)?.challenge()?.round_seed != seed {
            eprintln!("The round seed changed during solving (new Epoch) — solving again.");
            continue;
        }
        let hash = tx::submit(
            t,
            acct,
            RuntimeCall::Admission(madar_admission::Call::submit_admission_solution { nonce }),
        )?;
        println!("Solution submitted: {hash}");
        return Ok(());
    }
    Err("The round seed changed on every attempt — try again (is the network switching Epochs quickly?).".into())
}

fn register_keys(r: RegisterKeysArgs) -> Result<(), String> {
    match (&r.keys, &r.base_path, &r.chain) {
        (Some(keys), Some(base), Some(chain)) => register_local_keys(&r.tx, keys, base, chain),
        (None, _, _) => register_keys_via_node(r.tx),
        _ => Err("--keys needs --base-path and --chain".into()),
    }
}

/// `register-keys --keys`: the keys were generated with `gen-keys` in the node's Keystore; the proof is produced and checked here, and the safe RPC is enough.
fn register_local_keys(
    a: &TxArgs,
    keys_hex: &str,
    base: &std::path::Path,
    chain: &str,
) -> Result<(), String> {
    let g = sessionkeys::parse_keys(keys_hex)?;
    let dir = sessionkeys::keystore_dir(base, &sessionkeys::chain_id(chain)?)?;
    // Both files exist before anything else (no registration of keys this node does not own).
    for n in g.file_names() {
        if !dir.join(&n).is_file() {
            return Err(format!(
                "Key {n} is not in this node's Keystore ({}) — it will not be registered.",
                dir.display()
            ));
        }
    }
    let ctx = context(&a.rpc, &a.account_file, a.yes)?;
    status::gate_register_keys(&ctx.s)?;
    let proof = sessionkeys::ownership_proof(&dir, &g, &ctx.who)?;
    confirm(&ctx, "Register the session keys generated in this node's Keystore on chain with a local ownership proof. The private keys never leave this computer.")?;
    let acct = load_account(&a.account_file, &a.passphrase_file, &ctx.who)?;
    let hash = tx::submit(
        &ctx.t,
        &acct,
        RuntimeCall::Session(pallet_session::Call::set_keys {
            keys: g.session_keys(),
            proof,
        }),
    )?;
    println!("Session keys registered (only the public keys appear on chain): {hash}");
    println!(
        "Check after inclusion: madar-node join status --account-file {} --rpc {}",
        a.account_file.display(),
        a.rpc
    );
    Ok(())
}

fn register_keys_via_node(a: TxArgs) -> Result<(), String> {
    let ctx = context(&a.rpc, &a.account_file, a.yes)?;
    if !ctx.t.is_loopback() {
        return Err("register-keys must run on the Validator node's own machine (local RPC): session keys are generated inside the node's Keystore via unsafe RPC, which must never be exposed to the network.".into());
    }
    status::gate_register_keys(&ctx.s)?;
    confirm(&ctx, "Generate new session keys inside the local node's Keystore (requires --rpc-methods unsafe on Loopback) and register them on chain with a proof of ownership. The private keys never leave the node.")?;
    let acct = load_account(&a.account_file, &a.passphrase_file, &ctx.who)?;
    let owner = format!(
        "0x{}",
        hex::encode(parity_scale_codec::Encode::encode(&ctx.who))
    );
    let generated = ctx.t.call("author_rotateKeysWithOwner", json!([owner])).map_err(|e| {
        format!("Could not generate keys on the node: {e}\nMake sure the node runs with --validator and that unsafe RPC is enabled on Loopback (--rpc-methods unsafe).")
    })?;
    let bytes = |k: &str| -> Result<Vec<u8>, String> {
        hex::decode(
            generated
                .get(k)
                .and_then(|v| v.as_str())
                .ok_or("Incomplete key generation response")?
                .trim_start_matches("0x"),
        )
        .map_err(|_| "Invalid key generation response".to_string())
    };
    let keys_bytes = bytes("keys")?;
    let proof = bytes("proof")?;
    let keys = SessionKeys::decode(&mut &keys_bytes[..])
        .map_err(|_| "The generated session keys cannot be decoded")?;
    let hash = tx::submit(
        &ctx.t,
        &acct,
        RuntimeCall::Session(pallet_session::Call::set_keys { keys, proof }),
    )?;
    println!("Session keys registered (only the public keys appear on chain): {hash}");
    println!(
        "Check after inclusion: madar-node join status --account-file {} --rpc {}",
        a.account_file.display(),
        a.rpc
    );
    Ok(())
}

fn rotate_keys(a: RotateArgs) -> Result<(), String> {
    use super::rotation::{self, Inputs, Intent, Step};
    let ctx = context(&a.rpc, &a.account_file, a.yes)?;
    if !ctx.t.is_loopback() {
        return Err("rotate-keys runs on the new node's own machine (local RPC): keys are generated inside the node's Keystore via unsafe RPC.".into());
    }
    status::gate_register_keys(&ctx.s)?;
    let ipath = rotation::intent_path(&a.account_file);
    let mut acct: Option<Account> = None;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(a.wait_timeout_secs);
    let mut resubmits = 0;
    let mut announced_wait = false;
    loop {
        let reader = Reader::at_best(&ctx.t)?;
        let st = reader.status(&ctx.who)?;
        let (babe, grandpa) = reader.authorities()?;
        let intent = rotation::read_intent(&ipath)?;
        let onchain = st.session_keys.clone();
        let holds_on = onchain.as_deref().and_then(|k| reader.node_has_keys(k));
        let holds_int = intent
            .as_ref()
            .and_then(|i| hex::decode(i.new_keys.trim_start_matches("0x")).ok())
            .and_then(|k| reader.node_has_keys(&k));
        let step = rotation::decide(&Inputs {
            onchain: onchain.as_deref(),
            intent: intent.as_ref(),
            node_holds_onchain: holds_on,
            node_holds_intent: holds_int,
            babe_active: &babe,
            grandpa_active: &grandpa,
        });
        match step {
            Step::Refuse(m) => return Err(m),
            Step::Done => {
                let old_still_active = intent
                    .as_ref()
                    .and_then(|i| i.old_keys.as_ref())
                    .and_then(|k| hex::decode(k).ok())
                    .map_or(false, |k| {
                        rotation::raw_keys(&k).map_or(false, |(b, _)| babe.contains(&b))
                    });
                if old_still_active {
                    println!("This node's keys are active, but the old machine's keys are still among the current BABE authorities — wait for the Epoch to change, then rerun the command before stopping the old machine.");
                    if a.no_wait || std::time::Instant::now() > deadline {
                        return Ok(());
                    }
                } else {
                    rotation::clear_intent(&ipath);
                    println!("Rotation complete: this node's keys are active, and the old machine's keys are no longer an authority. You may now stop the old machine and delete its keys at your discretion (nothing was deleted automatically).");
                    return Ok(());
                }
            }
            Step::WaitActivation => {
                if !announced_wait {
                    println!("This node's keys are registered and awaiting activation (they become an authority after two session rotations); the old machine keeps its role until then.");
                    announced_wait = true;
                }
                if a.no_wait {
                    println!("Rerun the command to follow activation: madar-node join rotate-keys --account-file {} --rpc {}", a.account_file.display(), a.rpc);
                    return Ok(());
                }
            }
            Step::GenerateAndRegister | Step::RegisterIntent => {
                let plan = if step == Step::GenerateAndRegister {
                    "Generate new session keys in this node's Keystore and register them in place of the currently registered ones (they become an authority after two rotations; the old ones stay active until then and are not deleted)."
                } else {
                    "Resubmit the registration of the previously generated new keys (present in this node's Keystore) — no new generation."
                };
                if resubmits == 0 {
                    confirm(&ctx, plan)?;
                }
                if resubmits > 3 {
                    return Err("The registration was resubmitted several times with no effect on chain — check the node/transaction pool, then rerun the command.".into());
                }
                if acct.is_none() {
                    acct = Some(load_account(&a.account_file, &a.passphrase_file, &ctx.who)?);
                }
                let acct = acct.as_ref().unwrap();
                let (keys_hex, proof_hex) = if step == Step::GenerateAndRegister {
                    let owner = format!(
                        "0x{}",
                        hex::encode(parity_scale_codec::Encode::encode(&ctx.who))
                    );
                    let g = ctx.t.call("author_rotateKeysWithOwner", json!([owner])).map_err(|e| format!("Could not generate keys on this node: {e}\nMake sure it runs with --validator and that unsafe RPC is enabled on Loopback."))?;
                    let get = |k: &str| {
                        g.get(k)
                            .and_then(|v| v.as_str())
                            .map(|s| s.trim_start_matches("0x").to_string())
                            .ok_or_else(|| "Incomplete key generation response".to_string())
                    };
                    let (keys_hex, proof_hex) = (get("keys")?, get("proof")?);
                    // The intent is written **before** submission: an interruption after it = resume without new generation.
                    rotation::write_intent(
                        &ipath,
                        &Intent {
                            old_keys: onchain.as_ref().map(hex::encode),
                            new_keys: keys_hex.clone(),
                            proof: proof_hex.clone(),
                            created_at_session: st.current_session,
                        },
                    )?;
                    (keys_hex, proof_hex)
                } else {
                    let i = intent.as_ref().ok_or("No saved intent")?;
                    (i.new_keys.clone(), i.proof.clone())
                };
                let keys_bytes = hex::decode(&keys_hex).map_err(|_| "Invalid intent keys")?;
                let keys = SessionKeys::decode(&mut &keys_bytes[..])
                    .map_err(|_| "The session keys cannot be decoded")?;
                let proof = hex::decode(&proof_hex).map_err(|_| "Invalid proof of ownership")?;
                let hash = tx::submit(
                    &ctx.t,
                    acct,
                    RuntimeCall::Session(pallet_session::Call::set_keys { keys, proof }),
                )?;
                println!("Registration of the new keys submitted (public only): {hash}");
                resubmits += 1;
                if a.no_wait {
                    println!("Rerun the command to follow registration and activation.");
                    return Ok(());
                }
            }
        }
        if std::time::Instant::now() > deadline {
            return Err("Timed out waiting for activation — nothing was deleted; rerun the same command to continue.".into());
        }
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Join {
        #[command(subcommand)]
        c: JoinCmd,
    }

    fn parse(args: &[&str]) -> Result<JoinCmd, clap::Error> {
        Join::try_parse_from(std::iter::once("join").chain(args.iter().copied())).map(|j| j.c)
    }

    #[test]
    fn the_old_command_lines_keep_working_and_the_new_ones_parse() {
        // As in the operator scripts and the documentation: unchanged
        let old = parse(&[
            "register-keys",
            "--rpc",
            "127.0.0.1:9944",
            "--account-file",
            "a.enc",
            "--passphrase-file",
            "p",
            "--yes",
        ])
        .unwrap();
        assert!(matches!(
            old,
            JoinCmd::RegisterKeys(RegisterKeysArgs { keys: None, .. })
        ));
        assert!(parse(&[
            "status",
            "--rpc",
            "127.0.0.1:9944",
            "--account-file",
            "op.enc"
        ])
        .is_ok());
        // The new form: the public keys + the Keystore location
        let new = parse(&[
            "register-keys",
            "--account-file",
            "a.enc",
            "--keys",
            "0xab",
            "--base-path",
            "b",
            "--chain",
            "c",
            "--yes",
        ])
        .unwrap();
        assert!(matches!(
            new,
            JoinCmd::RegisterKeys(RegisterKeysArgs {
                keys: Some(_),
                base_path: Some(_),
                chain: Some(_),
                ..
            })
        ));
        assert!(
            parse(&["register-keys", "--account-file", "a.enc", "--keys", "0xab"]).is_err(),
            "--keys needs the keystore location"
        );
        assert!(matches!(
            parse(&["gen-keys", "--base-path", "b", "--chain", "c", "--json"]).unwrap(),
            JoinCmd::GenKeys(GenKeysArgs { json: true, .. })
        ));
        assert!(parse(&["gen-keys", "--chain", "c"]).is_err());
        assert!(parse(&[
            "export",
            "--account-file",
            "a",
            "--passphrase-file",
            "p",
            "--backup-pass-file",
            "q",
            "--out",
            "o"
        ])
        .is_ok());
        assert!(parse(&[
            "import",
            "--in",
            "f",
            "--backup-pass-file",
            "q",
            "--out",
            "o",
            "--passphrase-file",
            "p"
        ])
        .is_ok());
        assert!(
            parse(&[
                "status",
                "--account-file",
                "a",
                "--json",
                "--passphrase-file",
                "p"
            ])
            .is_ok(),
            "a half-created account"
        );
        assert!(
            who_from(
                &None,
                &Some(format!("0x{}", "00".repeat(32))),
                &Some(PathBuf::from("p"))
            )
            .is_err(),
            "the passphrase only goes with an account file"
        );
    }
}
