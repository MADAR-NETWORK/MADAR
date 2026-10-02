//! The text interface of the join tool: clap commands, messages, confirmations. All logic lives in the other modules; replacing this interface does not touch the protocol.

use super::account::{self, Account};
use super::chain::Reader;
use super::rpc::{HttpRpc, Transport};
use super::status::{self, JoinStatus};
use super::{puzzle, tx};
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
    /// Join (or re-apply): solves the current round's puzzle and submits it. The first transaction creates the account on chain.
    Apply(TxArgs),
    /// Register session keys: generated inside the local node's Keystore (they never leave it) and registered on chain with a proof of ownership.
    RegisterKeys(TxArgs),
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
    #[arg(long)]
    pub secret_file: Option<PathBuf>,
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
    }
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

fn who_from(account_file: &Option<PathBuf>, address: &Option<String>) -> Result<AccountId, String> {
    match (account_file, address) {
        (Some(f), _) => account::read_public(f),
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
    let who = who_from(&a.account_file, &a.address)?;
    let s = snapshot(&HttpRpc::new(&a.rpc), &who)?;
    if a.json {
        let out = json!({"account": who.to_ss58check(), "status": s});
        println!(
            "{}",
            serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?
        );
    } else {
        print_status(&who, &s);
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

fn apply(a: TxArgs) -> Result<(), String> {
    let ctx = context(&a.rpc, &a.account_file, a.yes)?;
    status::gate_apply(&ctx.s)?;
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
        (None, None) => return Err("Specify --secret-file or --account-file".into()),
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

fn register_keys(a: TxArgs) -> Result<(), String> {
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
