//! `madar-node doctor` (T3): a **read-only** check of a running node's state, with no new service and no external connection, reusing the official membership status (`MembershipApi` via the `join` module).
//! Each check yields: OK / Warning / Fail / Unverifiable. **Principle:** never present stale state as current — if the node is not synced, membership is reported as "Unverifiable". No automatic renewal.
//! Clock: the only trusted reference without an external connection is the timestamp of the latest block on the chain itself (valid only if the chain is advancing at check time).
//! The report is redacted by default (paths, addresses, PeerIDs, user names, truncated SS58 accounts) so it is safe to share; `--no-redact` for local viewing.

use crate::join::{
    account,
    chain::Reader,
    rpc::{HttpRpc, Transport},
    status::{self, Phase},
};
use serde::Serialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, clap::Args)]
pub struct DoctorCmd {
    /// Node RPC address (HTTP: host:port).
    #[arg(long, default_value = "127.0.0.1:9944")]
    pub rpc: String,
    /// Operator account (a `.enc` file with a `.pub` next to it) for checking membership and keys. Optional.
    #[arg(long, conflicts_with = "address")]
    pub account_file: Option<PathBuf>,
    /// Or the account's SS58 / Hex address.
    #[arg(long)]
    pub address: Option<String>,
    /// Expected genesis hash (0x…): the check fails if the node is on a different chain.
    #[arg(long)]
    pub expected_genesis_hash: Option<String>,
    /// Expected role: `validator` or `full`.
    #[arg(long, value_parser = ["validator", "full"])]
    pub expect_role: Option<String>,
    /// Node data directory (`--base-path`) for checking the disk and Keystore permissions.
    #[arg(long)]
    pub base_path: Option<PathBuf>,
    /// Seconds to watch block and finality progress (0 = no watching).
    #[arg(long, default_value_t = 30)]
    pub watch_seconds: u64,
    /// Warn when membership removal is this many sessions away or fewer.
    #[arg(long, default_value_t = 3)]
    pub renew_warn_sessions: u32,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
    /// Do not redact paths/addresses (local viewing only).
    #[arg(long)]
    pub no_redact: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// OK
    Ok,
    /// Unverifiable
    Unknown,
    /// Warning
    Warn,
    /// Fail
    Fail,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Level::Ok => "OK",
            Level::Unknown => "Unverifiable",
            Level::Warn => "Warning",
            Level::Fail => "Fail",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub title: &'static str,
    pub level: Level,
    pub detail: String,
    pub hint: Option<String>,
}

fn check(
    id: &'static str,
    title: &'static str,
    level: Level,
    detail: impl Into<String>,
    hint: Option<&str>,
) -> Check {
    Check {
        id,
        title,
        level,
        detail: detail.into(),
        hint: hint.map(str::to_string),
    }
}

// ---------------------------------------------------------------- Pure logic (tested without a network)

/// Disk: free space ratio and amount.
pub fn disk_level(free_bytes: u64, total_bytes: u64) -> Level {
    const GIB: u64 = 1 << 30;
    if total_bytes == 0 {
        return Level::Unknown;
    }
    let pct = free_bytes as f64 / total_bytes as f64 * 100.0;
    if free_bytes < 2 * GIB || pct < 5.0 {
        Level::Fail
    } else if free_bytes < 10 * GIB || pct < 15.0 {
        Level::Warn
    } else {
        Level::Ok
    }
}

/// Local clock skew relative to the latest block's timestamp (ms). BABE is sensitive to skew; we only judge if the block is recent (the chain is advancing).
pub fn clock_level(local_ms: u64, block_ms: u64, chain_is_advancing: bool) -> (Level, i64) {
    let skew = local_ms as i64 - block_ms as i64;
    if !chain_is_advancing || skew < -3_600_000 {
        return (Level::Unknown, skew);
    }
    let a = skew.unsigned_abs();
    (
        if a > 30_000 {
            Level::Fail
        } else if a > 8_000 {
            Level::Warn
        } else {
            Level::Ok
        },
        skew,
    )
}

/// Overall status = the worst (Fail > Warning > Unverifiable > OK). Exit code: 0 OK, 1 Warning, 2 Fail, 3 Unverifiable only.
pub fn overall(checks: &[Check]) -> Level {
    checks.iter().map(|c| c.level).max().unwrap_or(Level::Ok)
}

pub fn exit_code(l: Level) -> i32 {
    match l {
        Level::Ok => 0,
        Level::Warn => 1,
        Level::Fail => 2,
        Level::Unknown => 3,
    }
}

/// Redact a report for sharing: paths, IP addresses/ports, PeerIDs, user names, and SS58 accounts (truncated).
pub fn redact(text: &str, home_hint: &[String]) -> String {
    let mut out = text.to_string();
    for h in home_hint {
        if h.len() > 3 {
            out = out.replace(h.as_str(), "<path>");
        }
    }
    let mut res = String::new();
    for tok in out.split_inclusive(|c: char| c.is_whitespace() || "(),;\u{060C}\"'".contains(c)) {
        let core =
            tok.trim_end_matches(|c: char| c.is_whitespace() || "(),;\u{060C}\"'.".contains(c));
        let tail = &tok[core.len()..];
        let repl = if looks_like_ip(core) {
            "<addr>".to_string()
        } else if core.starts_with("12D3KooW") || core.starts_with("Qm") && core.len() > 40 {
            "<peer-id>".to_string()
        } else if core.len() >= 46
            && core.chars().all(|c| c.is_ascii_alphanumeric())
            && (core.starts_with('5') || core.starts_with('1') || core.starts_with('4'))
        {
            format!("{}…{}", &core[..6], &core[core.len() - 4..])
        } else if core.contains('\\')
            || (core.starts_with('/') && core.matches('/').count() >= 2)
            || core.contains(":\\")
        {
            "<path>".to_string()
        } else {
            core.to_string()
        };
        res.push_str(&repl);
        res.push_str(tail);
    }
    res
}

fn looks_like_ip(s: &str) -> bool {
    let host = s.rsplit_once(':').map_or(s, |(h, p)| {
        if p.chars().all(|c| c.is_ascii_digit()) {
            h
        } else {
            s
        }
    });
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.chars().all(|c| c.is_ascii_digit()))
}

// ---------------------------------------------------------------- Collecting and evaluating facts

fn u64_of(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| {
        v.as_str()
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
    })
}

fn best_and_finalized(t: &dyn Transport) -> Option<(u64, u64)> {
    let best = u64_of(&t.call("chain_getHeader", json!([])).ok()?["number"])?;
    let fin_hash = t.call("chain_getFinalizedHead", json!([])).ok()?;
    let fin = u64_of(&t.call("chain_getHeader", json!([fin_hash])).ok()?["number"])?;
    Some((best, fin))
}

pub fn run_checks(
    t: &dyn Transport,
    cmd: &DoctorCmd,
    local_now_ms: u64,
    watch: &dyn Fn(Duration),
) -> Vec<Check> {
    let mut out = Vec::new();
    let started = std::time::Instant::now();

    // 1) Reachability
    let health = match t.call("system_health", json!([])) {
        Ok(h) => h,
        Err(e) => {
            out.push(check("rpc", "Node reachability", Level::Fail, format!("No response from RPC: {e}"), Some("Make sure the node is running and that --rpc matches its port (default 127.0.0.1:9944)")));
            for (id, title) in [
                ("genesis", "Chain identity"),
                ("sync", "Sync"),
                ("finality", "Finality progress"),
                ("peers", "Peers"),
                ("role", "Role"),
                ("membership", "Membership and keys"),
                ("clock", "Clock"),
            ] {
                out.push(check(
                    id,
                    title,
                    Level::Unknown,
                    "Unavailable because the node is not responding",
                    None,
                ));
            }
            disk_and_keystore(cmd, &mut out);
            return out;
        }
    };
    out.push(check(
        "rpc",
        "Node reachability",
        Level::Ok,
        "Responds to RPC",
        None,
    ));

    // 2) Chain identity
    let genesis = t
        .call("chain_getBlockHash", json!([0]))
        .ok()
        .and_then(|v| v.as_str().map(str::to_string));
    out.push(match (&cmd.expected_genesis_hash, &genesis) {
        (Some(want), Some(got)) if want.eq_ignore_ascii_case(got) => check("genesis", "Chain identity", Level::Ok, "Genesis matches the expected value", None),
        (Some(want), Some(got)) => check("genesis", "Chain identity", Level::Fail, format!("Genesis {got} ≠ expected {want}"), Some("This node is on a different chain: check the chain spec file and the bootnode addresses")),
        (Some(_), None) => check("genesis", "Chain identity", Level::Unknown, "Could not read the genesis hash", None),
        (None, Some(got)) => check("genesis", "Chain identity", Level::Unknown, format!("No verification requested (current genesis {got}); pass --expected-genesis-hash"), None),
        (None, None) => check("genesis", "Chain identity", Level::Unknown, "Could not read the genesis hash", None),
    });

    // 3) Sync
    let syncing = health.get("isSyncing").and_then(|v| v.as_bool());
    let state = t.call("system_syncState", json!([])).ok();
    let (cur, high) = state
        .as_ref()
        .map(|s| (u64_of(&s["currentBlock"]), u64_of(&s["highestBlock"])))
        .unwrap_or((None, None));
    let behind = match (cur, high) {
        (Some(c), Some(h)) => h.saturating_sub(c),
        _ => 0,
    };
    let synced = syncing == Some(false) && behind <= 3;
    out.push(match syncing {
        Some(false) if behind <= 3 => check("sync", "Sync", Level::Ok, "In sync with the best known block", None),
        Some(false) => check("sync", "Sync", Level::Warn, format!("Not in sync mode but {behind} blocks behind the highest known block"), Some("Check peers and connectivity")),
        Some(true) => check("sync", "Sync", Level::Warn, format!("Currently syncing (at {:?} of {:?})", cur, high), Some("Wait for sync to complete before taking any action; membership status below will be reported as unverifiable")),
        None => check("sync", "Sync", Level::Unknown, "system_health response has no isSyncing", None),
    });

    // 4) Finality (short watch: are blocks and finality advancing?)
    let first = best_and_finalized(t);
    let advancing_chain;
    if cmd.watch_seconds > 0 && synced {
        watch(Duration::from_secs(cmd.watch_seconds));
        let second = best_and_finalized(t);
        match (first, second) {
            (Some((b1, f1)), Some((b2, f2))) => {
                advancing_chain = b2 > b1;
                out.push(if b2 <= b1 {
                    check("finality", "Finality progress", Level::Fail, format!("Blocks did not advance within {} s (best #{b2}, finalized #{f2})", cmd.watch_seconds), Some("This node may be isolated (0 peers) or the network may be halted; check peers"))
                } else if f2 <= f1 {
                    check("finality", "Finality progress", Level::Warn, format!("Blocks advance (#{b1}→#{b2}) but finality is stuck at #{f2} (lag {} blocks)", b2.saturating_sub(f2)), Some("Finality needs a majority of validators voting; one of them may be down"))
                } else {
                    check("finality", "Finality progress", Level::Ok, format!("Blocks #{b1}→#{b2}, finalized #{f1}→#{f2}"), None)
                });
            }
            _ => {
                advancing_chain = false;
                out.push(check(
                    "finality",
                    "Finality progress",
                    Level::Unknown,
                    "Could not read the headers",
                    None,
                ));
            }
        }
    } else if let Some((b, f)) = first {
        advancing_chain = false;
        let why = if !synced {
            "The node is not synced"
        } else {
            "Watching is disabled (--watch-seconds 0)"
        };
        out.push(check(
            "finality",
            "Finality progress",
            Level::Unknown,
            format!(
                "{why}; best #{b}, finalized #{f} (lag {})",
                b.saturating_sub(f)
            ),
            None,
        ));
    } else {
        advancing_chain = false;
        out.push(check(
            "finality",
            "Finality progress",
            Level::Unknown,
            "Could not read the headers",
            None,
        ));
    }

    // 5) Peers
    let peers = health.get("peers").and_then(|v| v.as_u64());
    let should = health
        .get("shouldHavePeers")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    out.push(match peers {
        Some(0) if should => check("peers", "Peers", Level::Fail, "0 peers", Some("No blocks are produced or finalized without peers: check --bootnodes, the P2P port and the firewall")),
        Some(0) => check("peers", "Peers", Level::Ok, "0 peers (expected for this network)", None),
        Some(1) => check("peers", "Peers", Level::Warn, "Only one peer", Some("A single peer is fragile; add more bootnodes")),
        Some(n) => check("peers", "Peers", Level::Ok, format!("{n} peers"), None),
        None => check("peers", "Peers", Level::Unknown, "system_health response has no peers", None),
    });

    // 6) Role
    let roles: Vec<String> = t
        .call("system_nodeRoles", json!([]))
        .ok()
        .and_then(|v| {
            v.as_array().map(|a| {
                a.iter()
                    .filter_map(|r| r.as_str().map(str::to_string))
                    .collect()
            })
        })
        .unwrap_or_default();
    let is_authority = roles.iter().any(|r| r == "Authority");
    out.push(match (&cmd.expect_role, roles.is_empty()) {
        (_, true) => check(
            "role",
            "Role",
            Level::Unknown,
            "Could not read the node role (system_nodeRoles)",
            None,
        ),
        (Some(w), _) if (w == "validator") == is_authority => check(
            "role",
            "Role",
            Level::Ok,
            format!("Role {roles:?} as expected"),
            None,
        ),
        (Some(w), _) => check(
            "role",
            "Role",
            Level::Fail,
            format!("Expected {w} but the actual role is {roles:?}"),
            Some(if w == "validator" {
                "Run the node with --validator"
            } else {
                "Remove --validator"
            }),
        ),
        (None, _) => check("role", "Role", Level::Ok, format!("Role {roles:?}"), None),
    });

    // 7) Membership and keys (stale state is never shown as current)
    out.push(membership_check(t, cmd, synced, is_authority));

    // 8) Clock, from the block timestamp
    let block_ms = t
        .call(
            "state_getStorage",
            json!([format!(
                "0x{}",
                hex::encode(
                    [
                        sp_io::hashing::twox_128(b"Timestamp"),
                        sp_io::hashing::twox_128(b"Now")
                    ]
                    .concat()
                )
            )]),
        )
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .and_then(|h| hex::decode(h.trim_start_matches("0x")).ok())
        .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
        .map(u64::from_le_bytes);
    out.push(match block_ms {
        Some(b) => {
            let (lvl, skew) = clock_level(local_now_ms + started.elapsed().as_millis() as u64, b, advancing_chain || (synced && peers.unwrap_or(0) > 0));
            match lvl {
                Level::Ok => check("clock", "Clock", Level::Ok, format!("Skew {:+.1} s from the latest block time", skew as f64 / 1000.0), None),
                Level::Unknown => check("clock", "Clock", Level::Unknown, "No trusted reference right now (the chain is not advancing or the node is not synced)", None),
                l => check("clock", "Clock", l, format!("Skew {:+.1} s from the latest block time", skew as f64 / 1000.0), Some("Set up time synchronization (NTP); BABE is sensitive to clock skew")),
            }
        },
        None => check("clock", "Clock", Level::Unknown, "Could not read the block timestamp", None),
    });

    disk_and_keystore(cmd, &mut out);
    out
}

fn membership_check(t: &dyn Transport, cmd: &DoctorCmd, synced: bool, is_authority: bool) -> Check {
    let who = match (&cmd.account_file, &cmd.address) {
        (Some(f), _) => account::read_public(f),
        (None, Some(a)) => account::parse_address(a),
        (None, None) => {
            return check(
                "membership",
                "Membership and keys",
                Level::Unknown,
                "No account specified (--account-file or --address)",
                None,
            )
        }
    };
    let who = match who {
        Ok(w) => w,
        Err(e) => return check("membership", "Membership and keys", Level::Fail, e, None),
    };
    if !synced {
        return check("membership", "Membership and keys", Level::Unknown, "The node is not synced: any membership state read now may be stale, so it is not shown as current", Some("Rerun the check after sync completes"));
    }
    let (view, params) = match Reader::at_best(t).and_then(|r| r.view(&who)) {
        Ok(v) => v,
        Err(e) => return check("membership", "Membership and keys", Level::Unknown, e, None),
    };
    let s = status::interpret(&view, params);
    let keys = match (s.keys_registered, s.keys_held_by_node) {
        (false, _) => "session keys not registered",
        (true, Some(true)) => "session keys registered and held by this node",
        (true, Some(false)) => "session keys registered but this node does not hold them",
        (true, None) => "session keys registered (could not verify that this node holds them)",
    };
    let state = match s.phase {
        Phase::Banned => "Banned",
        Phase::NotStarted => "Not started",
        Phase::Candidate => "Candidate awaiting the draw",
        Phase::KeysOnly => "Keys registered but not a candidate",
        Phase::Member if s.active_authority => "Member and active authority",
        Phase::Member => "Member (active authority not started yet)",
        Phase::MemberInGrace => "Member in grace period",
        Phase::Exiting => "Voluntary exit registered",
    };
    let sessions_left = s
        .removal_session
        .map(|r| r.saturating_sub(s.current_session));
    let mut level = Level::Ok;
    let mut hint: Option<String> = s.next_steps.first().cloned();
    match s.phase {
        Phase::Banned => level = Level::Fail,
        Phase::MemberInGrace => level = Level::Warn,
        Phase::Member | Phase::Exiting => {
            if matches!(sessions_left, Some(n) if n <= cmd.renew_warn_sessions)
                && s.phase == Phase::Member
            {
                level = Level::Warn;
            }
        }
        Phase::Candidate if !s.keys_registered => level = Level::Warn,
        _ => {}
    }
    if s.keys_registered && s.keys_held_by_node == Some(false) {
        level = level.max(Level::Fail);
        hint = Some(
            "Register new keys on this node (join register-keys) or move the correct Keystore here"
                .into(),
        );
    }
    if is_authority && !s.keys_registered && matches!(s.phase, Phase::Member | Phase::MemberInGrace)
    {
        level = level.max(Level::Fail);
    }
    let window = match (s.expiry_session, s.removal_session) {
        (Some(e), Some(r)) => format!(
            "; expires at session {e} and is removed at {r} (current {}, {} left)",
            s.current_session,
            sessions_left.unwrap_or(0)
        ),
        _ => String::new(),
    };
    let mut c = check(
        "membership",
        "Membership and keys",
        level,
        format!("{state}; {keys}{window}"),
        None,
    );
    c.hint = hint;
    c
}

fn disk_and_keystore(cmd: &DoctorCmd, out: &mut Vec<Check>) {
    let Some(base) = &cmd.base_path else {
        out.push(check(
            "disk",
            "Disk space",
            Level::Unknown,
            "--base-path not specified",
            None,
        ));
        out.push(check(
            "keystore",
            "Keystore permissions",
            Level::Unknown,
            "--base-path not specified",
            None,
        ));
        return;
    };
    let canon = std::fs::canonicalize(base).ok().map(|p| {
        p.display()
            .to_string()
            .trim_start_matches(r"\\?\")
            .to_string()
    });
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let best = canon.as_ref().and_then(|c| {
        disks
            .list()
            .iter()
            .filter(|d| {
                c.to_lowercase()
                    .starts_with(&d.mount_point().display().to_string().to_lowercase())
            })
            .max_by_key(|d| d.mount_point().display().to_string().len())
    });
    out.push(match best {
        Some(d) => {
            let (free, total) = (d.available_space(), d.total_space());
            let lvl = disk_level(free, total);
            let detail = format!(
                "{:.1} GiB free of {:.1} GiB ({:.0}%)",
                free as f64 / 1073741824.0,
                total as f64 / 1073741824.0,
                free as f64 / total.max(1) as f64 * 100.0
            );
            check(
                "disk",
                "Disk space",
                lvl,
                detail,
                if lvl >= Level::Warn {
                    Some("Free up space or move --base-path; a full disk stops the node")
                } else {
                    None
                },
            )
        }
        None => check(
            "disk",
            "Disk space",
            Level::Unknown,
            "Could not determine the disk for the --base-path",
            None,
        ),
    });
    out.push(keystore_check(base));
}

#[cfg(unix)]
fn keystore_check(base: &std::path::Path) -> Check {
    use std::os::unix::fs::PermissionsExt;
    let mut bad = Vec::new();
    let mut found = false;
    if let Ok(chains) = std::fs::read_dir(base.join("chains")) {
        for c in chains.flatten() {
            let ks = c.path().join("keystore");
            if let Ok(files) = std::fs::read_dir(&ks) {
                found = true;
                for f in files.flatten() {
                    if f.metadata()
                        .map(|m| m.permissions().mode() & 0o077 != 0)
                        .unwrap_or(false)
                    {
                        bad.push(
                            f.file_name()
                                .to_string_lossy()
                                .chars()
                                .take(8)
                                .collect::<String>(),
                        );
                    }
                }
            }
        }
    }
    if !found {
        check(
            "keystore",
            "Keystore permissions",
            Level::Unknown,
            "No Keystore directory under --base-path",
            None,
        )
    } else if bad.is_empty() {
        check(
            "keystore",
            "Keystore permissions",
            Level::Ok,
            "Key files are restricted to the owner",
            None,
        )
    } else {
        check(
            "keystore",
            "Keystore permissions",
            Level::Fail,
            format!(
                "{} key file(s) readable by users other than the owner",
                bad.len()
            ),
            Some("chmod 600 on the Keystore files, and 700 on the directory"),
        )
    }
}

#[cfg(not(unix))]
fn keystore_check(_base: &std::path::Path) -> Check {
    check(
        "keystore",
        "Keystore permissions",
        Level::Unknown,
        "Permission check is not available on this system (ACL)",
        Some("Manually make sure the --base-path directory is readable by your account only"),
    )
}

// ---------------------------------------------------------------- Interface

fn render_text(checks: &[Check], overall: Level) -> String {
    let mut s = String::new();
    for c in checks {
        let icon = match c.level {
            Level::Ok => "✅",
            Level::Unknown => "❔",
            Level::Warn => "⚠️ ",
            Level::Fail => "❌",
        };
        s.push_str(&format!(
            "{icon} [{}] {}: {}\n",
            c.level.label(),
            c.title,
            c.detail
        ));
        if let Some(h) = &c.hint {
            s.push_str(&format!("     ← {h}\n"));
        }
    }
    s.push_str(&format!("\nOverall status: {}\n", overall.label()));
    s
}

pub fn run(cmd: DoctorCmd) -> Result<i32, String> {
    let t = HttpRpc::new(&cmd.rpc);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_millis() as u64;
    let mut checks = run_checks(&t, &cmd, now_ms, &|d| std::thread::sleep(d));
    let level = overall(&checks);
    let mut homes: Vec<String> = ["USERPROFILE", "HOME", "USERNAME", "USER"]
        .iter()
        .filter_map(|k| std::env::var(k).ok())
        .collect();
    if let Some(b) = &cmd.base_path {
        homes.push(b.display().to_string());
    }
    // Redact the text fields **before** serialization (redacting escaped JSON text mixes quote marks into paths).
    if !cmd.no_redact {
        for c in checks.iter_mut() {
            c.detail = redact(&c.detail, &homes);
            c.hint = c.hint.as_ref().map(|h| redact(h, &homes));
        }
    }
    let body = if cmd.json {
        serde_json::to_string_pretty(
            &json!({"overall": level, "exit_code": exit_code(level), "checks": checks}),
        )
        .map_err(|e| e.to_string())?
    } else {
        render_text(&checks, level)
    };
    println!("{body}");
    Ok(exit_code(level))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::join::chain::tests::mock;
    use madar_consensus::VERSION;
    use std::cell::RefCell;

    /// Fake RPC: answers system_* with configurable values, delegates state_call/RuntimeVersion to the fake API, and advances time on "watch".
    struct Fake {
        health: Value,
        sync_state: Value,
        roles: Value,
        genesis: &'static str,
        heads: RefCell<(u64, u64)>, // (best, finalized) current
        timestamp_ms: u64,
        api: crate::join::chain::tests::Mock,
    }
    impl Transport for Fake {
        fn call(&self, method: &str, p: Value) -> Result<Value, String> {
            match method {
                "system_health" => Ok(self.health.clone()),
                "system_syncState" => Ok(self.sync_state.clone()),
                "system_nodeRoles" => Ok(self.roles.clone()),
                "chain_getBlockHash" if p == json!([0]) => Ok(json!(self.genesis)),
                "chain_getHeader" => {
                    let (b, f) = *self.heads.borrow();
                    Ok(json!({"number": format!("0x{:x}", if p == json!([]) { b } else { f })}))
                }
                "chain_getFinalizedHead" => Ok(json!("0xfin")),
                "state_getStorage" => Ok(json!(format!(
                    "0x{}",
                    hex::encode(self.timestamp_ms.to_le_bytes())
                ))),
                _ => self.api.call(method, p),
            }
        }
    }

    fn fake() -> Fake {
        Fake {
            health: json!({"peers": 4, "isSyncing": false, "shouldHavePeers": true}),
            sync_state: json!({"currentBlock": 100, "highestBlock": 100}),
            roles: json!(["Authority"]),
            genesis: "0xgen",
            heads: RefCell::new((100, 98)),
            timestamp_ms: 1_000_000,
            api: mock(Some(1), VERSION.transaction_version),
        }
    }

    fn cmd() -> DoctorCmd {
        DoctorCmd {
            rpc: "x".into(),
            account_file: None,
            address: Some(format!("0x{}", hex::encode([7u8; 32]))),
            expected_genesis_hash: Some("0xgen".into()),
            expect_role: Some("validator".into()),
            base_path: None,
            watch_seconds: 10,
            renew_warn_sessions: 3,
            json: false,
            no_redact: false,
        }
    }

    fn by<'a>(cs: &'a [Check], id: &str) -> &'a Check {
        cs.iter().find(|c| c.id == id).unwrap()
    }

    /// Watching: advances the heads via the closure according to the scenario.
    fn run(f: &Fake, c: &DoctorCmd, advance: (u64, u64)) -> Vec<Check> {
        run_checks(f, c, 1_000_000 + 2_000, &|_| {
            let mut h = f.heads.borrow_mut();
            h.0 += advance.0;
            h.1 += advance.1;
        })
    }

    #[test]
    fn a_healthy_synced_validator_is_all_ok() {
        let mut f = fake();
        f.api.status.exit_pending = false;
        f.api.status.is_active_authority = true;
        let cs = run(&f, &cmd(), (3, 3));
        for id in [
            "rpc", "genesis", "sync", "finality", "peers", "role", "clock",
        ] {
            assert_eq!(by(&cs, id).level, Level::Ok, "{id}: {:?}", by(&cs, id));
        }
        let m = by(&cs, "membership");
        assert_eq!(m.level, Level::Ok, "{m:?}");
        assert!(m.detail.contains("Member"), "{m:?}");
        assert_eq!(by(&cs, "disk").level, Level::Unknown, "no base path given");
    }

    #[test]
    fn an_unsynced_node_never_shows_a_membership_state_as_current() {
        let mut f = fake();
        f.health = json!({"peers": 3, "isSyncing": true, "shouldHavePeers": true});
        f.sync_state = json!({"currentBlock": 10, "highestBlock": 100});
        let cs = run(&f, &cmd(), (0, 0));
        let m = by(&cs, "membership");
        assert_eq!(m.level, Level::Unknown);
        assert!(
            m.detail.contains("may be stale") && !m.detail.contains("Member and active authority"),
            "{m:?}"
        );
        assert_eq!(by(&cs, "sync").level, Level::Warn);
        assert_eq!(
            by(&cs, "finality").level,
            Level::Unknown,
            "no verdict on finality while syncing"
        );
    }

    #[test]
    fn stalled_finality_stalled_blocks_no_peers_wrong_genesis_and_wrong_role_are_reported() {
        assert_eq!(
            by(&run(&fake(), &cmd(), (3, 0)), "finality").level,
            Level::Warn,
            "blocks advance, finality does not"
        );
        assert_eq!(
            by(&run(&fake(), &cmd(), (0, 0)), "finality").level,
            Level::Fail,
            "nothing advances"
        );
        let mut f = fake();
        f.health = json!({"peers": 0, "isSyncing": false, "shouldHavePeers": true});
        assert_eq!(by(&run(&f, &cmd(), (1, 1)), "peers").level, Level::Fail);
        let mut c = cmd();
        c.expected_genesis_hash = Some("0xother".into());
        assert_eq!(by(&run(&fake(), &c, (1, 1)), "genesis").level, Level::Fail);
        let mut c = cmd();
        c.expect_role = Some("full".into());
        assert_eq!(by(&run(&fake(), &c, (1, 1)), "role").level, Level::Fail);
        let mut c = cmd();
        c.expected_genesis_hash = None;
        assert_eq!(
            by(&run(&fake(), &c, (1, 1)), "genesis").level,
            Level::Unknown,
            "no expectation given: informational only"
        );
    }

    #[test]
    fn membership_states_map_to_levels_including_grace_and_missing_node_keys() {
        // Fake: expiry 15, grace 3 → removal at 18.
        let mut f = fake();
        f.api.status.exit_pending = false;
        f.api.status.is_active_authority = true;
        f.api.status.current_session = 12;
        assert_eq!(
            by(&run(&f, &cmd(), (1, 1)), "membership").level,
            Level::Ok,
            "removal is 6 sessions away"
        );
        f.api.status.current_session = 16;
        assert_eq!(
            by(&run(&f, &cmd(), (1, 1)), "membership").level,
            Level::Warn,
            "in grace (expiry 15 passed), removal in 2"
        );
        f.api.params.renewal_grace_sessions = 1; // removal at 16 and validity not yet expired (session 14): 2 left ≤ 3
        f.api.status.current_session = 14;
        assert_eq!(
            by(&run(&f, &cmd(), (1, 1)), "membership").level,
            Level::Warn,
            "member whose removal is within the warning window"
        );
        f.api.params.renewal_grace_sessions = 3;
        f.api.has_keys = Some(false);
        let m = by(&run(&f, &cmd(), (1, 1)), "membership").clone();
        assert_eq!(
            m.level,
            Level::Fail,
            "on-chain keys the node does not hold: {m:?}"
        );
        f.api.has_keys = Some(true);
        f.api.status.is_banned = true;
        assert_eq!(
            by(&run(&f, &cmd(), (1, 1)), "membership").level,
            Level::Fail
        );
    }

    #[test]
    fn an_unreachable_node_fails_the_first_check_and_marks_the_rest_unknown() {
        struct Dead;
        impl Transport for Dead {
            fn call(&self, _: &str, _: Value) -> Result<Value, String> {
                Err("connection refused".into())
            }
        }
        let cs = run_checks(&Dead, &cmd(), 0, &|_| {});
        assert_eq!(by(&cs, "rpc").level, Level::Fail);
        assert!([
            "genesis",
            "sync",
            "finality",
            "peers",
            "role",
            "membership",
            "clock"
        ]
        .iter()
        .all(|i| by(&cs, i).level == Level::Unknown));
        assert_eq!(overall(&cs), Level::Fail);
        assert_eq!(exit_code(Level::Fail), 2);
    }

    #[test]
    fn disk_and_clock_thresholds() {
        const G: u64 = 1 << 30;
        assert_eq!(disk_level(500 * G, 1000 * G), Level::Ok);
        assert_eq!(disk_level(8 * G, 100 * G), Level::Warn);
        assert_eq!(disk_level(50 * G, 1000 * G), Level::Warn, "under 15%");
        assert_eq!(disk_level(G, 1000 * G), Level::Fail);
        assert_eq!(disk_level(0, 0), Level::Unknown);
        assert_eq!(clock_level(1_000_000, 1_002_000, true).0, Level::Ok);
        assert_eq!(clock_level(1_000_000, 1_012_000, true).0, Level::Warn);
        assert_eq!(clock_level(1_000_000, 1_060_000, true).0, Level::Fail);
        assert_eq!(
            clock_level(1_000_000, 500_000, false).0,
            Level::Unknown,
            "a stalled chain is not a clock reference"
        );
        let mut f = fake();
        f.timestamp_ms = 1_000_000 - 90_000;
        assert_eq!(
            by(&run(&f, &cmd(), (2, 2)), "clock").level,
            Level::Fail,
            "local clock 90s ahead of the chain"
        );
    }

    #[test]
    fn overall_is_the_worst_and_unknown_does_not_hide_a_failure() {
        let c = |l| check("x", "x", l, "", None);
        assert_eq!(overall(&[c(Level::Ok), c(Level::Unknown)]), Level::Unknown);
        assert_eq!(
            overall(&[
                c(Level::Ok),
                c(Level::Unknown),
                c(Level::Fail),
                c(Level::Warn)
            ]),
            Level::Fail
        );
        assert_eq!(exit_code(overall(&[c(Level::Ok)])), 0);
    }

    #[test]
    fn a_shared_report_leaks_no_paths_addresses_peer_ids_users_or_full_accounts() {
        let raw = "path C:\\Users\\alice\\data\\chains; /home/bob/madar/db; connection 192.168.1.20:30333 with 12D3KooWABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef; account 5G3u2gA7TMMyjRrycwubzx4gLzY4SeuMwwVisxp4xfZw3mxx (alice)";
        let out = redact(raw, &["alice".to_string(), "bob".to_string()]);
        for leak in [
            "C:\\Users",
            "/home/bob",
            "192.168.1.20",
            "12D3KooW",
            "5G3u2gA7TMMyjRrycwubzx4gLzY4SeuMwwVisxp4xfZw3mxx",
            "alice",
            "/madar/db",
        ] {
            assert!(!out.contains(leak), "{leak} leaked in: {out}");
        }
        assert!(out.contains("5G3u2g…3mxx"), "{out}");
    }
}
