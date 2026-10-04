//! Madar TxCheck — explains a Substrate / Polkadot SDK transaction before it is signed, and warns about risks.
//!
//!   madar-txcheck init [config]              write a sample madar-txcheck.toml
//!   madar-txcheck check <request.json> [config]   check one request, print the verdict
//!   madar-txcheck serve [config]             HTTP API (POST /v1/check), signed verdicts
//!
//! Every API answer is signed (Ed25519) over the exact response body: headers X-Madar-Signature / X-Madar-Key.

mod chains;
mod decode;
mod phishing;
mod rules;
mod ss58;

use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default = "d_listen")]
    listen: String,
    #[serde(default = "d_key")]
    key_file: String,
    /// Use the community scam-site / scam-address lists (downloaded from GitHub, refreshed every 6 h).
    #[serde(default = "d_true")]
    phishing_lists: bool,
    /// Optional file with one IP per line whose requests are not counted in the usage totals
    /// (e.g. the operator's own tests). Re-read every minute. Requires the proxy to send X-Real-IP.
    #[serde(default)]
    exclude_ips_file: Option<String>,
    #[serde(rename = "chain", default)]
    chains: Vec<chains::ChainCfg>,
}
fn d_listen() -> String {
    "127.0.0.1:9630".into()
}
fn d_key() -> String {
    "madar-txcheck.key".into()
}
fn d_true() -> bool {
    true
}

const SAMPLE: &str = r#"# Madar TxCheck — https://madar-network.com/txcheck/
listen = "127.0.0.1:9630"          # put a reverse proxy (TLS, rate limit) in front if you expose it
key_file = "madar-txcheck.key"     # Ed25519 key that signs every verdict (created on first start)
phishing_lists = true              # community scam lists (github.com/polkadot-js/phishing)

# Networks to read. JSON-RPC over HTTP(S). Without any [[chain]], Polkadot, Kusama and their Asset Hubs are used.
[[chain]]
name = "polkadot"
rpc = "https://rpc.polkadot.io"

[[chain]]
name = "polkadot-asset-hub"
rpc = "https://polkadot-asset-hub-rpc.polkadot.io"

# [[chain]]
# name = "my-chain"
# rpc = "http://127.0.0.1:9944"
# ss58_prefix = 42      # optional overrides when the node does not report them
# symbol = "UNIT"
# decimals = 12
"#;

fn load(path: &str) -> Config {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) if path == "madar-txcheck.toml" => String::new(),
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            std::process::exit(2)
        }
    };
    let mut c: Config = toml::from_str(&text).unwrap_or_else(|e| {
        eprintln!("config: {e}");
        std::process::exit(2)
    });
    if c.chains.is_empty() {
        c.chains = chains::defaults();
    }
    for ch in &c.chains {
        if !(ch.rpc.starts_with("http://") || ch.rpc.starts_with("https://"))
            || ch.name.is_empty()
            || ch.name.len() > 40
        {
            eprintln!(
                "config: chain \"{}\": name 1–40 chars and rpc http(s):// required",
                ch.name
            );
            std::process::exit(2);
        }
    }
    c
}

fn signing_key(path: &str) -> SigningKey {
    if let Ok(b) = std::fs::read(path) {
        if let Ok(s) = <[u8; 32]>::try_from(b.as_slice()) {
            return SigningKey::from_bytes(&s);
        }
        eprintln!("{path}: not a 32-byte key");
        std::process::exit(2);
    }
    let mut s = [0u8; 32];
    getrandom::getrandom(&mut s).expect("random");
    write_private(path, &s);
    eprintln!("created signing key {path}");
    SigningKey::from_bytes(&s)
}

#[cfg(unix)]
fn write_private(path: &str, b: &[u8]) {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("create key file");
    f.write_all(b).expect("write key");
}
#[cfg(not(unix))]
fn write_private(path: &str, b: &[u8]) {
    std::fs::write(path, b).expect("write key");
}

struct App {
    chains: chains::Chains,
    phishing: phishing::Phishing,
    key: SigningKey,
    /// Aggregate counts only (UTC day -> [ok, caution, danger]); nothing about the requests themselves.
    usage: Mutex<BTreeMap<String, [u64; 3]>>,
    exclude_file: Option<String>,
    /// (loaded at, IPs) — refreshed from exclude_file at most once a minute
    excluded: Mutex<(u64, std::collections::HashSet<String>)>,
}

/// UTC calendar day for a unix time (no date library needed).
fn utc_day(t: u64) -> String {
    let z = (t / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

impl App {
    fn is_excluded(&self, ip: &str) -> bool {
        let Some(path) = &self.exclude_file else {
            return false;
        };
        let mut ex = self.excluded.lock().unwrap();
        if now().saturating_sub(ex.0) >= 60 {
            ex.1 = std::fs::read_to_string(path)
                .map(|t| {
                    t.lines()
                        .map(|l| l.trim().to_string())
                        .filter(|l| !l.is_empty() && !l.starts_with('#'))
                        .collect()
                })
                .unwrap_or_default();
            ex.0 = now();
        }
        ex.1.contains(ip)
    }

    fn verdict(&self, req: &rules::Request, count: bool) -> serde_json::Value {
        let o = rules::check(req, &self.chains, &self.phishing);
        if count {
            let mut u = self.usage.lock().unwrap();
            u.entry(utc_day(now())).or_default()[o.verdict as usize] += 1;
            while u.len() > 3 {
                let first = u.keys().next().cloned().unwrap();
                u.remove(&first);
            }
        }
        let ar = req.lang.as_deref() == Some("ar");
        let (v, headline) = match o.verdict {
            rules::Level::Danger => ("danger", if ar { "لا توقّع" } else { "Do not sign" }),
            rules::Level::Caution => (
                "caution",
                if ar {
                    "تحقّق جيدا قبل التوقيع"
                } else {
                    "Check carefully before signing"
                },
            ),
            rules::Level::Info => (
                "ok",
                if ar {
                    "لم نجد مخاطر معروفة"
                } else {
                    "No known risks found"
                },
            ),
        };
        serde_json::json!({
            "verdict": v,
            "headline": headline,
            "actions": o.actions,
            "findings": o.findings,
            "chain": o.chain,
            "call_hash": o.call_hash,
            "calls": o.calls,
            "checked_at": now(),
            "engine": concat!("madar-txcheck ", env!("CARGO_PKG_VERSION")),
        })
    }

    fn key_hex(&self) -> String {
        format!("0x{}", hex::encode(self.key.verifying_key().to_bytes()))
    }
}

// ---------- HTTP ----------

const MAX_BODY: usize = 256 * 1024;
const MAX_CONN: usize = 64;

fn respond(s: &mut TcpStream, code: u16, body: &str, sig: Option<(&str, &str)>) {
    let reason = match code {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        413 => "Payload Too Large",
        _ => "Service Unavailable",
    };
    let extra = sig
        .map(|(sg, k)| format!("X-Madar-Signature: {sg}\r\nX-Madar-Key: {k}\r\n"))
        .unwrap_or_default();
    let _ = write!(
        s,
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nAccess-Control-Expose-Headers: X-Madar-Signature, X-Madar-Key\r\nAccess-Control-Max-Age: 86400\r\n{extra}Connection: close\r\n\r\n{body}",
        body.len()
    );
}

fn handle(app: &App, mut s: TcpStream) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = s.set_write_timeout(Some(Duration::from_secs(10)));
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
        if buf.len() > 16 * 1024 {
            return respond(&mut s, 413, r#"{"error":"headers too large"}"#, None);
        }
        match s.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split_whitespace();
    let (method, path) = (first.next().unwrap_or(""), first.next().unwrap_or("/"));
    let path = path.split('?').next().unwrap_or("/");
    let header = |name: &str| {
        head.split("\r\n").skip(1).find_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.trim().eq_ignore_ascii_case(name))
                .map(|(_, v)| v.trim().to_string())
        })
    };

    match (method, path) {
        ("OPTIONS", _) => respond(&mut s, 204, "", None),
        ("GET", "/v1/health") => {
            let mut h = serde_json::json!({"ok": true, "engine": concat!("madar-txcheck ", env!("CARGO_PKG_VERSION")), "key": app.key_hex(), "chains": app.chains.names(), "phishing": app.phishing.stats()});
            // Usage totals only for a direct local caller (the operator's own tools), never through the public proxy.
            let direct_local = s.peer_addr().map(|a| a.ip().is_loopback()).unwrap_or(false) && header("x-real-ip").is_none();
            if direct_local {
                h["usage"] = app
                    .usage
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(d, c)| (d.clone(), serde_json::json!({"ok": c[0], "caution": c[1], "danger": c[2]})))
                    .collect::<serde_json::Map<_, _>>()
                    .into();
            }
            let body = h.to_string();
            respond(&mut s, 200, &body, None)
        },
        ("GET", "/v1/key") => respond(&mut s, 200, &serde_json::json!({"key": app.key_hex(), "scheme": "ed25519", "signs": "the exact bytes of every /v1/check response body"}).to_string(), None),
        ("POST", "/v1/check") => {
            if header("transfer-encoding").is_some() {
                return respond(&mut s, 411, r#"{"error":"send Content-Length"}"#, None);
            }
            let Some(len) = header("content-length").and_then(|v| v.parse::<usize>().ok()) else {
                return respond(&mut s, 411, r#"{"error":"Content-Length required"}"#, None);
            };
            if len > MAX_BODY {
                return respond(&mut s, 413, r#"{"error":"request too large"}"#, None);
            }
            let mut body = buf[head_end..].to_vec();
            while body.len() < len {
                match s.read(&mut chunk) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => body.extend_from_slice(&chunk[..n]),
                }
            }
            body.truncate(len);
            let req: rules::Request = match serde_json::from_slice(&body) {
                Ok(r) => r,
                Err(e) => return respond(&mut s, 400, &serde_json::json!({"error": format!("bad request: {e}")}).to_string(), None),
            };
            if req.payload.is_none() && req.call.is_none() && req.raw.is_none() && req.origin.is_none() {
                return respond(&mut s, 400, r#"{"error":"send one of: payload, call, raw, origin"}"#, None);
            }
            let peer_local = s.peer_addr().map(|a| a.ip().is_loopback()).unwrap_or(false);
            let client = if peer_local { header("x-real-ip").unwrap_or_default() } else { s.peer_addr().map(|a| a.ip().to_string()).unwrap_or_default() };
            let out = app.verdict(&req, !app.is_excluded(&client)).to_string();
            let sig = format!("0x{}", hex::encode(app.key.sign(out.as_bytes()).to_bytes()));
            respond(&mut s, 200, &out, Some((&sig, &app.key_hex())))
        },
        (_, "/v1/check") => respond(&mut s, 405, r#"{"error":"use POST"}"#, None),
        _ => respond(&mut s, 404, r#"{"error":"not found — POST /v1/check, GET /v1/health, GET /v1/key"}"#, None),
    }
}

fn serve(cfg: Config) {
    let app = Arc::new(App {
        chains: chains::Chains::new(cfg.chains),
        phishing: phishing::Phishing::new(cfg.phishing_lists),
        key: signing_key(&cfg.key_file),
        usage: Mutex::default(),
        exclude_file: cfg.exclude_ips_file.clone(),
        excluded: Mutex::default(),
    });
    eprintln!("verdict signing key: {}", app.key_hex());
    {
        let a = app.clone();
        std::thread::spawn(move || {
            a.chains.warm_up();
            if a.phishing.enabled {
                loop {
                    match a.phishing.refresh() {
                        Ok((s, ad)) => eprintln!("scam lists: {s} sites, {ad} addresses"),
                        Err(e) => eprintln!("scam lists not updated: {e}"),
                    }
                    std::thread::sleep(Duration::from_secs(6 * 3600));
                }
            }
        });
    }
    let listener = std::net::TcpListener::bind(&cfg.listen).unwrap_or_else(|e| {
        eprintln!("cannot listen on {}: {e}", cfg.listen);
        std::process::exit(1)
    });
    eprintln!(
        "madar-txcheck listening on http://{}  (POST /v1/check)",
        cfg.listen
    );
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming().flatten() {
        if active.load(Ordering::SeqCst) >= MAX_CONN {
            let mut s = stream;
            respond(&mut s, 503, r#"{"error":"busy, retry shortly"}"#, None);
            continue;
        }
        active.fetch_add(1, Ordering::SeqCst);
        let (a, act) = (app.clone(), active.clone());
        std::thread::spawn(move || {
            // released even if the handler panics
            struct Slot(Arc<AtomicUsize>);
            impl Drop for Slot {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::SeqCst);
                }
            }
            let _slot = Slot(act);
            handle(&a, stream);
        });
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");
    match cmd {
        "init" => {
            let path = args.get(2).cloned().unwrap_or_else(|| "madar-txcheck.toml".into());
            if std::path::Path::new(&path).exists() {
                eprintln!("{path} already exists — not overwriting");
                std::process::exit(1);
            }
            std::fs::write(&path, SAMPLE).expect("write config");
            println!("wrote {path}");
        },
        "check" => {
            let Some(file) = args.get(2) else {
                eprintln!("usage: madar-txcheck check <request.json|-> [config]");
                std::process::exit(2)
            };
            let cfg = load(args.get(3).map(String::as_str).unwrap_or("madar-txcheck.toml"));
            let text = if file == "-" {
                let mut t = String::new();
                std::io::stdin().read_to_string(&mut t).expect("stdin");
                t
            } else {
                std::fs::read_to_string(file).expect("read request")
            };
            let req: rules::Request = serde_json::from_str(&text).unwrap_or_else(|e| {
                eprintln!("bad request: {e}");
                std::process::exit(2)
            });
            let app = App { chains: chains::Chains::new(cfg.chains), phishing: phishing::Phishing::new(cfg.phishing_lists), key: SigningKey::from_bytes(&[7; 32]), usage: Mutex::default(), exclude_file: None, excluded: Mutex::default() };
            if app.phishing.enabled {
                if let Err(e) = app.phishing.refresh() {
                    eprintln!("scam lists not loaded: {e}");
                }
            }
            println!("{}", serde_json::to_string_pretty(&app.verdict(&req, false)).unwrap());
        },
        "serve" => serve(load(args.get(2).map(String::as_str).unwrap_or("madar-txcheck.toml"))),
        "--version" | "version" => println!("madar-txcheck {}", env!("CARGO_PKG_VERSION")),
        _ => println!(
            "Madar TxCheck {} — read a transaction before you sign it\n\n  madar-txcheck init [config]                  create madar-txcheck.toml\n  madar-txcheck check <request.json|-> [config] check one request\n  madar-txcheck serve [config]                 HTTP API: POST /v1/check\n\nhttps://madar-network.com/txcheck/",
            env!("CARGO_PKG_VERSION")
        ),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn utc_days() {
        assert_eq!(super::utc_day(0), "1970-01-01");
        assert_eq!(super::utc_day(1_791_131_349), "2026-10-04");
        assert_eq!(super::utc_day(951_782_400), "2000-02-29");
    }
}
