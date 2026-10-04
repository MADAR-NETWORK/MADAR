//! Madar Ops — keeps watch over Substrate / Polkadot SDK nodes and tells the operator the moment something is wrong.
//!
//!   madar-ops init                 write a sample madar-ops.toml
//!   madar-ops check [config]       one round, print the result (good for testing a config)
//!   madar-ops test-alert [config]  send a test message to every configured channel
//!   madar-ops run [config]         keep watching (status page on the configured loopback address)

mod config;
mod notify;
mod probe;
mod rules;

use config::Config;
use rules::{NodeMemory, Notice, Tracker};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn host() -> String {
    sysinfo::System::host_name().unwrap_or_else(|| "unknown-host".into())
}

#[derive(Default, serde::Serialize)]
struct Snapshot {
    checked_at: u64,
    nodes: BTreeMap<String, NodeMemory>,
    open_issues: Vec<rules::Issue>,
    disk_free_pct: Option<f64>,
    last_delivery: Vec<String>,
}

fn round(
    cfg: &Config,
    mem: &mut BTreeMap<String, NodeMemory>,
    tracker: &mut Tracker,
    snap: &Mutex<Snapshot>,
    send: bool,
) -> Vec<Notice> {
    let t = now();
    let mut issues = Vec::new();
    for n in &cfg.nodes {
        let p = probe::probe(&n.rpc);
        let m = mem.entry(n.name.clone()).or_default();
        issues.extend(rules::evaluate(n, &p, m, &cfg.thresholds, t));
    }
    let disk = probe::disk_free_pct(std::path::Path::new(&cfg.disk_path));
    issues.extend(rules::disk_issue(disk, &cfg.thresholds));
    let notices = tracker.update(issues, t, cfg.thresholds.remind_minutes);
    let mut delivery = Vec::new();
    if send {
        let h = host();
        for n in &notices {
            let m = notify::render(n, &h);
            let res = notify::send(&cfg.alerts, &m);
            eprintln!("{} {} -> {}", t, m.title, res.join(", "));
            delivery = res;
        }
    }
    let mut s = snap.lock().unwrap();
    s.checked_at = t;
    s.nodes = mem.clone();
    s.open_issues = tracker.open.values().map(|(i, _, _)| i.clone()).collect();
    s.disk_free_pct = disk;
    if !delivery.is_empty() {
        s.last_delivery = delivery;
    }
    notices
}

fn serve(addr: String, snap: Arc<Mutex<Snapshot>>) {
    let listener = match std::net::TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("status page disabled: cannot listen on {addr}: {e}");
            return;
        }
    };
    eprintln!("status page: http://{addr}/");
    for stream in listener.incoming().flatten() {
        let snap = snap.clone();
        std::thread::spawn(move || {
            let mut s = stream;
            let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(3)));
            let mut buf = [0u8; 2048];
            let n = s.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]);
            let path = req.split_whitespace().nth(1).unwrap_or("/");
            let (ctype, body) = if path == "/status.json" {
                (
                    "application/json",
                    serde_json::to_string(&*snap.lock().unwrap()).unwrap_or_default(),
                )
            } else {
                ("text/html; charset=utf-8", STATUS_PAGE.to_string())
            };
            let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        });
    }
}

const STATUS_PAGE: &str = include_str!("status.html");

fn load(path: &str) -> Config {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("cannot read {path}: {e}\nrun `madar-ops init` to create one");
        std::process::exit(2)
    });
    Config::parse(&text).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2)
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");
    let path = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "madar-ops.toml".into());
    match cmd {
        "init" => {
            if std::path::Path::new(&path).exists() {
                eprintln!("{path} already exists — not overwriting");
                std::process::exit(1);
            }
            std::fs::write(&path, config::SAMPLE).expect("write config");
            println!(
                "wrote {path} — edit the [[node]] and [alerts] sections, then: madar-ops check"
            );
        }
        "check" => {
            let cfg = load(&path);
            let snap = Mutex::new(Snapshot::default());
            let (mut mem, mut tr) = (BTreeMap::new(), Tracker::default());
            round(&cfg, &mut mem, &mut tr, &snap, false);
            let s = snap.lock().unwrap();
            for (name, m) in &s.nodes {
                match &m.last {
                    Some(p) if p.ok => println!(
                        "✓ {name}: #{} finalized #{} peers {} {}",
                        p.best.unwrap_or(0),
                        p.finalized.unwrap_or(0),
                        p.peers.unwrap_or(0),
                        p.version.clone().unwrap_or_default()
                    ),
                    Some(p) => println!("✗ {name}: {}", p.error.clone().unwrap_or_default()),
                    None => println!("? {name}"),
                }
            }
            if let Some(d) = s.disk_free_pct {
                println!("disk free: {d:.1}%");
            }
            println!(
                "{} open issue(s) (a node counts as down only after {} failed checks in `run`)",
                s.open_issues.len(),
                cfg.thresholds.down_after_failures
            );
        }
        "test-alert" => {
            let cfg = load(&path);
            let m = notify::Message {
                title: "✅ Madar Ops test".into(),
                body: format!("Alerts from {} reach you. Nothing is wrong.", host()),
                severity: "resolved",
                node: String::new(),
            };
            for line in notify::send(&cfg.alerts, &m) {
                println!("{line}");
            }
        }
        "run" => {
            let cfg = load(&path);
            let snap = Arc::new(Mutex::new(Snapshot::default()));
            {
                let s = snap.clone();
                let a = cfg.listen.clone();
                std::thread::spawn(move || serve(a, s));
            }
            eprintln!(
                "madar-ops watching {} node(s) every {} s",
                cfg.nodes.len(),
                cfg.interval_secs
            );
            let (mut mem, mut tr) = (BTreeMap::new(), Tracker::default());
            loop {
                round(&cfg, &mut mem, &mut tr, &snap, true);
                std::thread::sleep(std::time::Duration::from_secs(cfg.interval_secs));
            }
        }
        "--version" | "version" => println!("madar-ops {}", env!("CARGO_PKG_VERSION")),
        _ => {
            println!("Madar Ops {} — node monitoring and alerts\n\n  madar-ops init                 create madar-ops.toml\n  madar-ops check [config]       one check, printed\n  madar-ops test-alert [config]  send a test alert\n  madar-ops run [config]         keep watching\n\nhttps://madar-network.com/ops/", env!("CARGO_PKG_VERSION"));
        }
    }
}
