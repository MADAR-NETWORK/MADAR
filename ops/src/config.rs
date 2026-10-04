//! madar-ops.toml — everything the operator configures. Defaults are safe and quiet.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Seconds between checks.
    #[serde(default = "d_interval")]
    pub interval_secs: u64,
    /// Local status page (loopback only by default).
    #[serde(default = "d_listen")]
    pub listen: String,
    /// Folder on the disk that holds the node database (free space is checked there).
    #[serde(default = "d_disk")]
    pub disk_path: String,
    #[serde(default)]
    pub thresholds: Thresholds,
    #[serde(rename = "node", default)]
    pub nodes: Vec<NodeCfg>,
    #[serde(default)]
    pub alerts: Alerts,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeCfg {
    pub name: String,
    /// JSON-RPC over HTTP, e.g. http://127.0.0.1:9944
    pub rpc: String,
    /// Validators get stricter checks (finality, peers).
    #[serde(default)]
    pub validator: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Thresholds {
    /// Consecutive failed checks before "down".
    pub down_after_failures: u32,
    /// Best block not moving for this long = "stalled".
    pub stall_secs: u64,
    /// best − finalized above this = finality warning.
    pub finality_lag_blocks: u64,
    pub min_peers: u32,
    /// Free disk below this percent (on the disk holding `disk_path`).
    pub min_disk_free_pct: f64,
    /// Repeat an unresolved alert every N minutes (0 = never).
    pub remind_minutes: u64,
}
impl Default for Thresholds {
    fn default() -> Self {
        Thresholds {
            down_after_failures: 3,
            stall_secs: 120,
            finality_lag_blocks: 20,
            min_peers: 2,
            min_disk_free_pct: 10.0,
            remind_minutes: 60,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Alerts {
    /// Full ntfy topic URL, e.g. https://ntfy.sh/my-secret-topic (install the ntfy app on the phone).
    pub ntfy: Option<String>,
    pub telegram_bot_token: Option<String>,
    pub telegram_chat_id: Option<String>,
    /// POSTs {"title","message","severity","node"} as JSON (Slack/Discord-compatible bridges, own systems).
    pub webhook: Option<String>,
}

fn d_interval() -> u64 {
    15
}
fn d_listen() -> String {
    "127.0.0.1:9620".into()
}
fn d_disk() -> String {
    if cfg!(windows) {
        "C:\\".into()
    } else {
        "/".into()
    }
}

impl Config {
    pub fn parse(text: &str) -> Result<Config, String> {
        let c: Config = toml::from_str(text).map_err(|e| format!("config: {e}"))?;
        c.validate()?;
        Ok(c)
    }

    fn validate(&self) -> Result<(), String> {
        if self.nodes.is_empty() {
            return Err("config: add at least one [[node]] with name and rpc".into());
        }
        if !(5..=3600).contains(&self.interval_secs) {
            return Err("config: interval_secs must be 5–3600".into());
        }
        for n in &self.nodes {
            if n.name.trim().is_empty() || n.name.len() > 40 {
                return Err("config: node name must be 1–40 characters".into());
            }
            if !(n.rpc.starts_with("http://") || n.rpc.starts_with("https://")) {
                return Err(format!(
                    "config: node \"{}\": rpc must start with http:// or https://",
                    n.name
                ));
            }
        }
        if let Some(u) = &self.alerts.ntfy {
            if !u.starts_with("https://") {
                return Err("config: alerts.ntfy must be an https:// topic URL".into());
            }
        }
        if let Some(u) = &self.alerts.webhook {
            if !u.starts_with("https://") {
                return Err("config: alerts.webhook must be https://".into());
            }
        }
        if self.alerts.telegram_bot_token.is_some() != self.alerts.telegram_chat_id.is_some() {
            return Err(
                "config: telegram needs both telegram_bot_token and telegram_chat_id".into(),
            );
        }
        Ok(())
    }
}

pub const SAMPLE: &str = r#"# Madar Ops — https://madar-network.com/ops/
# Runs next to your node. Only alert text leaves this machine.

interval_secs = 15
listen = "127.0.0.1:9620"   # local status page
disk_path = "/"              # folder on the disk with your node database (e.g. /var/lib/node)

[[node]]
name = "validator-1"
rpc = "http://127.0.0.1:9944"
validator = true

# [[node]]
# name = "rpc-node"
# rpc = "http://10.0.0.5:9944"

[thresholds]
down_after_failures = 3
stall_secs = 120
finality_lag_blocks = 20
min_peers = 2
min_disk_free_pct = 10
remind_minutes = 60

[alerts]
# Phone push: install the free "ntfy" app, subscribe to a long random topic, paste its URL here.
# ntfy = "https://ntfy.sh/your-long-random-topic"
# telegram_bot_token = "123456:ABC..."
# telegram_chat_id = "123456789"
# webhook = "https://example.com/hooks/madar-ops"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_parses_and_has_safe_defaults() {
        let c = Config::parse(SAMPLE).unwrap();
        assert_eq!(c.nodes.len(), 1);
        assert!(c.nodes[0].validator);
        assert_eq!(c.thresholds.stall_secs, 120);
        assert!(c.listen.starts_with("127.0.0.1:"));
    }

    #[test]
    fn rejects_bad_configs() {
        assert!(Config::parse("interval_secs = 15").is_err(), "no nodes");
        assert!(
            Config::parse("[[node]]\nname=\"a\"\nrpc=\"ws://x\"").is_err(),
            "bad scheme"
        );
        assert!(
            Config::parse(
                "[[node]]\nname=\"a\"\nrpc=\"http://x\"\n[alerts]\nntfy=\"http://ntfy.sh/t\""
            )
            .is_err(),
            "plain http ntfy"
        );
        assert!(
            Config::parse(
                "[[node]]\nname=\"a\"\nrpc=\"http://x\"\n[alerts]\ntelegram_chat_id=\"1\""
            )
            .is_err(),
            "half telegram"
        );
        assert!(
            Config::parse("[[node]]\nname=\"a\"\nrpc=\"http://x\"\ntypo=1").is_err(),
            "unknown field"
        );
    }
}
