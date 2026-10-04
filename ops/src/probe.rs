//! Reads a node's state over its HTTP JSON-RPC (read-only, "safe" methods only).

use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Probe {
    pub ok: bool,
    pub error: Option<String>,
    pub best: Option<u64>,
    pub finalized: Option<u64>,
    pub peers: Option<u32>,
    pub syncing: Option<bool>,
    pub version: Option<String>,
    pub chain: Option<String>,
}

fn call(agent: &ureq::Agent, url: &str, method: &str, params: Value) -> Result<Value, String> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let resp: Value = agent
        .post(url)
        .set("Content-Type", "application/json")
        .send_json(body)
        .map_err(|e| short(&e.to_string()))?
        .into_json()
        .map_err(|e| short(&e.to_string()))?;
    if let Some(err) = resp.get("error") {
        return Err(short(&err.to_string()));
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| "empty result".into())
}

fn short(s: &str) -> String {
    s.chars().take(160).collect()
}

fn hex_number(v: &Value) -> Option<u64> {
    v.get("number")
        .and_then(|n| n.as_str())
        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
}

pub fn probe(url: &str) -> Probe {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(6))
        .build();
    let mut p = Probe::default();
    match call(&agent, url, "system_health", json!([])) {
        Ok(h) => {
            p.peers = h.get("peers").and_then(|x| x.as_u64()).map(|x| x as u32);
            p.syncing = h.get("isSyncing").and_then(|x| x.as_bool());
        }
        Err(e) => {
            p.error = Some(e);
            return p;
        }
    }
    p.best = call(&agent, url, "chain_getHeader", json!([]))
        .ok()
        .as_ref()
        .and_then(hex_number);
    if let Ok(hash) = call(&agent, url, "chain_getFinalizedHead", json!([])) {
        p.finalized = call(&agent, url, "chain_getHeader", json!([hash]))
            .ok()
            .as_ref()
            .and_then(hex_number);
    }
    p.version = call(&agent, url, "system_version", json!([]))
        .ok()
        .and_then(|v| v.as_str().map(str::to_string));
    p.chain = call(&agent, url, "system_chain", json!([]))
        .ok()
        .and_then(|v| v.as_str().map(str::to_string));
    p.ok = p.best.is_some();
    if !p.ok {
        p.error = Some("node answered health but not chain_getHeader".into());
    }
    p
}

/// Free space (percent) of the disk holding `path` — the node data usually lives next to madar-ops.
pub fn disk_free_pct(path: &std::path::Path) -> Option<f64> {
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let canon = std::fs::canonicalize(path).ok()?;
    disks
        .list()
        .iter()
        .filter(|d| canon.starts_with(d.mount_point()))
        .max_by_key(|d| d.mount_point().as_os_str().len())
        .filter(|d| d.total_space() > 0)
        .map(|d| d.available_space() as f64 * 100.0 / d.total_space() as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_block_numbers() {
        assert_eq!(hex_number(&json!({"number": "0x11f2a"})), Some(73514));
        assert_eq!(hex_number(&json!({"number": "zz"})), None);
        assert_eq!(hex_number(&json!({})), None);
    }

    #[test]
    fn unreachable_node_is_reported_not_panicking() {
        let p = probe("http://127.0.0.1:1");
        assert!(!p.ok);
        assert!(p.error.is_some());
    }
}
