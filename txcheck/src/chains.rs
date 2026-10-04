//! Networks we can read: talks to each chain's JSON-RPC once to learn its genesis, address format, token,
//! and runtime metadata (cached per runtime version, refreshed when the chain upgrades).

use crate::decode::Meta;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainCfg {
    /// Short id used in requests, e.g. "polkadot".
    pub name: String,
    /// JSON-RPC over HTTP(S).
    pub rpc: String,
    /// Optional overrides when the node does not report them.
    pub ss58_prefix: Option<u16>,
    pub symbol: Option<String>,
    pub decimals: Option<u32>,
}

pub fn defaults() -> Vec<ChainCfg> {
    let c = |n: &str, r: &str| ChainCfg {
        name: n.into(),
        rpc: r.into(),
        ss58_prefix: None,
        symbol: None,
        decimals: None,
    };
    vec![
        c("polkadot", "https://rpc.polkadot.io"),
        c(
            "polkadot-asset-hub",
            "https://polkadot-asset-hub-rpc.polkadot.io",
        ),
        c("kusama", "https://kusama-rpc.polkadot.io"),
        c(
            "kusama-asset-hub",
            "https://kusama-asset-hub-rpc.polkadot.io",
        ),
    ]
}

pub struct Info {
    pub name: String,
    pub genesis: String,
    pub prefix: u16,
    pub symbol: String,
    pub decimals: u32,
}

struct ChainState {
    cfg: ChainCfg,
    info: Option<Arc<Info>>,
    /// spec_version -> metadata
    metas: HashMap<u32, Arc<Meta>>,
    latest_spec: Option<(u32, Instant)>,
}

pub struct Chains {
    list: Vec<Mutex<ChainState>>,
    agent: ureq::Agent,
}

impl Chains {
    pub fn new(cfgs: Vec<ChainCfg>) -> Chains {
        Chains {
            list: cfgs
                .into_iter()
                .map(|cfg| {
                    Mutex::new(ChainState {
                        cfg,
                        info: None,
                        metas: HashMap::new(),
                        latest_spec: None,
                    })
                })
                .collect(),
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(25))
                .build(),
        }
    }

    fn rpc(
        &self,
        url: &str,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        let r = self
            .agent
            .post(url)
            .send_json(
                serde_json::json!({"id": 1, "jsonrpc": "2.0", "method": method, "params": params}),
            )
            .map_err(|e| format!("{method}: {e}"))?;
        let v: serde_json::Value = r.into_json().map_err(|e| format!("{method}: {e}"))?;
        if let Some(e) = v.get("error") {
            return Err(format!("{method}: {e}"));
        }
        Ok(v.get("result").cloned().unwrap_or(serde_json::Value::Null))
    }

    /// Learn genesis / prefix / token once per chain. Called at start and lazily.
    fn info_of(&self, st: &mut ChainState) -> Result<Arc<Info>, String> {
        if let Some(i) = &st.info {
            return Ok(i.clone());
        }
        let g = self.rpc(&st.cfg.rpc, "chain_getBlockHash", serde_json::json!([0]))?;
        let genesis = g.as_str().ok_or("no genesis")?.to_lowercase();
        let p = self
            .rpc(&st.cfg.rpc, "system_properties", serde_json::json!([]))
            .unwrap_or_default();
        let first = |v: &serde_json::Value| {
            if let Some(a) = v.as_array() {
                a.first().cloned().unwrap_or_default()
            } else {
                v.clone()
            }
        };
        let info = Arc::new(Info {
            name: st.cfg.name.clone(),
            genesis,
            prefix: st
                .cfg
                .ss58_prefix
                .or_else(|| {
                    p.get("ss58Format")
                        .and_then(|x| x.as_u64())
                        .map(|x| x as u16)
                })
                .unwrap_or(42),
            symbol: st
                .cfg
                .symbol
                .clone()
                .or_else(|| {
                    p.get("tokenSymbol")
                        .map(first)
                        .and_then(|x| x.as_str().map(String::from))
                })
                .unwrap_or_default(),
            decimals: st
                .cfg
                .decimals
                .or_else(|| {
                    p.get("tokenDecimals")
                        .map(first)
                        .and_then(|x| x.as_u64())
                        .map(|x| x as u32)
                })
                .unwrap_or(0),
        });
        st.info = Some(info.clone());
        Ok(info)
    }

    pub fn warm_up(&self) {
        for c in &self.list {
            let mut st = c.lock().unwrap();
            let name = st.cfg.name.clone();
            match self
                .info_of(&mut st)
                .and_then(|_| self.meta_latest(&mut st))
            {
                Ok(_) => eprintln!("chain {name}: ready"),
                Err(e) => eprintln!("chain {name}: not reachable yet ({e})"),
            }
        }
    }

    fn meta_latest(&self, st: &mut ChainState) -> Result<(u32, Arc<Meta>), String> {
        let fresh = st
            .latest_spec
            .filter(|(_, at)| at.elapsed() < Duration::from_secs(600));
        let spec = match fresh {
            Some((s, _)) => s,
            None => {
                let v = self.rpc(
                    &st.cfg.rpc,
                    "state_getRuntimeVersion",
                    serde_json::json!([]),
                )?;
                let s = v
                    .get("specVersion")
                    .and_then(|x| x.as_u64())
                    .ok_or("no specVersion")? as u32;
                st.latest_spec = Some((s, Instant::now()));
                s
            }
        };
        self.meta_for(st, spec, None).map(|m| (spec, m))
    }

    fn meta_for(
        &self,
        st: &mut ChainState,
        spec: u32,
        at: Option<&str>,
    ) -> Result<Arc<Meta>, String> {
        if let Some(m) = st.metas.get(&spec) {
            return Ok(m.clone());
        }
        let params = match at {
            Some(h) => serde_json::json!([h]),
            None => serde_json::json!([]),
        };
        let hexs = self.rpc(&st.cfg.rpc, "state_getMetadata", params)?;
        let raw = hex::decode(hexs.as_str().ok_or("no metadata")?.trim_start_matches("0x"))
            .map_err(|_| "metadata hex")?;
        let meta = Arc::new(Meta::from_bytes(&raw)?);
        if st.metas.len() >= 3 {
            let oldest = *st.metas.keys().min().unwrap();
            st.metas.remove(&oldest);
        }
        st.metas.insert(spec, meta.clone());
        Ok(meta)
    }

    /// Find a chain by name or genesis hash and return its info + the metadata matching `spec` (or latest).
    pub fn resolve(
        &self,
        name: Option<&str>,
        genesis: Option<&str>,
        spec: Option<u32>,
        block: Option<&str>,
    ) -> Result<(Arc<Info>, Arc<Meta>), Lookup> {
        let genesis = genesis.map(|g| g.to_lowercase());
        for c in &self.list {
            let mut st = c.lock().unwrap();
            let by_name = name.is_some_and(|n| n.eq_ignore_ascii_case(&st.cfg.name));
            if !by_name && genesis.is_none() {
                continue;
            }
            let info = match self.info_of(&mut st) {
                Ok(i) => i,
                Err(e) if by_name => return Err(Lookup::Unreachable(e)),
                Err(_) => continue,
            };
            if !by_name && genesis.as_deref() != Some(info.genesis.as_str()) {
                continue;
            }
            if by_name {
                if let Some(g) = &genesis {
                    if *g != info.genesis {
                        return Err(Lookup::GenesisMismatch(info));
                    }
                }
            }
            let (latest, latest_meta) = self.meta_latest(&mut st).map_err(Lookup::Unreachable)?;
            let meta = match spec {
                Some(s) if s != latest => match block.filter(|b| is_hash(b)) {
                    Some(b) => self
                        .meta_for(&mut st, s, Some(b))
                        .map_err(Lookup::Unreachable)?,
                    None => latest_meta,
                },
                _ => latest_meta,
            };
            return Ok((info, meta));
        }
        Err(Lookup::Unknown)
    }

    pub fn names(&self) -> Vec<serde_json::Value> {
        self.list
            .iter()
            .map(|c| {
                let st = c.lock().unwrap();
                serde_json::json!({"name": st.cfg.name, "ready": st.info.is_some() && !st.metas.is_empty(), "genesis": st.info.as_ref().map(|i| i.genesis.clone())})
            })
            .collect()
    }
}

pub enum Lookup {
    Unknown,
    Unreachable(String),
    GenesisMismatch(Arc<Info>),
}

pub fn is_hash(s: &str) -> bool {
    s.len() == 66 && s.starts_with("0x") && s[2..].bytes().all(|c| c.is_ascii_hexdigit())
}
