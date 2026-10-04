//! Known scam sites and addresses (community list github.com/polkadot-js/phishing, Apache-2.0), plus our own
//! look-alike detection for sites that imitate well-known Polkadot apps.

use std::collections::HashSet;
use std::sync::RwLock;
use std::time::Duration;

const ALL_URL: &str = "https://raw.githubusercontent.com/polkadot-js/phishing/master/all.json";
const ADDR_URL: &str = "https://raw.githubusercontent.com/polkadot-js/phishing/master/address.json";

/// Well-known legitimate sites. A site that looks like one of these but is not one of them is a red flag.
pub const KNOWN_GOOD: &[&str] = &[
    "polkadot.js.org",
    "polkadot.network",
    "polkadot.com",
    "polkadot.cloud",
    "kusama.network",
    "subscan.io",
    "statescan.io",
    "subwallet.app",
    "talisman.xyz",
    "novawallet.io",
    "polkassembly.io",
    "subsquare.io",
    "hydration.net",
    "bifrost.io",
    "bifrost.app",
    "moonbeam.network",
    "astar.network",
    "acala.network",
    "phala.network",
    "unique.network",
    "kodadot.xyz",
    "interlay.io",
    "parity.io",
    "web3.foundation",
    "dotapps.io",
    "polkawallet.io",
    "fearlesswallet.io",
    "ledger.com",
    "madar-network.com",
];

#[derive(Default)]
pub struct Lists {
    deny: HashSet<String>,
    allow: HashSet<String>,
    addresses: HashSet<[u8; 32]>,
    pub updated_at: u64,
}

pub struct Phishing {
    pub lists: RwLock<Lists>,
    pub enabled: bool,
}

impl Phishing {
    pub fn new(enabled: bool) -> Phishing {
        Phishing {
            lists: RwLock::new(Lists::default()),
            enabled,
        }
    }

    pub fn refresh(&self) -> Result<(usize, usize), String> {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(60))
            .build();
        let all: serde_json::Value = agent
            .get(ALL_URL)
            .call()
            .map_err(|e| e.to_string())?
            .into_json()
            .map_err(|e| e.to_string())?;
        let addr: serde_json::Value = agent
            .get(ADDR_URL)
            .call()
            .map_err(|e| e.to_string())?
            .into_json()
            .map_err(|e| e.to_string())?;
        let set = |k: &str| -> HashSet<String> {
            all.get(k)
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str())
                        .map(|s| s.trim().to_lowercase())
                        .collect()
                })
                .unwrap_or_default()
        };
        let mut addresses = HashSet::new();
        if let Some(o) = addr.as_object() {
            for list in o.values() {
                for a in list
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|x| x.as_str())
                {
                    if let Some(k) = crate::ss58::decode(a) {
                        addresses.insert(k);
                    }
                }
            }
        }
        let deny = set("deny");
        if deny.len() < 100 {
            return Err("phishing list looks truncated; keeping the previous one".into());
        }
        let counts = (deny.len(), addresses.len());
        *self.lists.write().unwrap() = Lists {
            deny,
            allow: set("allow"),
            addresses,
            updated_at: crate::now(),
        };
        Ok(counts)
    }

    pub fn site_listed(&self, host: &str) -> bool {
        let l = self.lists.read().unwrap();
        // the host itself or any parent domain (evil.example.com is caught by example.com)
        let labels: Vec<&str> = host.split('.').collect();
        (0..labels.len().saturating_sub(1)).any(|i| {
            let d = labels[i..].join(".");
            l.deny.contains(&d) && !l.allow.contains(&d)
        })
    }

    pub fn address_listed(&self, key: &[u8; 32]) -> bool {
        self.lists.read().unwrap().addresses.contains(key)
    }

    pub fn stats(&self) -> serde_json::Value {
        let l = self.lists.read().unwrap();
        serde_json::json!({"enabled": self.enabled, "sites": l.deny.len(), "addresses": l.addresses.len(), "updated_at": l.updated_at})
    }
}

/// Host part of an origin / URL, lower-case, without port. None when it is not a web origin.
pub fn host_of(origin: &str) -> Option<(String, bool)> {
    let o = origin.trim();
    let (https, rest) = if let Some(r) = o.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = o.strip_prefix("http://") {
        (false, r)
    } else {
        return None;
    };
    let host = rest.split(['/', '?', '#']).next()?.rsplit('@').next()?;
    let host = host.split(':').next()?.trim_end_matches('.').to_lowercase();
    (!host.is_empty() && host.len() <= 253).then_some((host, https))
}

fn is_same_or_sub(host: &str, good: &str) -> bool {
    host == good || host.ends_with(&format!(".{good}"))
}

/// The site imitates a known-good one (typo, swapped letters, look-alike characters) without being it.
pub fn lookalike(host: &str) -> Option<&'static str> {
    if KNOWN_GOOD.iter().any(|g| is_same_or_sub(host, g)) {
        return None;
    }
    let skel_host = skeleton(host);
    for g in KNOWN_GOOD {
        let sg = skeleton(g);
        // compare against the same number of trailing labels as the good domain
        let n = g.split('.').count();
        let labels: Vec<&str> = skel_host.split('.').collect();
        let tail = if labels.len() >= n {
            labels[labels.len() - n..].join(".")
        } else {
            skel_host.clone()
        };
        let d = distance(&tail, &sg);
        let limit = if sg.len() >= 12 { 2 } else { 1 };
        if tail == sg || (d <= limit && sg.len() >= 8) {
            return Some(g);
        }
        // brand used as a sub-label of a different domain: polkadot.js.org.claim-airdrop.xyz
        if skel_host.contains(&format!("{sg}."))
            || skel_host.contains(&format!("{}-", sg.replace('.', "-")))
        {
            return Some(g);
        }
    }
    None
}

fn skeleton(s: &str) -> String {
    s.replace("rn", "m")
        .replace("vv", "w")
        .replace("cl", "d")
        .chars()
        .map(|c| match c {
            '0' => 'o',
            '1' | 'i' => 'l',
            '3' => 'e',
            '5' => 's',
            '@' => 'a',
            _ => c,
        })
        .collect()
}

fn distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1; b.len() + 1];
        for (j, cb) in b.iter().enumerate() {
            cur[j + 1] = (prev[j] + (ca != cb) as usize)
                .min(prev[j + 1] + 1)
                .min(cur[j] + 1);
        }
        prev = cur;
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert_eq!(
            host_of("https://Polkadot.JS.org/apps/#/accounts").unwrap(),
            ("polkadot.js.org".into(), true)
        );
        assert_eq!(
            host_of("http://user@evil.com:8080/x").unwrap(),
            ("evil.com".into(), false)
        );
        assert!(host_of("chrome-extension://abc").is_none());
    }

    #[test]
    fn lookalikes() {
        assert_eq!(lookalike("polkadot.js.org"), None);
        assert_eq!(lookalike("staking.polkadot.cloud"), None);
        assert_eq!(lookalike("app.subwallet.app"), None);
        assert_eq!(lookalike("polkadot-js.org"), Some("polkadot.js.org"));
        assert_eq!(lookalike("po1kadot.network"), Some("polkadot.network"));
        assert_eq!(
            lookalike("polkadot.js.org.claim-airdrop.xyz"),
            Some("polkadot.js.org")
        );
        assert_eq!(lookalike("subwalet.app"), Some("subwallet.app"));
        assert_eq!(lookalike("example.com"), None);
        assert_eq!(lookalike("github.com"), None);
    }
}
