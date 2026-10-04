//! Turns probes into issues, and issues into alerts: one message when a problem starts, a reminder while it lasts,
//! one message when it is resolved. No flapping spam: a node is "down" only after N consecutive failures.

use crate::config::{NodeCfg, Thresholds};
use crate::probe::Probe;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Issue {
    pub key: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
}

/// Memory of one node between checks.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct NodeMemory {
    pub failures: u32,
    pub last_best: Option<u64>,
    pub best_since: u64,
    pub last: Option<Probe>,
}

pub fn evaluate(
    node: &NodeCfg,
    p: &Probe,
    mem: &mut NodeMemory,
    th: &Thresholds,
    now: u64,
) -> Vec<Issue> {
    let mut out = Vec::new();
    let n = &node.name;
    if !p.ok {
        mem.failures += 1;
        if mem.failures >= th.down_after_failures {
            out.push(Issue {
                key: format!("{n}:down"),
                severity: Severity::Critical,
                title: format!("{n} is not responding"),
                detail: format!(
                    "{} failed checks in a row: {}",
                    mem.failures,
                    p.error.clone().unwrap_or_default()
                ),
            });
        }
        mem.last = Some(p.clone());
        return out;
    }
    mem.failures = 0;
    let best = p.best.unwrap_or(0);
    if mem.last_best != Some(best) {
        mem.last_best = Some(best);
        mem.best_since = now;
    } else if now.saturating_sub(mem.best_since) >= th.stall_secs {
        out.push(Issue {
            key: format!("{n}:stalled"),
            severity: Severity::Critical,
            title: format!("{n}: no new blocks"),
            detail: format!(
                "best block #{best} has not moved for {} s",
                now - mem.best_since
            ),
        });
    }
    if let (Some(b), Some(f)) = (p.best, p.finalized) {
        let lag = b.saturating_sub(f);
        if lag > th.finality_lag_blocks {
            out.push(Issue {
                key: format!("{n}:finality"),
                severity: if node.validator {
                    Severity::Critical
                } else {
                    Severity::Warning
                },
                title: format!("{n}: finality is behind"),
                detail: format!(
                    "best #{b}, finalized #{f} ({lag} blocks behind; limit {})",
                    th.finality_lag_blocks
                ),
            });
        }
    }
    if let Some(peers) = p.peers {
        if peers < th.min_peers {
            out.push(Issue {
                key: format!("{n}:peers"),
                severity: if peers == 0 {
                    Severity::Critical
                } else {
                    Severity::Warning
                },
                title: format!("{n}: too few peers"),
                detail: format!("{peers} peers (minimum {})", th.min_peers),
            });
        }
    }
    if p.syncing == Some(true) && now.saturating_sub(mem.best_since) > 0 && node.validator {
        out.push(Issue {
            key: format!("{n}:syncing"),
            severity: Severity::Warning,
            title: format!("{n} is syncing"),
            detail: "a validator that is still syncing cannot author or vote".into(),
        });
    }
    mem.last = Some(p.clone());
    out
}

pub fn disk_issue(free_pct: Option<f64>, th: &Thresholds) -> Option<Issue> {
    let f = free_pct?;
    (f < th.min_disk_free_pct).then(|| Issue {
        key: "host:disk".into(),
        severity: if f < th.min_disk_free_pct / 2.0 {
            Severity::Critical
        } else {
            Severity::Warning
        },
        title: "Disk is almost full".into(),
        detail: format!(
            "{f:.1}% free (minimum {}%) — a full disk stops the node",
            th.min_disk_free_pct
        ),
    })
}

/// What to send this round.
#[derive(Debug, Clone, PartialEq)]
pub enum Notice {
    Opened(Issue),
    Reminder(Issue, u64),
    Resolved(Issue),
}

#[derive(Debug, Default)]
pub struct Tracker {
    /// key -> (issue, opened_at, last_sent_at)
    pub open: BTreeMap<String, (Issue, u64, u64)>,
}

impl Tracker {
    pub fn update(&mut self, current: Vec<Issue>, now: u64, remind_minutes: u64) -> Vec<Notice> {
        let mut notices = Vec::new();
        let keys: Vec<String> = current.iter().map(|i| i.key.clone()).collect();
        let resolved: Vec<String> = self
            .open
            .keys()
            .filter(|k| !keys.contains(k))
            .cloned()
            .collect();
        for k in resolved {
            if let Some((issue, _, _)) = self.open.remove(&k) {
                notices.push(Notice::Resolved(issue));
            }
        }
        for issue in current {
            match self.open.get_mut(&issue.key) {
                None => {
                    self.open
                        .insert(issue.key.clone(), (issue.clone(), now, now));
                    notices.push(Notice::Opened(issue));
                }
                Some((stored, opened, last)) => {
                    *stored = issue.clone();
                    if remind_minutes > 0 && now.saturating_sub(*last) >= remind_minutes * 60 {
                        *last = now;
                        notices.push(Notice::Reminder(issue, (now - *opened) / 60));
                    }
                }
            }
        }
        notices
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(v: bool) -> NodeCfg {
        NodeCfg {
            name: "v1".into(),
            rpc: "http://x".into(),
            validator: v,
        }
    }
    fn ok(best: u64, fin: u64, peers: u32) -> Probe {
        Probe {
            ok: true,
            best: Some(best),
            finalized: Some(fin),
            peers: Some(peers),
            syncing: Some(false),
            ..Default::default()
        }
    }
    fn down() -> Probe {
        Probe {
            ok: false,
            error: Some("connection refused".into()),
            ..Default::default()
        }
    }

    #[test]
    fn down_only_after_consecutive_failures() {
        let th = Thresholds::default();
        let mut m = NodeMemory::default();
        assert!(evaluate(&node(true), &down(), &mut m, &th, 0).is_empty());
        assert!(evaluate(&node(true), &down(), &mut m, &th, 15).is_empty());
        let i = evaluate(&node(true), &down(), &mut m, &th, 30);
        assert_eq!(i[0].key, "v1:down");
        assert!(
            evaluate(&node(true), &ok(10, 9, 5), &mut m, &th, 45).is_empty(),
            "one good check clears it"
        );
    }

    #[test]
    fn stall_finality_and_peers() {
        let th = Thresholds::default();
        let mut m = NodeMemory::default();
        assert!(evaluate(&node(true), &ok(100, 98, 5), &mut m, &th, 0).is_empty());
        let i = evaluate(&node(true), &ok(100, 98, 5), &mut m, &th, 130);
        assert!(i.iter().any(|x| x.key == "v1:stalled"));
        let i = evaluate(&node(true), &ok(200, 150, 1), &mut m, &th, 140);
        assert!(i
            .iter()
            .any(|x| x.key == "v1:finality" && x.severity == Severity::Critical));
        assert!(i
            .iter()
            .any(|x| x.key == "v1:peers" && x.severity == Severity::Warning));
        let i = evaluate(&node(false), &ok(300, 250, 0), &mut m, &th, 150);
        assert!(
            i.iter()
                .any(|x| x.key == "v1:finality" && x.severity == Severity::Warning),
            "non-validator: warning only"
        );
        assert!(
            i.iter()
                .any(|x| x.key == "v1:peers" && x.severity == Severity::Critical),
            "0 peers is critical"
        );
    }

    #[test]
    fn tracker_opens_reminds_and_resolves_once() {
        let mut t = Tracker::default();
        let issue = Issue {
            key: "a".into(),
            severity: Severity::Critical,
            title: "t".into(),
            detail: "d".into(),
        };
        assert!(matches!(
            t.update(vec![issue.clone()], 0, 60)[0],
            Notice::Opened(_)
        ));
        assert!(
            t.update(vec![issue.clone()], 600, 60).is_empty(),
            "no spam inside the reminder window"
        );
        assert!(matches!(
            t.update(vec![issue.clone()], 3600, 60)[0],
            Notice::Reminder(_, 60)
        ));
        assert!(matches!(t.update(vec![], 3700, 60)[0], Notice::Resolved(_)));
        assert!(t.update(vec![], 3800, 60).is_empty());
    }

    #[test]
    fn disk_threshold() {
        let th = Thresholds::default();
        assert!(disk_issue(Some(50.0), &th).is_none());
        assert_eq!(
            disk_issue(Some(8.0), &th).unwrap().severity,
            Severity::Warning
        );
        assert_eq!(
            disk_issue(Some(3.0), &th).unwrap().severity,
            Severity::Critical
        );
    }
}
