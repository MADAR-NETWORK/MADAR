//! Sends alerts to the operator's channels. A failing channel never stops the others or the monitor.

use crate::config::Alerts;
use crate::rules::{Notice, Severity};
use std::time::Duration;

pub struct Message {
    pub title: String,
    pub body: String,
    pub severity: &'static str,
    pub node: String,
}

pub fn render(n: &Notice, host: &str) -> Message {
    let (prefix, issue, extra) = match n {
        Notice::Opened(i) => (
            if i.severity == Severity::Critical {
                "🔴"
            } else {
                "🟠"
            },
            i,
            String::new(),
        ),
        Notice::Reminder(i, mins) => ("⏰", i, format!(" (still open after {mins} min)")),
        Notice::Resolved(i) => ("✅", i, String::new()),
    };
    let resolved = matches!(n, Notice::Resolved(_));
    Message {
        title: format!(
            "{prefix} {}{}",
            if resolved { "Resolved: " } else { "" },
            issue.title
        ),
        body: format!("{}{extra}\nhost: {host}", issue.detail),
        severity: if resolved {
            "resolved"
        } else if issue.severity == Severity::Critical {
            "critical"
        } else {
            "warning"
        },
        node: issue.key.split(':').next().unwrap_or("").to_string(),
    }
}

/// Returns one line per channel: "ntfy: ok" / "telegram: error …".
pub fn send(cfg: &Alerts, m: &Message) -> Vec<String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .build();
    let mut out = Vec::new();
    if let Some(url) = &cfg.ntfy {
        let prio = match m.severity {
            "critical" => "5",
            "warning" => "4",
            _ => "3",
        };
        let r = agent
            .post(url)
            .set("Title", &ascii_header(&m.title))
            .set("Priority", prio)
            .set("Tags", "madar-ops")
            .send_string(&format!("{}\n{}", m.title, m.body));
        out.push(format!(
            "ntfy: {}",
            r.map(|_| "ok".to_string())
                .unwrap_or_else(|e| format!("error {e}"))
        ));
    }
    if let (Some(token), Some(chat)) = (&cfg.telegram_bot_token, &cfg.telegram_chat_id) {
        let url = format!("https://api.telegram.org/bot{token}/sendMessage");
        let r = agent.post(&url).send_json(serde_json::json!({"chat_id": chat, "text": format!("{}\n{}", m.title, m.body), "disable_web_page_preview": true}));
        // never echo the token in logs
        out.push(format!(
            "telegram: {}",
            r.map(|_| "ok".to_string()).unwrap_or_else(|e| format!(
                "error {}",
                e.to_string().replace(token.as_str(), "***")
            ))
        ));
    }
    if let Some(url) = &cfg.webhook {
        let r = agent.post(url).send_json(serde_json::json!({"title": m.title, "message": m.body, "severity": m.severity, "node": m.node, "source": "madar-ops"}));
        out.push(format!(
            "webhook: {}",
            r.map(|_| "ok".to_string())
                .unwrap_or_else(|e| format!("error {e}"))
        ));
    }
    if out.is_empty() {
        out.push("no alert channel configured — add [alerts] to receive notifications".into());
    }
    out
}

/// HTTP header values must be ASCII; keep the readable part, drop emoji/accents.
fn ascii_header(s: &str) -> String {
    let a: String = s
        .chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control())
        .collect();
    a.trim().chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Issue;

    #[test]
    fn renders_open_reminder_resolved() {
        let i = Issue {
            key: "v1:down".into(),
            severity: Severity::Critical,
            title: "v1 is not responding".into(),
            detail: "3 failed".into(),
        };
        let m = render(&Notice::Opened(i.clone()), "box");
        assert!(
            m.title.contains("v1 is not responding") && m.severity == "critical" && m.node == "v1"
        );
        assert!(render(&Notice::Reminder(i.clone(), 60), "box")
            .body
            .contains("60 min"));
        let r = render(&Notice::Resolved(i), "box");
        assert!(r.title.contains("Resolved") && r.severity == "resolved");
    }

    #[test]
    fn header_is_ascii_only() {
        assert_eq!(ascii_header("🔴 v1 is down"), "v1 is down");
    }

    #[test]
    fn no_channels_is_explained() {
        let m = Message {
            title: "t".into(),
            body: "b".into(),
            severity: "warning",
            node: "n".into(),
        };
        assert!(send(&Alerts::default(), &m)[0].contains("no alert channel"));
    }
}
