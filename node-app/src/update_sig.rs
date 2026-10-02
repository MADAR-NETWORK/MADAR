//! Update-signature message shared by the app and the release tool: everything the app trusts from `latest.json`
//! (the version, the installer and its fingerprint, and the fast-sync snapshot if present) is inside the signature.

use serde_json::Value;

pub fn update_message(v: &Value) -> String {
    let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
    let snap = &v["snapshot"];
    format!(
        "MADAR-UPDATE-v1\n{}\n{}\n{}\n{}\n{}\n{}",
        s("version"),
        s("url"),
        s("sha256").to_lowercase(),
        snap["url"].as_str().unwrap_or(""),
        snap["sha256"].as_str().unwrap_or("").to_lowercase(),
        snap["block"]
            .as_u64()
            .map(|b| b.to_string())
            .unwrap_or_default(),
    )
}
