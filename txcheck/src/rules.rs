//! The judgement: what the transaction really does (in plain words) and what could hurt the signer.

use crate::chains::{Chains, Info, Lookup};
use crate::decode::{Call, Decoder, Value};
use crate::phishing::{self, Phishing};
use crate::ss58;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Info,
    Caution,
    Danger,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub level: Level,
    pub code: &'static str,
    pub message: String,
}

/// polkadot.js `SignerPayloadJSON` (what a wallet receives from a dApp). Extra fields are ignored.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Payload {
    pub address: Option<String>,
    pub block_hash: Option<String>,
    pub era: Option<String>,
    pub genesis_hash: Option<String>,
    pub method: Option<String>,
    pub spec_version: Option<serde_json::Value>,
    pub tip: Option<serde_json::Value>,
}

/// polkadot.js `SignerPayloadRaw` (a message signature request).
#[derive(Debug, Default, Deserialize)]
pub struct RawReq {
    pub address: Option<String>,
    pub data: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Network id ("polkadot", "kusama", …). Optional when `payload.genesisHash` is given.
    pub chain: Option<String>,
    pub payload: Option<Payload>,
    /// A bare call (hex) instead of a full payload.
    pub call: Option<String>,
    pub raw: Option<RawReq>,
    /// The site asking for the signature, e.g. "https://app.example.com".
    pub origin: Option<String>,
    /// "en" (default) or "ar".
    pub lang: Option<String>,
}

pub struct Ctx<'a> {
    ar: bool,
    info: Option<&'a Info>,
    signer: Option<[u8; 32]>,
    phishing: &'a Phishing,
    pub findings: Vec<Finding>,
    pub actions: Vec<String>,
}

impl<'a> Ctx<'a> {
    fn t(&self, en: String, ar: String) -> String {
        if self.ar {
            ar
        } else {
            en
        }
    }
    fn flag(&mut self, level: Level, code: &'static str, en: String, ar: String) {
        let message = self.t(en, ar);
        if !self
            .findings
            .iter()
            .any(|f| f.code == code && f.message == message)
        {
            self.findings.push(Finding {
                level,
                code,
                message,
            });
        }
    }
    fn act(&mut self, en: String, ar: String) {
        let a = self.t(en, ar);
        self.actions.push(a);
    }
    fn amount(&self, v: Option<&Value>) -> String {
        let Some(n) = v.and_then(|v| v.num()) else {
            return "?".into();
        };
        match self.info {
            Some(i) if !i.symbol.is_empty() => format!("{} {}", fmt_units(n, i.decimals), i.symbol),
            _ => format!("{n} (smallest units)"),
        }
    }
    fn who(&self, v: Option<&Value>) -> String {
        let Some(a) = v.and_then(|v| v.account()) else {
            return "?".into();
        };
        let me = self.signer.is_some() && ss58::decode(a) == self.signer;
        let s = ss58::short(a);
        if me {
            self.t(
                format!("{s} (your own account)"),
                format!("{s} (حسابك أنت)"),
            )
        } else {
            s
        }
    }
    fn is_me(&self, v: Option<&Value>) -> bool {
        self.signer.is_some() && v.and_then(|v| v.account()).and_then(ss58::decode) == self.signer
    }
}

pub fn fmt_units(n: u128, decimals: u32) -> String {
    if decimals == 0 || decimals > 38 {
        return n.to_string();
    }
    let d = 10u128.pow(decimals);
    let (i, f) = (n / d, n % d);
    if f == 0 {
        return i.to_string();
    }
    let frac = format!("{f:0>w$}", w = decimals as usize);
    format!("{i}.{}", frac.trim_end_matches('0'))
}

fn parse_num(v: &serde_json::Value) -> Option<u128> {
    match v {
        serde_json::Value::Number(n) => n.as_u64().map(u128::from),
        serde_json::Value::String(s) => match s.strip_prefix("0x") {
            Some(h) => u128::from_str_radix(h, 16).ok(),
            None => s.parse().ok(),
        },
        _ => None,
    }
}

fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    let h = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    if h.len() > 2 * 256 * 1024 {
        return None;
    }
    hex::decode(h).ok()
}

pub struct Outcome {
    pub verdict: Level,
    pub chain: Option<String>,
    pub findings: Vec<Finding>,
    pub actions: Vec<String>,
    pub calls: Vec<serde_json::Value>,
    pub call_hash: Option<String>,
}

pub fn check(req: &Request, chains: &Chains, phishing: &Phishing) -> Outcome {
    let ar = req.lang.as_deref() == Some("ar");
    let signer_str = req
        .payload
        .as_ref()
        .and_then(|p| p.address.clone())
        .or_else(|| req.raw.as_ref().and_then(|r| r.address.clone()));
    let mut cx = Ctx {
        ar,
        info: None,
        signer: signer_str.as_deref().and_then(ss58::decode),
        phishing,
        findings: vec![],
        actions: vec![],
    };
    let mut calls = vec![];
    let mut call_hash = None;

    // 1. the site asking
    if let Some(o) = &req.origin {
        match phishing::host_of(o) {
            Some((host, https)) => {
                if phishing.site_listed(&host) {
                    cx.flag(
                        Level::Danger,
                        "PHISHING_SITE",
                        format!("{host} is on the community list of known scam sites."),
                        format!("الموقع {host} مدرج في القائمة العامة للمواقع الاحتيالية."),
                    );
                }
                if let Some(g) = phishing::lookalike(&host) {
                    cx.flag(
                        Level::Danger,
                        "LOOKALIKE_SITE",
                        format!("{host} imitates {g} but is a different site."),
                        format!("الموقع {host} يقلّد {g} وهو موقع مختلف."),
                    );
                }
                if host.split('.').any(|l| l.starts_with("xn--")) {
                    cx.flag(
                        Level::Caution,
                        "PUNYCODE_SITE",
                        format!("{host} uses look-alike international characters in its name."),
                        format!("اسم الموقع {host} يستخدم حروفا دولية قد تشبه حروفا أخرى."),
                    );
                }
                let local =
                    host == "localhost" || host == "127.0.0.1" || host.ends_with(".localhost");
                if !https && !local {
                    cx.flag(
                        Level::Caution,
                        "INSECURE_SITE",
                        format!("{host} is not using a secure (https) connection."),
                        format!("الموقع {host} لا يستخدم اتصالا آمنا (https)."),
                    );
                }
            }
            None => {}
        }
    }

    // 2. the network
    let p = req.payload.as_ref();
    let spec = p
        .and_then(|p| p.spec_version.as_ref())
        .and_then(parse_num)
        .map(|x| x as u32);
    let resolved = if req.chain.is_some() || p.and_then(|p| p.genesis_hash.as_ref()).is_some() {
        Some(chains.resolve(
            req.chain.as_deref(),
            p.and_then(|p| p.genesis_hash.as_deref()),
            spec,
            p.and_then(|p| p.block_hash.as_deref()),
        ))
    } else {
        None
    };
    let (info, meta) = match resolved {
        Some(Ok((i, m))) => (Some(i), Some(m)),
        Some(Err(Lookup::GenesisMismatch(i))) => {
            cx.flag(Level::Danger, "WRONG_NETWORK", format!("This transaction is for a different network than {} — it does not match what you were told.", i.name), format!("هذه المعاملة لشبكة غير {} — لا تطابق ما أُخبرت به.", i.name));
            (None, None)
        }
        Some(Err(Lookup::Unreachable(e))) => {
            eprintln!("network not reachable: {e}");
            cx.flag(
                Level::Caution,
                "NETWORK_UNAVAILABLE",
                "We could not reach this network right now, so the transaction was not read."
                    .into(),
                "تعذّر الوصول إلى هذه الشبكة الآن، فلم تُقرأ المعاملة.".into(),
            );
            (None, None)
        }
        Some(Err(Lookup::Unknown)) => {
            cx.flag(
                Level::Caution,
                "UNKNOWN_NETWORK",
                "This network is not supported by this checker, so the transaction was not read."
                    .into(),
                "هذه الشبكة غير مدعومة في هذا الفاحص، فلم تُقرأ المعاملة.".into(),
            );
            (None, None)
        }
        None => (None, None),
    };
    cx.info = info.as_deref();
    let prefix = info.as_ref().map(|i| i.prefix).unwrap_or(42);

    // 3. raw message signature
    if let Some(r) = &req.raw {
        let d = r.data.trim();
        let bytes = hex_bytes(d).unwrap_or_else(|| d.as_bytes().to_vec());
        let wrapped = bytes.starts_with(b"<Bytes>") && bytes.ends_with(b"</Bytes>");
        if wrapped {
            let inner = String::from_utf8_lossy(&bytes[7..bytes.len() - 8]).into_owned();
            cx.act(
                format!("Sign a message: “{}”", clip(&inner)),
                format!("توقيع رسالة: «{}»", clip(&inner)),
            );
        } else {
            let looks_tx = meta.as_ref().is_some_and(|m| {
                bytes.len() > 4
                    && Decoder::new(m, prefix)
                        .call(&mut bytes.as_slice(), 0)
                        .is_ok()
            });
            if looks_tx {
                cx.flag(Level::Danger, "RAW_IS_TRANSACTION", "This “message” is really a transaction in disguise. Signing it can authorise a transfer.".into(), "هذه «الرسالة» معاملة متنكرة، وتوقيعها قد يجيز تحويلا من حسابك.".into());
            } else {
                cx.flag(
                    Level::Caution,
                    "RAW_UNWRAPPED",
                    "The site asks you to sign raw data that is not a normal readable message."
                        .into(),
                    "الموقع يطلب توقيع بيانات خام ليست رسالة مقروءة عادية.".into(),
                );
            }
        }
    }

    // 4. payload details
    if let Some(p) = p {
        if p.era.as_deref().map(str::trim) == Some("0x00") {
            cx.flag(
                Level::Caution,
                "NEVER_EXPIRES",
                "This transaction never expires: it can be submitted at any time in the future."
                    .into(),
                "هذه المعاملة لا تنتهي صلاحيتها، ويمكن إرسالها في أي وقت مستقبلا.".into(),
            );
        }
        if let (Some(tip), Some(i)) = (p.tip.as_ref().and_then(parse_num), info.as_ref()) {
            if tip > 0 && i.decimals > 0 && tip >= 10u128.pow(i.decimals.min(38)) {
                cx.flag(
                    Level::Caution,
                    "HIGH_TIP",
                    format!(
                        "Includes a large tip of {} {} to the block producer.",
                        fmt_units(tip, i.decimals),
                        i.symbol
                    ),
                    format!(
                        "تتضمن إكرامية كبيرة قدرها {} {} لمنتج الكتلة.",
                        fmt_units(tip, i.decimals),
                        i.symbol
                    ),
                );
            }
        }
    }

    // 5. the call itself
    let method = p
        .and_then(|p| p.method.clone())
        .or_else(|| req.call.clone());
    if let Some(m) = method {
        match (hex_bytes(&m), &meta) {
            (None, _) => cx.flag(
                Level::Danger,
                "UNREADABLE",
                "The transaction data is malformed. Do not sign what cannot be read.".into(),
                "بيانات المعاملة تالفة. لا توقّع ما لا يمكن قراءته.".into(),
            ),
            (Some(bytes), Some(meta)) => {
                call_hash = Some(format!("0x{}", hex::encode(blake2_256(&bytes))));
                let mut s = bytes.as_slice();
                match Decoder::new(meta, prefix).call(&mut s, 0) {
                    Ok(c) if s.is_empty() => {
                        walk(&mut cx, &c, 0);
                        calls.push(call_json(&c));
                    },
                    _ => cx.flag(Level::Danger, "UNREADABLE", "This transaction does not match the network's format. Do not sign what cannot be read.".into(), "هذه المعاملة لا تطابق صيغة الشبكة. لا توقّع ما لا يمكن قراءته.".into()),
                }
            }
            (Some(bytes), None) => {
                call_hash = Some(format!("0x{}", hex::encode(blake2_256(&bytes))))
            }
        }
    }

    let verdict = cx
        .findings
        .iter()
        .map(|f| f.level)
        .max()
        .unwrap_or(Level::Info);
    let mut findings = cx.findings;
    findings.sort_by(|a, b| b.level.cmp(&a.level));
    let chain = info.as_ref().map(|i| i.name.clone());
    Outcome {
        verdict,
        chain,
        findings,
        actions: cx.actions,
        calls,
        call_hash,
    }
}

fn clip(s: &str) -> String {
    let c: String = s.chars().filter(|c| !c.is_control()).take(140).collect();
    if s.chars().count() > 140 {
        format!("{c}…")
    } else {
        c
    }
}

pub fn blake2_256(b: &[u8]) -> [u8; 32] {
    use blake2::digest::{consts::U32, Digest};
    let mut h = blake2::Blake2b::<U32>::new();
    h.update(b);
    h.finalize().into()
}

fn walk(cx: &mut Ctx, c: &Call, depth: u32) {
    let a = &c.args;
    let f = |n: &str| Value::field(a, n);
    let pallet = c.pallet.as_str();
    let call = c.call.as_str();

    // every account touched: is any of them a known scam address?
    let mut accts = vec![];
    a.iter().for_each(|(_, v)| v.accounts(&mut accts));
    for acc in accts {
        if let Some(k) = ss58::decode(acc) {
            if cx.phishing.address_listed(&k) {
                cx.flag(
                    Level::Danger,
                    "SCAM_ADDRESS",
                    format!("{} is a reported scam address.", ss58::short(acc)),
                    format!("العنوان {} مُبلَّغ عنه كعنوان احتيال.", ss58::short(acc)),
                );
            }
        }
    }

    match (pallet, call) {
        ("Balances", "transfer" | "transfer_allow_death" | "transfer_keep_alive") => {
            let (amt, to) = (cx.amount(f("value")), cx.who(f("dest")));
            cx.act(
                format!("Send {amt} to {to}"),
                format!("إرسال {amt} إلى {to}"),
            );
        }
        ("Balances", "transfer_all") => {
            let to = cx.who(f("dest"));
            cx.act(
                format!("Send your ENTIRE balance to {to}"),
                format!("إرسال رصيدك بالكامل إلى {to}"),
            );
            if !cx.is_me(f("dest")) {
                cx.flag(
                    Level::Caution,
                    "SENDS_EVERYTHING",
                    format!("Moves all of your transferable balance to {to}."),
                    format!("تنقل كل رصيدك القابل للتحويل إلى {to}."),
                );
            }
        }
        ("Balances", c2) if c2.starts_with("force_") => admin(cx, c),
        ("Assets" | "ForeignAssets" | "PoolAssets", "transfer" | "transfer_keep_alive") => {
            let (to, n) = (
                cx.who(f("target")),
                f("amount").and_then(|v| v.num()).unwrap_or(0),
            );
            cx.act(
                format!("Send {n} units of asset {} to {to}", short_val(f("id"))),
                format!("إرسال {n} وحدة من الأصل {} إلى {to}", short_val(f("id"))),
            );
        }
        ("Assets" | "ForeignAssets" | "PoolAssets", "transfer_all") => {
            let to = cx.who(f("dest"));
            cx.act(
                format!("Send all of asset {} to {to}", short_val(f("id"))),
                format!("إرسال كل رصيدك من الأصل {} إلى {to}", short_val(f("id"))),
            );
            cx.flag(
                Level::Caution,
                "SENDS_EVERYTHING",
                format!("Moves all of this asset to {to}."),
                format!("تنقل كل رصيدك من هذا الأصل إلى {to}."),
            );
        }
        ("Assets" | "ForeignAssets" | "PoolAssets", "approve_transfer") => {
            let (to, n) = (
                cx.who(f("delegate")),
                f("amount").and_then(|v| v.num()).unwrap_or(0),
            );
            cx.act(
                format!(
                    "Allow {to} to spend up to {n} units of asset {} from your account",
                    short_val(f("id"))
                ),
                format!(
                    "السماح لـ {to} بصرف حتى {n} وحدة من الأصل {} من حسابك",
                    short_val(f("id"))
                ),
            );
            if n >= u128::MAX / 2 {
                cx.flag(
                    Level::Danger,
                    "UNLIMITED_APPROVAL",
                    format!(
                        "Gives {to} unlimited permission to take this asset from you at any time."
                    ),
                    format!("تمنح {to} صلاحية غير محدودة لأخذ هذا الأصل منك في أي وقت."),
                );
            } else {
                cx.flag(
                    Level::Caution,
                    "SPEND_APPROVAL",
                    format!(
                        "{to} will be able to take this asset from you later without asking again."
                    ),
                    format!("سيتمكن {to} من أخذ هذا الأصل منك لاحقا دون الرجوع إليك."),
                );
            }
        }
        ("Assets" | "ForeignAssets" | "PoolAssets" | "Nfts" | "Uniques", "transfer_ownership") => {
            let to = cx.who(f("owner"));
            cx.act(
                format!(
                    "Hand over ownership of {} {} to {to}",
                    pallet,
                    short_val(f("id").or(f("collection")))
                ),
                format!(
                    "نقل ملكية {} {} إلى {to}",
                    pallet,
                    short_val(f("id").or(f("collection")))
                ),
            );
            cx.flag(
                Level::Caution,
                "OWNERSHIP_TRANSFER",
                format!("You give up ownership to {to}."),
                format!("تتنازل عن الملكية لصالح {to}."),
            );
        }
        ("Nfts" | "Uniques", "transfer") => {
            let to = cx.who(f("dest"));
            cx.act(
                format!(
                    "Give NFT {}/{} to {to}",
                    short_val(f("collection")),
                    short_val(f("item"))
                ),
                format!(
                    "إعطاء الرمز غير القابل للاستبدال {}/{} إلى {to}",
                    short_val(f("collection")),
                    short_val(f("item"))
                ),
            );
        }
        ("Nfts" | "Uniques", "approve_transfer") => {
            let to = cx.who(f("delegate"));
            cx.act(
                format!(
                    "Allow {to} to move NFT {}/{}",
                    short_val(f("collection")),
                    short_val(f("item"))
                ),
                format!(
                    "السماح لـ {to} بنقل الرمز {}/{}",
                    short_val(f("collection")),
                    short_val(f("item"))
                ),
            );
            cx.flag(
                Level::Caution,
                "SPEND_APPROVAL",
                format!("{to} will be able to take this NFT later."),
                format!("سيتمكن {to} من أخذ هذا الرمز لاحقا."),
            );
        }
        ("Proxy", "add_proxy") => {
            let to = cx.who(f("delegate"));
            let kind = f("proxy_type")
                .and_then(|v| v.variant_name())
                .unwrap_or("?")
                .to_string();
            cx.act(
                format!("Give {to} “{kind}” control over your account"),
                format!("منح {to} صلاحية «{kind}» على حسابك"),
            );
            if kind == "Any" {
                cx.flag(Level::Danger, "FULL_CONTROL", format!("{to} would get FULL control of your account, including moving all your funds."), format!("سيحصل {to} على تحكم كامل بحسابك، بما في ذلك نقل كل أموالك."));
            } else {
                cx.flag(
                    Level::Caution,
                    "PARTIAL_CONTROL",
                    format!("{to} would be able to act for your account ({kind})."),
                    format!("سيتمكن {to} من التصرف نيابة عن حسابك ({kind})."),
                );
            }
        }
        ("Proxy", "remove_proxies") => {
            cx.act(
                "Remove all proxies of your account".into(),
                "إزالة جميع الوكلاء من حسابك".into(),
            );
        }
        ("Proxy", "kill_pure" | "kill_anonymous") => {
            cx.act(
                "Destroy a pure proxy account".into(),
                "إلغاء حساب وكيل مستقل".into(),
            );
            cx.flag(
                Level::Danger,
                "DESTROYS_ACCOUNT",
                "Any funds left in that pure proxy account become lost forever.".into(),
                "أي أموال متبقية في ذلك الحساب تضيع إلى الأبد.".into(),
            );
        }
        ("Proxy", "proxy" | "proxy_announced") => {
            let real = cx.who(f("real"));
            cx.act(
                format!("Act on behalf of {real}:"),
                format!("التصرف نيابة عن {real}:"),
            );
            nested(cx, f("call"), depth);
        }
        ("Utility", "batch" | "batch_all" | "force_batch") => {
            let n = match f("calls") {
                Some(Value::Seq(s)) => s.len(),
                _ => 0,
            };
            cx.act(
                format!("{n} actions in one transaction:"),
                format!("{n} إجراءات في معاملة واحدة:"),
            );
            if let Some(Value::Seq(s)) = f("calls") {
                for v in s.iter().take(64) {
                    nested(cx, Some(v), depth);
                }
            }
        }
        ("Utility", "as_derivative") => {
            cx.act(
                format!("Act from your sub-account #{}:", short_val(f("index"))),
                format!("التصرف من حسابك الفرعي رقم {}:", short_val(f("index"))),
            );
            cx.flag(
                Level::Caution,
                "SUB_ACCOUNT",
                "Acts from a hidden sub-account derived from yours.".into(),
                "تتصرف من حساب فرعي مخفي مشتق من حسابك.".into(),
            );
            nested(cx, f("call"), depth);
        }
        ("Utility", "dispatch_as" | "with_weight" | "dispatch_as_fallible" | "if_else") => {
            admin(cx, c)
        }
        ("Multisig", "as_multi" | "as_multi_threshold_1") => {
            cx.act(
                "Approve and run a shared-account (multisig) action:".into(),
                "الموافقة على إجراء حساب مشترك وتنفيذه:".into(),
            );
            nested(cx, f("call"), depth);
        }
        ("Multisig", "approve_as_multi") => {
            cx.act(
                "Approve a shared-account (multisig) action by its fingerprint only".into(),
                "الموافقة على إجراء حساب مشترك ببصمته فقط".into(),
            );
            cx.flag(Level::Caution, "BLIND_APPROVAL", "You approve an action you cannot see here (only its hash). Ask the other signers what it is.".into(), "توافق على إجراء لا يظهر هنا (بصمته فقط). اسأل بقية الموقّعين عن مضمونه.".into());
        }
        ("Sudo", _) => {
            cx.act(
                "Use the network's administrator (sudo) key:".into(),
                "استخدام مفتاح إدارة الشبكة (sudo):".into(),
            );
            cx.flag(
                Level::Danger,
                "ADMIN_ACTION",
                "This is a network administrator action. Normal users never need to sign this."
                    .into(),
                "هذا إجراء إداري للشبكة، ولا يحتاج المستخدم العادي إلى توقيعه أبدا.".into(),
            );
            nested(cx, f("call"), depth);
        }
        ("System", "remark" | "remark_with_event") => {
            let note = match f("remark") {
                Some(Value::Text(t)) => clip(t),
                Some(Value::Bytes(b)) => clip(b),
                _ => String::new(),
            };
            cx.act(
                format!("Write a public note on the chain: “{note}”"),
                format!("كتابة ملاحظة عامة على السلسلة: «{note}»"),
            );
        }
        (
            "System",
            "set_code"
            | "set_code_without_checks"
            | "authorize_upgrade"
            | "authorize_upgrade_without_checks"
            | "set_storage"
            | "kill_storage"
            | "kill_prefix",
        ) => admin(cx, c),
        ("Staking", "bond") => {
            let amt = cx.amount(f("value"));
            cx.act(
                format!("Lock {amt} for staking"),
                format!("قفل {amt} للتخزين (Staking)"),
            );
            payee(cx, f("payee"));
        }
        ("Staking", "bond_extra") => {
            let amt = cx.amount(f("max_additional"));
            cx.act(
                format!("Lock {amt} more for staking"),
                format!("قفل {amt} إضافية للتخزين"),
            );
        }
        ("Staking", "unbond") => {
            let amt = cx.amount(f("value"));
            cx.act(
                format!("Start unlocking {amt} from staking"),
                format!("بدء فك قفل {amt} من التخزين"),
            );
        }
        ("Staking", "set_payee") => {
            cx.act(
                "Change where staking rewards are paid".into(),
                "تغيير وجهة مكافآت التخزين".into(),
            );
            payee(cx, f("payee"));
        }
        ("Staking", "nominate") => {
            let n = match f("targets") {
                Some(Value::Seq(s)) => s.len(),
                _ => 0,
            };
            cx.act(
                format!("Nominate {n} validator(s)"),
                format!("ترشيح {n} من المدققين"),
            );
        }
        ("Staking", "chill") => cx.act(
            "Stop nominating / validating".into(),
            "إيقاف الترشيح أو التدقيق".into(),
        ),
        ("Staking", "withdraw_unbonded") => cx.act(
            "Withdraw unlocked staking funds".into(),
            "سحب أموال التخزين المفكوكة".into(),
        ),
        ("NominationPools", "join") => {
            let amt = cx.amount(f("amount"));
            cx.act(
                format!("Join staking pool #{} with {amt}", short_val(f("pool_id"))),
                format!(
                    "الانضمام إلى مجمع التخزين رقم {} بمبلغ {amt}",
                    short_val(f("pool_id"))
                ),
            );
        }
        ("NominationPools", "claim_payout") => cx.act(
            "Claim staking pool rewards".into(),
            "استلام مكافآت مجمع التخزين".into(),
        ),
        ("NominationPools", "unbond") => cx.act(
            "Start leaving a staking pool".into(),
            "بدء الخروج من مجمع التخزين".into(),
        ),
        ("ConvictionVoting", "vote") => cx.act(
            format!("Vote on referendum #{}", short_val(f("poll_index"))),
            format!("التصويت على الاستفتاء رقم {}", short_val(f("poll_index"))),
        ),
        ("ConvictionVoting", "delegate") => {
            let (to, amt) = (cx.who(f("to")), cx.amount(f("balance")));
            cx.act(
                format!("Delegate your votes to {to} (locks {amt})"),
                format!("تفويض أصواتك إلى {to} (يقفل {amt})"),
            );
            cx.flag(
                Level::Caution,
                "VOTE_DELEGATION",
                format!("{to} will vote with your weight until you undelegate."),
                format!("سيصوّت {to} بوزن صوتك حتى تلغي التفويض."),
            );
        }
        ("Identity", "set_identity") => cx.act(
            "Publish identity details (name, links) publicly".into(),
            "نشر بيانات هوية (اسم وروابط) بشكل علني".into(),
        ),
        ("PolkadotXcm" | "XcmPallet", "execute") => {
            cx.act(
                "Run a raw cross-chain (XCM) program".into(),
                "تشغيل برنامج عابر للسلاسل (XCM) خام".into(),
            );
            cx.flag(Level::Danger, "RAW_XCM", "A raw cross-chain program can move your assets anywhere. Only sign if you fully understand it.".into(), "برنامج عابر للسلاسل خام يمكنه نقل أصولك إلى أي مكان. لا توقّع إلا إذا فهمته تماما.".into());
        }
        ("PolkadotXcm" | "XcmPallet" | "XTokens", _)
            if call.contains("transfer") || call.contains("teleport") =>
        {
            let to = f("beneficiary")
                .map(|v| cx.who(Some(v)))
                .unwrap_or_else(|| "?".into());
            cx.act(
                format!("Move assets to another chain, for {to}"),
                format!("نقل أصول إلى سلسلة أخرى لصالح {to}"),
            );
            cx.flag(
                Level::Caution,
                "CROSS_CHAIN",
                "Sends assets to another chain. A wrong destination is usually unrecoverable."
                    .into(),
                "ترسل أصولا إلى سلسلة أخرى، والخطأ في الوجهة غالبا لا يمكن تداركه.".into(),
            );
        }
        _ => cx.act(
            format!("{pallet}: {}", call.replace('_', " ")),
            format!("{pallet}: {}", call.replace('_', " ")),
        ),
    }
}

fn nested(cx: &mut Ctx, v: Option<&Value>, depth: u32) {
    if let Some(Value::Call(c)) = v {
        if depth < 8 {
            walk(cx, c, depth + 1);
        }
    }
}

fn payee(cx: &mut Ctx, v: Option<&Value>) {
    if let Some(Value::Variant(name, _)) = v {
        if name == "Account" && !cx.is_me(v) {
            let to = cx.who(v);
            cx.flag(
                Level::Caution,
                "REWARDS_ELSEWHERE",
                format!("Staking rewards will be paid to {to}, not to you."),
                format!("ستُدفع مكافآت التخزين إلى {to} وليس إليك."),
            );
        }
    }
}

fn admin(cx: &mut Ctx, c: &Call) {
    cx.act(
        format!("Administrator action: {}.{}", c.pallet, c.call),
        format!("إجراء إداري: {}.{}", c.pallet, c.call),
    );
    cx.flag(
        Level::Danger,
        "ADMIN_ACTION",
        "This is a network administrator action. Normal users never need to sign this.".into(),
        "هذا إجراء إداري للشبكة، ولا يحتاج المستخدم العادي إلى توقيعه أبدا.".into(),
    );
}

fn short_val(v: Option<&Value>) -> String {
    match v {
        Some(Value::Num(n)) => n.clone(),
        Some(Value::Text(t)) => clip(t),
        Some(Value::Account(a)) => ss58::short(a),
        Some(Value::Variant(n, f)) if f.is_empty() => n.clone(),
        Some(v) => {
            let s = to_json(v).to_string();
            if s.len() > 60 {
                format!(
                    "{}…",
                    &s[..s.char_indices().nth(57).map(|x| x.0).unwrap_or(s.len())]
                )
            } else {
                s
            }
        }
        None => "?".into(),
    }
}

pub fn call_json(c: &Call) -> serde_json::Value {
    let mut args = serde_json::Map::new();
    for (k, v) in &c.args {
        args.insert(
            if k.is_empty() { "_".into() } else { k.clone() },
            to_json(v),
        );
    }
    serde_json::json!({"pallet": c.pallet, "call": c.call, "args": args})
}

pub fn to_json(v: &Value) -> serde_json::Value {
    use serde_json::Value as J;
    let obj = |f: &[(String, Value)]| -> J {
        if !f.is_empty() && f.iter().all(|(k, _)| k.is_empty()) {
            return J::Array(f.iter().map(|(_, v)| to_json(v)).collect());
        }
        J::Object(
            f.iter()
                .map(|(k, v)| {
                    (
                        if k.is_empty() { "_".into() } else { k.clone() },
                        to_json(v),
                    )
                })
                .collect(),
        )
    };
    match v {
        Value::Bool(b) => J::Bool(*b),
        Value::Num(n) | Value::Text(n) | Value::Bytes(n) | Value::Account(n) => {
            J::String(n.clone())
        }
        Value::Seq(s) => J::Array(s.iter().map(to_json).collect()),
        Value::Fields(f) => obj(f),
        Value::Variant(n, f) if f.is_empty() => J::String(n.clone()),
        Value::Variant(n, f) => {
            let inner = if f.len() == 1 && f[0].0.is_empty() {
                to_json(&f[0].1)
            } else {
                obj(f)
            };
            serde_json::json!({ n.clone(): inner })
        }
        Value::Call(c) => call_json(c),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units() {
        assert_eq!(fmt_units(12_500_000_000, 10), "1.25");
        assert_eq!(fmt_units(10_000_000_000, 10), "1");
        assert_eq!(fmt_units(1, 12), "0.000000000001");
        assert_eq!(fmt_units(7, 0), "7");
    }

    #[test]
    fn origin_rules_without_network() {
        let ph = Phishing::new(false);
        let chains = Chains::new(vec![]);
        let req = Request {
            origin: Some("http://po1kadot.network/claim".into()),
            ..Default::default()
        };
        let o = check(&req, &chains, &ph);
        assert_eq!(o.verdict, Level::Danger);
        assert!(o.findings.iter().any(|f| f.code == "LOOKALIKE_SITE"));
        assert!(o.findings.iter().any(|f| f.code == "INSECURE_SITE"));
        let ok = check(
            &Request {
                origin: Some("https://polkadot.js.org/apps".into()),
                ..Default::default()
            },
            &chains,
            &ph,
        );
        assert_eq!(ok.verdict, Level::Info);
    }

    #[test]
    fn unknown_network_is_not_ok() {
        let ph = Phishing::new(false);
        let chains = Chains::new(vec![]);
        let req = Request {
            chain: Some("nowhere".into()),
            call: Some("0x0000".into()),
            ..Default::default()
        };
        let o = check(&req, &chains, &ph);
        assert_eq!(o.verdict, Level::Caution);
        assert!(o.calls.is_empty());
    }
}
