//! MADAR Node 2.0: the public node app for Windows 10/11 x64.
//!
//! - Local-only page on `127.0.0.1`: "Account" (name + email, locked after saving), then "Status".
//! - Runs `madar-node.exe` as a full (non-voting) node with no window, at Below Normal priority, on a share of the cores,
//!   with pruning and limited memory; RPC, metrics and P2P on 127.0.0.1 only (outbound connection to the gateway).
//! - Sends **only the name, the node-ID suffix and the email** to the MADAR registry once its address is set in `config.json`
//!   (no password; until then the registration is kept locally and resent automatically).
//! - Checks `latest.json` on open; if a newer version exists a mandatory update bar appears, and the update keeps `data`.
//!
//! Commands: `start` (default; opens the page) · `stop` · `status` · `serve` (internal).

#![cfg_attr(not(test), windows_subsystem = "windows")]

use std::collections::hash_map::RandomState;
use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::hash::{BuildHasher, Hasher};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

mod health;
mod tray;
mod update_sig;

/// Public key for update signatures (ed25519). The private key is kept outside the repository.
/// An update or sync snapshot without a valid signature from this key is rejected.
const UPDATE_PUBKEY_HEX: &str = "6354d4b50f7ef3b672379288ca274923e29a5f1bfd9813d13ff52afd205b9a94";

/// Verifies the `latest.json` signature over the `update_sig::update_message` message.
pub fn update_signature_ok(v: &Value) -> bool {
    signature_ok_with(v, UPDATE_PUBKEY_HEX)
}

pub fn signature_ok_with(v: &Value, pubkey_hex: &str) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let unhex = |s: &str| -> Option<Vec<u8>> {
        (s.len() % 2 == 0).then_some(())?;
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
            .collect()
    };
    let (Some(pk), Some(sig)) = (unhex(pubkey_hex), v["signature"].as_str().and_then(unhex)) else {
        return false;
    };
    let (Ok(pk), Ok(sig)) = (
        <[u8; 32]>::try_from(pk.as_slice()),
        <[u8; 64]>::try_from(sig.as_slice()),
    ) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    key.verify(
        update_sig::update_message(v).as_bytes(),
        &Signature::from_bytes(&sig),
    )
    .is_ok()
}

const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The only gateway: the primary server (full node, non-voting).
const BOOTNODE: &str =
    "/ip4/188.241.241.253/tcp/30333/p2p/12D3KooWDAr7FDtAeUx51zowWytNKeeuQfB5B2cyF4bZmDEp9j9K";
/// Backup server: a second gateway at a different hosting provider; if the primary fails, the node connects through it automatically.
const BOOTNODE_BACKUP: &str =
    "/ip4/103.254.60.222/tcp/30333/p2p/12D3KooWQqcRoYDfHLGrj7kUcNFQHnHvpcgZvKMfU1RuPRqnhuXS";
const GENESIS: &str = "0xec491025ce422aebac0a5e20fb4c868bb3dacefe56cb051060492ceedd6f5e5c";
const UI_PORT: u16 = 17766;
const RPC_PORT: u16 = 9966;
const PROM_PORT: u16 = 9636;
const P2P_PORT: u16 = 30444;
/// Length of the node-ID suffix sent to the registry (last N characters of the PeerId).
const PEER_SUFFIX_LEN: usize = 8;
const UPDATE_CHECK_EVERY: Duration = Duration::from_secs(6 * 3600);
const UPDATE_RECHECK_MIN: Duration = Duration::from_secs(60);
const REGISTRY_RETRY_SECS: u64 = 600;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
const DETACHED_PROCESS: u32 = 0x0000_0008;
const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x0000_4000;

// ---------------------------------------------------------------- Win32 (no extra crates)

#[link(name = "kernel32")]
extern "system" {
    fn AttachConsole(pid: u32) -> i32;
    fn FreeConsole() -> i32;
    fn SetConsoleCtrlHandler(handler: *const c_void, add: i32) -> i32;
    fn GenerateConsoleCtrlEvent(event: u32, group: u32) -> i32;
}
const CTRL_C_EVENT: u32 = 0;
#[link(name = "user32")]
extern "system" {
    fn MessageBoxW(hwnd: *mut c_void, text: *const u16, caption: *const u16, kind: u32) -> i32;
}
const MB_ICONERROR: u32 = 0x10;
const MB_ICONINFORMATION: u32 = 0x40;
const MB_SETFOREGROUND: u32 = 0x0001_0000;

static mut HAS_CONSOLE: bool = false;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// UI language saved in `data/settings.json` (default English). Native dialogs are English-only;
/// the page itself supports more languages.
fn ui_lang() -> String {
    load_settings(&paths())["lang"]
        .as_str()
        .unwrap_or("en")
        .to_string()
}

/// Native dialog/console message texts by fixed key (English). `_lang` is kept for future localization.
pub fn msg(key: &str, _lang: &str) -> &'static str {
    match key {
        "spec_missing" => "The chain file is missing. Please reinstall MADAR.",
        "spec_mismatch" => "The chain file does not match its official fingerprint, so the node will not start. Please reinstall MADAR from the official site.",
        "node_missing" => "The node program is missing. Please reinstall MADAR.",
        "already_running" => "MADAR is already running from this folder.",
        "start_failed" => "MADAR could not start. Please try again.",
        "page_slow" => "MADAR started, but its page is slow to open. See data\\app.log",
        "not_running" => "MADAR is not running.",
        "stopped" => "MADAR has stopped. Your data is kept.",
        "stop_timeout" => "MADAR did not stop in time. Please try again.",
        "commands" => "Commands: start | stop | status | uninstall",
        "uninstall_confirm" => "Remove MADAR Node from this computer?",
        "uninstall_data" => "Also delete your data (account and node data)?\n\nChoose No to keep it, so your account comes back if you reinstall.",
        "uninstall_done" => "MADAR Node has been removed.",
        "uninstall_done_kept" => "MADAR Node has been removed. Your data was kept in the data folder.",
        _ => "",
    }
}

/// Message to the user: in the console if launched from one, otherwise a message box.
fn notify(text: &str, error: bool) {
    // SAFETY: written once at the start of main, before any thread.
    if unsafe { HAS_CONSOLE } {
        println!("{text}");
        return;
    }
    let icon = if error {
        MB_ICONERROR
    } else {
        MB_ICONINFORMATION
    };
    let (t, c) = (wide(text), wide("MADAR"));
    // SAFETY: null-terminated UTF-16 strings that live until the end of the call.
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            t.as_ptr(),
            c.as_ptr(),
            icon | MB_SETFOREGROUND,
        )
    };
}

/// Yes/no question (defaults to "No"). In the console: `--yes` means yes, and `--delete-data` answers the data question.
fn ask_yes_no(text: &str, cli_flag: &str) -> bool {
    // SAFETY: read-only after initialization.
    if unsafe { HAS_CONSOLE } {
        return std::env::args().any(|a| a == cli_flag);
    }
    const MB_YESNO: u32 = 0x4;
    const MB_ICONQUESTION: u32 = 0x20;
    const MB_DEFBUTTON2: u32 = 0x100;
    const IDYES: i32 = 6;
    let (t, c) = (wide(text), wide("MADAR"));
    // SAFETY: null-terminated UTF-16 strings that live until the end of the call.
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            t.as_ptr(),
            c.as_ptr(),
            MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2 | MB_SETFOREGROUND,
        ) == IDYES
    }
}

/// Windows "Apps" key (current user, no admin rights): written by the installer and removed by this command.
const UNINSTALL_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\MADARNode";

/// Uninstall: confirm, then ask about the data (kept by default), graceful stop, remove autostart,
/// the shortcut and the "Apps" entry, then delete the program files after this process exits.
fn cmd_uninstall() -> i32 {
    let lang = ui_lang();
    // Safeguard: only ever delete a real MADAR install folder (VERSION with the MADAR title + chain fingerprint), so it can never reach another folder.
    let p0 = paths();
    let is_install = fs::read_to_string(p0.root.join("VERSION"))
        .map(|v| v.starts_with("MADAR Node"))
        .unwrap_or(false)
        && p0.spec_sha.exists();
    if !is_install {
        notify(
            &format!("Not a MADAR Node installation: {}", p0.root.display()),
            true,
        );
        return 2;
    }
    if !ask_yes_no(msg("uninstall_confirm", &lang), "--yes") {
        return 1;
    }
    let delete_data = ask_yes_no(msg("uninstall_data", &lang), "--delete-data");
    let p = paths();
    // Stop the app and the node if they are running (graceful stop).
    if try_lock(&p).is_none() {
        if let (Some(ui), Ok(token)) = (
            read_ports(&p).and_then(|v| v["ui"].as_u64()),
            fs::read_to_string(&p.token),
        ) {
            let _ = local_call(ui, "POST", "/api/stop", Some(token.trim()));
        }
        let deadline = Instant::now() + NODE_STOP_GRACE + Duration::from_secs(10);
        while Instant::now() < deadline && try_lock(&p).is_none() {
            std::thread::sleep(Duration::from_millis(300));
        }
    }
    // Autostart and the "Apps" entry are removed only if they belong to this installation (another copy on the machine is left alone).
    let exe_path = std::env::current_exe()
        .map(|e| e.display().to_string())
        .unwrap_or_default();
    let reg_value_has = |key: &str, value: &str, needle: &str| -> bool {
        Command::new("reg")
            .args(["query", key, "/v", value])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .to_lowercase()
                    .contains(&needle.to_lowercase())
            })
            .unwrap_or(false)
    };
    if reg_value_has(RUN_KEY, RUN_VALUE, &exe_path) {
        let _ = set_autostart(false);
    }
    let owns_apps_entry = reg_value_has(
        UNINSTALL_KEY,
        "InstallLocation",
        &p.root.display().to_string(),
    );
    let reg = |args: &[&str]| {
        let _ = Command::new("reg")
            .args(args)
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    };
    if owns_apps_entry {
        reg(&["delete", UNINSTALL_KEY, "/f"]);
    }
    // Desktop shortcut: only if it points to this installation.
    let exe = std::env::current_exe()
        .map(|e| e.display().to_string())
        .unwrap_or_default();
    let _ = powershell(&format!(
        "$l = Join-Path ([Environment]::GetFolderPath('Desktop')) 'MADAR Network.lnk'; \
         if ((Test-Path -LiteralPath $l) -and ((New-Object -ComObject WScript.Shell).CreateShortcut($l).TargetPath -eq {})) {{ Remove-Item -LiteralPath $l -Force }}",
        ps_quote(&exe)
    ));
    // Program files are deleted after this process exits (a running file cannot be deleted). Data is kept unless explicitly requested.
    let root = p.root.display().to_string();
    let mut targets: Vec<String> = ["bin", "chain", "ui"]
        .iter()
        .map(|d| format!("rmdir /s /q \"{root}\\{d}\""))
        .collect();
    for f in [
        "config.json",
        "VERSION",
        "madar.ico",
        "tray-good.ico",
        "tray-warn.ico",
        "tray-bad.ico",
        "tray-idle.ico",
    ] {
        targets.push(format!("del /f /q \"{root}\\{f}\""));
    }
    if delete_data {
        targets.push(format!("rmdir /s /q \"{root}\\data\""));
        targets.push(format!("rmdir \"{root}\""));
    }
    let script = format!("ping 127.0.0.1 -n 3 >nul & {}", targets.join(" & "));
    // raw_arg: cmd does not understand the escaped quotes Rust adds automatically, so the command is passed as is.
    let _ = Command::new("cmd")
        .raw_arg(format!("/C \"{script}\""))
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
    say(
        if delete_data {
            "uninstall_done"
        } else {
            "uninstall_done_kept"
        },
        false,
    );
    0
}

fn say(key: &str, error: bool) {
    notify(msg(key, &ui_lang()), error);
}

// ---------------------------------------------------------------- Paths and configuration

struct Paths {
    root: PathBuf,
    node_exe: PathBuf,
    spec: PathBuf,
    spec_sha: PathBuf,
    ui: PathBuf,
    config: PathBuf,
    data: PathBuf,
    base: PathBuf,
    node_log: PathBuf,
    app_log: PathBuf,
    account: PathBuf,
    registration: PathBuf,
    ports: PathBuf,
    token: PathBuf,
    lock: PathBuf,
    updates: PathBuf,
}

fn paths() -> Paths {
    let exe = std::env::current_exe().expect("exe path");
    let root = exe
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let data = root.join("data");
    Paths {
        node_exe: root.join("bin").join("madar-node.exe"),
        spec: root.join("chain").join("madar-spec.json"),
        spec_sha: root.join("chain").join("spec.sha256"),
        ui: root.join("ui").join("index.html"),
        config: root.join("config.json"),
        base: data.join("node"),
        node_log: data.join("node.log"),
        app_log: data.join("app.log"),
        account: data.join("account.json"),
        registration: data.join("registration.json"),
        ports: data.join("ports.json"),
        token: data.join("ui-token"),
        lock: data.join("app.lock"),
        updates: data.join("updates"),
        data,
        root,
    }
}

#[derive(Clone, Default)]
struct Config {
    /// MADAR registry endpoint (POST JSON). Empty = not enabled yet.
    registry_url: String,
    latest_url: String,
}

fn load_config(p: &Paths) -> Config {
    let v: Value = fs::read_to_string(&p.config)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(Value::Null);
    Config {
        registry_url: v["registry_url"].as_str().unwrap_or("").trim().to_string(),
        latest_url: v["latest_url"].as_str().unwrap_or("").trim().to_string(),
    }
}

/// Languages supported by the page (default English).
pub const LANGS: [&str; 5] = ["en", "fr", "es", "tr", "id"];

/// User settings: `data/settings.json` = {"lang": "en", ...}.
fn load_settings(p: &Paths) -> Value {
    fs::read_to_string(p.data.join("settings.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}))
}

fn save_settings(p: &Paths, v: &Value) {
    let f = p.data.join("settings.json");
    let tmp = f.with_extension("tmp");
    if fs::write(&tmp, serde_json::to_string_pretty(v).unwrap_or_default()).is_ok() {
        let _ = fs::rename(&tmp, &f);
    }
}

// Start with Windows: a value under HKCU\...\Run for the current user only (no admin rights), running `start --background`.
const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "MADAR Node";

fn autostart_enabled() -> bool {
    Command::new("reg")
        .args(["query", RUN_KEY, "/v", RUN_VALUE])
        .creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn set_autostart(on: bool) -> bool {
    let exe = std::env::current_exe()
        .map(|e| e.display().to_string())
        .unwrap_or_default();
    let mut c = Command::new("reg");
    if on {
        c.args([
            "add",
            RUN_KEY,
            "/v",
            RUN_VALUE,
            "/t",
            "REG_SZ",
            "/d",
            &format!("\"{exe}\" start --background"),
            "/f",
        ]);
    } else {
        c.args(["delete", RUN_KEY, "/v", RUN_VALUE, "/f"]);
    }
    c.creation_flags(CREATE_NO_WINDOW)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn is_madar_https(url: &str) -> bool {
    [
        "https://madar-network.com/",
        "https://www.madar-network.com/",
    ]
    .iter()
    .any(|p| url.starts_with(p))
}

fn is_loopback_http(url: &str) -> bool {
    url.starts_with("http://127.0.0.1:") || url.starts_with("http://localhost:")
}

/// The registry receives email addresses: HTTPS on the MADAR domain only (or loopback for local testing).
pub fn registry_url_ok(url: &str) -> bool {
    !url.contains(char::is_whitespace) && (is_madar_https(url) || is_loopback_http(url))
}

/// `latest.json`: the MADAR domain over HTTPS, or a local file/loopback (testing).
pub fn latest_url_ok(url: &str) -> bool {
    !url.contains(char::is_whitespace)
        && (is_madar_https(url) || is_loopback_http(url) || url.starts_with("file:///"))
}

/// Origin of a URL (`scheme://host[:port]/`): the update file must come from the same origin as `latest.json`.
pub fn origin(url: &str) -> Option<String> {
    if url.starts_with("file:///") {
        return Some("file:///".into());
    }
    let (scheme, rest) = url.split_once("://")?;
    let host = rest.split('/').next()?;
    (!host.is_empty()).then(|| format!("{scheme}://{host}/"))
}

pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v
        .trim()
        .trim_start_matches('v')
        .split('.')
        .map(|x| x.parse::<u64>().ok());
    let t = (it.next()??, it.next()??, it.next().unwrap_or(Some(0))?);
    Some(t)
}

// ---------------------------------------------------------------- Utilities

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn log(p: &Paths, msg: &str) {
    if fs::metadata(&p.app_log)
        .map(|m| m.len() > 5 * 1024 * 1024)
        .unwrap_or(false)
    {
        let _ = fs::rename(&p.app_log, p.data.join("app.log.1"));
    }
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&p.app_log)
    {
        let _ = writeln!(f, "{} {msg}", now_unix());
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Returns a message key (`msg`) on failure.
fn verify_spec(p: &Paths) -> Result<(), &'static str> {
    let bytes = fs::read(&p.spec).map_err(|_| "spec_missing")?;
    let expected = fs::read_to_string(&p.spec_sha)
        .unwrap_or_default()
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_lowercase();
    if hex(&Sha256::digest(&bytes)) != expected {
        return Err("spec_mismatch");
    }
    Ok(())
}

fn try_lock(p: &Paths) -> Option<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(&p.lock)
        .ok()
}

fn random_token() -> String {
    (0..4u64)
        .map(|i| {
            let mut h = RandomState::new().build_hasher();
            h.write_u64(i ^ now_unix());
            h.write_u32(std::process::id());
            format!("{:016x}", h.finish())
        })
        .collect()
}

fn pick(start: u16) -> u16 {
    (start..start + 50)
        .find(|p| TcpListener::bind(("127.0.0.1", *p)).is_ok())
        .unwrap_or(start)
}

fn read_ports(p: &Paths) -> Option<Value> {
    fs::read_to_string(&p.ports)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
}

/// Path to Microsoft Edge if present (installed by default on Windows 10/11).
fn find_edge() -> Option<PathBuf> {
    ["ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"]
        .iter()
        .filter_map(|v| std::env::var_os(v))
        .map(|d| PathBuf::from(d).join(r"Microsoft\Edge\Application\msedge.exe"))
        .find(|p| p.exists())
}

/// Opens the MADAR page in an **app window**: Edge in `--app` mode (no address bar or tabs) with a dedicated MADAR
/// profile inside data (so it shows as a separate app in the taskbar). Without Edge: the default browser.
fn open_browser(url: &str) {
    if let Some(edge) = find_edge() {
        let profile = paths().data.join("window");
        let ok = Command::new(edge)
            .arg(format!("--app={url}"))
            .arg(format!("--user-data-dir={}", profile.display()))
            .args([
                "--window-size=660,920",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-sync",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .is_ok();
        if ok {
            return;
        }
    }
    let _ = Command::new("cmd")
        .args(["/C", "start", "", url])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Hidden PowerShell with an encoded command (no quoting issues). Used for HTTPS only, since std has no TLS.
fn powershell(script: &str) -> Result<String, String> {
    let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let full = format!(
        "$ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[Text.Encoding]::UTF8; \
         [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; \
         try {{ & ([ScriptBlock]::Create([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{}')))) }} \
         catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}",
        b64(&utf16)
    );
    let enc: Vec<u8> = full.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &b64(&enc),
        ])
        .stdin(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr)
            .trim()
            .chars()
            .take(300)
            .collect())
    }
}

fn file_url_path(url: &str) -> PathBuf {
    PathBuf::from(url.trim_start_matches("file:///").replace("%20", " "))
}

fn http_get_text(url: &str) -> Result<String, String> {
    if url.starts_with("file:///") {
        return fs::read_to_string(file_url_path(url)).map_err(|e| e.to_string());
    }
    powershell(&format!(
        "$r = Invoke-WebRequest -UseBasicParsing -Uri {} -TimeoutSec 15; [Text.Encoding]::UTF8.GetString($r.RawContentStream.ToArray())",
        ps_quote(url)
    ))
}

fn http_download(url: &str, to: &Path) -> Result<(), String> {
    if url.starts_with("file:///") {
        return fs::copy(file_url_path(url), to)
            .map(|_| ())
            .map_err(|e| e.to_string());
    }
    powershell(&format!(
        "Invoke-WebRequest -UseBasicParsing -Uri {} -OutFile {} -TimeoutSec 900",
        ps_quote(url),
        ps_quote(&to.display().to_string())
    ))
    .map(|_| ())
}

fn http_post_json(url: &str, body_file: &Path) -> Result<u16, String> {
    let out = powershell(&format!(
        "$b = [IO.File]::ReadAllBytes({}); $r = Invoke-WebRequest -UseBasicParsing -Uri {} -Method Post \
         -ContentType 'application/json; charset=utf-8' -Body $b -TimeoutSec 20; 'STATUS:' + [int]$r.StatusCode",
        ps_quote(&body_file.display().to_string()),
        ps_quote(url)
    ))?;
    out.lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("STATUS:")
                .and_then(|c| c.parse().ok())
        })
        .ok_or_else(|| "Unexpected response from the registry".to_string())
}

// ---------------------------------------------------------------- Account validation

/// Display name: 3-20 characters; letters of any language, digits, space and hyphen, no links. The error is a key the page translates.
pub fn normalize_name(raw: &str) -> Result<String, &'static str> {
    let name = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if !(3..=20).contains(&name.chars().count()) {
        return Err("name_length");
    }
    // Letters and digits of any language (Latin with diacritics, Turkish, non-Latin scripts...), with no symbols, control or direction marks.
    let ok = |c: char| c.is_alphanumeric() || c == ' ' || c == '-';
    if !name.chars().all(ok) {
        return Err("name_chars");
    }
    let lower = name.to_lowercase();
    if lower.contains("http") || lower.contains("www") {
        return Err("name_link");
    }
    if name.chars().filter(|c| c.is_alphanumeric()).count() < 2 {
        return Err("name_letters");
    }
    Ok(name)
}

/// Email in a simple form: `local@domain.tld`, ASCII, no spaces, up to 254 characters.
pub fn normalize_email(raw: &str) -> Result<String, &'static str> {
    let e = raw.trim().to_lowercase();
    let bad = || Err("email_invalid");
    if e.is_empty()
        || e.len() > 254
        || !e.is_ascii()
        || e.chars()
            .any(|c| c.is_whitespace() || "<>\"'(),;:\\[]".contains(c))
    {
        return bad();
    }
    let Some((local, domain)) = e.split_once('@') else {
        return bad();
    };
    if local.is_empty()
        || local.len() > 64
        || domain.contains('@')
        || local.starts_with('.')
        || local.ends_with('.')
    {
        return bad();
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2
        || labels.iter().any(|l| {
            l.is_empty()
                || l.starts_with('-')
                || l.ends_with('-')
                || !l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
        || labels
            .last()
            .map(|t| t.len() < 2 || !t.chars().all(|c| c.is_ascii_alphabetic()))
            .unwrap_or(true)
    {
        return bad();
    }
    Ok(e)
}

pub fn peer_suffix(peer_id: &str) -> Option<String> {
    let n = peer_id.chars().count();
    (n > PEER_SUFFIX_LEN && peer_id.chars().all(|c| c.is_ascii_alphanumeric()))
        .then(|| peer_id.chars().skip(n - PEER_SUFFIX_LEN).collect())
}

/// Payload sent to the registry: exactly three fields.
pub fn registry_payload(name: &str, peer_id_suffix: &str, email: &str) -> Value {
    json!({ "name": name, "peer_id_suffix": peer_id_suffix, "email": email })
}

// ---------------------------------------------------------------- main

fn main() {
    // SAFETY: AttachConsole takes no pointers; HAS_CONSOLE is written only here, before any thread.
    unsafe { HAS_CONSOLE = AttachConsole(u32::MAX) != 0 };
    let cmd = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "start".to_string());
    let code = match cmd.as_str() {
        "start" => cmd_start(),
        "serve" => cmd_serve(),
        "stop" => cmd_stop(),
        "status" => cmd_status(),
        "uninstall" => cmd_uninstall(),
        "--version" | "version" => {
            notify(&format!("MADAR Node {VERSION}"), false);
            0
        }
        _ => {
            say("commands", false);
            2
        }
    };
    std::process::exit(code);
}

fn cmd_start() -> i32 {
    // --background: from "Start with Windows"; the node starts silently without opening the browser.
    let background = std::env::args().any(|a| a == "--background");
    let p = paths();
    let _ = fs::create_dir_all(&p.data);
    if let Err(key) = verify_spec(&p) {
        say(key, true);
        return 2;
    }
    if !p.node_exe.exists() {
        say("node_missing", true);
        return 2;
    }
    match try_lock(&p) {
        // Already running: opening the shortcut again only opens the page (and the page checks for updates when it opens).
        None => {
            if background {
                return 0;
            }
            match read_ports(&p).and_then(|v| v["ui"].as_u64()) {
                Some(ui) => open_browser(&format!("http://127.0.0.1:{ui}/")),
                None => say("already_running", false),
            }
            return 0;
        }
        Some(f) => drop(f),
    }
    let _ = fs::remove_file(&p.ports);
    let spawned = Command::new(std::env::current_exe().expect("exe"))
        .arg("serve")
        .current_dir(&p.root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(
            CREATE_NO_WINDOW
                | CREATE_NEW_PROCESS_GROUP
                | DETACHED_PROCESS
                | BELOW_NORMAL_PRIORITY_CLASS,
        )
        .spawn();
    if spawned.is_err() {
        say("start_failed", true);
        return 1;
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Some(ui) = read_ports(&p).and_then(|v| v["ui"].as_u64()) {
            let url = format!("http://127.0.0.1:{ui}/");
            if !background {
                open_browser(&url);
            }
            // SAFETY: read-only after initialization.
            if unsafe { HAS_CONSOLE } {
                println!("MADAR is running in the background: {url}");
            }
            return 0;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    if !background {
        say("page_slow", true);
    }
    1
}

fn local_call(port: u64, method: &str, path: &str, token: Option<&str>) -> Option<String> {
    let mut s = TcpStream::connect_timeout(
        &([127, 0, 0, 1], port as u16).into(),
        Duration::from_secs(3),
    )
    .ok()?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
    let tok = token
        .map(|t| format!("X-Madar-Token: {t}\r\n"))
        .unwrap_or_default();
    write!(s, "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{tok}Content-Length: 0\r\nConnection: close\r\n\r\n").ok()?;
    let mut buf = String::new();
    s.read_to_string(&mut buf).ok()?;
    buf.split_once("\r\n\r\n").map(|(_, b)| b.to_string())
}

fn cmd_stop() -> i32 {
    let p = paths();
    let (Some(ui), Ok(token)) = (
        read_ports(&p).and_then(|v| v["ui"].as_u64()),
        fs::read_to_string(&p.token),
    ) else {
        say("not_running", false);
        return 0;
    };
    if TcpStream::connect_timeout(&([127, 0, 0, 1], ui as u16).into(), Duration::from_secs(2))
        .is_err()
    {
        say("not_running", false);
        return 0;
    }
    let _ = local_call(ui, "POST", "/api/stop", Some(token.trim()));
    // A graceful stop can take up to NODE_STOP_GRACE before the forced stop.
    let deadline = Instant::now() + NODE_STOP_GRACE + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(f) = try_lock(&p) {
            drop(f);
            say("stopped", false);
            return 0;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    say("stop_timeout", true);
    1
}

fn cmd_status() -> i32 {
    let p = paths();
    let Some(ports) = read_ports(&p) else {
        say("not_running", false);
        return 1;
    };
    let ui = ports["ui"].as_u64().unwrap_or(UI_PORT as u64);
    let Some(v) = local_call(ui, "GET", "/api/status", None)
        .and_then(|b| serde_json::from_str::<Value>(&b).ok())
    else {
        say("not_running", false);
        return 1;
    };
    let show = |x: &Value| {
        if x.is_null() {
            "—".to_string()
        } else {
            x.to_string()
        }
    };
    let text = format!(
        "Name: {}\nState: {}\nBest block: {} · Finalized: {} · Peers: {} · Sync: {}%\nRegistry: {}\nVersion: {}{}\nPage: http://127.0.0.1:{ui}/",
        v["account"]["name"].as_str().unwrap_or("—"),
        v["state"].as_str().unwrap_or("—"),
        show(&v["best"]),
        show(&v["finalized"]),
        show(&v["peers"]),
        show(&v["sync"]["percent"]),
        v["registration"]["state"].as_str().unwrap_or("—"),
        VERSION,
        v["update"]["available"].as_str().map(|n| format!(" (update {n} required)")).unwrap_or_default(),
    );
    notify(&text, false);
    // SAFETY: read-only after initialization.
    if let (true, Some(rpc)) = (unsafe { HAS_CONSOLE }, ports["rpc"].as_u64()) {
        println!("\nNode check (read-only, 30 seconds):");
        let _ = Command::new(&p.node_exe)
            .args([
                "doctor",
                "--rpc",
                &format!("127.0.0.1:{rpc}"),
                "--expect-role",
                "full",
                "--watch-seconds",
                "30",
            ])
            .args(["--expected-genesis-hash", GENESIS])
            .arg("--base-path")
            .arg(&p.base)
            .status();
    }
    0
}

// ---------------------------------------------------------------- serve

#[derive(Clone)]
struct Account {
    name: String,
    email: String,
}

#[derive(Default, Clone)]
struct UpdateInfo {
    checked_unix: u64,
    available: Option<String>,
    url: Option<String>,
    sha256: Option<String>,
    notes: Value,
    error: Option<String>,
    /// "downloading" | "verifying" | "launching" | "failed"
    progress: Option<String>,
    /// Signed fast-sync snapshot from `latest.json`: (url, sha256, block).
    snapshot: Option<(String, String, u64)>,
}

/// Sample every 30 seconds for the last-hour chart: (unix, best block, peers).
type Sample = (u64, u64, u64);
const HISTORY_LEN: usize = 120;

/// Device clock drift shown as a warning (seconds).
const CLOCK_BAD_SECS: f64 = 4.0;

struct State {
    ports: (u16, u16, u16, u16), // ui, rpc, prom, p2p
    token: String,
    account: Option<Account>,
    child: Option<Child>,
    stopping: bool,
    last_best: Option<u64>,
    last_best_change: Instant,
    node_started: Instant,
    restarts: u32,
    update: UpdateInfo,
    last_update_check: Option<Instant>,
    history: std::collections::VecDeque<Sample>,
    /// Blocks verified by this node since it was installed (saved in data/stats.json).
    blocks_verified: u64,
    last_counted_best: Option<u64>,
    /// Paused by saver mode: "battery" | "metered".
    paused: Option<&'static str>,
    /// Times the node stopped on its own: 3 within 10 minutes = needs repair (no blind restarts).
    crashes: Vec<Instant>,
    needs_repair: bool,
    /// "downloading" | "extracting" during fast sync from a snapshot.
    bootstrap: Option<&'static str>,
    disconnected_since: Option<Instant>,
    disconnect_notified: bool,
    health: Value,
    /// First run is being prepared (checking/downloading the snapshot); the watchdog does not intervene until it finishes.
    boot_pending: bool,
    /// "Stuck" guard (2.0.3): the last finalized number seen and when it changed, when the peerless period began, and the last self-restart.
    last_finalized: Option<u64>,
    last_finalized_change: Instant,
    no_peers_since: Option<Instant>,
    last_self_heal: Option<Instant>,
}

/// Stuck guard (pure, tested): a node running for at least 10 minutes whose **finality has been stuck for 10 minutes while its head advances** (gap >= 40 blocks),
/// or that has had **no peers for 10 minutes** => restarted once, and no more than once every 30 minutes. (Incident 2026-09-28: the device clock drifted 9 seconds, so the node got stuck
/// in an old voting round and its finality stayed stuck for hours until it was restarted manually.)
pub fn should_self_heal(
    uptime: Duration,
    lag: Option<u64>,
    finalized_still: Duration,
    no_peers_for: Option<Duration>,
    since_last_heal: Option<Duration>,
) -> bool {
    const TEN_MIN: Duration = Duration::from_secs(600);
    if uptime < TEN_MIN
        || since_last_heal
            .map(|d| d < Duration::from_secs(1800))
            .unwrap_or(false)
    {
        return false;
    }
    let finality_stuck = lag.map(|l| l >= 40).unwrap_or(false) && finalized_still >= TEN_MIN;
    let isolated = no_peers_for.map(|d| d >= TEN_MIN).unwrap_or(false);
    finality_stuck || isolated
}

fn load_account(p: &Paths) -> Option<Account> {
    let v: Value = serde_json::from_str(&fs::read_to_string(&p.account).ok()?).ok()?;
    Some(Account {
        name: v["name"].as_str()?.to_string(),
        email: v["email"].as_str()?.to_string(),
    })
}

fn load_registration(p: &Paths) -> Value {
    fs::read_to_string(&p.registration)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}))
}

fn save_registration(p: &Paths, v: &Value) {
    let tmp = p.registration.with_extension("tmp");
    if fs::write(&tmp, serde_json::to_string_pretty(v).unwrap_or_default()).is_ok() {
        let _ = fs::rename(&tmp, &p.registration);
    }
}

/// Registration state as a code only; the page translates it.
fn registration_view(p: &Paths, cfg: &Config) -> Value {
    let r = load_registration(p);
    let state = if r["sent_unix"].as_u64().is_some() {
        "sent"
    } else if r["peer_id_suffix"].as_str().is_none() {
        "waiting_peer_id"
    } else if cfg.registry_url.is_empty() {
        "waiting_registry"
    } else if !registry_url_ok(&cfg.registry_url) {
        "bad_registry"
    } else if r["last_error"].as_str().is_some() {
        "retrying"
    } else {
        "pending"
    };
    json!({ "state": state, "peer_id_suffix": r["peer_id_suffix"] })
}

fn start_node(p: &Paths, st: &mut State) {
    let Some(acc) = st.account.clone() else {
        return;
    };
    // One node only: no second launch while the first is running (otherwise they fight over the database lock).
    if node_alive(st) {
        return;
    }
    if fs::metadata(&p.node_log)
        .map(|m| m.len() > 20 * 1024 * 1024)
        .unwrap_or(false)
    {
        let _ = fs::rename(&p.node_log, p.data.join("node.log.1"));
    }
    let (Ok(out), Ok(err)) = (
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p.node_log),
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&p.node_log),
    ) else {
        log(p, "cannot open node.log");
        return;
    };
    let (_, rpc, prom, p2p) = st.ports;
    let help = load_settings(p)["help_network"].as_bool().unwrap_or(false);
    let args: Vec<String> = vec![
        "--chain".into(),
        p.spec.display().to_string(),
        "--base-path".into(),
        p.base.display().to_string(),
        "--name".into(),
        acc.name,
        "--bootnodes".into(),
        BOOTNODE.into(),
        "--bootnodes".into(),
        BOOTNODE_BACKUP.into(),
        // P2P on 127.0.0.1 only: no port open on the network and no firewall prompt; the connection is outbound to the gateway.
        // "Help the network" (optional): accepts connections from other nodes. Default is 127.0.0.1 only (outbound only).
        "--listen-addr".into(),
        if help {
            format!("/ip4/0.0.0.0/tcp/{p2p}")
        } else {
            format!("/ip4/127.0.0.1/tcp/{p2p}")
        },
        "--rpc-port".into(),
        rpc.to_string(),
        "--rpc-methods".into(),
        "safe".into(),
        "--rpc-max-connections".into(),
        "10".into(),
        "--prometheus-port".into(),
        prom.to_string(),
        "--no-telemetry".into(),
        "--no-mdns".into(),
        "--in-peers".into(),
        (if help { "16" } else { "8" }).into(),
        "--out-peers".into(),
        "4".into(),
        "--state-pruning".into(),
        "256".into(),
        "--blocks-pruning".into(),
        "4096".into(),
        "--db-cache".into(),
        "64".into(),
        "--trie-cache-size".into(),
        (64u64 * 1024 * 1024).to_string(),
        "--pool-limit".into(),
        "1024".into(),
        "--pool-kbytes".into(),
        "4096".into(),
        "--max-runtime-instances".into(),
        "2".into(),
    ];
    // For a graceful stop with Ctrl+C: no CREATE_NEW_PROCESS_GROUP (it disables Ctrl+C in the node), and we re-enable the inherited
    // Ctrl+C handling (the serve process itself was created in a new group, so it inherited "ignore Ctrl+C").
    // SAFETY: Win32 call with no pointers.
    unsafe { SetConsoleCtrlHandler(std::ptr::null(), 0) };
    match Command::new(&p.node_exe)
        .args(&args)
        .current_dir(&p.root)
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        .creation_flags(CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS)
        .spawn()
    {
        Ok(child) => {
            let _ = fs::write(p.data.join("node.pid"), child.id().to_string());
            limit_cores(p, child.id());
            log(p, &format!("node started pid {}", child.id()));
            st.child = Some(child);
            st.last_best_change = Instant::now();
            st.node_started = Instant::now();
        }
        Err(e) => log(p, &format!("node spawn failed: {e}")),
    }
}

/// Grace period for a graceful stop before a forced stop.
const NODE_STOP_GRACE: Duration = Duration::from_secs(30);

/// Sends Ctrl+C to the node's (hidden) console so it closes its database cleanly. The serve process has no console
/// of its own, so it briefly attaches to the node's console and ignores the signal itself.
fn send_ctrl_c(pid: u32) -> bool {
    // SAFETY: Win32 calls with no pointers; the order ensures the signal does not terminate the serve process itself.
    unsafe {
        FreeConsole();
        if AttachConsole(pid) == 0 {
            return false;
        }
        SetConsoleCtrlHandler(std::ptr::null(), 1);
        let ok = GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0) != 0;
        std::thread::sleep(Duration::from_millis(200));
        FreeConsole();
        SetConsoleCtrlHandler(std::ptr::null(), 0);
        ok
    }
}

/// Graceful stop (Ctrl+C), then forced only after `NODE_STOP_GRACE` if it has not stopped.
fn stop_node(p: &Paths, st: &mut State) {
    if let Some(mut c) = st.child.take() {
        let graceful = send_ctrl_c(c.id());
        let deadline = Instant::now() + NODE_STOP_GRACE;
        let mut exited = false;
        while graceful && Instant::now() < deadline {
            if matches!(c.try_wait(), Ok(Some(_))) {
                exited = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        if !exited {
            let _ = c.kill();
        }
        let _ = c.wait();
        log(
            p,
            if exited {
                "node stopped gracefully"
            } else {
                "node force-stopped"
            },
        );
    }
    let _ = fs::remove_file(p.data.join("node.pid"));
}

/// A node left over from a previous run: closed only if its command line carries this installation's data folder.
fn stop_orphan_node(p: &Paths) {
    let Some(pid) = fs::read_to_string(p.data.join("node.pid"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
    else {
        return;
    };
    let script = format!(
        "$x = Get-CimInstance Win32_Process -Filter 'ProcessId={pid}'; if ($x -and $x.Name -eq 'madar-node.exe' -and $x.CommandLine -and $x.CommandLine.Contains({})) {{ Stop-Process -Id {pid} -Force; 'stopped' }}",
        ps_quote(&p.base.display().to_string())
    );
    if powershell(&script)
        .map(|o| o.contains("stopped"))
        .unwrap_or(false)
    {
        log(p, &format!("stopped orphan node pid {pid}"));
        std::thread::sleep(Duration::from_secs(2));
    }
    let _ = fs::remove_file(p.data.join("node.pid"));
}

/// Half of the cores, at most 4.
fn limit_cores(p: &Paths, pid: u32) {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    if cores < 2 {
        return;
    }
    let use_cores = (cores / 2).clamp(1, 4);
    let mask: u64 = (1u64 << use_cores) - 1;
    let r = powershell(&format!(
        "(Get-Process -Id {pid}).ProcessorAffinity = {mask}"
    ));
    log(
        p,
        &format!("affinity {use_cores}/{cores} cores: {}", r.is_ok()),
    );
}

fn node_alive(st: &mut State) -> bool {
    st.child
        .as_mut()
        .map(|c| matches!(c.try_wait(), Ok(None)))
        .unwrap_or(false)
}

fn rpc(port: u16, method: &str, params: Value) -> Option<Value> {
    let body = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let mut s =
        TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), Duration::from_secs(2)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(4))).ok()?;
    write!(s, "POST / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).ok()?;
    let mut buf = String::new();
    s.read_to_string(&mut buf).ok()?;
    let v: Value = serde_json::from_str(buf.split_once("\r\n\r\n")?.1).ok()?;
    v.get("result").cloned()
}

fn hex_num(v: &Value) -> Option<u64> {
    u64::from_str_radix(v.as_str()?.trim_start_matches("0x"), 16).ok()
}

fn status_json(p: &Paths, st: &mut State) -> Value {
    let alive = node_alive(st);
    let rpc_port = st.ports.1;
    let health = if alive {
        rpc(rpc_port, "system_health", json!([]))
    } else {
        None
    };
    let best = health
        .as_ref()
        .and_then(|_| rpc(rpc_port, "chain_getHeader", json!([])))
        .and_then(|h| hex_num(&h["number"]));
    let finalized = health
        .as_ref()
        .and_then(|_| rpc(rpc_port, "chain_getFinalizedHead", json!([])))
        .and_then(|h| rpc(rpc_port, "chain_getHeader", json!([h])))
        .and_then(|h| hex_num(&h["number"]));
    if best.is_some() && best != st.last_best {
        st.last_best = best;
        st.last_best_change = Instant::now();
    }
    let peers = health.as_ref().and_then(|h| h["peers"].as_u64());
    let syncing = health
        .as_ref()
        .and_then(|h| h["isSyncing"].as_bool())
        .unwrap_or(false);
    let stalled = st.last_best_change.elapsed() > Duration::from_secs(90);
    // The state is a code only; the page translates it (multiple languages).
    let state = if st.account.is_none() {
        "needs_account"
    } else if st.bootstrap.is_some() {
        "bootstrapping"
    } else if st.needs_repair {
        "needs_repair"
    } else if st.paused.is_some() {
        "paused"
    } else if st.stopping || !alive {
        "stopped"
    } else if health.is_none() {
        "starting"
    } else if peers == Some(0) && st.node_started.elapsed() < Duration::from_secs(90) {
        "connecting"
    } else if peers == Some(0) || stalled {
        "disconnected"
    } else if syncing {
        "catching_up"
    } else {
        "running"
    };
    // Sync progress: the current block out of the highest block known to peers.
    let sync = health
        .as_ref()
        .and_then(|_| rpc(rpc_port, "system_syncState", json!([])))
        .map(|s| {
            let cur = s["currentBlock"].as_u64().unwrap_or(0);
            let high = s["highestBlock"].as_u64().unwrap_or(cur).max(cur);
            let pct = if high == 0 {
                0.0
            } else {
                (cur as f64 / high as f64 * 1000.0).floor() / 10.0
            };
            json!({ "current": cur, "highest": high, "percent": pct })
        });
    let cfg = load_config(p);
    let settings = load_settings(p);
    let u = &st.update;
    json!({
        "version": VERSION,
        "account": st.account.as_ref().map(|a| json!({"name": a.name, "email": a.email})),
        "registration": if st.account.is_some() { registration_view(p, &cfg) } else { Value::Null },
        "state": state,
        "best": best, "finalized": finalized, "peers": peers, "sync": sync,
        "uptime_secs": if alive { json!(st.node_started.elapsed().as_secs()) } else { Value::Null },
        "settings": {
            "lang": settings["lang"].as_str().unwrap_or("en"),
            "autostart": autostart_enabled(),
            "saver": settings["saver"].as_bool().unwrap_or(false),
            "help_network": settings["help_network"].as_bool().unwrap_or(false),
            "onboarded": settings["onboarded"].as_bool().unwrap_or(false),
        },
        "paused": st.paused, "bootstrap": st.bootstrap,
        "blocks_verified": st.blocks_verified,
        "history": st.history.iter().map(|(t, b, n)| json!([t, b, n])).collect::<Vec<_>>(),
        "health": st.health.clone(),
        "update": {
            "available": u.available, "notes": u.notes, "progress": u.progress,
            "error": u.error, "checked_unix": if u.checked_unix > 0 { json!(u.checked_unix) } else { Value::Null },
        },
    })
}

/// Checks `latest.json`: sets `update.available` if the published version is newer.
/// Result of checking `latest.json` after verifying the signature: available update (if any) and sync snapshot (if any).
pub struct Latest {
    pub update: Option<(String, String, String, Value)>, // version, url, sha256, notes
    pub snapshot: Option<(String, String, u64)>,         // url, sha256, block
}

/// Verifies `latest.json`: signature first (no field is trusted before it), then the origin and fingerprints. Errors are codes.
pub fn parse_latest(v: &Value, latest_url: &str) -> Result<Latest, &'static str> {
    if !update_signature_ok(v) {
        return Err("bad_signature");
    }
    let hex64 = |s: &str| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit());
    let snapshot = match (
        v["snapshot"]["url"].as_str(),
        v["snapshot"]["sha256"].as_str(),
        v["snapshot"]["block"].as_u64(),
    ) {
        (Some(u), Some(s), Some(b)) if origin(u) == origin(latest_url) && hex64(s) => {
            Some((u.to_string(), s.to_lowercase(), b))
        }
        _ => None,
    };
    let (Some(ver), Some(url), Some(sha)) = (
        v["version"].as_str(),
        v["url"].as_str(),
        v["sha256"].as_str(),
    ) else {
        return Err("latest_incomplete");
    };
    let (Some(new), Some(cur)) = (parse_version(ver), parse_version(VERSION)) else {
        return Err("version_invalid");
    };
    if new <= cur {
        return Ok(Latest {
            update: None,
            snapshot,
        });
    }
    if origin(url) != origin(latest_url) || !hex64(sha) {
        return Err("foreign_origin");
    }
    // Release notes: {"notes": {"en": "...", ...}}.
    let notes = if v["notes"].is_object() {
        v["notes"].clone()
    } else {
        Value::Null
    };
    Ok(Latest {
        update: Some((ver.to_string(), url.to_string(), sha.to_lowercase(), notes)),
        snapshot,
    })
}

fn check_update(p: &Paths, state: &Arc<Mutex<State>>) {
    let cfg = load_config(p);
    let result: Result<Latest, String> = (|| {
        if !latest_url_ok(&cfg.latest_url) {
            return Err("latest_not_set".into());
        }
        let text = http_get_text(&cfg.latest_url).map_err(|e| {
            log(p, &format!("update check failed: {e}"));
            "check_failed".to_string()
        })?;
        let v: Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))
            .map_err(|_| "latest_invalid".to_string())?;
        parse_latest(&v, &cfg.latest_url).map_err(|e| {
            log(p, &format!("latest.json rejected: {e}"));
            e.to_string()
        })
    })();
    let mut st = state.lock().unwrap();
    st.update.checked_unix = now_unix();
    match result {
        Ok(l) => {
            st.update.snapshot = l.snapshot;
            match l.update {
                Some((ver, url, sha, notes)) => {
                    if st.update.available.as_deref() != Some(ver.as_str()) {
                        log(p, &format!("update available {ver}"));
                    }
                    st.update.available = Some(ver);
                    st.update.url = Some(url);
                    st.update.sha256 = Some(sha);
                    st.update.notes = notes;
                }
                None => st.update.available = None,
            }
            st.update.error = None;
        }
        Err(e) => st.update.error = Some(e),
    }
}
/// Downloads the latest installer, verifies its fingerprint, runs it in update mode (keeps `data`), then exits.
fn apply_update(p: &Paths, state: &Arc<Mutex<State>>) {
    let (ver, url, sha) = {
        let st = state.lock().unwrap();
        match (&st.update.available, &st.update.url, &st.update.sha256) {
            (Some(v), Some(u), Some(s)) => (v.clone(), u.clone(), s.clone()),
            _ => return,
        }
    };
    let set = |s: &str, err: Option<String>| {
        let mut st = state.lock().unwrap();
        st.update.progress = Some(s.to_string());
        st.update.error = err;
    };
    set("downloading", None);
    let _ = fs::create_dir_all(&p.updates);
    let file = p.updates.join(format!(
        "MADAR-Setup-{}.exe",
        ver.replace(|c: char| !c.is_ascii_alphanumeric() && c != '.', "")
    ));
    let _ = fs::remove_file(&file);
    if let Err(e) = http_download(&url, &file) {
        log(p, &format!("update download failed: {e}"));
        return set("failed", Some("download_failed".into()));
    }
    set("verifying", None);
    let ok = fs::read(&file)
        .map(|b| hex(&Sha256::digest(&b)) == sha)
        .unwrap_or(false);
    if !ok {
        let _ = fs::remove_file(&file);
        log(p, "update sha256 mismatch");
        return set("failed", Some("sha_mismatch".into()));
    }
    set("launching", None);
    log(p, &format!("launching update {ver}"));
    let spawned = Command::new(&file)
        .args(["--update", "--dir"])
        .arg(&p.root)
        .current_dir(&p.updates)
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .spawn();
    if spawned.is_err() {
        return set("failed", Some("launch_failed".into()));
    }
    {
        let mut st = state.lock().unwrap();
        st.stopping = true;
        stop_node(p, &mut st);
    }
    std::thread::sleep(Duration::from_millis(500));
    let _ = fs::remove_file(&p.ports);
    std::process::exit(0);
}

/// Sends the registration: name + ID suffix + email only, to the registry configured in the settings, with automatic retry.
fn registration_tick(p: &Paths, state: &Arc<Mutex<State>>) {
    let (acc, rpc_port) = {
        let st = state.lock().unwrap();
        match &st.account {
            Some(a) => (a.clone(), st.ports.1),
            None => return,
        }
    };
    let mut r = load_registration(p);
    if r["sent_unix"].as_u64().is_some() {
        return;
    }
    if r["peer_id_suffix"].as_str().is_none() {
        match rpc(rpc_port, "system_localPeerId", json!([]))
            .and_then(|v| v.as_str().and_then(peer_suffix))
        {
            Some(sfx) => {
                r["peer_id_suffix"] = json!(sfx);
                save_registration(p, &r);
            }
            None => return,
        }
    }
    let cfg = load_config(p);
    if cfg.registry_url.is_empty() || !registry_url_ok(&cfg.registry_url) {
        return;
    }
    let last = r["last_attempt_unix"].as_u64().unwrap_or(0);
    if r["last_error"].is_string() && now_unix().saturating_sub(last) < REGISTRY_RETRY_SECS {
        return;
    }
    let sfx = r["peer_id_suffix"].as_str().unwrap_or_default().to_string();
    let body_file = p.data.join("registration-body.json");
    if fs::write(
        &body_file,
        registry_payload(&acc.name, &sfx, &acc.email).to_string(),
    )
    .is_err()
    {
        return;
    }
    r["last_attempt_unix"] = json!(now_unix());
    match http_post_json(&cfg.registry_url, &body_file) {
        Ok(code) if (200..300).contains(&code) => {
            r["sent_unix"] = json!(now_unix());
            r["last_error"] = Value::Null;
            log(p, &format!("registration sent ({code})"));
        }
        Ok(code) => {
            r["last_error"] = json!(format!("HTTP {code}"));
            log(p, &format!("registration rejected HTTP {code}"));
        }
        Err(e) => {
            r["last_error"] = json!(e.chars().take(200).collect::<String>());
            log(p, "registration send failed");
        }
    }
    let _ = fs::remove_file(&body_file);
    save_registration(p, &r);
}

fn load_stats(p: &Paths) -> u64 {
    fs::read_to_string(p.data.join("stats.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| v["blocks_verified"].as_u64())
        .unwrap_or(0)
}

fn save_stats(p: &Paths, blocks: u64) {
    let _ = fs::write(
        p.data.join("stats.json"),
        json!({ "blocks_verified": blocks }).to_string(),
    );
}

/// Chain database folders inside base-path (does not touch `network` = the node identity).
fn chain_db_dirs(p: &Paths) -> Vec<PathBuf> {
    fs::read_dir(p.base.join("chains"))
        .map(|d| {
            d.flatten()
                .map(|e| e.path().join("db"))
                .filter(|db| db.exists())
                .collect()
        })
        .unwrap_or_default()
}

fn tray_texts(state: &str, best: Option<u64>, peers: Option<u64>, _lang: &str) -> String {
    let label = match state {
        "running" => "Running",
        "catching_up" => "Catching up",
        "connecting" | "starting" => "Starting",
        "disconnected" => "Disconnected",
        "paused" => "Paused (saver mode)",
        "needs_repair" => "Needs repair",
        "bootstrapping" => "Fast setup",
        _ => "Stopped",
    };
    let nums = match (best, peers) {
        (Some(b), Some(n)) => format!(" · #{b} · {n} peers"),
        _ => String::new(),
    };
    format!("MADAR — {label}{nums}")
}

fn tray_labels(_lang: &str) -> (String, String) {
    ("Open MADAR".into(), "Stop node".into())
}

/// First run with no database: if the site publishes a signed snapshot, it is downloaded and extracted, then the node starts (seconds instead of a full sync).
/// Any failure = normal sync from the network, with no error shown to the user.
fn bootstrap_then_start(state: &Arc<Mutex<State>>) {
    let p = paths();
    // New network (genesis changed via an update): the old chain database is unusable, so only it is deleted; the identity and account are kept.
    let marker = p.base.join("genesis");
    if fs::read_to_string(&marker)
        .map(|g| g.trim() != GENESIS)
        .unwrap_or(true)
    {
        for db in chain_db_dirs(&p) {
            let _ = fs::remove_dir_all(&db);
            log(
                &p,
                "new network (genesis changed): old chain database removed",
            );
        }
        let _ = fs::create_dir_all(&p.base);
        let _ = fs::write(&marker, GENESIS);
    }
    if chain_db_dirs(&p).is_empty() {
        check_update(&p, state);
        let snap = state.lock().unwrap().update.snapshot.clone();
        if let Some((url, sha, block)) = snap {
            state.lock().unwrap().bootstrap = Some("downloading");
            let _ = fs::create_dir_all(&p.updates);
            let zip = p.updates.join("snapshot.zip");
            let ok = http_download(&url, &zip).is_ok()
                && fs::read(&zip)
                    .map(|b| hex(&Sha256::digest(&b)) == sha)
                    .unwrap_or(false);
            if ok {
                state.lock().unwrap().bootstrap = Some("extracting");
                let _ = fs::create_dir_all(&p.base);
                let r = powershell(&format!(
                    "Expand-Archive -LiteralPath {} -DestinationPath {} -Force",
                    ps_quote(&zip.display().to_string()),
                    ps_quote(&p.base.display().to_string())
                ));
                log(&p, &format!("snapshot #{block} applied: {}", r.is_ok()));
            } else {
                log(&p, "snapshot download/verify failed — normal sync");
            }
            let _ = fs::remove_file(&zip);
            state.lock().unwrap().bootstrap = None;
        }
    }
    let mut st = state.lock().unwrap();
    if st.account.is_some() && !st.stopping {
        start_node(&p, &mut st);
    }
    st.boot_pending = false;
}

/// Repair: delete only the chain database (the identity and account are kept), then start clean (or from a snapshot).
fn repair(state: &Arc<Mutex<State>>) {
    let p = paths();
    {
        let mut st = state.lock().unwrap();
        stop_node(&p, &mut st);
        for db in chain_db_dirs(&p) {
            let _ = fs::remove_dir_all(&db);
        }
        st.crashes.clear();
        st.needs_repair = false;
        st.last_counted_best = None;
        st.boot_pending = true;
        log(&p, "repair: chain database removed");
    }
    bootstrap_then_start(state);
}

/// Watchdog loop (every 15 seconds): restarts, repeated-failure detection, saver mode, samples, the icon and notifications.
fn monitor_tick(
    p: &Paths,
    state: &Arc<Mutex<State>>,
    env: &mut (bool, Option<bool>, Option<Instant>, Option<Instant>),
) {
    let settings = load_settings(p);
    let lang = settings["lang"].as_str().unwrap_or("en").to_string();
    let saver = settings["saver"].as_bool().unwrap_or(false);
    // Power every loop; metered internet every 5 minutes; the clock every hour.
    env.0 = health::on_battery();
    if env
        .2
        .map(|t| t.elapsed() >= Duration::from_secs(300))
        .unwrap_or(true)
    {
        env.1 = health::metered();
        env.2 = Some(Instant::now());
    }
    let clock = if env
        .3
        .map(|t| t.elapsed() >= Duration::from_secs(3600))
        .unwrap_or(true)
    {
        env.3 = Some(Instant::now());
        Some(health::clock_offset_secs())
    } else {
        None
    };
    let disk = health::disk_free(&p.data);
    let pause_reason = if saver && env.0 {
        Some("battery")
    } else if saver && env.1 == Some(true) {
        Some("metered")
    } else {
        None
    };

    let mut st = state.lock().unwrap();
    if st.account.is_none() || st.bootstrap.is_some() || st.boot_pending {
        return;
    }
    // Saver mode
    match (pause_reason, st.paused) {
        (Some(r), None) => {
            stop_node(p, &mut st);
            st.paused = Some(r);
            log(p, &format!("paused ({r})"));
        }
        (None, Some(_)) => {
            st.paused = None;
            log(p, "resumed");
            start_node(p, &mut st);
        }
        _ => {}
    }
    let alive = node_alive(&mut st);
    // Stopped on its own: restart, unless it happened 3 times within 10 minutes (then "needs repair").
    if !alive && !st.stopping && st.paused.is_none() && !st.needs_repair {
        st.crashes
            .retain(|t| t.elapsed() < Duration::from_secs(600));
        st.crashes.push(Instant::now());
        if st.crashes.len() >= 3 {
            st.needs_repair = true;
            log(p, "node keeps stopping — needs repair");
            tray::notify(
                "MADAR",
                "The node keeps stopping. Open MADAR and press Repair.",
                true,
            );
        } else {
            st.restarts += 1;
            log(p, &format!("node not running — restart #{}", st.restarts));
            start_node(p, &mut st);
        }
    }
    // Chart samples + verified blocks
    let rpc_port = st.ports.1;
    let alive = node_alive(&mut st);
    let (best, peers) = if alive {
        let h = rpc(rpc_port, "system_health", json!([]));
        (
            rpc(rpc_port, "chain_getHeader", json!([])).and_then(|h| hex_num(&h["number"])),
            h.and_then(|h| h["peers"].as_u64()),
        )
    } else {
        (None, None)
    };
    if let Some(b) = best {
        if let Some(prev) = st.last_counted_best {
            if b > prev {
                st.blocks_verified += b - prev;
            }
        }
        st.last_counted_best = Some(b);
        let last_sample = st.history.back().map(|s| s.0).unwrap_or(0);
        if now_unix().saturating_sub(last_sample) >= 30 {
            if st.history.len() >= HISTORY_LEN {
                st.history.pop_front();
            }
            st.history.push_back((now_unix(), b, peers.unwrap_or(0)));
            save_stats(p, st.blocks_verified);
        }
    }
    // Device health
    let disk_low = disk.map(|d| d < 1_500_000_000).unwrap_or(false);
    st.health["disk_free_gb"] = json!(disk.map(|d| (d as f64 / 1e9 * 10.0).round() / 10.0));
    if disk_low && !st.health["disk_low"].as_bool().unwrap_or(false) {
        tray::notify(
            "MADAR",
            "Disk space is low. Free some space so the node can keep running.",
            true,
        );
    }
    st.health["disk_low"] = json!(disk_low);
    st.health["on_battery"] = json!(env.0);
    st.health["metered"] = json!(env.1);
    if let Some(c) = clock {
        st.health["clock_offset_s"] = json!(c.map(|x| (x * 10.0).round() / 10.0));
        // 4 seconds (not 30): a 9-second drift was enough to get the node stuck (2026-09-28).
        st.health["clock_bad"] = json!(c.map(|x| x.abs() > CLOCK_BAD_SECS).unwrap_or(false));
    }
    // Stuck guard: self-restart the node if its finality is stuck or it has no peers.
    if alive && !st.stopping && st.paused.is_none() {
        let fin = rpc(rpc_port, "chain_getFinalizedHead", json!([]))
            .and_then(|h| rpc(rpc_port, "chain_getHeader", json!([h])))
            .and_then(|h| hex_num(&h["number"]));
        if fin.is_some() && fin != st.last_finalized {
            st.last_finalized = fin;
            st.last_finalized_change = Instant::now();
        }
        if peers == Some(0) {
            st.no_peers_since.get_or_insert_with(Instant::now);
        } else if peers.is_some() {
            st.no_peers_since = None;
        }
        let lag = match (best, fin) {
            (Some(b), Some(f)) => Some(b.saturating_sub(f)),
            _ => None,
        };
        if should_self_heal(
            st.node_started.elapsed(),
            lag,
            st.last_finalized_change.elapsed(),
            st.no_peers_since.map(|t| t.elapsed()),
            st.last_self_heal.map(|t| t.elapsed()),
        ) {
            log(p, &format!("self-heal: finality lag {lag:?}, finalized unchanged {}s, no peers {:?} — restarting the node", st.last_finalized_change.elapsed().as_secs(), st.no_peers_since.map(|t| t.elapsed().as_secs())));
            st.last_self_heal = Some(Instant::now());
            st.no_peers_since = None;
            st.last_finalized_change = Instant::now();
            stop_node(p, &mut st);
            start_node(p, &mut st);
            return;
        }
    }
    // Disconnected for more than 5 minutes: notify once until the connection returns.
    let disconnected =
        alive && peers == Some(0) && st.node_started.elapsed() > Duration::from_secs(90);
    if disconnected {
        let since = *st.disconnected_since.get_or_insert_with(Instant::now);
        if since.elapsed() > Duration::from_secs(300) && !st.disconnect_notified {
            st.disconnect_notified = true;
            tray::notify("MADAR", "Your node has been disconnected for over 5 minutes. Check your internet connection.", true);
        }
    } else {
        if st.disconnect_notified && alive {
            tray::notify("MADAR", "Your node is connected again.", false);
        }
        st.disconnected_since = None;
        st.disconnect_notified = false;
    }
    // Icon
    let v = status_json(p, &mut st);
    let s = v["state"].as_str().unwrap_or("stopped");
    let tone = match s {
        "running" => tray::Tone::Good,
        "catching_up" | "connecting" | "starting" | "bootstrapping" => tray::Tone::Warn,
        "disconnected" | "needs_repair" => tray::Tone::Bad,
        _ => tray::Tone::Idle,
    };
    tray::set(tone, &tray_texts(s, best, peers, &lang), tray_labels(&lang));
}

fn cmd_serve() -> i32 {
    let p = paths();
    let _ = fs::create_dir_all(&p.data);
    let Some(_lock) = try_lock(&p) else { return 3 };
    if verify_spec(&p).is_err() {
        log(&p, "spec fingerprint mismatch — refusing to run");
        return 2;
    }
    let ports = (
        pick(UI_PORT),
        pick(RPC_PORT),
        pick(PROM_PORT),
        pick(P2P_PORT),
    );
    let token = random_token();
    let _ = fs::write(&p.token, &token);
    let Ok(listener) = TcpListener::bind(("127.0.0.1", ports.0)) else {
        log(&p, "ui port bind failed");
        return 1;
    };
    let _ = fs::write(
        &p.ports,
        json!({"ui":ports.0,"rpc":ports.1,"prom":ports.2,"p2p":ports.3}).to_string(),
    );
    log(&p, &format!("serve {VERSION} ports {ports:?}"));
    stop_orphan_node(&p);
    let state = Arc::new(Mutex::new(State {
        ports,
        token,
        account: load_account(&p),
        child: None,
        stopping: false,
        last_best: None,
        last_best_change: Instant::now(),
        node_started: Instant::now(),
        restarts: 0,
        last_finalized: None,
        last_finalized_change: Instant::now(),
        no_peers_since: None,
        last_self_heal: None,
        update: UpdateInfo::default(),
        last_update_check: Some(Instant::now()),
        history: std::collections::VecDeque::with_capacity(HISTORY_LEN),
        blocks_verified: load_stats(&p),
        last_counted_best: None,
        paused: None,
        crashes: Vec::new(),
        needs_repair: false,
        bootstrap: None,
        disconnected_since: None,
        disconnect_notified: false,
        health: json!({}),
        boot_pending: false,
    }));

    // Taskbar icon: click = the page; menu = open / stop.
    {
        let lang = ui_lang();
        let url = format!("http://127.0.0.1:{}/", ports.0);
        let stop_state = Arc::clone(&state);
        tray::start(
            p.root.clone(),
            tray_texts("starting", None, None, &lang),
            tray_labels(&lang),
            Box::new(move || open_browser(&url)),
            Box::new(move || {
                // On a separate thread: the icon lock is not held during the stop.
                let st = Arc::clone(&stop_state);
                std::thread::spawn(move || {
                    let p = paths();
                    {
                        let mut s = st.lock().unwrap();
                        s.stopping = true;
                        stop_node(&p, &mut s);
                    }
                    log(&p, "stopped by user via tray");
                    tray::remove();
                    let _ = fs::remove_file(&p.ports);
                    std::process::exit(0);
                });
            }),
        );
    }

    if state.lock().unwrap().account.is_some() {
        state.lock().unwrap().boot_pending = true;
        let s = Arc::clone(&state);
        std::thread::spawn(move || bootstrap_then_start(&s));
    }
    // Check for updates on open, then every 6 hours.
    {
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            let p = paths();
            loop {
                check_update(&p, &state);
                std::thread::sleep(UPDATE_CHECK_EVERY);
            }
        });
    }
    // Watchdog + registration sending.
    {
        let state = Arc::clone(&state);
        std::thread::spawn(move || {
            let p = paths();
            let mut env = (false, None, None, None);
            loop {
                std::thread::sleep(Duration::from_secs(15));
                monitor_tick(&p, &state, &mut env);
                registration_tick(&p, &state);
            }
        });
    }
    for stream in listener.incoming().flatten() {
        let state = Arc::clone(&state);
        std::thread::spawn(move || handle(stream, &state));
    }
    0
}
/// `{"force": true}` allows a manual repair even without repeated failures (a button in the page for rare cases).
/// Replaces IPv4 addresses with `x.x.x.x`: a problem report never carries the user's or anyone else's machine address.
pub fn redact_ips(line: &str) -> String {
    let b = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;
    while i < b.len() {
        // Try to read a.b.c.d starting at i (1-3 digit numbers, not preceded by a digit or a dot)
        let prev_ok = i == 0 || !(b[i - 1].is_ascii_digit() || b[i - 1] == b'.');
        if prev_ok && b[i].is_ascii_digit() {
            let (mut j, mut parts) = (i, 0);
            loop {
                let start = j;
                while j < b.len() && b[j].is_ascii_digit() && j - start < 3 {
                    j += 1;
                }
                if j == start {
                    break;
                }
                parts += 1;
                if parts == 4 || j >= b.len() || b[j] != b'.' {
                    break;
                }
                j += 1;
            }
            let next_ok = j >= b.len() || !b[j].is_ascii_digit();
            if parts == 4 && next_ok {
                out.push_str("x.x.x.x");
                i = j;
                continue;
            }
        }
        out.push(line[i..].chars().next().unwrap());
        i += line[i..].chars().next().unwrap().len_utf8();
    }
    out
}

fn tail_lines(path: &Path, max: usize) -> String {
    let text = fs::read(path)
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(max)..]
        .iter()
        .map(|l| redact_ips(l))
        .collect::<Vec<_>>()
        .join("\n")
}

/// User-initiated problem report: logs, state and settings only, with no email, account, keys or IP addresses.
/// A zip file is saved in data\reports, then its folder and a ready email are opened (the user attaches the file and sends it themselves).
fn make_report(p: &Paths, status: &Value) -> Result<PathBuf, String> {
    let dir = p.data.join("reports");
    let stage = dir.join("stage");
    let _ = fs::remove_dir_all(&stage);
    fs::create_dir_all(&stage).map_err(|e| e.to_string())?;
    let mut st = status.clone();
    st["account"] = json!(st["account"].is_object()); // whether an account exists, not the name or email
    st["registration"] = json!(st["registration"]["state"]);
    let settings = load_settings(p);
    let info = json!({
        "version": VERSION,
        "created_unix": now_unix(),
        "windows": std::env::var("OS").unwrap_or_default(),
        "cpu_threads": std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0),
        "settings": { "lang": settings["lang"], "saver": settings["saver"] },
        "status": st,
    });
    // The display name appears in the node log ("Node name: ..."); it is replaced so the report carries no account data.
    let account_name = load_account(p).map(|a| a.name);
    let scrub = |text: String| match &account_name {
        Some(n) if !n.is_empty() => text.replace(n.as_str(), "[name]"),
        _ => text,
    };
    let write =
        |name: &str, body: &str| fs::write(stage.join(name), body).map_err(|e| e.to_string());
    write(
        "info.json",
        &serde_json::to_string_pretty(&info).unwrap_or_default(),
    )?;
    write("app.log", &scrub(tail_lines(&p.app_log, 2000)))?;
    write("node.log", &scrub(tail_lines(&p.node_log, 3000)))?;
    let version = fs::read_to_string(p.root.join("VERSION")).unwrap_or_default();
    write(
        "VERSION",
        &version
            .lines()
            .map(redact_ips)
            .collect::<Vec<_>>()
            .join("\n"),
    )?;
    let zip = dir.join(format!("MADAR-report-{}.zip", now_unix()));
    powershell(&format!(
        "Compress-Archive -Path {} -DestinationPath {} -Force",
        ps_quote(&stage.join("*").display().to_string()),
        ps_quote(&zip.display().to_string())
    ))?;
    let _ = fs::remove_dir_all(&stage);
    // Show the file, and open a ready email to the support address.
    let _ = Command::new("explorer")
        .raw_arg(format!("/select,\"{}\"", zip.display()))
        .spawn();
    let subject = "MADAR%20Node%20problem%20report";
    let body = format!(
        "Please%20attach%20this%20file%3A%20{}",
        zip.display()
            .to_string()
            .replace('\\', "%5C")
            .replace(' ', "%20")
    );
    let _ = Command::new("cmd")
        .raw_arg(format!(
            "/C start \"\" \"mailto:{SUPPORT_EMAIL}?subject={subject}&body={body}\""
        ))
        .creation_flags(CREATE_NO_WINDOW)
        .spawn();
    log(p, &format!("problem report created: {}", zip.display()));
    Ok(zip)
}

const SUPPORT_EMAIL: &str = "contact@madar-network.com";

fn req_force(body: &str) -> bool {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v["force"].as_bool())
        .unwrap_or(false)
}

fn respond(s: &mut TcpStream, status: &str, ctype: &str, body: &[u8]) {
    let _ = write!(
        s,
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Frame-Options: DENY\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = s.write_all(body);
}

fn respond_json(s: &mut TcpStream, status: &str, v: Value) {
    respond(
        s,
        status,
        "application/json; charset=utf-8",
        v.to_string().as_bytes(),
    );
}

fn handle(mut s: TcpStream, state: &Arc<Mutex<State>>) {
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = vec![0u8; 16 * 1024];
    let mut len = 0;
    loop {
        match s.read(&mut buf[len..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                len += n;
                let text = String::from_utf8_lossy(&buf[..len]);
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let cl = head.lines().find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse::<usize>().ok())
                            .flatten()
                    });
                    if body.len() >= cl.unwrap_or(0) {
                        break;
                    }
                }
                if len == buf.len() {
                    return respond(&mut s, "413 Payload Too Large", "text/plain", b"too large");
                }
            }
        }
    }
    let text = String::from_utf8_lossy(&buf[..len]).to_string();
    let Some((head, body)) = text.split_once("\r\n\r\n") else {
        return;
    };
    let mut first = head.lines().next().unwrap_or("").split_whitespace();
    let (method, path) = (first.next().unwrap_or(""), first.next().unwrap_or(""));
    let header = |name: &str| {
        head.lines().skip(1).find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case(name)
                .then(|| v.trim().to_string())
        })
    };
    let (ui_port, token) = {
        let st = state.lock().unwrap();
        (st.ports.0, st.token.clone())
    };
    // DNS rebinding protection.
    let host_ok = matches!(header("host").as_deref(), Some(h) if h == format!("127.0.0.1:{ui_port}") || h == format!("localhost:{ui_port}"));
    if !host_ok {
        return respond(&mut s, "403 Forbidden", "text/plain", b"forbidden");
    }
    // Every state-changing command: the page token + (if an Origin is present) the page's own origin.
    let origin_ok = match header("origin") {
        None => true,
        Some(o) => {
            o == format!("http://127.0.0.1:{ui_port}") || o == format!("http://localhost:{ui_port}")
        }
    };
    let token_ok = origin_ok && header("x-madar-token").as_deref() == Some(token.as_str());
    let p = paths();
    match (method, path) {
        ("GET", "/") => {
            let html = fs::read_to_string(&p.ui)
                .unwrap_or_else(|_| "<p>ui/index.html missing</p>".into())
                .replace("{{TOKEN}}", &token);
            respond(
                &mut s,
                "200 OK",
                "text/html; charset=utf-8",
                html.as_bytes(),
            );
        }
        ("GET", "/favicon.ico") => match fs::read(p.root.join("madar.ico")) {
            Ok(b) => respond(&mut s, "200 OK", "image/x-icon", &b),
            Err(_) => respond(&mut s, "404 Not Found", "text/plain", b""),
        },
        ("GET", "/api/status") => {
            let v = status_json(&p, &mut state.lock().unwrap());
            respond_json(&mut s, "200 OK", v);
        }
        ("POST", "/api/account") if token_ok => {
            let req: Value = serde_json::from_str(body).unwrap_or(Value::Null);
            let mut st = state.lock().unwrap();
            if st.account.is_some() || p.account.exists() {
                return respond_json(&mut s, "409 Conflict", json!({"error":"account_locked"}));
            }
            let name = match normalize_name(req["name"].as_str().unwrap_or("")) {
                Ok(n) => n,
                Err(e) => return respond_json(&mut s, "400 Bad Request", json!({"error":e})),
            };
            let email = match normalize_email(req["email"].as_str().unwrap_or("")) {
                Ok(e) => e,
                Err(e) => return respond_json(&mut s, "400 Bad Request", json!({"error":e})),
            };
            let rec = json!({"name":name,"email":email,"saved_unix":now_unix(),"version":VERSION});
            // create_new: never overwrite an existing account, even if two requests race.
            let saved = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&p.account)
                .and_then(|mut f| {
                    f.write_all(
                        serde_json::to_string_pretty(&rec)
                            .unwrap_or_default()
                            .as_bytes(),
                    )
                });
            if saved.is_err() {
                return respond_json(
                    &mut s,
                    "500 Internal Server Error",
                    json!({"error":"save_failed"}),
                );
            }
            log(&p, "account saved");
            st.account = Some(Account { name, email });
            drop(st);
            // First run: fast sync from a signed snapshot if available, otherwise a normal sync.
            state.lock().unwrap().boot_pending = true;
            let bs = Arc::clone(state);
            std::thread::spawn(move || bootstrap_then_start(&bs));
            respond_json(&mut s, "200 OK", json!({"ok":true}));
        }
        ("GET", "/logo.svg") => match fs::read(p.root.join("ui").join("logo.svg")) {
            Ok(b) => respond(&mut s, "200 OK", "image/svg+xml", &b),
            Err(_) => respond(&mut s, "404 Not Found", "text/plain", b""),
        },
        ("POST", "/api/settings") if token_ok => {
            let req: Value = serde_json::from_str(body).unwrap_or(Value::Null);
            let mut settings = load_settings(&p);
            if let Some(lang) = req["lang"].as_str() {
                if !LANGS.contains(&lang) {
                    return respond_json(&mut s, "400 Bad Request", json!({"error":"bad_lang"}));
                }
                settings["lang"] = json!(lang);
                save_settings(&p, &settings);
            }
            for key in ["saver", "onboarded"] {
                if let Some(b) = req[key].as_bool() {
                    settings[key] = json!(b);
                    save_settings(&p, &settings);
                }
            }
            // "Help the network": requires restarting the node to change the listen address (in the background).
            if let Some(b) = req["help_network"].as_bool() {
                if settings["help_network"].as_bool().unwrap_or(false) != b {
                    settings["help_network"] = json!(b);
                    save_settings(&p, &settings);
                    log(
                        &p,
                        &format!("help_network {}", if b { "on" } else { "off" }),
                    );
                    let st2 = Arc::clone(state);
                    std::thread::spawn(move || {
                        let p = paths();
                        let mut st = st2.lock().unwrap();
                        if st.child.is_some() {
                            stop_node(&p, &mut st);
                            std::thread::sleep(Duration::from_secs(2));
                            st.crashes.clear();
                            start_node(&p, &mut st);
                        }
                    });
                }
            }
            if let Some(on) = req["autostart"].as_bool() {
                if !set_autostart(on) {
                    return respond_json(
                        &mut s,
                        "500 Internal Server Error",
                        json!({"error":"autostart_failed"}),
                    );
                }
                log(&p, &format!("autostart {}", if on { "on" } else { "off" }));
            }
            respond_json(
                &mut s,
                "200 OK",
                json!({"ok":true,"lang":settings["lang"],"autostart":autostart_enabled()}),
            );
        }
        ("POST", "/api/report") if token_ok => {
            let snapshot = status_json(&p, &mut state.lock().unwrap());
            match make_report(&p, &snapshot) {
                Ok(path) => respond_json(
                    &mut s,
                    "200 OK",
                    json!({"ok":true,"file":path.display().to_string()}),
                ),
                Err(e) => {
                    log(&p, &format!("report failed: {e}"));
                    respond_json(
                        &mut s,
                        "500 Internal Server Error",
                        json!({"error":"report_failed"}),
                    )
                }
            }
        }
        ("POST", "/api/repair") if token_ok => {
            if !state.lock().unwrap().needs_repair && !req_force(body) {
                return respond_json(&mut s, "409 Conflict", json!({"error":"no_repair_needed"}));
            }
            let st2 = Arc::clone(state);
            std::thread::spawn(move || repair(&st2));
            respond_json(&mut s, "200 OK", json!({"ok":true}));
        }
        ("POST", "/api/check-update") if token_ok => {
            let due = {
                let mut st = state.lock().unwrap();
                let due = st
                    .last_update_check
                    .map(|t| t.elapsed() >= UPDATE_RECHECK_MIN)
                    .unwrap_or(true);
                if due {
                    st.last_update_check = Some(Instant::now());
                }
                due
            };
            if due {
                let state = Arc::clone(state);
                std::thread::spawn(move || check_update(&paths(), &state));
            }
            respond_json(&mut s, "200 OK", json!({"ok":true,"started":due}));
        }
        ("POST", "/api/update") if token_ok => {
            let busy = {
                let st = state.lock().unwrap();
                st.update.available.is_none()
                    || matches!(
                        st.update.progress.as_deref(),
                        Some("downloading" | "verifying" | "launching")
                    )
            };
            if busy {
                return respond_json(&mut s, "409 Conflict", json!({"error":"no_update"}));
            }
            let state = Arc::clone(state);
            std::thread::spawn(move || apply_update(&paths(), &state));
            respond_json(&mut s, "200 OK", json!({"ok":true}));
        }
        ("POST", "/api/stop") if token_ok => {
            {
                let mut st = state.lock().unwrap();
                st.stopping = true;
                stop_node(&p, &mut st);
            }
            log(
                &p,
                &format!(
                    "stopped by user via {}",
                    if header("origin").is_some() {
                        "page"
                    } else {
                        "cli"
                    }
                ),
            );
            respond_json(&mut s, "200 OK", json!({"ok":true}));
            let _ = s.flush();
            std::thread::sleep(Duration::from_millis(300));
            let _ = fs::remove_file(&p.ports);
            std::process::exit(0);
        }
        ("POST", _) => respond_json(&mut s, "403 Forbidden", json!({"error":"bad_token"})),
        _ => respond(&mut s, "404 Not Found", "text/plain", b"not found"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stuck_or_isolated_node_is_restarted_but_not_too_early_or_too_often() {
        let m = |x: u64| Duration::from_secs(x * 60);
        // The incident: finality stuck for hours while the head advances => restart.
        assert!(should_self_heal(m(300), Some(2200), m(240), None, None));
        // No peers for 10 minutes => restart.
        assert!(should_self_heal(m(60), Some(0), m(0), Some(m(10)), None));
        // Healthy: small gap or finality moving.
        assert!(!should_self_heal(m(60), Some(3), m(30), None, None));
        assert!(
            !should_self_heal(m(60), Some(500), m(2), None, None),
            "finality moving, just catching up"
        );
        // Just started, or restarted less than 30 minutes ago => wait.
        assert!(!should_self_heal(m(5), Some(2200), m(240), None, None));
        assert!(!should_self_heal(
            m(300),
            Some(2200),
            m(240),
            None,
            Some(m(20))
        ));
        assert!(should_self_heal(
            m(300),
            Some(2200),
            m(240),
            None,
            Some(m(31))
        ));
    }

    #[test]
    fn display_name_rules() {
        assert_eq!(normalize_name("  Ahmad   N-1 ").as_deref(), Ok("Ahmad N-1"));
        assert!(normalize_name("Дмитрий").is_ok());
        assert!(normalize_name("ab").is_err());
        assert!(normalize_name(&"a".repeat(21)).is_err());
        assert!(normalize_name("http x").is_err());
        assert!(normalize_name("site.com").is_err());
        // Letters of any language, and errors as codes the page translates.
        assert!(normalize_name("José Müller").is_ok());
        assert!(normalize_name("Çağrı-7").is_ok());
        assert_eq!(normalize_name("ab"), Err("name_length"));
        assert_eq!(normalize_name("a<b>c"), Err("name_chars"));
        assert_eq!(
            normalize_name("\u{202E}abc"),
            Err("name_chars"),
            "no bidi control characters"
        );
        assert_eq!(normalize_email("x"), Err("email_invalid"));
    }

    #[test]
    fn update_signatures_are_required_and_bound_to_every_trusted_field() {
        use ed25519_dalek::{Signer, SigningKey};
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let pk: String = key
            .verifying_key()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let mut v = json!({
            "version": "2.0.1", "url": "https://madar-network.com/downloads/x.exe", "sha256": "a".repeat(64),
            "snapshot": {"url": "https://madar-network.com/downloads/s.zip", "sha256": "b".repeat(64), "block": 40000}
        });
        assert!(!signature_ok_with(&v, &pk), "unsigned is rejected");
        let sig = key
            .sign(update_sig::update_message(&v).as_bytes())
            .to_bytes();
        v["signature"] = json!(sig.iter().map(|b| format!("{b:02x}")).collect::<String>());
        assert!(signature_ok_with(&v, &pk), "valid signature accepted");
        for (field, bad) in [
            ("url", json!("https://madar-network.com/downloads/evil.exe")),
            ("sha256", json!("c".repeat(64))),
            ("version", json!("9.9.9")),
        ] {
            let mut t = v.clone();
            t[field] = bad;
            assert!(!signature_ok_with(&t, &pk), "tampered {field} rejected");
        }
        let mut t = v.clone();
        t["snapshot"]["block"] = json!(1);
        assert!(!signature_ok_with(&t, &pk), "tampered snapshot rejected");
        assert!(
            !signature_ok_with(&v, &"0".repeat(64)),
            "another key rejected"
        );
        // the real embedded key did not sign this test file
        assert_eq!(
            parse_latest(&v, "https://madar-network.com/downloads/latest.json").err(),
            Some("bad_signature")
        );
    }

    #[test]
    fn problem_reports_never_carry_ip_addresses() {
        assert_eq!(
            redact_ips("Discovered external address /ip4/188.248.190.112/tcp/30333"),
            "Discovered external address /ip4/x.x.x.x/tcp/30333"
        );
        assert_eq!(
            redact_ips("peer 10.0.0.5:30333 and 127.0.0.1"),
            "peer x.x.x.x:30333 and x.x.x.x"
        );
        assert_eq!(
            redact_ips("version 2.0.0 block #34 1.2.3"),
            "version 2.0.0 block #34 1.2.3",
            "not an address"
        );
        assert_eq!(
            redact_ips("узел 192.168.1.4 работает"),
            "узел x.x.x.x работает",
            "unicode kept"
        );
        assert_eq!(redact_ips("1234.5.6.7"), "1234.5.6.7", "too many digits");
    }

    #[test]
    fn languages_and_messages() {
        assert_eq!(LANGS[0], "en", "English is the default");
        for key in ["spec_mismatch", "not_running", "stopped", "commands"] {
            assert!(!msg(key, "en").is_empty(), "{key}");
            assert_eq!(
                msg(key, "fr"),
                msg(key, "en"),
                "native dialogs are English for every language"
            );
        }
    }

    #[test]
    fn email_rules() {
        assert_eq!(
            normalize_email("  Ali@Example.COM ").as_deref(),
            Ok("ali@example.com")
        );
        assert!(normalize_email("a.b-c+d@mail.co.sa").is_ok());
        for bad in [
            "",
            "a",
            "a@b",
            "a@b.c",
            "@b.com",
            "a@.com",
            "a@b..com",
            "a b@c.com",
            "a@b.com<x>",
            "a@@b.com",
            "иван@пример.com",
            "a@-b.com",
            ".a@b.com",
        ] {
            assert!(normalize_email(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn registry_payload_has_exactly_three_fields() {
        let v = registry_payload("Ali", "abcd1234", "a@b.co");
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(keys.len(), 3);
        for k in ["name", "peer_id_suffix", "email"] {
            assert!(v.get(k).is_some(), "{k}");
        }
    }

    #[test]
    fn peer_suffix_is_last_8() {
        assert_eq!(
            peer_suffix("12D3KooWDAr7FDtAeUx51zowWytNKeeuQfB5B2cyF4bZmDEp9j9K").as_deref(),
            Some("mDEp9j9K")
        );
        assert_eq!(peer_suffix("short"), None);
        assert_eq!(peer_suffix("12D3KooW/../../x"), None);
    }

    #[test]
    fn url_rules() {
        assert!(registry_url_ok("https://madar-network.com/api/registry"));
        assert!(registry_url_ok("https://www.madar-network.com/r"));
        assert!(registry_url_ok("http://127.0.0.1:8099/r"));
        for bad in [
            "http://madar-network.com/r",
            "https://madar-network.com.evil.io/r",
            "https://evil.io/madar-network.com/",
            "file:///c:/x",
            "https://madar-network.com/ x",
        ] {
            assert!(!registry_url_ok(bad), "{bad}");
        }
        assert!(latest_url_ok(
            "https://madar-network.com/downloads/latest.json"
        ));
        assert!(latest_url_ok("file:///C:/tmp/latest.json"));
        assert!(!latest_url_ok("https://evil.io/latest.json"));
        assert_eq!(
            origin("https://madar-network.com/downloads/latest.json").as_deref(),
            Some("https://madar-network.com/")
        );
        assert_ne!(
            origin("https://evil.io/x.exe"),
            origin("https://madar-network.com/latest.json")
        );
    }

    #[test]
    fn versions_compare_numerically() {
        assert!(parse_version("2.0.10").unwrap() > parse_version("2.0.9").unwrap());
        assert!(parse_version("v2.1").unwrap() > parse_version("2.0.9").unwrap());
        assert_eq!(
            parse_version(env!("CARGO_PKG_VERSION")),
            parse_version(VERSION)
        );
        assert!(parse_version("x.y").is_none());
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(b64(b""), "");
        assert_eq!(b64(b"f"), "Zg==");
        assert_eq!(b64(b"fo"), "Zm8=");
        assert_eq!(b64(b"foobar"), "Zm9vYmFy");
    }
}
