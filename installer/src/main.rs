//! MADAR Node 2.0 installer for Windows 10/11 x64: a single file carrying the node and the app, compressed.
//!
//! - No administrator rights (asInvoker manifest): installs into `%SystemDrive%\MADAR-Network`, or, if that is not writable,
//!   into `%LOCALAPPDATA%\MADAR-Network`.
//! - Desktop shortcut "MADAR Network" with the MADAR icon.
//! - Update (`--update`, launched from the app) stops the app, replaces the programs only, and never touches `data`.
//!
//! Options: `--update` · `--dir <path>` · `--shortcut-dir <path>` · `--quiet` · `--no-launch` · `--no-shortcut`.

#![cfg_attr(not(test), windows_subsystem = "windows")]

use std::ffi::c_void;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

const VERSION: &str = env!("CARGO_PKG_VERSION");
static PAYLOAD: &[u8] = include_bytes!(env!("MADAR_PAYLOAD_FILE"));
const MAGIC: &[u8; 8] = b"MDRPAY1\0";
const APP_NAME: &str = "MADAR Network";

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const DETACHED_PROCESS: u32 = 0x0000_0008;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

#[link(name = "kernel32")]
extern "system" {
    fn AttachConsole(pid: u32) -> i32;
}
#[link(name = "user32")]
extern "system" {
    fn MessageBoxW(hwnd: *mut c_void, text: *const u16, caption: *const u16, kind: u32) -> i32;
}
const MB_YESNO: u32 = 0x4;
const MB_ICONERROR: u32 = 0x10;
const MB_ICONQUESTION: u32 = 0x20;
const MB_ICONINFORMATION: u32 = 0x40;
const MB_SETFOREGROUND: u32 = 0x0001_0000;
const IDYES: i32 = 6;

struct Opts {
    update: bool,
    dir: Option<PathBuf>,
    shortcut_dir: Option<PathBuf>,
    quiet: bool,
    launch: bool,
    shortcut: bool,
}

fn parse_opts() -> Opts {
    let mut o = Opts {
        update: false,
        dir: None,
        shortcut_dir: None,
        quiet: false,
        launch: true,
        shortcut: true,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--update" => o.update = true,
            "--dir" => o.dir = args.next().map(PathBuf::from),
            "--shortcut-dir" => o.shortcut_dir = args.next().map(PathBuf::from),
            "--quiet" => o.quiet = true,
            "--no-launch" => o.launch = false,
            "--no-shortcut" => o.shortcut = false,
            _ => {}
        }
    }
    o
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// User-facing installer message (English).
fn tr(en: &str) -> String {
    en.to_string()
}

fn message(text: &str, kind: u32) -> i32 {
    let (t, c) = (wide(text), wide(&format!("MADAR {VERSION}")));
    // SAFETY: null-terminated UTF-16 strings that live until the end of the call.
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            t.as_ptr(),
            c.as_ptr(),
            kind | MB_SETFOREGROUND,
        )
    }
}

fn log_path() -> PathBuf {
    std::env::temp_dir().join("madar-setup.log")
}

fn log(msg: &str) {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path())
    {
        let _ = writeln!(f, "{t} {msg}");
    }
    eprintln!("{msg}");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// ---------------------------------------------------------------- Payload

pub struct Entry {
    pub name: String,
    pub data: Vec<u8>,
}

/// Format (after Deflate decompression): MAGIC · u32 count · per file: u16 name length · UTF-8 name · sha256 (32) · u64 length · data.
pub fn parse_payload(raw: &[u8]) -> Result<Vec<Entry>, String> {
    let bad = |m: &str| Err(format!("{} ({m}).", tr("The installer payload is damaged")));
    if raw.len() < 12 || &raw[..8] != MAGIC {
        return bad("magic");
    }
    let count = u32::from_le_bytes(raw[8..12].try_into().unwrap()) as usize;
    let mut pos: usize = 12;
    let mut take = |n: usize| -> Option<&[u8]> {
        let s = raw.get(pos..pos.checked_add(n)?)?;
        pos += n;
        Some(s)
    };
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let Some(nl) = take(2).map(|b| u16::from_le_bytes([b[0], b[1]]) as usize) else {
            return bad("name len");
        };
        let Some(name) = take(nl).and_then(|b| String::from_utf8(b.to_vec()).ok()) else {
            return bad("name");
        };
        let Some(sha) = take(32).map(<[u8]>::to_vec) else {
            return bad("sha");
        };
        let Some(len) = take(8).map(|b| u64::from_le_bytes(b.try_into().unwrap()) as usize) else {
            return bad("len");
        };
        let Some(data) = take(len).map(<[u8]>::to_vec) else {
            return bad("data");
        };
        // Safe relative paths only, and nothing inside data.
        let safe = !name.is_empty()
            && !name.starts_with('/')
            && !name.contains('\\')
            && !name.contains(':')
            && name
                .split('/')
                .all(|s| !s.is_empty() && s != "." && s != "..")
            && !name.eq_ignore_ascii_case("data")
            && !name.to_ascii_lowercase().starts_with("data/");
        if !safe {
            return bad("path");
        }
        if Sha256::digest(&data)[..] != sha[..] {
            return Err(tr(
                &format!("The fingerprint of {name} inside the installer does not match. Please download the installer again."),
            ));
        }
        out.push(Entry { name, data });
    }
    Ok(out)
}

fn unpack() -> Result<Vec<Entry>, String> {
    if PAYLOAD.is_empty() {
        return Err(tr(
            "This build has no payload. Use the installer produced by build-installer.ps1.",
        ));
    }
    let raw = miniz_oxide::inflate::decompress_to_vec_with_limit(PAYLOAD, 1 << 30)
        .map_err(|_| tr("The installer payload could not be unpacked."))?;
    parse_payload(&raw)
}

// ---------------------------------------------------------------- Install folder

fn writable(dir: &Path) -> bool {
    if fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(".madar-write-test");
    let ok = fs::write(&probe, b"ok").is_ok();
    let _ = fs::remove_file(&probe);
    ok
}

fn system_dir() -> PathBuf {
    let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
    PathBuf::from(format!("{drive}\\MADAR-Network"))
}

fn local_dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("MADAR-Network"))
}

fn choose_dir(o: &Opts) -> Result<PathBuf, String> {
    if let Some(d) = &o.dir {
        return if writable(d) {
            Ok(d.clone())
        } else {
            Err(format!("{}\n{}", tr("Cannot write to:"), d.display()))
        };
    }
    let sys = system_dir();
    let local = local_dir();
    let installed = |d: &Path| d.join("bin").join("madar-app.exe").exists();
    if installed(&sys) && writable(&sys) {
        return Ok(sys);
    }
    if let Some(l) = local.as_ref().filter(|l| installed(l)) {
        return Ok(l.clone());
    }
    if writable(&sys) {
        return Ok(sys);
    }
    match local {
        Some(l) if writable(&l) => Ok(l),
        _ => Err(tr(
            "Cannot write to C:\\MADAR-Network or to the local apps folder.",
        )),
    }
}

// ---------------------------------------------------------------- Install

fn lock_free(dir: &Path) -> bool {
    let lock = dir.join("data").join("app.lock");
    if !lock.exists() {
        return true;
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0)
        .open(&lock)
        .is_ok()
}

fn stop_running(dir: &Path) {
    let app = dir.join("bin").join("madar-app.exe");
    if lock_free(dir) || !app.exists() {
        return;
    }
    log("stopping running app");
    let _ = Command::new(&app)
        .arg("stop")
        .current_dir(dir)
        .stdin(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .status();
    let deadline = Instant::now() + Duration::from_secs(40);
    while Instant::now() < deadline && !lock_free(dir) {
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// Atomic write: temporary file then replace, retrying if the old file is still locked.
fn write_file(target: &Path, data: &[u8]) -> Result<(), String> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    let tmp = target.with_extension(format!(
        "{}.new",
        target.extension().and_then(|e| e.to_str()).unwrap_or("")
    ));
    fs::write(&tmp, data).map_err(|e| format!("{}: {e}", tmp.display()))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match fs::rename(&tmp, target) {
            Ok(()) => return Ok(()),
            Err(e) if Instant::now() >= deadline => {
                let _ = fs::remove_file(&tmp);
                return Err(format!("{}: {e}", target.display()));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(500)),
        }
    }
}

fn verify_spec(dir: &Path) -> bool {
    let (Ok(spec), Ok(sha)) = (
        fs::read(dir.join("chain").join("madar-spec.json")),
        fs::read_to_string(dir.join("chain").join("spec.sha256")),
    ) else {
        return false;
    };
    sha.split_whitespace()
        .next()
        .map(|e| e.eq_ignore_ascii_case(&hex(&Sha256::digest(&spec))))
        .unwrap_or(false)
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            out.push(if i <= c.len() {
                T[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// `only_existing` (update mode): only updates an existing shortcut that points to this same installation; it does not re-add a shortcut
/// the user deleted, and does not touch another installation's shortcut.
/// A folder at the root of C:\ inherits "Authenticated Users: Modify" from Windows, so any other account on the machine could replace
/// madar-app.exe (which then runs as the owner on autostart) or read the email, the token and the node key.
/// Fix: disable inheritance and grant access only to the current owner, SYSTEM and Administrators.
fn lock_down_permissions(dir: &Path) {
    let sid = Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .split(',')
                .nth(1)
                .map(|s| s.trim().trim_matches('"').to_string())
        })
        .filter(|s| s.starts_with("S-1-"));
    let Some(sid) = sid else {
        log("permissions: could not read current user SID — left unchanged");
        return;
    };
    let run = |args: &[String]| {
        Command::new("icacls")
            .args(args)
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    // 1) The main folder only: disable inheritance and grant (OI)(CI), without /T (applying OI/CI to files directly leaves them with no permissions).
    let root = dir.display().to_string();
    let locked = run(&[
        root.clone(),
        "/inheritance:r".into(),
        "/grant:r".into(),
        format!("*{sid}:(OI)(CI)F"),
        "*S-1-5-18:(OI)(CI)F".into(),
        "*S-1-5-32-544:(OI)(CI)F".into(),
    ]);
    // 2) Everything inside inherits from the main folder.
    let inherited = run(&[
        format!("{root}\\*"),
        "/reset".into(),
        "/T".into(),
        "/C".into(),
        "/Q".into(),
    ]);
    log(&format!(
        "permissions locked to owner/SYSTEM/Administrators: root={locked} children={inherited}"
    ));
}

/// Adds "MADAR Node" to Windows "Apps" (HKCU: current user, no admin rights) with an uninstall command.
fn register_uninstall(dir: &Path, entries: &[Entry]) {
    let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\MADARNode";
    let app = dir.join("bin").join("madar-app.exe");
    let size_kb = (entries.iter().map(|e| e.data.len() as u64).sum::<u64>() / 1024).to_string();
    let values: [(&str, &str, String); 9] = [
        ("DisplayName", "REG_SZ", "MADAR Node".into()),
        ("DisplayVersion", "REG_SZ", VERSION.into()),
        ("Publisher", "REG_SZ", "MADAR NETWORK".into()),
        (
            "DisplayIcon",
            "REG_SZ",
            dir.join("madar.ico").display().to_string(),
        ),
        ("InstallLocation", "REG_SZ", dir.display().to_string()),
        (
            "UninstallString",
            "REG_SZ",
            format!("\"{}\" uninstall", app.display()),
        ),
        ("EstimatedSize", "REG_DWORD", size_kb),
        ("NoModify", "REG_DWORD", "1".into()),
        ("NoRepair", "REG_DWORD", "1".into()),
    ];
    for (name, kind, data) in values {
        let _ = Command::new("reg")
            .args(["add", key, "/v", name, "/t", kind, "/d", &data, "/f"])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn create_shortcut(
    dir: &Path,
    shortcut_dir: Option<&Path>,
    only_existing: bool,
) -> Result<Option<PathBuf>, String> {
    let folder = match shortcut_dir {
        Some(d) => ps_quote(&d.display().to_string()),
        None => "[Environment]::GetFolderPath('Desktop')".to_string(),
    };
    let script = format!(
        "$d = {folder}; $l = Join-Path $d {name}; $w = New-Object -ComObject WScript.Shell; \
         if (${only}) {{ if (-not (Test-Path -LiteralPath $l)) {{ return }}; if ($w.CreateShortcut($l).TargetPath -ne {target}) {{ return }} }}; \
         $s = $w.CreateShortcut($l); \
         $s.TargetPath = {target}; $s.Arguments = 'start'; $s.WorkingDirectory = {wd}; $s.IconLocation = {icon}; \
         $s.Description = {desc}; $s.Save(); $l",
        only = only_existing,
        name = ps_quote(&format!("{APP_NAME}.lnk")),
        target = ps_quote(&dir.join("bin").join("madar-app.exe").display().to_string()),
        wd = ps_quote(&dir.display().to_string()),
        icon = ps_quote(&format!("{},0", dir.join("madar.ico").display())),
        desc = ps_quote("MADAR Network node"),
    );
    let enc: Vec<u8> = format!("[Console]::OutputEncoding=[Text.Encoding]::UTF8; {script}")
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
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
    let link = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok((!link.is_empty()).then(|| PathBuf::from(link)))
}

fn install(o: &Opts) -> Result<(PathBuf, Option<PathBuf>), String> {
    let entries = unpack()?;
    let dir = choose_dir(o)?;
    log(&format!(
        "install {VERSION} into {} (update={})",
        dir.display(),
        o.update
    ));
    if !o.update && !o.quiet {
        let existing = dir.join("bin").join("madar-app.exe").exists();
        let d = dir.display();
        let q = if existing {
            tr(
                &format!("MADAR is installed in:\n{d}\n\nUpdate it to {VERSION}? Your data and account are kept."),
            )
        } else {
            tr(
                &format!("MADAR {VERSION} will be installed in:\n{d}\n\nNo administrator rights are needed. Continue?"),
            )
        };
        if message(&q, MB_YESNO | MB_ICONQUESTION) != IDYES {
            return Err(String::new());
        }
    }
    stop_running(&dir);
    if !lock_free(&dir) {
        return Err(tr("MADAR is still running and did not stop. Stop it from its page, then run the installer again."));
    }
    for e in &entries {
        write_file(&dir.join(e.name.replace('/', "\\")), &e.data)?;
    }
    fs::create_dir_all(dir.join("data")).map_err(|e| e.to_string())?;
    if !verify_spec(&dir) {
        return Err(tr("The chain file check failed after installation."));
    }
    let link = if o.shortcut {
        match create_shortcut(&dir, o.shortcut_dir.as_deref(), o.update) {
            Ok(l) => l,
            Err(e) => {
                log(&format!("shortcut failed: {e}"));
                None
            }
        }
    } else {
        None
    };
    lock_down_permissions(&dir);
    register_uninstall(&dir, &entries);
    log(&format!("installed ok; shortcut={link:?}"));
    Ok((dir, link))
}

fn main() {
    // SAFETY: AttachConsole takes no pointers.
    let console = unsafe { AttachConsole(u32::MAX) } != 0;
    let o = parse_opts();
    let quiet = o.quiet || o.update || console;
    match install(&o) {
        Ok((dir, link)) => {
            if o.launch {
                let _ = Command::new(dir.join("bin").join("madar-app.exe"))
                    .arg("start")
                    .current_dir(&dir)
                    .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
                    .spawn();
            }
            let msg = format!(
                "{}\n{}\n\n{}{}",
                tr(&format!("MADAR {VERSION} is installed in:")),
                dir.display(),
                if link.is_some() {
                    tr(&format!(
                        "You will find the \"{APP_NAME}\" shortcut on your desktop.\n"
                    ))
                } else {
                    String::new()
                },
                if o.launch {
                    tr("Your page opens now to create your account.")
                } else {
                    String::new()
                }
            );
            if quiet {
                println!("{msg}");
            } else {
                message(&msg, MB_ICONINFORMATION);
            }
            std::process::exit(0);
        }
        Err(e) if e.is_empty() => std::process::exit(1),
        Err(e) => {
            log(&format!("failed: {e}"));
            let msg = format!("{e}\n\n{} {}", tr("Log:"), log_path().display());
            if o.quiet || console {
                eprintln!("{msg}");
            } else {
                message(&msg, MB_ICONERROR);
            }
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut v = MAGIC.to_vec();
        v.extend((files.len() as u32).to_le_bytes());
        for (n, d) in files {
            v.extend((n.len() as u16).to_le_bytes());
            v.extend(n.as_bytes());
            v.extend(Sha256::digest(d));
            v.extend((d.len() as u64).to_le_bytes());
            v.extend(*d);
        }
        v
    }

    #[test]
    fn payload_roundtrip_and_path_safety() {
        let ok = parse_payload(&pack(&[("bin/a.exe", b"x"), ("VERSION", b"2")])).unwrap();
        assert_eq!(ok.len(), 2);
        assert_eq!(ok[0].name, "bin/a.exe");
        for bad in [
            "../x",
            "/x",
            "c:/x",
            "bin\\x",
            "data/account.json",
            "DATA",
            "a//b",
            "./x",
        ] {
            assert!(parse_payload(&pack(&[(bad, b"x")])).is_err(), "{bad}");
        }
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let mut p = pack(&[("VERSION", b"2.0.0")]);
        let last = p.len() - 1;
        p[last] ^= 1;
        assert!(parse_payload(&p).is_err());
        assert!(parse_payload(b"nope").is_err());
        let mut t = pack(&[("VERSION", b"2.0.0")]);
        t.truncate(t.len() - 2);
        assert!(parse_payload(&t).is_err(), "truncated");
    }
}
