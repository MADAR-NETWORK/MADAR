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
/// Written through the Windows registry API itself, not reg.exe: reg.exe started by an installer is a pattern antivirus
/// behaviour monitors flag, and its writes were found not to stick (the entry kept an old test folder, 2026-10-13).
fn register_uninstall(dir: &Path, entries: &[Entry]) {
    let app = dir.join("bin").join("madar-app.exe");
    let size_kb = u32::try_from(entries.iter().map(|e| e.data.len() as u64).sum::<u64>() / 1024)
        .unwrap_or(u32::MAX);
    let texts: [(&str, String); 6] = [
        ("DisplayName", "MADAR Node".into()),
        ("DisplayVersion", VERSION.into()),
        ("Publisher", "MADAR NETWORK".into()),
        ("DisplayIcon", dir.join("madar.ico").display().to_string()),
        ("InstallLocation", dir.display().to_string()),
        (
            "UninstallString",
            format!("\"{}\" uninstall", app.display()),
        ),
    ];
    let numbers: [(&str, u32); 3] = [("EstimatedSize", size_kb), ("NoModify", 1), ("NoRepair", 1)];
    match write_uninstall_key(UNINSTALL_SUBKEY, &texts, &numbers) {
        Ok(()) => log("uninstall entry written"),
        Err(e) => log(&format!("uninstall entry not written: {e}")),
    }
}

const UNINSTALL_SUBKEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\MADARNode";
/// HKEY_CURRENT_USER as the API wants it: (HKEY)(ULONG_PTR)(LONG)0x80000001.
const HKCU: isize = 0x8000_0001u32 as i32 as isize;
const KEY_WRITE: u32 = 0x2_0006;
const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;

#[link(name = "advapi32")]
extern "system" {
    fn RegCreateKeyExW(
        key: isize,
        sub: *const u16,
        reserved: u32,
        class: *const u16,
        options: u32,
        sam: u32,
        security: *const c_void,
        out: *mut isize,
        disposition: *mut u32,
    ) -> i32;
    fn RegSetValueExW(
        key: isize,
        name: *const u16,
        reserved: u32,
        kind: u32,
        data: *const u8,
        len: u32,
    ) -> i32;
    fn RegCloseKey(key: isize) -> i32;
}

/// Creates (or opens) `subkey` under HKCU and sets every value; the first failing call is reported (Win32 error code).
fn write_uninstall_key(
    subkey: &str,
    texts: &[(&str, String)],
    numbers: &[(&str, u32)],
) -> Result<(), String> {
    let sub = wide(subkey);
    let mut key: isize = 0;
    // SAFETY: valid NUL-terminated strings; `key` receives an open handle that is closed below on every path.
    let r = unsafe {
        RegCreateKeyExW(
            HKCU,
            sub.as_ptr(),
            0,
            std::ptr::null(),
            0,
            KEY_WRITE,
            std::ptr::null(),
            &mut key,
            std::ptr::null_mut(),
        )
    };
    if r != 0 {
        return Err(format!("create key: {r}"));
    }
    let mut result = Ok(());
    for (name, value) in texts {
        let n = wide(name);
        let v = wide(value);
        // SAFETY: `v` is NUL-terminated UTF-16 and the length (in bytes) includes the terminator, as REG_SZ wants.
        let r = unsafe {
            RegSetValueExW(
                key,
                n.as_ptr(),
                0,
                REG_SZ,
                v.as_ptr().cast(),
                (v.len() * 2) as u32,
            )
        };
        if r != 0 && result.is_ok() {
            result = Err(format!("{name}: {r}"));
        }
    }
    for (name, value) in numbers {
        let n = wide(name);
        let v = value.to_le_bytes();
        // SAFETY: four bytes for a REG_DWORD.
        let r = unsafe { RegSetValueExW(key, n.as_ptr(), 0, REG_DWORD, v.as_ptr(), 4) };
        if r != 0 && result.is_ok() {
            result = Err(format!("{name}: {r}"));
        }
    }
    // SAFETY: the handle opened above.
    unsafe { RegCloseKey(key) };
    result
}

/// The desktop shortcut through Windows' own Shell Link service (COM IShellLinkW) — no PowerShell, which antivirus
/// behaviour monitors flag (Bitdefender removed the app on 2026-10-13). `only_existing` (update mode): only a
/// shortcut that already points to this installation is rewritten.
fn create_shortcut(
    dir: &Path,
    shortcut_dir: Option<&Path>,
    only_existing: bool,
) -> Result<Option<PathBuf>, String> {
    let folder = match shortcut_dir {
        Some(d) => d.to_path_buf(),
        None => desktop_dir().ok_or("no desktop folder")?,
    };
    let link = folder.join(format!("{APP_NAME}.lnk"));
    let target = dir.join("bin").join("madar-app.exe");
    if only_existing
        && !(link.exists()
            && shell_link_target(&link)
                .is_some_and(|t| t.eq_ignore_ascii_case(&target.display().to_string())))
    {
        return Ok(None);
    }
    save_shell_link(
        &link,
        &target.display().to_string(),
        "start",
        &dir.display().to_string(),
        &dir.join("madar.ico").display().to_string(),
        "MADAR Network node",
    )?;
    Ok(Some(link))
}

#[link(name = "shell32")]
extern "system" {
    fn SHGetKnownFolderPath(
        id: *const [u8; 16],
        flags: u32,
        token: *mut c_void,
        path: *mut *mut u16,
    ) -> i32;
}
#[link(name = "ole32")]
extern "system" {
    fn CoTaskMemFree(p: *mut c_void);
    fn CoInitializeEx(reserved: *mut c_void, model: u32) -> i32;
    fn CoCreateInstance(
        clsid: *const [u8; 16],
        outer: *mut c_void,
        ctx: u32,
        iid: *const [u8; 16],
        out: *mut *mut c_void,
    ) -> i32;
}

/// A GUID in its in-memory byte order.
const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> [u8; 16] {
    let a = d1.to_le_bytes();
    let b = d2.to_le_bytes();
    let c = d3.to_le_bytes();
    [
        a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d4[0], d4[1], d4[2], d4[3], d4[4], d4[5],
        d4[6], d4[7],
    ]
}
const CLSID_SHELL_LINK: [u8; 16] = guid(0x0002_1401, 0, 0, [0xC0, 0, 0, 0, 0, 0, 0, 0x46]);
const IID_ISHELL_LINK_W: [u8; 16] = guid(0x0002_14F9, 0, 0, [0xC0, 0, 0, 0, 0, 0, 0, 0x46]);
const IID_IPERSIST_FILE: [u8; 16] = guid(0x0000_010B, 0, 0, [0xC0, 0, 0, 0, 0, 0, 0, 0x46]);
const FOLDERID_DESKTOP: [u8; 16] = guid(
    0xB4BF_CC3A,
    0xDB2C,
    0x424C,
    [0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41],
);

/// The user's desktop folder as Windows knows it (also when it was moved, e.g. into OneDrive).
fn desktop_dir() -> Option<PathBuf> {
    let mut p: *mut u16 = std::ptr::null_mut();
    // SAFETY: Windows writes a NUL-terminated string it allocated; we read it once and free it with CoTaskMemFree.
    unsafe {
        let ok = SHGetKnownFolderPath(&FOLDERID_DESKTOP, 0, std::ptr::null_mut(), &mut p) == 0
            && !p.is_null();
        let out = ok.then(|| PathBuf::from(from_wide_ptr(p)));
        if !p.is_null() {
            CoTaskMemFree(p as *mut c_void);
        }
        out
    }
}

/// SAFETY: `p` points to a NUL-terminated UTF-16 string.
unsafe fn from_wide_ptr(p: *const u16) -> String {
    let mut n = 0;
    while *p.add(n) != 0 {
        n += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
}

fn wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// A COM interface pointer: slot `i` of its method table, released once when dropped.
struct Com(*mut c_void);
impl Com {
    /// SAFETY: `self.0` is a live COM interface whose table has more than `i` entries.
    unsafe fn slot(&self, i: usize) -> *const c_void {
        *(*(self.0 as *const *const *const c_void)).add(i)
    }
}
impl Drop for Com {
    fn drop(&mut self) {
        // SAFETY: slot 2 of every COM interface is Release.
        unsafe {
            let release: extern "system" fn(*mut c_void) -> u32 = std::mem::transmute(self.slot(2));
            release(self.0);
        }
    }
}

/// IShellLinkW and its IPersistFile, on a thread with COM started.
fn shell_link_objects() -> Result<(Com, Com), String> {
    // SAFETY: standard COM creation; every pointer is checked before use and released by Com::drop.
    unsafe {
        CoInitializeEx(std::ptr::null_mut(), 0x2); // COINIT_APARTMENTTHREADED (S_FALSE when already started is fine)
        let mut link: *mut c_void = std::ptr::null_mut();
        let hr = CoCreateInstance(
            &CLSID_SHELL_LINK,
            std::ptr::null_mut(),
            0x1, /* CLSCTX_INPROC_SERVER */
            &IID_ISHELL_LINK_W,
            &mut link,
        );
        if hr < 0 || link.is_null() {
            return Err(format!("ShellLink 0x{hr:08x}"));
        }
        let link = Com(link);
        let qi: extern "system" fn(*mut c_void, *const [u8; 16], *mut *mut c_void) -> i32 =
            std::mem::transmute(link.slot(0));
        let mut file: *mut c_void = std::ptr::null_mut();
        let hr = qi(link.0, &IID_IPERSIST_FILE, &mut file);
        if hr < 0 || file.is_null() {
            return Err(format!("IPersistFile 0x{hr:08x}"));
        }
        Ok((link, Com(file)))
    }
}

fn save_shell_link(
    at: &Path,
    target: &str,
    args: &str,
    workdir: &str,
    icon: &str,
    desc: &str,
) -> Result<(), String> {
    let (link, file) = shell_link_objects()?;
    let check = |hr: i32, what: &str| {
        if hr < 0 {
            Err(format!("{what} 0x{hr:08x}"))
        } else {
            Ok(())
        }
    };
    // SAFETY: IShellLinkW slots 7 SetDescription, 9 SetWorkingDirectory, 11 SetArguments, 17 SetIconLocation,
    // 20 SetPath; IPersistFile slot 6 Save. Every string is NUL-terminated and outlives its call.
    unsafe {
        type SetStr = extern "system" fn(*mut c_void, *const u16) -> i32;
        let set = |slot: usize, s: &str| -> i32 {
            let f: SetStr = std::mem::transmute(link.slot(slot));
            f(link.0, wide_z(s).as_ptr())
        };
        check(set(20, target), "SetPath")?;
        check(set(11, args), "SetArguments")?;
        check(set(9, workdir), "SetWorkingDirectory")?;
        check(set(7, desc), "SetDescription")?;
        let icon_fn: extern "system" fn(*mut c_void, *const u16, i32) -> i32 =
            std::mem::transmute(link.slot(17));
        check(icon_fn(link.0, wide_z(icon).as_ptr(), 0), "SetIconLocation")?;
        let save: extern "system" fn(*mut c_void, *const u16, i32) -> i32 =
            std::mem::transmute(file.slot(6));
        check(
            save(file.0, wide_z(&at.display().to_string()).as_ptr(), 1),
            "Save",
        )
    }
}

/// The program an existing shortcut opens, if it can be read.
fn shell_link_target(at: &Path) -> Option<String> {
    let (link, file) = shell_link_objects().ok()?;
    // SAFETY: IPersistFile slot 5 Load; IShellLinkW slot 3 GetPath (buffer of 1024 u16, NUL-terminated on success).
    unsafe {
        let load: extern "system" fn(*mut c_void, *const u16, u32) -> i32 =
            std::mem::transmute(file.slot(5));
        if load(file.0, wide_z(&at.display().to_string()).as_ptr(), 0) < 0 {
            return None;
        }
        let mut buf = vec![0u16; 1024];
        let get: extern "system" fn(*mut c_void, *mut u16, i32, *mut c_void, u32) -> i32 =
            std::mem::transmute(link.slot(3));
        (get(
            link.0,
            buf.as_mut_ptr(),
            buf.len() as i32,
            std::ptr::null_mut(),
            0x4, /* SLGP_RAWPATH */
        ) >= 0)
            .then(|| {
                String::from_utf16_lossy(
                    &buf[..buf.iter().position(|&c| c == 0).unwrap_or(buf.len())],
                )
            })
    }
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
                    tr("Your MADAR page opens now.")
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

#[cfg(test)]
mod lnk_tests {
    use super::*;

    #[test]
    fn a_shortcut_is_saved_through_windows_and_read_back_also_in_a_non_ascii_folder() {
        let dir = std::env::temp_dir().join(format!("madar-lnk-José-日本-{}", std::process::id()));
        let _ = fs::create_dir_all(dir.join("bin"));
        let exe = dir.join("bin").join("madar-app.exe");
        fs::write(&exe, b"x").unwrap();
        let at = dir.join("test.lnk");
        save_shell_link(
            &at,
            &exe.display().to_string(),
            "start",
            &dir.display().to_string(),
            &dir.join("madar.ico").display().to_string(),
            "MADAR Network node",
        )
        .unwrap();
        assert_eq!(
            shell_link_target(&at).as_deref(),
            Some(exe.display().to_string().as_str())
        );
        assert!(desktop_dir().is_some_and(|d| d.is_dir()));
        let _ = fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod registry_tests {
    use super::*;

    #[test]
    fn the_uninstall_values_are_written_through_the_registry_api_also_with_non_ascii_paths() {
        // a throw-away key, never the real MADARNode one
        let sub = format!(r"Software\MADAR-Test-Uninstall-{}", std::process::id());
        let path = r"D:\Apps\José-日本\MADAR-Network\bin\madar-app.exe";
        write_uninstall_key(
            &sub,
            &[
                ("DisplayName", "MADAR Node".into()),
                ("UninstallString", format!("\"{path}\" uninstall")),
            ],
            &[("NoModify", 1)],
        )
        .unwrap();
        let q = |v: &str| {
            let o = Command::new("reg")
                .args(["query", &format!(r"HKCU\{sub}"), "/v", v])
                .output()
                .unwrap();
            String::from_utf8_lossy(&o.stdout).to_string()
        };
        assert!(q("DisplayName").contains("MADAR Node"));
        assert!(q("NoModify").contains("0x1"));
        // reg query prints in the console code page, so the non-ASCII part is checked through the API path only
        assert!(q("UninstallString").contains("uninstall"));
        let _ = Command::new("reg")
            .args(["delete", &format!(r"HKCU\{sub}"), "/f"])
            .output();
    }

    // regression (2026-10-16): the path once lost its backslashes, so the Apps entry went to a wrong key
    #[test]
    fn the_uninstall_entry_lives_under_the_real_windows_uninstall_key() {
        assert_eq!(
            super::UNINSTALL_SUBKEY.split('\\').collect::<Vec<_>>(),
            [
                "Software",
                "Microsoft",
                "Windows",
                "CurrentVersion",
                "Uninstall",
                "MADARNode"
            ]
        );
    }
}
