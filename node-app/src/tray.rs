//! MADAR icon in the taskbar notification area (next to the clock), using Win32 directly with no extra crates.
//!
//! - Its color follows the node state (running / catching up / disconnected / stopped), and its tooltip shows the state and block.
//! - Click: opens the page. Right-click menu: open the page, stop the node.
//! - Balloon notification when needed, e.g. disconnected for more than 5 minutes.
//! - Re-adds itself if Windows Explorer restarts (TaskbarCreated message).

use std::ffi::c_void;
use std::path::PathBuf;
use std::sync::atomic::{AtomicIsize, AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};

type Hwnd = isize;

#[repr(C)]
struct WndClassExW {
    cb_size: u32,
    style: u32,
    wnd_proc: extern "system" fn(Hwnd, u32, usize, isize) -> isize,
    cls_extra: i32,
    wnd_extra: i32,
    instance: isize,
    icon: isize,
    cursor: isize,
    background: isize,
    menu_name: *const u16,
    class_name: *const u16,
    icon_sm: isize,
}

#[repr(C)]
struct Msg {
    hwnd: Hwnd,
    message: u32,
    wparam: usize,
    lparam: isize,
    time: u32,
    pt: [i32; 2],
    private: u32,
}

#[repr(C)]
struct NotifyIconDataW {
    cb_size: u32,
    hwnd: Hwnd,
    id: u32,
    flags: u32,
    callback_message: u32,
    icon: isize,
    tip: [u16; 128],
    state: u32,
    state_mask: u32,
    info: [u16; 256],
    version_or_timeout: u32,
    info_title: [u16; 64],
    info_flags: u32,
    guid: [u8; 16],
    balloon_icon: isize,
}

#[link(name = "user32")]
extern "system" {
    fn RegisterClassExW(c: *const WndClassExW) -> u16;
    fn CreateWindowExW(
        ex: u32,
        class: *const u16,
        name: *const u16,
        style: u32,
        x: i32,
        y: i32,
        w: i32,
        h: i32,
        parent: Hwnd,
        menu: isize,
        inst: isize,
        param: *mut c_void,
    ) -> Hwnd;
    fn DefWindowProcW(h: Hwnd, m: u32, w: usize, l: isize) -> isize;
    fn GetMessageW(m: *mut Msg, h: Hwnd, min: u32, max: u32) -> i32;
    fn TranslateMessage(m: *const Msg) -> i32;
    fn DispatchMessageW(m: *const Msg) -> isize;
    fn PostMessageW(h: Hwnd, m: u32, w: usize, l: isize) -> i32;
    fn CreatePopupMenu() -> isize;
    fn AppendMenuW(menu: isize, flags: u32, id: usize, text: *const u16) -> i32;
    fn TrackPopupMenu(
        menu: isize,
        flags: u32,
        x: i32,
        y: i32,
        reserved: i32,
        h: Hwnd,
        rect: *const c_void,
    ) -> i32;
    fn DestroyMenu(menu: isize) -> i32;
    fn SetForegroundWindow(h: Hwnd) -> i32;
    fn GetCursorPos(p: *mut [i32; 2]) -> i32;
    fn RegisterWindowMessageW(name: *const u16) -> u32;
    fn LoadImageW(inst: isize, name: *const u16, kind: u32, cx: i32, cy: i32, flags: u32) -> isize;
}
#[link(name = "shell32")]
extern "system" {
    fn Shell_NotifyIconW(msg: u32, data: *mut NotifyIconDataW) -> i32;
}
#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleW(name: *const u16) -> isize;
}

const WM_APP: u32 = 0x8000;
const WM_TRAY: u32 = WM_APP + 1; // from the icon
const WM_REFRESH: u32 = WM_APP + 2; // state/tooltip/notification changed
const WM_LBUTTONUP: u32 = 0x0202;
const WM_RBUTTONUP: u32 = 0x0205;
const WM_CONTEXTMENU: u32 = 0x007B;
const NIM_ADD: u32 = 0;
const NIM_MODIFY: u32 = 1;
const NIF_MESSAGE: u32 = 1;
const NIF_ICON: u32 = 2;
const NIF_TIP: u32 = 4;
const NIF_INFO: u32 = 0x10;
const NIIF_INFO: u32 = 1;
const NIIF_WARNING: u32 = 2;
const MF_STRING: u32 = 0;
const MF_SEPARATOR: u32 = 0x800;
const TPM_RETURNCMD: u32 = 0x100;
const TPM_RIGHTBUTTON: u32 = 2;
const IMAGE_ICON: u32 = 1;
const LR_LOADFROMFILE: u32 = 0x10;
const HWND_MESSAGE: Hwnd = -3;
const CMD_OPEN: usize = 1;
const CMD_STOP: usize = 2;

/// Icon state: determines its color.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Good,
    Warn,
    Bad,
    Idle,
}

struct Shared {
    icons: [isize; 4], // Good, Warn, Bad, Idle
    tone: Tone,
    tip: String,
    balloon: Option<(String, String, bool)>, // title, text, warning?
    labels: (String, String),                // "Open MADAR", "Stop node"
    on_open: Box<dyn Fn() + Send>,
    on_stop: Box<dyn Fn() + Send>,
}

static HWND: AtomicIsize = AtomicIsize::new(0);
static TASKBAR_CREATED: AtomicU32 = AtomicU32::new(0);
static SHARED: OnceLock<Mutex<Shared>> = OnceLock::new();

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn fill(dst: &mut [u16], s: &str) {
    let w: Vec<u16> = s.encode_utf16().take(dst.len() - 1).collect();
    dst[..w.len()].copy_from_slice(&w);
    dst[w.len()] = 0;
}

fn tone_index(t: Tone) -> usize {
    match t {
        Tone::Good => 0,
        Tone::Warn => 1,
        Tone::Bad => 2,
        Tone::Idle => 3,
    }
}

fn nid(hwnd: Hwnd) -> NotifyIconDataW {
    NotifyIconDataW {
        cb_size: std::mem::size_of::<NotifyIconDataW>() as u32,
        hwnd,
        id: 1,
        flags: 0,
        callback_message: WM_TRAY,
        icon: 0,
        tip: [0; 128],
        state: 0,
        state_mask: 0,
        info: [0; 256],
        version_or_timeout: 0,
        info_title: [0; 64],
        info_flags: 0,
        guid: [0; 16],
        balloon_icon: 0,
    }
}

/// Adds/updates the icon from the shared state, and shows the pending notification if any.
fn sync_icon(hwnd: Hwnd, op: u32) {
    let Some(shared) = SHARED.get() else { return };
    let mut s = shared.lock().unwrap();
    let mut d = nid(hwnd);
    d.flags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    d.icon = s.icons[tone_index(s.tone)];
    fill(&mut d.tip, &s.tip);
    if let Some((title, text, warn)) = s.balloon.take() {
        d.flags |= NIF_INFO;
        fill(&mut d.info_title, &title);
        fill(&mut d.info, &text);
        d.info_flags = if warn { NIIF_WARNING } else { NIIF_INFO };
    }
    // SAFETY: fully initialized struct that lives until the end of the call.
    unsafe { Shell_NotifyIconW(op, &mut d) };
}

fn show_menu(hwnd: Hwnd) {
    let Some(shared) = SHARED.get() else { return };
    let (open, stop) = shared.lock().unwrap().labels.clone();
    let (w_open, w_stop) = (wide(&open), wide(&stop));
    // SAFETY: handles are created and destroyed here; strings live until the end of the function.
    let cmd = unsafe {
        let menu = CreatePopupMenu();
        AppendMenuW(menu, MF_STRING, CMD_OPEN, w_open.as_ptr());
        AppendMenuW(menu, MF_SEPARATOR, 0, std::ptr::null());
        AppendMenuW(menu, MF_STRING, CMD_STOP, w_stop.as_ptr());
        let mut pt = [0i32; 2];
        GetCursorPos(&mut pt);
        SetForegroundWindow(hwnd); // otherwise the menu does not close when clicking outside it
        let cmd = TrackPopupMenu(
            menu,
            TPM_RETURNCMD | TPM_RIGHTBUTTON,
            pt[0],
            pt[1],
            0,
            hwnd,
            std::ptr::null(),
        );
        DestroyMenu(menu);
        cmd as usize
    };
    run_command(cmd);
}

fn run_command(cmd: usize) {
    let Some(shared) = SHARED.get() else { return };
    let s = shared.lock().unwrap();
    match cmd {
        CMD_OPEN => (s.on_open)(),
        CMD_STOP => (s.on_stop)(),
        _ => {}
    }
}

extern "system" fn wnd_proc(hwnd: Hwnd, msg: u32, wparam: usize, lparam: isize) -> isize {
    match msg {
        WM_TRAY => {
            match (lparam & 0xFFFF) as u32 {
                WM_LBUTTONUP => run_command(CMD_OPEN),
                WM_RBUTTONUP | WM_CONTEXTMENU => show_menu(hwnd),
                _ => {}
            }
            0
        }
        WM_REFRESH => {
            sync_icon(hwnd, NIM_MODIFY);
            0
        }
        m if m != 0 && m == TASKBAR_CREATED.load(Ordering::Relaxed) => {
            sync_icon(hwnd, NIM_ADD);
            0
        }
        // SAFETY: default handling for all other messages.
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

fn load_icon(path: &PathBuf) -> isize {
    let w = wide(&path.display().to_string());
    // SAFETY: null-terminated path; LoadImage returns 0 on failure.
    unsafe { LoadImageW(0, w.as_ptr(), IMAGE_ICON, 16, 16, LR_LOADFROMFILE) }
}

/// Starts the icon on its own thread with a message loop. `icons_dir` contains tray-good/warn/bad/idle.ico.
pub fn start(
    icons_dir: PathBuf,
    tip: String,
    labels: (String, String),
    on_open: Box<dyn Fn() + Send>,
    on_stop: Box<dyn Fn() + Send>,
) {
    let names = [
        "tray-good.ico",
        "tray-warn.ico",
        "tray-bad.ico",
        "tray-idle.ico",
    ];
    let fallback = load_icon(&icons_dir.join("madar.ico"));
    let icons = names.map(|n| {
        let h = load_icon(&icons_dir.join(n));
        if h == 0 {
            fallback
        } else {
            h
        }
    });
    let _ = SHARED.set(Mutex::new(Shared {
        icons,
        tone: Tone::Idle,
        tip,
        balloon: None,
        labels,
        on_open,
        on_stop,
    }));
    std::thread::spawn(|| {
        let class = wide("MadarNodeTray");
        // SAFETY: registers a class and a (hidden) message-only window, then runs a message loop until the process exits.
        unsafe {
            let inst = GetModuleHandleW(std::ptr::null());
            let wc = WndClassExW {
                cb_size: std::mem::size_of::<WndClassExW>() as u32,
                style: 0,
                wnd_proc,
                cls_extra: 0,
                wnd_extra: 0,
                instance: inst,
                icon: 0,
                cursor: 0,
                background: 0,
                menu_name: std::ptr::null(),
                class_name: class.as_ptr(),
                icon_sm: 0,
            };
            RegisterClassExW(&wc);
            TASKBAR_CREATED.store(
                RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()),
                Ordering::Relaxed,
            );
            let hwnd = CreateWindowExW(
                0,
                class.as_ptr(),
                class.as_ptr(),
                0,
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                0,
                inst,
                std::ptr::null_mut(),
            );
            if hwnd == 0 {
                return;
            }
            HWND.store(hwnd, Ordering::Relaxed);
            sync_icon(hwnd, NIM_ADD);
            let mut m: Msg = std::mem::zeroed();
            while GetMessageW(&mut m, 0, 0, 0) > 0 {
                TranslateMessage(&m);
                DispatchMessageW(&m);
            }
        }
    });
}

fn poke() {
    let h = HWND.load(Ordering::Relaxed);
    if h != 0 {
        // SAFETY: the icon window lives until the process exits.
        unsafe { PostMessageW(h, WM_REFRESH, 0, 0) };
    }
}

/// Updates the color and tooltip (ignored if nothing changed).
pub fn set(tone: Tone, tip: &str, labels: (String, String)) {
    let Some(shared) = SHARED.get() else { return };
    {
        let mut s = shared.lock().unwrap();
        if s.tone == tone && s.tip == tip && s.labels == labels {
            return;
        }
        s.tone = tone;
        s.tip = tip.to_string();
        s.labels = labels;
    }
    poke();
}

/// Balloon notification from the icon.
pub fn notify(title: &str, text: &str, warning: bool) {
    let Some(shared) = SHARED.get() else { return };
    shared.lock().unwrap().balloon = Some((title.to_string(), text.to_string(), warning));
    poke();
}

/// Removes the icon (on exit) so it does not linger as a "ghost" in the taskbar.
pub fn remove() {
    let h = HWND.load(Ordering::Relaxed);
    if h != 0 {
        let mut d = nid(h);
        // SAFETY: delete the icon with the same identifier.
        unsafe {
            Shell_NotifyIconW(2 /* NIM_DELETE */, &mut d)
        };
    }
}
