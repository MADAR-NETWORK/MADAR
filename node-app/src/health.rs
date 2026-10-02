//! Device self-checks: disk space, power (on battery?), metered internet, and clock drift.
//! All read-only; the decision (warn / pause / repair) is made in main.

use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[repr(C)]
struct SystemPowerStatus {
    ac_line_status: u8,
    battery_flag: u8,
    battery_life_percent: u8,
    system_status_flag: u8,
    battery_life_time: u32,
    battery_full_life_time: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn GetDiskFreeSpaceExW(
        dir: *const u16,
        free_to_caller: *mut u64,
        total: *mut u64,
        total_free: *mut u64,
    ) -> i32;
    fn GetSystemPowerStatus(s: *mut SystemPowerStatus) -> i32;
}

/// Free space available to the user on the disk of `dir` (bytes).
pub fn disk_free(dir: &Path) -> Option<u64> {
    let w: Vec<u16> = dir
        .display()
        .to_string()
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let (mut free, mut total, mut tfree) = (0u64, 0u64, 0u64);
    // SAFETY: null-terminated path and pointers to local variables.
    (unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut free, &mut total, &mut tfree) } != 0)
        .then_some(free)
}

/// Is the device running on battery right now (charger unplugged)?
pub fn on_battery() -> bool {
    let mut s = SystemPowerStatus {
        ac_line_status: 255,
        battery_flag: 0,
        battery_life_percent: 0,
        system_status_flag: 0,
        battery_life_time: 0,
        battery_full_life_time: 0,
    };
    // SAFETY: local struct of the correct size.
    (unsafe { GetSystemPowerStatus(&mut s) } != 0) && s.ac_line_status == 0
}

fn hidden_powershell(script: &str) -> Option<String> {
    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .stdin(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Is the current internet connection metered (mobile data or a data-capped connection)? None = unknown.
pub fn metered() -> Option<bool> {
    let o = hidden_powershell(
        "$p=[Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile(); \
         if ($p) { $p.GetConnectionCost().NetworkCostType } else { 'None' }",
    )?;
    match o.as_str() {
        "Fixed" | "Variable" => Some(true),
        "Unrestricted" => Some(false),
        _ => None,
    }
}

/// Device clock drift in seconds from the Windows time server (positive = device is ahead). None = could not measure.
pub fn clock_offset_secs() -> Option<f64> {
    let out = Command::new("w32tm")
        .args([
            "/stripchart",
            "/computer:time.windows.com",
            "/dataonly",
            "/samples:1",
        ])
        .stdin(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    parse_w32tm(&String::from_utf8_lossy(&out.stdout))
}

/// Parses a line like `22:10:01, +00.0123456s` and returns the drift with the sign inverted (w32tm prints "server - device").
pub fn parse_w32tm(text: &str) -> Option<f64> {
    text.lines().rev().find_map(|l| {
        let (_, v) = l.split_once(',')?;
        let v = v.trim().trim_end_matches('s');
        v.parse::<f64>().ok().map(|x| -x)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn w32tm_output_is_parsed() {
        let t = "Tracking time.windows.com [1.2.3.4:123].\nCollecting 1 samples.\nThe current time is 26/09/2026 22:10:01.\n22:10:01, +00.0123456s\n";
        assert!((parse_w32tm(t).unwrap() + 0.0123456).abs() < 1e-9);
        assert!((parse_w32tm("22:10:01, -45.5s").unwrap() - 45.5).abs() < 1e-9);
        assert_eq!(parse_w32tm("error: 0x800705B4"), None);
    }

    #[test]
    fn disk_free_reads_the_system_drive() {
        assert!(disk_free(Path::new("C:\\")).unwrap_or(0) > 0);
    }
}
