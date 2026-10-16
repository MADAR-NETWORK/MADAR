//! The few registry values the app needs (start with Windows, the "Apps" entry), read and written through the
//! Windows registry API itself, under HKEY_CURRENT_USER only. Not reg.exe: a program starting reg.exe is a pattern
//! antivirus behaviour monitors flag (lesson of 2026-10-13), and a console tool is slower and harder to check.

use std::ffi::c_void;

/// HKEY_CURRENT_USER as the API wants it: (HKEY)(ULONG_PTR)(LONG)0x80000001.
const HKCU: isize = 0x8000_0001u32 as i32 as isize;
const KEY_READ: u32 = 0x2_0019;
const KEY_WRITE: u32 = 0x2_0006;
const REG_SZ: u32 = 1;
const RRF_RT_REG_SZ: u32 = 0x0000_0002;
const ERROR_FILE_NOT_FOUND: i32 = 2;

#[link(name = "advapi32")]
extern "system" {
    fn RegOpenKeyExW(key: isize, sub: *const u16, options: u32, sam: u32, out: *mut isize) -> i32;
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
    fn RegGetValueW(
        key: isize,
        sub: *const u16,
        value: *const u16,
        flags: u32,
        kind: *mut u32,
        data: *mut c_void,
        len: *mut u32,
    ) -> i32;
    fn RegDeleteValueW(key: isize, name: *const u16) -> i32;
    fn RegDeleteKeyW(key: isize, sub: *const u16) -> i32;
    fn RegCloseKey(key: isize) -> i32;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// A text value under HKCU\`sub`; None when the key or value is missing (or is not text).
pub fn get_string(sub: &str, value: &str) -> Option<String> {
    let (s, v) = (wide(sub), wide(value));
    let mut len: u32 = 0;
    // SAFETY: first call only asks the size (null buffer); strings are NUL-terminated.
    let r = unsafe {
        RegGetValueW(
            HKCU,
            s.as_ptr(),
            v.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut len,
        )
    };
    if r != 0 || len == 0 || len > 64 * 1024 {
        return None;
    }
    let mut buf = vec![0u16; (len as usize).div_ceil(2)];
    let mut got = (buf.len() * 2) as u32;
    // SAFETY: `buf` holds `got` bytes; the API writes at most that and NUL-terminates REG_SZ data.
    let r = unsafe {
        RegGetValueW(
            HKCU,
            s.as_ptr(),
            v.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut got,
        )
    };
    if r != 0 {
        return None;
    }
    let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
    Some(String::from_utf16_lossy(&buf[..end]))
}

/// Sets a text value under HKCU\`sub` (the key is created when missing).
pub fn set_string(sub: &str, value: &str, data: &str) -> bool {
    let (s, v, d) = (wide(sub), wide(value), wide(data));
    let mut key: isize = 0;
    // SAFETY: NUL-terminated strings; the handle is closed below.
    if unsafe {
        RegCreateKeyExW(
            HKCU,
            s.as_ptr(),
            0,
            std::ptr::null(),
            0,
            KEY_WRITE,
            std::ptr::null(),
            &mut key,
            std::ptr::null_mut(),
        )
    } != 0
    {
        return false;
    }
    // SAFETY: REG_SZ length in bytes includes the terminator.
    let ok = unsafe {
        RegSetValueExW(
            key,
            v.as_ptr(),
            0,
            REG_SZ,
            d.as_ptr().cast(),
            (d.len() * 2) as u32,
        )
    } == 0;
    // SAFETY: the handle opened above.
    unsafe { RegCloseKey(key) };
    ok
}

/// Removes one value under HKCU\`sub`; true also when it was not there.
pub fn delete_value(sub: &str, value: &str) -> bool {
    let (s, v) = (wide(sub), wide(value));
    let mut key: isize = 0;
    // SAFETY: NUL-terminated strings; the handle is closed below.
    match unsafe { RegOpenKeyExW(HKCU, s.as_ptr(), 0, KEY_WRITE | KEY_READ, &mut key) } {
        0 => {}
        ERROR_FILE_NOT_FOUND => return true,
        _ => return false,
    }
    // SAFETY: an open handle and a NUL-terminated name.
    let r = unsafe { RegDeleteValueW(key, v.as_ptr()) };
    // SAFETY: the handle opened above.
    unsafe { RegCloseKey(key) };
    r == 0 || r == ERROR_FILE_NOT_FOUND
}

/// Removes HKCU\`sub` (a key without subkeys, like the "Apps" entry); true also when it was not there.
pub fn delete_key(sub: &str) -> bool {
    let s = wide(sub);
    // SAFETY: a NUL-terminated path under HKCU.
    let r = unsafe { RegDeleteKeyW(HKCU, s.as_ptr()) };
    r == 0 || r == ERROR_FILE_NOT_FOUND
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_written_read_and_removed_also_with_non_ascii_text() {
        // a throw-away key, never the real Run or Apps keys
        let sub = format!(r"Software\MADAR-Test-Reg-{}", std::process::id());
        assert_eq!(get_string(&sub, "x"), None);
        let path = r#""D:\Apps\José-日本\MADAR-Network\bin\madar-app.exe" start --background"#;
        assert!(set_string(&sub, "MADAR Node", path));
        assert_eq!(get_string(&sub, "MADAR Node").as_deref(), Some(path));
        assert!(delete_value(&sub, "MADAR Node"));
        assert_eq!(get_string(&sub, "MADAR Node"), None);
        assert!(delete_value(&sub, "MADAR Node"), "already gone is fine");
        assert!(delete_key(&sub));
        assert!(delete_key(&sub), "already gone is fine");
        assert!(delete_value(&sub, "x"), "missing key is fine");
    }
}
