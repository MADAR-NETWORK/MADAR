//! The voting node's secret file **sealed** with Windows protection (DPAPI) instead of a plain, exposed JSON file (`--sealed-secret-file`).
//!
//! - The same format MADAR's operator tools use for their sealed secrets (`SealedSecret`: scope + hex data) inside a small JSON wrapper
//!   that states the format and the purpose: `{"format":"madar-dpapi-v1","purpose":"validator-secret","scope":"CurrentUser","data":"<hex>"}`.
//!   The fixed entropy `MADAR-validator-secret-v1` binds the seal to this purpose only (another secret sealed by the same account is not accepted here).
//! - Sealing and unsealing go through Win32 directly (`crypt32`), **no PowerShell**: reading a secret and then running PowerShell is behaviour antivirus software stops
//!   (a lesson from node app 2.0.9), and the secret never passes through another process at all.
//! - `CurrentUser` (the default): only this Windows account on this machine can unseal it. `LocalMachine` is optional, for tasks that run without
//!   the account password (S4U) — weaker: **it only protects against copying the file to another machine**; any program running on this machine (including
//!   malware under any account) can unseal it. And even `CurrentUser` does not protect against malware running under your own account.
//! - Overwriting with zeros (`--shred`) guarantees nothing on an SSD, in Volume Shadow Copies, in backups or in
//!   cloud sync: old copies of the plain file may remain there. The real protection for leftovers: disk encryption (BitLocker) and not
//!   keeping the plain file in a folder that is backed up.
//! - If the sealed file already exists, its real scope read from it is printed, and the command is refused if another scope was requested (no misleading scope).
//! - The plain file is opened once, read, verified and wiped through the same handle (with others blocked from writing to it on Windows),
//!   so it cannot be swapped between the check and the wipe.
//! - Every buffer holding the plain secret is `Zeroizing` and wiped on drop, and the DPAPI output is wiped before `LocalFree`. No error message carries content.
//!
//! The command `madar-node secret seal --in <plain.json> --out <sealed.json> [--shred]`: checks that the file is a valid node secret, seals it, writes
//! the sealed file (never replacing an existing file), reads it back from disk and makes sure it unseals to exactly the same bytes, and only then — with
//! `--shred` — writes zeros over the plain file and then deletes it.

use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const FORMAT: &str = "madar-dpapi-v1";
pub const PURPOSE: &str = "validator-secret";
const ENTROPY: &[u8] = b"MADAR-validator-secret-v1";
/// A node secret file is a small JSON (under 1 KiB); the cap prevents reading a huge wrong file into memory.
const MAX_FILE: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Scope {
    /// This Windows account only (the strongest; may not unseal inside an S4U scheduled task). Does not protect against malware running under your account.
    CurrentUser,
    /// Any account on this machine (for tasks without a password). Only protects against copying the file to another machine, not against malware on this machine.
    LocalMachine,
}

impl Scope {
    fn as_str(self) -> &'static str {
        match self {
            Scope::CurrentUser => "CurrentUser",
            Scope::LocalMachine => "LocalMachine",
        }
    }
    fn parse(s: &str) -> Option<Scope> {
        match s {
            "CurrentUser" => Some(Scope::CurrentUser),
            "LocalMachine" => Some(Scope::LocalMachine),
            _ => None,
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SealedFile {
    format: String,
    purpose: String,
    scope: String,
    data: String,
}

#[derive(Debug, Clone, clap::Subcommand)]
pub enum SecretCmd {
    /// Seals the voting node's secret file (JSON with secretPhrase) with Windows protection, verifies the unseal, and deletes the plain original with --shred.
    Seal(SealArgs),
    /// Unseals the sealed file in memory and prints only the public address (to confirm this account on this machine can unseal it). Never prints the secret.
    Check(CheckArgs),
}

#[derive(Debug, Clone, clap::Args)]
pub struct SealArgs {
    /// The plain secret file (read only; touched only with --shred and after the verification succeeded).
    #[arg(long = "in")]
    pub input: PathBuf,
    /// The resulting sealed file. If it exists, it is accepted only if it unseals to the same bytes with the same --scope (to rerun the command with --shred).
    #[arg(long)]
    pub out: PathBuf,
    /// The seal scope. local-machine only protects against copying the file to another machine (any program on this machine can unseal it).
    #[arg(long, value_enum, default_value = "current-user")]
    pub scope: Scope,
    /// After verification: write zeros over the plain file and then delete it. No guarantee on an SSD, in shadow copies or in backups.
    #[arg(long)]
    pub shred: bool,
}

#[derive(Debug, Clone, clap::Args)]
pub struct CheckArgs {
    #[arg(long)]
    pub sealed: PathBuf,
}

pub fn run(cmd: SecretCmd) -> Result<(), String> {
    match cmd {
        SecretCmd::Seal(a) => {
            let r = seal_file(&a.input, &a.out, a.scope, a.shred)?;
            println!("Account: {}", r.address);
            println!(
                "{}: {} (DPAPI {})",
                if r.already_sealed {
                    "Already sealed and the unseal was verified"
                } else {
                    "Sealed and the unseal from disk was verified"
                },
                a.out.display(),
                r.scope.as_str()
            );
            if r.scope == Scope::LocalMachine {
                println!("Note: the LocalMachine scope only protects against copying the file to another machine; any program on this machine can unseal it.");
            }
            if r.shredded {
                println!(
                    "The plain file was wiped and deleted: {}",
                    a.input.display()
                );
                println!("Note: wiping guarantees nothing on an SSD or in shadow copies and backups; full disk encryption is the protection.");
            } else {
                println!("The plain file is left as is (to delete it after testing, rerun the same command with --shred).");
            }
            Ok(())
        }
        SecretCmd::Check(a) => {
            let acct = load_account(&a.sealed)?;
            println!("Unseals on this machine. Account: {}", ss58(&acct));
            Ok(())
        }
    }
}

fn ss58(acct: &crate::join::account::Account) -> String {
    use sp_core::crypto::Ss58Codec;
    acct.id().to_ss58check()
}

/// For consumers (`join auto-renew --sealed-secret-file`): unseals the file and builds the account in memory; the secret is never written to disk or to the log.
pub fn load_account(path: &Path) -> Result<crate::join::account::Account, String> {
    let file = read_limited(path)?;
    let plain = unseal(&file)?;
    crate::join::account::Account::from_secret_json_bytes(&plain)
}

fn read_limited(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let meta =
        std::fs::metadata(path).map_err(|e| format!("Could not read {}: {e}", path.display()))?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return Err(format!(
            "{} is not a secret file (not a regular file or larger than {} KiB)",
            path.display(),
            MAX_FILE / 1024
        ));
    }
    std::fs::read(path)
        .map(Zeroizing::new)
        .map_err(|e| format!("Could not read {}: {e}", path.display()))
}

/// Seals the bytes and returns the content of the sealed file (JSON).
pub fn seal(plain: &[u8], scope: Scope) -> Result<Vec<u8>, String> {
    let blob = dpapi::protect(plain, ENTROPY, scope)?;
    let f = SealedFile {
        format: FORMAT.into(),
        purpose: PURPOSE.into(),
        scope: scope.as_str().into(),
        data: hex::encode(blob),
    };
    let mut out = serde_json::to_vec_pretty(&f).map_err(|e| e.to_string())?;
    out.push(b'\n');
    Ok(out)
}

/// Unseals the content of a sealed file to the original bytes (wiped on drop).
pub fn unseal(file: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    unseal_with_scope(file).map(|(plain, _)| plain)
}

/// Like `unseal`, and returns the seal scope written in the file itself.
fn unseal_with_scope(file: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Scope), String> {
    let f: SealedFile = serde_json::from_slice(file)
        .map_err(|_| "The sealed file is not in the madar-dpapi-v1 format".to_string())?;
    if f.format != FORMAT || f.purpose != PURPOSE {
        return Err(format!(
            "The sealed file is for another purpose (format={}, purpose={}) — will not use it",
            f.format, f.purpose
        ));
    }
    let scope = Scope::parse(&f.scope).ok_or("Unknown seal scope")?;
    let blob = hex::decode(f.data.trim())
        .map_err(|_| "The sealed file's data is corrupted".to_string())?;
    Ok((dpapi::unprotect(&blob, ENTROPY, scope)?, scope))
}

pub struct SealReport {
    pub address: String,
    /// The real scope of the sealed file (read from it if it already existed).
    pub scope: Scope,
    pub already_sealed: bool,
    pub shredded: bool,
}

/// See the module documentation. The plain file is touched only with `shred` and after verifying the unseal from disk.
pub fn seal_file(
    input: &Path,
    out: &Path,
    scope: Scope,
    shred: bool,
) -> Result<SealReport, String> {
    if same_path(input, out) {
        return Err("--in and --out are the same file".into());
    }
    // The plain file is opened once: reading, verification and wiping all go through this handle (no check-then-swap between the steps).
    let mut input_file = open_input(input, shred)?;
    let plain = read_limited_from(&mut input_file, input)?;
    // 1) Is it really a node secret file? (Prevents sealing a wrong file and then deleting it.)
    let acct = crate::join::account::Account::from_secret_json_bytes(&plain)?;
    let address = ss58(&acct);

    // 2) Seal and write (never replace an existing file: if it exists it must unseal to the same bytes).
    let already_sealed = out.exists();
    if already_sealed {
        let (back, existing_scope) = unseal_with_scope(&read_limited(out)?)?;
        if existing_scope != scope {
            return Err(format!(
                "{} is already sealed with scope {}, not the requested {} — will not replace it or delete anything",
                out.display(),
                existing_scope.as_str(),
                scope.as_str()
            ));
        }
        if back.as_slice() != plain.as_slice() {
            return Err(format!(
                "{} exists and does not match the plain file — will not replace it or delete anything",
                out.display()
            ));
        }
    } else {
        let sealed = seal(&plain, scope)?;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(out)
            .map_err(|e| format!("Could not create {}: {e}", out.display()))?;
        f.write_all(&sealed)
            .and_then(|_| f.sync_all())
            .map_err(|e| format!("Could not write {}: {e}", out.display()))?;
    }

    // 3) Verify from disk (not from memory): the written file unseals to exactly the same bytes and the same account.
    let (back, written_scope) = unseal_with_scope(&read_limited(out)?)?;
    if back.as_slice() != plain.as_slice() || written_scope != scope {
        return Err("The sealed file does not unseal to the same bytes with the requested scope — nothing was deleted".into());
    }
    if ss58(&crate::join::account::Account::from_secret_json_bytes(
        &back,
    )?) != address
    {
        return Err("The sealed file gives a different account — nothing was deleted".into());
    }

    // 4) Wipe, then delete (optional).
    let shredded = if shred {
        shred_file(input_file, input, plain.len())?;
        true
    } else {
        drop(input_file);
        false
    };
    Ok(SealReport {
        address,
        scope,
        already_sealed,
        shredded,
    })
}

fn same_path(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

/// Opens the plain file once (read, and with `--shred` also write). On Windows others are prevented from writing to it or deleting it while it is
/// open (read sharing only), so its content cannot be swapped between verification and wiping.
fn open_input(path: &Path, write: bool) -> Result<std::fs::File, String> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true).write(write);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x1;
        o.share_mode(FILE_SHARE_READ);
    }
    let f = o
        .open(path)
        .map_err(|e| format!("Could not open {}: {e}", path.display()))?;
    let meta = f
        .metadata()
        .map_err(|e| format!("Could not read {}: {e}", path.display()))?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return Err(format!(
            "{} is not a secret file (not a regular file or larger than {} KiB)",
            path.display(),
            MAX_FILE / 1024
        ));
    }
    Ok(f)
}

fn read_limited_from(f: &mut std::fs::File, path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    use std::io::Read;
    let mut buf = Zeroizing::new(Vec::new());
    Read::take(Read::by_ref(f), MAX_FILE + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("Could not read {}: {e}", path.display()))?;
    if buf.len() as u64 > MAX_FILE {
        return Err(format!(
            "{} is larger than {} KiB",
            path.display(),
            MAX_FILE / 1024
        ));
    }
    Ok(buf)
}

/// Writes zeros over the whole file (without truncating) through the same handle it was read and verified from, flushes them to disk, then deletes it.
/// Note: on SSD/NTFS this does not guarantee overwriting the same physical cells, and it does not touch shadow copies or backups; the real
/// protection for leftovers is disk encryption (BitLocker).
fn shred_file(mut f: std::fs::File, path: &Path, len: usize) -> Result<(), String> {
    use std::io::{Seek, SeekFrom};
    let zeros = vec![0u8; len.max(1)];
    f.seek(SeekFrom::Start(0))
        .and_then(|_| f.write_all(&zeros))
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("Could not wipe {}: {e}", path.display()))?;
    drop(f);
    std::fs::remove_file(path).map_err(|e| {
        format!(
            "The content was wiped but {} could not be deleted: {e}",
            path.display()
        )
    })
}

#[cfg(windows)]
#[allow(unsafe_code)] // A second deliberate exception (after SetConsoleCtrlHandler in main.rs): the two DPAPI calls through crypt32, confined here.
mod dpapi {
    use super::Scope;
    use core::ffi::c_void;
    use zeroize::{Zeroize, Zeroizing};

    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;
    const CRYPTPROTECT_LOCAL_MACHINE: u32 = 0x4;

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(
            data_in: *const DataBlob,
            description: *const u16,
            entropy: *const DataBlob,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            data_out: *mut DataBlob,
        ) -> i32;
        fn CryptUnprotectData(
            data_in: *const DataBlob,
            description: *mut *mut u16,
            entropy: *const DataBlob,
            reserved: *mut c_void,
            prompt: *mut c_void,
            flags: u32,
            data_out: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(mem: *mut c_void) -> *mut c_void;
    }

    fn blob(b: &[u8]) -> Result<DataBlob, String> {
        let len = u32::try_from(b.len())
            .map_err(|_| "The data is larger than the DPAPI limit".to_string())?;
        // DPAPI does not write to its inputs; the cast to *mut is only because the C signature is not const.
        Ok(DataBlob {
            cb_data: len,
            pb_data: b.as_ptr() as *mut u8,
        })
    }

    fn flags(scope: Scope) -> u32 {
        match scope {
            Scope::CurrentUser => CRYPTPROTECT_UI_FORBIDDEN,
            Scope::LocalMachine => CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
        }
    }

    /// Copies the DPAPI output, then (if it is a secret) wipes it, then frees it with LocalFree.
    ///
    /// SAFETY: `out` was returned by a successful DPAPI function: `pb_data` points to `cb_data` bytes allocated with LocalAlloc that we own.
    unsafe fn take(out: DataBlob, wipe: bool) -> Zeroizing<Vec<u8>> {
        let s = std::slice::from_raw_parts_mut(out.pb_data, out.cb_data as usize);
        let v = Zeroizing::new(s.to_vec());
        if wipe {
            s.zeroize();
        }
        LocalFree(out.pb_data.cast());
        v
    }

    pub fn protect(plain: &[u8], entropy: &[u8], scope: Scope) -> Result<Vec<u8>, String> {
        let (input, ent) = (blob(plain)?, blob(entropy)?);
        let mut out = DataBlob {
            cb_data: 0,
            pb_data: std::ptr::null_mut(),
        };
        // SAFETY: all pointers are valid for the whole call (borrowed from live or local slices), and the optional ones are NULL as the documentation allows.
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &ent,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                flags(scope),
                &mut out,
            )
        };
        if ok == 0 || out.pb_data.is_null() {
            return Err(format!(
                "DPAPI refused to seal ({}): {}",
                scope.as_str(),
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: the call above succeeded (see `take`). The output is sealed, not a plain secret.
        Ok(unsafe { take(out, false) }.to_vec())
    }

    pub fn unprotect(
        sealed: &[u8],
        entropy: &[u8],
        scope: Scope,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let (input, ent) = (blob(sealed)?, blob(entropy)?);
        let mut out = DataBlob {
            cb_data: 0,
            pb_data: std::ptr::null_mut(),
        };
        // SAFETY: as in `protect`; the data description is not needed (NULL).
        let ok = unsafe {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                &ent,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                flags(scope),
                &mut out,
            )
        };
        if ok == 0 || out.pb_data.is_null() {
            return Err(format!(
                "Could not unseal the sealed file with DPAPI ({}): {} — is this another Windows account or machine?",
                scope.as_str(),
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: the call above succeeded (see `take`); the output is a plain secret, so it is wiped before freeing.
        Ok(unsafe { take(out, true) })
    }
}

#[cfg(not(windows))]
mod dpapi {
    use super::Scope;
    use zeroize::Zeroizing;
    const MSG: &str =
        "Sealed files (DPAPI) are available on Windows only — use --secret-file with 600 permissions here";
    pub fn protect(_: &[u8], _: &[u8], _: Scope) -> Result<Vec<u8>, String> {
        Err(MSG.into())
    }
    pub fn unprotect(_: &[u8], _: &[u8], _: Scope) -> Result<Zeroizing<Vec<u8>>, String> {
        Err(MSG.into())
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// A test secret generated on every run (unrelated to any real key), in the same shape as `key generate --output-type json`.
    fn throwaway(dir: &Path) -> (PathBuf, Vec<u8>, String) {
        use sp_core::{crypto::Ss58Codec, sr25519, Pair};
        let (pair, phrase, seed) = sr25519::Pair::generate_with_phrase(None);
        let json = serde_json::json!({
            "secretPhrase": phrase,
            "secretSeed": format!("0x{}", hex::encode(seed)),
            "publicKey": format!("0x{}", hex::encode(pair.public().0)),
            "ss58Address": pair.public().to_ss58check(),
        });
        let bytes = serde_json::to_vec_pretty(&json).unwrap();
        let p = dir.join("throwaway.secret.json");
        std::fs::write(&p, &bytes).unwrap();
        (
            p,
            bytes,
            madar_consensus::AccountId::from(pair.public().0).to_ss58check(),
        )
    }

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("madar-sealed-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn seal_verifies_from_disk_keeps_the_plain_file_without_shred_and_loads_the_same_account() {
        let d = dir("keep");
        let (plain, bytes, addr) = throwaway(&d);
        let out = d.join("v.sealed.json");
        let r = seal_file(&plain, &out, Scope::CurrentUser, false).unwrap();
        assert_eq!(r.address, addr);
        assert!(!r.already_sealed && !r.shredded);
        assert_eq!(
            std::fs::read(&plain).unwrap(),
            bytes,
            "without --shred the plain file is untouched"
        );
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(
            !text.contains("secretPhrase") && !text.contains("secretSeed"),
            "the sealed file shows no secret field"
        );
        assert!(text.contains(FORMAT) && text.contains("CurrentUser"));
        assert_eq!(ss58(&load_account(&out).unwrap()), addr);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn rerun_with_shred_accepts_the_matching_sealed_file_then_wipes_and_deletes_the_plain_file() {
        let d = dir("shred");
        let (plain, _, addr) = throwaway(&d);
        let out = d.join("v.sealed.json");
        seal_file(&plain, &out, Scope::CurrentUser, false).unwrap();
        let before = std::fs::read(&out).unwrap();
        let r = seal_file(&plain, &out, Scope::CurrentUser, true).unwrap();
        assert!(r.already_sealed && r.shredded);
        assert!(!plain.exists(), "plain file removed");
        assert_eq!(
            std::fs::read(&out).unwrap(),
            before,
            "the existing sealed file is never rewritten"
        );
        assert_eq!(ss58(&load_account(&out).unwrap()), addr);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_different_existing_out_file_a_non_secret_input_or_same_path_change_nothing() {
        let d = dir("refuse");
        let (plain_a, bytes_a, _) = throwaway(&d);
        let out = d.join("v.sealed.json");
        seal_file(&plain_a, &out, Scope::CurrentUser, false).unwrap();
        // Another secret file + --shred: refused and nothing is deleted.
        let other = d.join("other");
        std::fs::create_dir_all(&other).unwrap();
        let (plain_b, bytes_b, _) = throwaway(&other);
        assert!(seal_file(&plain_b, &out, Scope::CurrentUser, true).is_err());
        assert_eq!(std::fs::read(&plain_b).unwrap(), bytes_b);
        // A file that is not a node secret: refused before any write.
        let junk = d.join("junk.json");
        std::fs::write(&junk, b"{\"hello\":1}").unwrap();
        let out2 = d.join("junk.sealed.json");
        assert!(seal_file(&junk, &out2, Scope::CurrentUser, true).is_err());
        assert!(junk.exists() && !out2.exists());
        assert!(seal_file(&plain_a, &plain_a, Scope::CurrentUser, true).is_err());
        assert_eq!(std::fs::read(&plain_a).unwrap(), bytes_a);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn errors_never_contain_the_secret_and_tampering_or_other_purposes_are_refused() {
        let d = dir("err");
        let (plain, bytes, _) = throwaway(&d);
        let phrase = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["secretPhrase"]
            .as_str()
            .unwrap()
            .to_string();
        let first_word = phrase.split_whitespace().next().unwrap().to_string();
        let sealed = seal(&bytes, Scope::CurrentUser).unwrap();
        // Tampering with one byte of the sealed data.
        let mut f: serde_json::Value = serde_json::from_slice(&sealed).unwrap();
        let mut data = f["data"].as_str().unwrap().to_string();
        let last = data.pop().unwrap();
        data.push(if last == '0' { '1' } else { '0' });
        f["data"] = data.into();
        let e = unseal(&serde_json::to_vec(&f).unwrap()).err().unwrap();
        assert!(!e.contains(&first_word));
        // The same seal with another purpose in the wrapper: refused.
        let mut g: serde_json::Value = serde_json::from_slice(&sealed).unwrap();
        g["purpose"] = "other-tool-secret".into();
        assert!(unseal(&serde_json::to_vec(&g).unwrap()).is_err());
        // A secret sealed with another entropy (like other tools' secrets) does not unseal here.
        let foreign =
            dpapi::protect(&bytes, b"MADAR-other-tool-secret-v1", Scope::CurrentUser).unwrap();
        let h = serde_json::json!({"format": FORMAT, "purpose": PURPOSE, "scope": "CurrentUser", "data": hex::encode(foreign)});
        assert!(unseal(&serde_json::to_vec(&h).unwrap()).is_err());
        // A secret file with an invalid phrase: the error is fixed and carries no content.
        let bad = br#"{"secretPhrase":"zebra zebra zebra secretword"}"#;
        let e = crate::join::account::Account::from_secret_json_bytes(bad)
            .err()
            .unwrap();
        assert!(!e.contains("secretword"));
        let _ = plain;
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// Independent review #4: an existing sealed file with another scope — the command is refused (no misleading scope printed) and nothing is deleted; with the
    /// same scope it is accepted and the file's real scope is returned.
    #[test]
    fn an_existing_sealed_file_with_another_scope_is_refused_and_the_real_scope_is_reported() {
        let d = dir("scope");
        let (plain, bytes, _) = throwaway(&d);
        let out = d.join("v.sealed.json");
        assert!(
            seal_file(&plain, &out, Scope::LocalMachine, false)
                .unwrap()
                .scope
                == Scope::LocalMachine
        );
        let e = seal_file(&plain, &out, Scope::CurrentUser, true)
            .err()
            .unwrap();
        assert!(
            e.contains("LocalMachine") && e.contains("CurrentUser"),
            "{e}"
        );
        assert_eq!(
            std::fs::read(&plain).unwrap(),
            bytes,
            "nothing shredded on a scope mismatch"
        );
        let r = seal_file(&plain, &out, Scope::LocalMachine, true).unwrap();
        assert!(r.already_sealed && r.shredded && r.scope == Scope::LocalMachine);
        assert!(!plain.exists());
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// Independent review #4: during sealing the plain file is open with read sharing only — nobody else can write to it between verification and wiping.
    #[test]
    fn the_plain_file_cannot_be_rewritten_by_others_while_it_is_open_for_sealing() {
        let d = dir("lock");
        let (plain, bytes, _) = throwaway(&d);
        let mut f = open_input(&plain, true).unwrap();
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(&plain)
                .is_err(),
            "another writer is refused"
        );
        assert_eq!(
            read_limited_from(&mut f, &plain).unwrap().as_slice(),
            bytes.as_slice()
        );
        shred_file(f, &plain, bytes.len()).unwrap();
        assert!(!plain.exists());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn local_machine_scope_round_trips_too() {
        let bytes = b"{\"secretPhrase\":\"x\"}";
        let s = seal(bytes, Scope::LocalMachine).unwrap();
        assert!(String::from_utf8_lossy(&s).contains("LocalMachine"));
        assert_eq!(unseal(&s).unwrap().as_slice(), bytes);
        let d = dir("lm");
        let (plain, _, addr) = throwaway(&d);
        let out = d.join("v.sealed.json");
        assert_eq!(
            seal_file(&plain, &out, Scope::LocalMachine, true)
                .unwrap()
                .address,
            addr
        );
        assert!(!plain.exists());
        assert_eq!(ss58(&load_account(&out).unwrap()), addr);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
