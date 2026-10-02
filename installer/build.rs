//! (1) Installer payload: `MADAR_PAYLOAD_FILE` (set by build-installer.ps1), otherwise an empty payload that the installer rejects.
//! (2) MADAR icon + asInvoker manifest via rc.exe. Required: without it Windows demands admin rights for any file
//!     whose name contains "setup" (Installer Detection).

use std::path::{Path, PathBuf};
use std::process::Command;

fn find_rc() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("RC_EXE") {
        return Some(PathBuf::from(p));
    }
    let kits = Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin");
    let mut vers: Vec<PathBuf> = std::fs::read_dir(kits)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join(r"x64\rc.exe").exists())
        .collect();
    vers.sort();
    vers.pop().map(|v| v.join(r"x64\rc.exe"))
}

fn main() {
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    println!("cargo:rerun-if-env-changed=MADAR_PAYLOAD_FILE");
    let payload = match std::env::var("MADAR_PAYLOAD_FILE") {
        Ok(p) if Path::new(&p).is_file() => {
            println!("cargo:rerun-if-changed={p}");
            PathBuf::from(p)
        }
        _ => {
            let empty = out.join("empty-payload.bin");
            std::fs::write(&empty, b"").unwrap();
            empty
        }
    };
    println!("cargo:rustc-env=MADAR_PAYLOAD_FILE={}", payload.display());

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let icon = manifest_dir
        .join("..")
        .join("node-app")
        .join("assets")
        .join("madar.ico");
    let manifest = manifest_dir.join("assets").join("setup.manifest");
    println!("cargo:rerun-if-changed={}", icon.display());
    println!("cargo:rerun-if-changed={}", manifest.display());
    println!("cargo:rerun-if-env-changed=RC_EXE");
    let esc = |p: &Path| p.display().to_string().replace('\\', "\\\\");
    let rc_file = out.join("setup.rc");
    std::fs::write(
        &rc_file,
        format!("1 ICON \"{}\"\n1 24 \"{}\"\n", esc(&icon), esc(&manifest)),
    )
    .unwrap();
    let res = out.join("setup.res");
    let rc = find_rc().expect("rc.exe (Windows SDK) is required: without the asInvoker manifest Windows would demand admin for a *setup* exe");
    let ok = Command::new(rc)
        .args(["/nologo", "/fo"])
        .arg(&res)
        .arg(&rc_file)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(ok, "rc.exe failed to compile setup.rc");
    println!("cargo:rustc-link-arg-bins={}", res.display());
}
