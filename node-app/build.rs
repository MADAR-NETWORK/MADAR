//! Embeds the MADAR icon and an asInvoker manifest (no admin elevation request) via rc.exe from the Windows SDK.

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
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("assets");
    for f in ["madar.ico", "app.manifest"] {
        println!("cargo:rerun-if-changed={}", dir.join(f).display());
    }
    println!("cargo:rerun-if-env-changed=RC_EXE");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let rc_file = out.join("app.rc");
    let esc = |p: PathBuf| p.display().to_string().replace('\\', "\\\\");
    std::fs::write(
        &rc_file,
        format!(
            "1 ICON \"{}\"\n1 24 \"{}\"\n",
            esc(dir.join("madar.ico")),
            esc(dir.join("app.manifest"))
        ),
    )
    .unwrap();
    let Some(rc) = find_rc() else {
        println!("cargo:warning=rc.exe not found: madar-app built without icon/manifest");
        return;
    };
    let res = out.join("app.res");
    let ok = Command::new(rc)
        .args(["/nologo", "/fo"])
        .arg(&res)
        .arg(&rc_file)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        println!("cargo:warning=rc.exe failed: madar-app built without icon/manifest");
        return;
    }
    println!("cargo:rustc-link-arg-bins={}", res.display());
}
