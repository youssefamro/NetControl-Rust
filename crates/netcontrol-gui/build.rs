//! Windows build steps for the GUI binary:
//!
//! 1. Embeds the application icon and version metadata (compiled with the
//!    Windows SDK `rc.exe`; skipped with a warning if it cannot be found).
//! 2. With `live-capture`, delay-loads `Packet.dll`. Npcap installs it under
//!    `System32\Npcap`, which is not on the default DLL search path; a static
//!    import would stop the program from launching at all on such machines.
//!    At runtime `netcontrol_net::capture::runtime_status` adds that directory
//!    and checks the DLL loads before any capture call.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=assets/app_icon.ico");
    println!("cargo:rerun-if-env-changed=RC");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os != "windows" || target_env != "msvc" {
        return;
    }

    if env::var_os("CARGO_FEATURE_LIVE_CAPTURE").is_some() {
        println!("cargo:rustc-link-arg-bins=/DELAYLOAD:Packet.dll");
        println!("cargo:rustc-link-arg-bins=delayimp.lib");
    }

    embed_resources();
}

fn embed_resources() {
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let icon = manifest_dir.join("assets").join("app_icon.ico");

    let version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let mut parts: Vec<u16> = version
        .split(['.', '-', '+'])
        .take(3)
        .map(|p| p.parse().unwrap_or(0))
        .collect();
    parts.resize(3, 0);
    let (ma, mi, pa) = (parts[0], parts[1], parts[2]);
    let edition = if env::var_os("CARGO_FEATURE_LIVE_CAPTURE").is_some() {
        "Live capture"
    } else {
        "Demonstration"
    };

    let rc = format!(
        r#"#include <winver.h>
1 ICON "{icon}"
1 VERSIONINFO
FILEVERSION {ma},{mi},{pa},0
PRODUCTVERSION {ma},{mi},{pa},0
FILEOS VOS_NT_WINDOWS32
FILETYPE VFT_APP
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904B0"
    BEGIN
      VALUE "CompanyName", "NetControl Rust rebuild contributors"
      VALUE "FileDescription", "NetControl - Network Traffic Management"
      VALUE "FileVersion", "{version}"
      VALUE "InternalName", "NetControl"
      VALUE "LegalCopyright", "MIT License. Based on NetControl (c) 2026 Abel Meza Enriquez (nov0caina)"
      VALUE "OriginalFilename", "NetControl.exe"
      VALUE "ProductName", "NetControl"
      VALUE "ProductVersion", "{version}"
      VALUE "Comments", "{edition} build"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x0409, 1200
  END
END
"#,
        icon = icon.display().to_string().replace('\\', "\\\\"),
    );

    let rc_path = out.join("netcontrol.rc");
    let res_path = out.join("netcontrol.res");
    std::fs::write(&rc_path, rc).expect("write .rc");

    let Some(rc_exe) = find_rc() else {
        println!(
            "cargo:warning=rc.exe (Windows SDK) not found: the executable will have no icon or \
             version metadata. Set RC to the full path of rc.exe to enable them."
        );
        return;
    };

    let mut cmd = Command::new(&rc_exe);
    cmd.arg("/nologo").arg("/fo").arg(&res_path);
    if let Some(inc) = sdk_include_dirs(&rc_exe) {
        for dir in inc {
            cmd.arg("/I").arg(dir);
        }
    }
    cmd.arg(&rc_path);

    match cmd.status() {
        Ok(s) if s.success() => {
            println!("cargo:rustc-link-arg-bins={}", res_path.display());
        }
        other => println!(
            "cargo:warning=rc.exe failed ({other:?}); building without icon/version metadata"
        ),
    }
}

/// `RC` env var, then the newest Windows 10/11 SDK `rc.exe` for the host.
fn find_rc() -> Option<PathBuf> {
    if let Some(rc) = env::var_os("RC").map(PathBuf::from).filter(|p| p.is_file()) {
        return Some(rc);
    }
    let host = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x64"
    };
    let roots = [
        env::var_os("ProgramFiles(x86)").map(PathBuf::from),
        Some(PathBuf::from(r"C:\Program Files (x86)")),
    ];
    for root in roots.into_iter().flatten() {
        let bin = root.join(r"Windows Kits\10\bin");
        let Ok(entries) = std::fs::read_dir(&bin) else {
            continue;
        };
        let mut versions: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("10."))
            })
            .collect();
        versions.sort();
        if let Some(rc) = versions
            .iter()
            .rev()
            .map(|v| v.join(host).join("rc.exe"))
            .find(|p| p.is_file())
        {
            return Some(rc);
        }
    }
    None
}

/// The SDK include dirs (for `winver.h`) matching `rc_exe`'s SDK version.
fn sdk_include_dirs(rc_exe: &Path) -> Option<Vec<PathBuf>> {
    // ...\Windows Kits\10\bin\<ver>\<arch>\rc.exe -> ...\Windows Kits\10\Include\<ver>
    let ver_dir = rc_exe.parent()?.parent()?;
    let version = ver_dir.file_name()?;
    let kit = ver_dir.parent()?.parent()?;
    let inc = kit.join("Include").join(version);
    let dirs: Vec<PathBuf> = ["um", "shared"]
        .iter()
        .map(|d| inc.join(d))
        .filter(|d| d.is_dir())
        .collect();
    (!dirs.is_empty()).then_some(dirs)
}
