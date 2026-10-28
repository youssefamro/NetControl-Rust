//! Locates the Npcap SDK import library (`Packet.lib`) for Windows builds with
//! the `live-capture` feature. pnet links `Packet.lib` but does not say where it
//! lives, so without this the link fails with `LNK1181: cannot open 'Packet.lib'`.
//!
//! Search order: `NPCAP_SDK_DIR` (or `NPCAP_SDK`), then common install paths.
//! The SDK is only needed to *build*; end users need the Npcap runtime instead.

use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=NPCAP_SDK_DIR");
    println!("cargo:rerun-if-env-changed=NPCAP_SDK");

    let live = env::var_os("CARGO_FEATURE_LIVE_CAPTURE").is_some();
    let windows = env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    if !live || !windows {
        return;
    }

    let arch_dir = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x64",
        Ok("aarch64") => "ARM64",
        _ => "",
    };

    let mut roots: Vec<PathBuf> = ["NPCAP_SDK_DIR", "NPCAP_SDK"]
        .iter()
        .filter_map(|v| env::var_os(v).map(PathBuf::from))
        .collect();
    roots.extend(
        [
            r"D:\DevTools\NpcapSDK",
            r"C:\Program Files\NpcapSDK",
            r"C:\NpcapSDK",
            r"C:\npcap-sdk",
        ]
        .iter()
        .map(PathBuf::from),
    );

    for root in &roots {
        let lib_dir = root.join("Lib").join(arch_dir);
        if lib_dir.join("Packet.lib").is_file() {
            println!("cargo:rustc-link-search=native={}", lib_dir.display());
            return;
        }
    }

    println!(
        "cargo:warning=Npcap SDK not found (Packet.lib). Download it from https://npcap.com/#download \
         and set NPCAP_SDK_DIR to its folder; linking the live-capture build will fail otherwise."
    );
}
