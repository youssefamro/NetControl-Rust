//! NetControl GUI entry point.
//!
//! Recreates the original Avalonia `MainWindow` interface over the P1–P5 Rust
//! modules. Demonstration mode (simulated, clearly labeled) is the default;
//! live packet capture is opt-in behind the `live-capture` build feature. No
//! ARP poisoning, interception, redirection, or traffic disruption is performed.

// On Windows, suppress the console window for the release GUI build.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() -> eframe::Result<()> {
    // Live builds: locate/verify the capture runtime (Npcap's Packet.dll is
    // delay-loaded) before any capture call. A missing runtime is reported in
    // the Live panel instead of preventing launch.
    let _ = netcontrol_net::capture::runtime_status();

    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([1024.0, 640.0])
        .with_min_inner_size([880.0, 560.0])
        .with_title("NetControl - Network Traffic Management")
        .with_app_id("netcontrol");
    if let Ok(icon) = eframe::icon_data::from_png_bytes(include_bytes!("../assets/app_icon.png")) {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "NetControl",
        options,
        Box::new(|cc| Ok(Box::new(netcontrol_gui::NetControlApp::new(cc)))),
    )
}
