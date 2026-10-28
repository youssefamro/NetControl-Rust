//! Lists OS interfaces, capture-backend devices, and how each OS interface
//! resolves to a capture device. Read-only: no device is opened and no packet
//! is captured or sent.
//!
//! ```text
//! cargo run -p netcontrol-net --features live-capture --example list_capture_devices
//! ```

use netcontrol_net::capture;
use netcontrol_net::interfaces;

fn main() {
    println!("Capture runtime: {}", capture::runtime_status().describe());

    let os = match interfaces::enumerate() {
        Ok(list) => list,
        Err(e) => {
            eprintln!("OS interface enumeration failed: {e}");
            std::process::exit(1);
        }
    };
    println!("\nOS interfaces ({}):", os.len());
    for i in &os {
        println!(
            "  {:<30} ipv4={:<15} id={}",
            i.name,
            i.ipv4,
            i.adapter_id.as_deref().unwrap_or("-")
        );
    }

    let devices = match capture::capture_devices() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("\nCapture device enumeration failed: {e}");
            std::process::exit(2);
        }
    };
    println!("\nCapture devices ({}):", devices.len());
    for d in &devices {
        println!("  {}  [{}]  ipv4={:?}", d.name, d.description, d.ipv4);
    }

    println!("\nResolution:");
    for i in os.iter().filter(|i| !i.is_loopback) {
        match capture::resolve_capture_device(i, &devices) {
            Ok(r) => println!("  {:<30} -> {}", i.name, r.summary()),
            Err(e) => println!("  {:<30} -> ERROR: {e}", i.name),
        }
    }
}
