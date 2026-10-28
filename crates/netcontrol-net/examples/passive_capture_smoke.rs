//! Passive capture smoke test: resolves an interface by its OS (friendly) name,
//! runs the ARP listener and traffic monitor for a few seconds, prints what was
//! observed, and times Stop. Read-only: nothing is transmitted.
//!
//! ```text
//! cargo run -p netcontrol-net --features live-capture --example passive_capture_smoke -- "Ethernet 2" 8
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};

use netcontrol_core::PcList;
use netcontrol_net::capture;
use netcontrol_net::interfaces;
use netcontrol_net::listener::{ArpListener, ObserveContext};
use netcontrol_net::traffic::TrafficMonitor;

fn main() {
    let mut args = std::env::args().skip(1);
    let name = args.next().unwrap_or_else(|| "Ethernet 2".into());
    let secs: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(8);

    println!("Capture runtime: {}", capture::runtime_status().describe());
    let iface = interfaces::enumerate()
        .expect("enumerate")
        .into_iter()
        .find(|i| i.name == name)
        .unwrap_or_else(|| panic!("no OS interface named {name:?}"));
    println!(
        "OS interface: {} {} {:?}",
        iface.name, iface.ipv4, iface.adapter_id
    );

    let resolved = match capture::resolve_live(&iface) {
        Ok(r) => r,
        Err(e) => {
            println!("RESOLVE ERROR: {e}");
            std::process::exit(2);
        }
    };
    println!("Capture device: {}", resolved.summary());

    // Raw frame count first, to tell "no frames delivered" from "no ARP seen".
    match capture::open_receiver(&resolved.device) {
        Ok(mut rx) => {
            let (mut frames, mut arp, mut ipv4, mut errors) = (0u32, 0u32, 0u32, 0u32);
            let t = Instant::now();
            while t.elapsed() < Duration::from_secs(3) {
                match rx.next() {
                    Ok(f) if f.len() >= 14 => {
                        frames += 1;
                        match (f[12], f[13]) {
                            (0x08, 0x06) => arp += 1,
                            (0x08, 0x00) => ipv4 += 1,
                            _ => {}
                        }
                    }
                    Ok(_) => frames += 1,
                    Err(e) if capture::is_idle_timeout(&e) => {}
                    Err(_) => errors += 1,
                }
            }
            println!("Raw 3s sample: {frames} frames ({ipv4} IPv4, {arp} ARP), {errors} errors");
        }
        Err(e) => println!("RAW OPEN ERROR: {e}"),
    }

    let list = Arc::new(PcList::new());
    let ctx = ObserveContext {
        local_mac: iface.mac.unwrap_or([0; 6]),
        local_ip: Some(iface.ipv4),
        router_ip: None,
    };
    let listener = match ArpListener::start(&resolved.device, list.clone(), ctx) {
        Ok(l) => l,
        Err(e) => {
            println!("LISTENER START ERROR: {e}");
            std::process::exit(3);
        }
    };
    let monitor = match TrafficMonitor::start(&resolved.device, list.clone()) {
        Ok(m) => m,
        Err(e) => {
            println!("MONITOR START ERROR: {e}");
            std::process::exit(4);
        }
    };
    println!("Listening passively for {secs}s ...");
    std::thread::sleep(Duration::from_secs(secs));

    println!(
        "Devices learned from ARP: {} (listener failed: {}, monitor failed: {})",
        list.len(),
        listener.has_failed(),
        monitor.has_failed()
    );
    for (ip, down, up) in
        list.map_devices(|p| (p.ip, p.download_speed_kbps(), p.upload_speed_kbps()))
    {
        println!("  {ip:?}  down {down:.2} KB/s  up {up:.2} KB/s");
    }

    let t = Instant::now();
    std::thread::scope(|s| {
        s.spawn(|| listener.stop());
        monitor.stop();
    });
    println!("Stop took {} ms", t.elapsed().as_millis());
}
