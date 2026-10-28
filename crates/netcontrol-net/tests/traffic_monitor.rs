//! Deterministic traffic-monitoring tests using synthetic frames. No live
//! capture or traffic generation occurs.

use std::net::Ipv4Addr;
use std::time::Duration;

use netcontrol_core::{Pc, PcList};
use netcontrol_net::traffic::{classify_ipv4_frame, CycleStats, DST_IP_OFFSET, SRC_IP_OFFSET};

const ALPHA: f64 = 0.65;

/// Builds a synthetic Ethernet/IPv4 frame of `size` bytes from `src` to `dst`.
fn ipv4_frame(src: Ipv4Addr, dst: Ipv4Addr, size: usize) -> Vec<u8> {
    let mut f = vec![0u8; size.max(34)];
    f[12] = 0x08; // EtherType IPv4
    f[13] = 0x00;
    f[SRC_IP_OFFSET..SRC_IP_OFFSET + 4].copy_from_slice(&src.octets());
    f[DST_IP_OFFSET..DST_IP_OFFSET + 4].copy_from_slice(&dst.octets());
    f
}

fn device(ip: Ipv4Addr) -> Pc {
    let mut p = Pc::new();
    p.ip = Some(ip);
    p
}

// ── Classification ─────────────────────────────────────────────────

#[test]
fn classify_extracts_addresses_and_size() {
    let src = Ipv4Addr::new(192, 168, 1, 10);
    let dst = Ipv4Addr::new(192, 168, 1, 20);
    let frame = ipv4_frame(src, dst, 1500);

    let info = classify_ipv4_frame(&frame).expect("IPv4 frame");
    assert_eq!(info.src_ip, src);
    assert_eq!(info.dst_ip, dst);
    assert_eq!(info.size, 1500);
}

#[test]
fn classify_rejects_short_and_non_ipv4() {
    // Too short.
    assert!(classify_ipv4_frame(&[0u8; 20]).is_none());

    // Right length but ARP ethertype.
    let mut frame = vec![0u8; 60];
    frame[12] = 0x08;
    frame[13] = 0x06; // ARP, not IPv4
    assert!(classify_ipv4_frame(&frame).is_none());
}

// ── Per-cycle attribution ──────────────────────────────────────────

#[test]
fn record_credits_upload_to_source_and_download_to_dest() {
    let a = Ipv4Addr::new(192, 168, 1, 10);
    let b = Ipv4Addr::new(192, 168, 1, 20);
    let mut stats = CycleStats::seeded([a, b]);

    // a -> b, 1000 bytes: a uploads, b downloads.
    assert!(stats.record(&ipv4_frame(a, b, 1000)));
    // b -> a, 500 bytes: b uploads, a downloads.
    assert!(stats.record(&ipv4_frame(b, a, 500)));

    // (download, upload)
    assert_eq!(stats.bytes_for(a), Some((500, 1000)));
    assert_eq!(stats.bytes_for(b), Some((1000, 500)));
}

#[test]
fn record_ignores_untracked_and_non_ipv4() {
    let a = Ipv4Addr::new(192, 168, 1, 10);
    let other = Ipv4Addr::new(8, 8, 8, 8);
    let mut stats = CycleStats::seeded([a]);

    // Traffic a <-> external: a is tracked, external is not.
    assert!(stats.record(&ipv4_frame(a, other, 1200)));
    assert_eq!(stats.bytes_for(a), Some((0, 1200))); // a uploaded only
    assert_eq!(stats.bytes_for(other), None);

    // Traffic between two untracked hosts is not counted.
    let c = Ipv4Addr::new(10, 0, 0, 1);
    assert!(!stats.record(&ipv4_frame(other, c, 800)));

    // Non-IPv4 frame ignored.
    let mut arp = vec![0u8; 60];
    arp[12] = 0x08;
    arp[13] = 0x06;
    assert!(!stats.record(&arp));
}

#[test]
fn record_accumulates_duplicate_flows() {
    let a = Ipv4Addr::new(192, 168, 1, 10);
    let b = Ipv4Addr::new(192, 168, 1, 20);
    let mut stats = CycleStats::seeded([a, b]);
    for _ in 0..3 {
        stats.record(&ipv4_frame(a, b, 1000));
    }
    assert_eq!(stats.bytes_for(a), Some((0, 3000)));
    assert_eq!(stats.bytes_for(b), Some((3000, 0)));
}

// ── Rate application + EMA ──────────────────────────────────────────

#[test]
fn apply_computes_ema_smoothed_rates() {
    let a = Ipv4Addr::new(192, 168, 1, 10);
    let b = Ipv4Addr::new(192, 168, 1, 20);
    let list = PcList::new();
    list.add_device(device(a));
    list.add_device(device(b));

    // a receives 1,024,000 bytes over 1s -> 1000 KB/s measured; prev 0.
    let mut stats = CycleStats::seeded([a, b]);
    stats.record(&ipv4_frame(b, a, 1_024_000)); // b->a: a downloads 1,024,000
    stats.apply(&list, Duration::from_secs(1), ALPHA);

    // smoothed_down = 0.65 * 1000 + 0.35 * 0 = 650.0
    let (down_kbps, down_fmt) = list
        .map_devices(|p| (p.download_speed_kbps(), p.download_speed_formatted()))
        .into_iter()
        .zip(list.map_devices(|p| p.ip))
        .find(|(_, ip)| *ip == Some(a))
        .map(|(v, _)| v)
        .unwrap();
    assert!((down_kbps - 650.0).abs() < 1e-9, "got {down_kbps}");
    assert_eq!(down_fmt, "650.0 KB/s");

    // The cycle byte counts were stored on the device.
    let a_bytes = list
        .map_devices(|p| (p.ip, p.bytes_received()))
        .into_iter()
        .find(|(ip, _)| *ip == Some(a))
        .map(|(_, rx)| rx)
        .unwrap();
    assert_eq!(a_bytes, 1_024_000);
}

#[test]
fn apply_decays_idle_devices_to_zero() {
    let a = Ipv4Addr::new(192, 168, 1, 10);
    let list = PcList::new();
    list.add_device(device(a));

    // Cycle 1: establish 650 KB/s download.
    let mut c1 = CycleStats::seeded([a]);
    c1.record(&ipv4_frame(Ipv4Addr::new(1, 1, 1, 1), a, 1_024_000));
    c1.apply(&list, Duration::from_secs(1), ALPHA);
    let after1 = list.map_devices(|p| p.download_speed_kbps())[0];
    assert!((after1 - 650.0).abs() < 1e-9);

    // Cycle 2: no traffic -> decays by (1 - alpha) = 0.35 -> 227.5.
    let c2 = CycleStats::seeded([a]);
    c2.apply(&list, Duration::from_secs(1), ALPHA);
    let after2 = list.map_devices(|p| p.download_speed_kbps())[0];
    assert!((after2 - 227.5).abs() < 1e-9, "got {after2}");

    // Many idle cycles -> snaps to exactly 0.
    for _ in 0..20 {
        CycleStats::seeded([a]).apply(&list, Duration::from_secs(1), ALPHA);
    }
    let settled = list.map_devices(|p| p.download_speed_kbps())[0];
    assert_eq!(settled, 0.0);
    assert_eq!(
        list.map_devices(|p| p.download_speed_formatted())[0],
        "0 KB/s"
    );
}

#[test]
fn apply_blends_upload_rate_on_subsequent_cycle() {
    let a = Ipv4Addr::new(192, 168, 1, 10);
    let list = PcList::new();
    list.add_device(device(a));

    // Cycle 1: upload 512 KB/s (524288 bytes / 1s), prev 0 -> 0.65*512 = 332.8.
    let mut c1 = CycleStats::seeded([a]);
    c1.record(&ipv4_frame(a, Ipv4Addr::new(1, 1, 1, 1), 524_288));
    c1.apply(&list, Duration::from_secs(1), ALPHA);
    let up1 = list.map_devices(|p| p.upload_speed_kbps())[0];
    assert!((up1 - 332.8).abs() < 1e-9, "got {up1}");

    // Cycle 2: upload 512 KB/s again -> 0.65*512 + 0.35*332.8 = 449.28.
    let mut c2 = CycleStats::seeded([a]);
    c2.record(&ipv4_frame(a, Ipv4Addr::new(1, 1, 1, 1), 524_288));
    c2.apply(&list, Duration::from_secs(1), ALPHA);
    let up2 = list.map_devices(|p| p.upload_speed_kbps())[0];
    assert!((up2 - 449.28).abs() < 1e-9, "got {up2}");
}

#[test]
fn apply_is_a_noop_for_empty_device_list() {
    let list = PcList::new();
    let stats = CycleStats::seeded(std::iter::empty());
    assert!(stats.is_empty());
    stats.apply(&list, Duration::from_secs(1), ALPHA); // must not panic
    assert_eq!(list.len(), 0);
}
