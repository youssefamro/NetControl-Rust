//! Mirrors the C# `TrafficRateTests`, plus coverage for the EMA helpers.

use netcontrol_core::throttling::ema_step;
use netcontrol_core::Pc;

#[test]
fn initial_rates_should_be_zero_and_inactive() {
    let pc = Pc::new();
    assert_eq!(pc.download_speed_formatted(), "0 KB/s");
    assert_eq!(pc.upload_speed_formatted(), "0 KB/s");
    assert!(!pc.has_active_traffic());
}

#[test]
fn transfer_rates_should_format_accurately() {
    let mut pc = Pc::new();

    // 1024 KB/s = 1.0 MB/s, and 512 KB/s.
    pc.set_download_speed_kbps(1024.0);
    pc.set_upload_speed_kbps(512.0);

    assert_eq!(pc.download_speed_formatted(), "1.0 MB/s");
    assert_eq!(pc.upload_speed_formatted(), "512.0 KB/s");
    assert!(pc.has_active_traffic());
    assert_eq!(pc.download_traffic_brush_hex(), "#3FB950");
    assert_eq!(pc.upload_traffic_brush_hex(), "#58A6FF");
}

#[test]
fn traffic_rate_should_decay_smoothly_via_ema() {
    let mut pc = Pc::new();
    pc.set_download_speed_kbps(1024.0);

    // One idle cycle with alpha = 0.65 -> 1024 * 0.35 = 358.4 KB/s.
    let decayed = pc.download_speed_kbps() * 0.35;
    pc.set_download_speed_kbps(decayed);
    assert_eq!((pc.download_speed_kbps() * 10.0).round() / 10.0, 358.4);
    assert_eq!(pc.download_speed_formatted(), "358.4 KB/s");

    // Further idle cycles until the rate drops below the 0.1 threshold.
    for _ in 0..10 {
        let next = pc.download_speed_kbps() * 0.35;
        pc.set_download_speed_kbps(if next < 0.1 { 0.0 } else { next });
    }

    assert_eq!(pc.download_speed_kbps(), 0.0);
    assert_eq!(pc.download_speed_formatted(), "0 KB/s");
    assert!(!pc.has_active_traffic());
    assert_eq!(pc.download_traffic_brush_hex(), "#6E7681");
}

#[test]
fn ema_step_decays_to_zero_when_idle() {
    // Matches the decay path of CArp.TrafficMonitorLoop.
    let rate = ema_step(0.0, 1024.0, 0, 0.65);
    assert!((rate - 358.4).abs() < 1e-9);

    // Below 0.1 snaps to exactly 0.
    assert_eq!(ema_step(0.0, 0.2, 0, 0.65), 0.0);
}

#[test]
fn ema_step_blends_measured_and_previous() {
    // 0.65 * 100 + 0.35 * 0 = 65.
    assert!((ema_step(100.0, 0.0, 150_000, 0.65) - 65.0).abs() < 1e-9);
}
