//! Mirrors the C# `DeviceCategorizationTests`.

use netcontrol_core::device_identifier::infer_device_type;
use netcontrol_core::{DeviceType, Pc};

fn dev(hostname: &str, vendor: &str) -> Pc {
    let mut p = Pc::new();
    if !hostname.is_empty() {
        p.hostname = Some(hostname.to_string());
    }
    if !vendor.is_empty() {
        p.vendor = Some(vendor.to_string());
    }
    p
}

#[test]
fn should_identify_smart_tvs() {
    assert_eq!(
        infer_device_type(&dev("LGwebOSTV-Room", "LG Electronics")),
        DeviceType::SmartTV
    );
    assert_eq!(
        infer_device_type(&dev("RokuUltra-4K", "Roku")),
        DeviceType::SmartTV
    );
    assert_eq!(
        infer_device_type(&dev("_googlecast", "")),
        DeviceType::SmartTV
    );
}

#[test]
fn should_identify_consoles() {
    assert_eq!(
        infer_device_type(&dev("PS5-LivingRoom", "Sony Interactive Entertainment")),
        DeviceType::Console
    );
    assert_eq!(
        infer_device_type(&dev("NintendoSwitch-Family", "Nintendo")),
        DeviceType::Console
    );
}

#[test]
fn should_identify_mobiles_and_tablets() {
    assert_eq!(
        infer_device_type(&dev("Pixel-8-Pro", "Google")),
        DeviceType::Mobile
    );
    assert_eq!(
        infer_device_type(&dev("iPad-Air", "Apple")),
        DeviceType::Tablet
    );
}

#[test]
fn should_identify_desktops() {
    assert_eq!(
        infer_device_type(&dev("MacBook-Pro-M2", "Apple")),
        DeviceType::Desktop
    );
    assert_eq!(
        infer_device_type(&dev("DESKTOP-ABC1234", "ASUSTeK COMPUTER INC.")),
        DeviceType::Desktop
    );
}

#[test]
fn should_identify_printers() {
    assert_eq!(
        infer_device_type(&dev("HP-LaserJet-M404", "HP Inc.")),
        DeviceType::Printer
    );
}

#[test]
fn should_identify_routers() {
    let mut router = Pc::new();
    router.is_gateway = true;
    router.hostname = Some("Gateway-AP".to_string());
    assert_eq!(infer_device_type(&router), DeviceType::Router);
}

#[test]
fn should_identify_iot() {
    assert_eq!(
        infer_device_type(&dev("Sonos-One", "Sonos")),
        DeviceType::IoT
    );
    assert_eq!(
        infer_device_type(&dev("esp32-sensor-temp", "Espressif")),
        DeviceType::IoT
    );
}
