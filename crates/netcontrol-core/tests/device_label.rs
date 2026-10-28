//! Mirrors the C# `DeviceLabelTests`.

mod common;

use netcontrol_core::{DeviceType, Pc};

#[test]
fn should_format_mobile_brand_and_hostname() {
    let mut pc = Pc::new();
    pc.hostname = Some("iPhone-de-Carlos".to_string());
    pc.vendor = Some("Apple".to_string());
    pc.device_category = DeviceType::Mobile;

    assert_eq!(pc.device_label(), "Mobile — iPhone-de-Carlos (Apple)");
}

#[test]
fn should_deduplicate_vendor_when_already_in_hostname() {
    let mut pc = Pc::new();
    pc.hostname = Some("Samsung-SmartTV".to_string());
    pc.vendor = Some("Samsung".to_string());
    pc.device_category = DeviceType::SmartTV;

    assert_eq!(pc.device_label(), "SmartTV — Samsung-SmartTV");
}

#[test]
fn should_format_randomized_mac() {
    // 74:D8:3E has the locally administered bit set (byte 0 bit 1 = 0x02).
    let mut pc = Pc::new();
    pc.mac = Some(common::parse_mac("74D83E6E1BC6"));
    pc.vendor = Some("Randomized MAC".to_string());

    assert_eq!(pc.device_label(), "Randomized 74:D8:3E:6E:1B:C6");
}

#[test]
fn should_apply_ellipsis_to_excessive_hostnames() {
    let mut pc = Pc::new();
    pc.hostname = Some(
        "VeryLongHostnameThatExceedsNormalLengthLimitForNetworkDevicesTesting12345".to_string(),
    );
    pc.device_category = DeviceType::Desktop;

    let label = pc.device_label();
    assert!(
        label.starts_with("Desktop — VeryLongHostnameThatExceedsNormalLengthLimit"),
        "got: {label}"
    );
    assert!(label.ends_with('…'), "got: {label}");
}
