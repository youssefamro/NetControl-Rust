//! Mirrors the C# `OuiAndIdentificationTests`.

mod common;

use netcontrol_core::device_identifier::infer_device_type;
use netcontrol_core::pc::machine_name;
use netcontrol_core::{oui, DeviceType, Pc};

#[test]
fn oui_lookup_should_resolve_intel_prefix() {
    let intel_mac = [0xBC, 0xF1, 0x71, 0xA2, 0x61, 0x2E];
    let vendor = oui::lookup(&intel_mac);
    assert_eq!(vendor, Some("Intel"));

    let mut intel_device = Pc::new();
    intel_device.mac = Some(common::parse_mac("BCF171A2612E"));
    intel_device.vendor = Some(vendor.unwrap().to_string());
    intel_device.device_category = DeviceType::Desktop;
    assert_eq!(intel_device.device_label(), "Desktop (Intel)");
}

#[test]
fn oui_lookup_should_resolve_common_vendors() {
    let cases = [
        ("00:E0:4C:11:22:33", "Realtek"),
        ("00:03:93:AA:BB:CC", "Apple"),
        ("24:0A:C4:01:02:03", "Espressif"),
        ("00:0C:E7:55:66:77", "MediaTek"),
        ("00:15:99:12:34:56", "Samsung"),
        ("F4:F5:E8:99:88:77", "Google"),
    ];
    for (mac_str, expected) in cases {
        let mac = common::parse_mac(mac_str);
        assert_eq!(oui::lookup(&mac), Some(expected), "mac {mac_str}");
    }
}

#[test]
fn device_label_should_sanitize_in_addr_arpa_reverse_dns_on_local_host() {
    let mut local_pc = Pc::new();
    local_pc.is_local_pc = true;
    local_pc.hostname = Some("1.1.168.192.in-addr.arpa".to_string());
    local_pc.name = Some("MyLinuxBox".to_string());

    assert_eq!(
        local_pc.device_label(),
        format!("{} (Local Host)", machine_name())
    );
}

#[test]
fn device_label_should_preserve_valid_local_host_hostnames() {
    let mut local_pc_valid = Pc::new();
    local_pc_valid.is_local_pc = true;
    local_pc_valid.hostname = Some("workstation-pro".to_string());
    local_pc_valid.name = Some("workstation-pro".to_string());

    assert_eq!(
        local_pc_valid.device_label(),
        "workstation-pro (Local Host)"
    );
}

#[test]
fn google_cast_should_be_inferred_as_smart_tv_and_formatted() {
    let mut cast_device = Pc::new();
    cast_device.hostname = Some("Chromecast / Google Cast".to_string());
    cast_device.device_category = DeviceType::SmartTV;

    let mut probe = Pc::new();
    probe.hostname = Some("_googlecast".to_string());
    assert_eq!(infer_device_type(&probe), DeviceType::SmartTV);

    assert_eq!(
        cast_device.device_label(),
        "SmartTV — Chromecast / Google Cast"
    );
}

#[test]
fn randomized_mac_detection_matches_locally_administered_bit() {
    // 0x72 has the locally-administered bit (0x02) set; 0xBC does not.
    assert!(oui::is_randomized_mac(&common::parse_mac("72D83E6E1BC6")));
    assert!(!oui::is_randomized_mac(&common::parse_mac("BCF171A2612E")));
}
