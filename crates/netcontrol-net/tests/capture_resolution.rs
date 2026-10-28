//! Regression tests for mapping OS interfaces to capture devices.
//!
//! Bug: selecting `Ethernet 2 — 192.168.1.119` in Live mode failed with
//! `interface not found: Ethernet 2`, because the GUI passed the Windows
//! friendly name to pnet, whose Windows backend names adapters
//! `\Device\NPF_{GUID}`. The device lists below mirror what this host reported
//! (OS: if-addrs; backend: pnet/Npcap) when the fix was made.

use std::io;
use std::net::Ipv4Addr;

use netcontrol_net::capture::{
    describe_packet_dll, is_idle_timeout, resolve_capture_device, CaptureDevice, CaptureHealth,
    MatchedBy, RuntimeStatus,
};
use netcontrol_net::error::capture_error_hint;
use netcontrol_net::{NetError, NetInterface};

const GUID: &str = "{D9CDEFFC-4074-43FD-AD80-22E83D29E268}";
const MAC: [u8; 6] = [0x18, 0xc0, 0x4d, 0x01, 0x02, 0x03];

fn ethernet2() -> NetInterface {
    NetInterface {
        name: "Ethernet 2".into(),
        adapter_id: Some(GUID.into()),
        ipv4: Ipv4Addr::new(192, 168, 1, 119),
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        mac: Some(MAC),
        is_loopback: false,
    }
}

fn npf(guid: &str, ip: Option<Ipv4Addr>, mac: Option<[u8; 6]>) -> CaptureDevice {
    CaptureDevice {
        name: format!(r"\Device\NPF_{guid}"),
        description: "Realtek Gaming 2.5GbE Family Controller".into(),
        mac,
        ipv4: ip.into_iter().collect(),
    }
}

fn windows_devices() -> Vec<CaptureDevice> {
    vec![
        npf(
            "{3F9334F3-EC12-42AD-ACD3-AFDC58C2A51F}",
            Some(Ipv4Addr::new(192, 168, 50, 1)),
            Some([0x00, 0x50, 0x56, 0xc0, 0x00, 0x08]),
        ),
        npf(GUID, Some(Ipv4Addr::new(192, 168, 1, 119)), Some(MAC)),
    ]
}

// ── Friendly name → GUID ───────────────────────────────────────────

#[test]
fn windows_friendly_name_resolves_by_adapter_guid() {
    let r = resolve_capture_device(&ethernet2(), &windows_devices()).expect("resolves");
    assert_eq!(r.device.name, format!(r"\Device\NPF_{GUID}"));
    assert_eq!(r.matched_by, MatchedBy::AdapterGuid);
    assert!(r.summary().contains("adapter GUID"));
}

#[test]
fn guid_match_is_case_and_brace_insensitive() {
    let mut iface = ethernet2();
    iface.adapter_id = Some("d9cdeffc-4074-43fd-ad80-22e83d29e268".into());
    let r = resolve_capture_device(&iface, &windows_devices()).unwrap();
    assert_eq!(r.matched_by, MatchedBy::AdapterGuid);
}

#[test]
fn friendly_name_is_never_matched_as_a_device_name() {
    // The pre-fix behavior: exact-name lookup only. With no GUID/IP/MAC to go
    // on, the friendly name alone must not match an NPF device.
    let iface = NetInterface {
        adapter_id: None,
        ipv4: Ipv4Addr::UNSPECIFIED,
        mac: None,
        ..ethernet2()
    };
    let err = resolve_capture_device(&iface, &windows_devices()).unwrap_err();
    assert!(matches!(err, NetError::CaptureDeviceNotFound { .. }));
}

// ── Exact name / fallbacks ─────────────────────────────────────────

#[test]
fn unix_names_match_exactly() {
    let iface = NetInterface {
        name: "eth0".into(),
        adapter_id: None,
        ..ethernet2()
    };
    let devices = vec![CaptureDevice {
        name: "eth0".into(),
        description: String::new(),
        mac: None,
        ipv4: vec![],
    }];
    let r = resolve_capture_device(&iface, &devices).unwrap();
    assert_eq!(r.matched_by, MatchedBy::Name);
}

#[test]
fn falls_back_to_unique_ipv4_when_guid_unknown() {
    let iface = NetInterface {
        adapter_id: Some("{00000000-0000-0000-0000-000000000000}".into()),
        mac: None,
        ..ethernet2()
    };
    let r = resolve_capture_device(&iface, &windows_devices()).unwrap();
    assert_eq!(r.matched_by, MatchedBy::Ipv4);
    assert!(r.device.name.contains(GUID));
}

#[test]
fn ambiguous_ipv4_is_skipped_in_favor_of_mac() {
    let ip = Some(Ipv4Addr::new(192, 168, 1, 119));
    let devices = vec![
        npf("{AAAAAAAA-0000-0000-0000-000000000001}", ip, None),
        npf("{AAAAAAAA-0000-0000-0000-000000000002}", ip, Some(MAC)),
    ];
    let iface = NetInterface {
        adapter_id: None,
        ..ethernet2()
    };
    let r = resolve_capture_device(&iface, &devices).unwrap();
    assert_eq!(r.matched_by, MatchedBy::Mac);
    assert!(r.device.name.ends_with("0002}"));
}

#[test]
fn zero_mac_is_never_used_for_matching() {
    let devices = vec![npf(
        "{AAAAAAAA-0000-0000-0000-000000000001}",
        None,
        Some([0; 6]),
    )];
    let iface = NetInterface {
        adapter_id: None,
        ipv4: Ipv4Addr::UNSPECIFIED,
        mac: Some([0; 6]),
        ..ethernet2()
    };
    assert!(resolve_capture_device(&iface, &devices).is_err());
}

// ── Missing interfaces / startup errors ────────────────────────────

#[test]
fn missing_device_lists_what_the_driver_reports() {
    // A VPN/TUN adapter that Npcap does not bind to.
    let tun = NetInterface {
        name: "nekoray-tun".into(),
        adapter_id: Some("{6A460D48-FB76-6C3F-A47D-EF97D3DC6B0E}".into()),
        ipv4: Ipv4Addr::new(172, 19, 0, 1),
        mac: None,
        ..ethernet2()
    };
    let err = resolve_capture_device(&tun, &windows_devices()).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("nekoray-tun"), "{msg}");
    assert!(msg.contains(r"\Device\NPF_"), "{msg}");
    assert!(msg.contains("Realtek"), "{msg}");
}

#[test]
fn empty_device_list_points_at_npcap() {
    let err = resolve_capture_device(&ethernet2(), &[]).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("Ethernet 2"), "{msg}");
    assert!(msg.contains("Npcap"), "{msg}");
}

#[test]
fn interface_not_found_suggests_refresh() {
    let msg = NetError::InterfaceNotFound("Ethernet 2".into()).to_string();
    assert!(
        msg.contains("Ethernet 2") && msg.contains("refresh"),
        "{msg}"
    );
}

#[test]
fn open_failure_with_access_denied_explains_privileges() {
    let error = if cfg!(windows) {
        io::Error::from_raw_os_error(5)
    } else {
        io::Error::from_raw_os_error(1)
    };
    let msg = NetError::CaptureOpenFailed {
        device: r"\Device\NPF_{X}".into(),
        error,
    }
    .to_string();
    assert!(msg.contains("Permission denied"), "{msg}");
    assert!(msg.contains(r"\Device\NPF_{X}"), "{msg}");
}

#[cfg(windows)]
#[test]
fn open_failure_with_missing_driver_device_mentions_npcap_service() {
    let hint = capture_error_hint(&io::Error::from_raw_os_error(2));
    assert!(hint.contains("Npcap") && hint.contains("service"), "{hint}");
}

#[test]
fn generic_open_failure_has_a_hint() {
    let hint = capture_error_hint(&io::Error::other("boom"));
    assert!(!hint.is_empty());
}

#[test]
fn read_timeouts_are_idle_not_failures() {
    assert!(is_idle_timeout(&io::Error::from(io::ErrorKind::TimedOut)));
    assert!(is_idle_timeout(&io::Error::from(io::ErrorKind::WouldBlock)));
    assert!(!is_idle_timeout(&io::Error::from(
        io::ErrorKind::PermissionDenied
    )));
}

// ── Runtime / health reporting ─────────────────────────────────────

#[test]
fn packet_dll_location_identifies_npcap_vs_winpcap() {
    assert!(describe_packet_dll(r"C:\Windows\System32\Npcap\Packet.dll").starts_with("Npcap"));
    let legacy = describe_packet_dll(r"C:\WINDOWS\SYSTEM32\packet.dll");
    assert!(legacy.contains("WinPcap") && legacy.contains("Npcap is recommended"));
}

#[test]
fn runtime_status_reports_availability() {
    assert!(RuntimeStatus::Available("x".into()).is_available());
    assert!(!RuntimeStatus::Missing("Npcap is not installed".into()).is_available());
    assert!(!RuntimeStatus::NotCompiled.is_available());
    assert!(RuntimeStatus::NotCompiled
        .describe()
        .contains("not compiled"));
}

#[cfg(not(feature = "live-capture"))]
#[test]
fn default_build_reports_capture_not_compiled() {
    assert_eq!(
        netcontrol_net::capture::runtime_status(),
        RuntimeStatus::NotCompiled
    );
}

#[test]
fn capture_health_records_terminal_failure() {
    let h = CaptureHealth::default();
    assert!(!h.has_failed() && h.last_error().is_none());
    h.fail("traffic monitor stopped: adapter removed");
    assert!(h.has_failed());
    assert_eq!(
        h.last_error().as_deref(),
        Some("traffic monitor stopped: adapter removed")
    );
}
