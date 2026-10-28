//! Integration & regression tests for the GUI state machine. These exercise
//! mode transitions, settings preservation/persistence, Demo/Live dataset
//! separation, English strings, Start/Stop, live-unavailable behavior, and the
//! unsupported-feature indicators — with no live capture or network probing.

use std::net::Ipv4Addr;

use netcontrol_gui::config::{config_path, resolve_data_dir, SavedMode, UiConfig, PORTABLE_MARKER};
use netcontrol_gui::state::{InterfaceEntry, Mode, StatusLevel};
use netcontrol_gui::{strings, UiState};

const GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);
const PHONE: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 37); // iPhone, controllable

fn live_ifaces() -> Vec<InterfaceEntry> {
    vec![
        InterfaceEntry {
            name: "eth0".into(),
            display: "eth0 — 192.168.1.42".into(),
            simulated: false,
            iface: None,
        },
        InterfaceEntry {
            name: "wlan0".into(),
            display: "wlan0 — 192.168.1.43".into(),
            simulated: false,
            iface: None,
        },
    ]
}

// ── Baseline ───────────────────────────────────────────────────────

#[test]
fn starts_in_demonstration_with_simulated_fleet() {
    let s = UiState::in_memory();
    assert_eq!(s.mode(), Mode::Demonstration);
    assert_eq!(s.device_count(), 11);
    assert!(!s.capture_running());
    assert!(s.interfaces().iter().all(|i| i.simulated));
}

#[test]
fn dashboard_counts_and_gateway() {
    let s = UiState::in_memory();
    let (total, spoof, blocked, gateway) = s.dashboard();
    assert_eq!((total, spoof, blocked), (11, 0, 0));
    assert_eq!(gateway, "192.168.1.1");
    assert_eq!(s.local_ip(), "192.168.1.42");
}

#[test]
fn offline_identification_populated_rows() {
    let s = UiState::in_memory();
    let rows = s.device_rows();
    let gw = rows.iter().find(|r| r.ip == GATEWAY).unwrap();
    assert!(gw.is_gateway && !gw.can_control);
    let phone = rows.iter().find(|r| r.ip == PHONE).unwrap();
    assert_eq!(phone.vendor, "Apple");
    assert_eq!(phone.category, "Mobile");
    assert!(phone.can_control);
}

// ── Controls ───────────────────────────────────────────────────────

#[test]
fn redirect_toggle_respects_control_and_counts() {
    let mut s = UiState::in_memory();
    s.toggle_redirect(PHONE);
    assert_eq!(s.dashboard().1, 1);
    s.toggle_redirect(GATEWAY); // uncontrollable -> no effect
    assert_eq!(s.dashboard().1, 1);
}

#[test]
fn block_and_redirect_are_mutually_exclusive() {
    let mut s = UiState::in_memory();
    s.toggle_redirect(PHONE);
    s.toggle_block(PHONE);
    let (_, spoof, blocked, _) = s.dashboard();
    assert_eq!((spoof, blocked), (0, 1));
}

#[test]
fn bandwidth_limit_sets_value_and_reports_dry_run() {
    let mut s = UiState::in_memory();
    s.toggle_redirect(PHONE);
    s.set_bandwidth_limit(PHONE, 512);
    let row = s.device_rows().into_iter().find(|r| r.ip == PHONE).unwrap();
    assert_eq!(row.bandwidth_limit_kb, 512);
    assert!(row.throttling_enabled);
    let summary = s.throttle_summary();
    assert!(summary.status.contains("Not Enforced") && summary.status.contains("Dry Run"));
}

// ── Mode separation + settings preservation (the reported bug) ─────

#[test]
fn switching_modes_preserves_demo_settings() {
    let mut s = UiState::in_memory();
    s.toggle_redirect(PHONE);
    s.set_bandwidth_limit(PHONE, 256);
    assert_eq!(s.dashboard().1, 1);

    // Demo -> Live -> Demo must NOT lose the configured limit/flag.
    s.set_mode(Mode::Live);
    s.set_mode(Mode::Demonstration);

    let row = s.device_rows().into_iter().find(|r| r.ip == PHONE).unwrap();
    assert_eq!(
        row.bandwidth_limit_kb, 256,
        "limit preserved across mode switch"
    );
    assert!(row.redirect, "redirect flag preserved across mode switch");
    assert_eq!(s.dashboard().1, 1);
}

#[test]
fn demo_and_live_datasets_are_separate() {
    let mut s = UiState::in_memory();
    assert_eq!(s.demo_device_count(), 11);
    assert_eq!(s.live_device_count(), 0);

    s.set_mode(Mode::Live);
    // Live view is empty (no simulated devices leak in), demo retained.
    assert_eq!(s.device_count(), 0);
    assert_eq!(s.demo_device_count(), 11);
    assert_eq!(s.live_device_count(), 0);
}

// ── Persistence / restart ──────────────────────────────────────────

#[test]
fn config_round_trips_through_ini() {
    let mut demo_devices = std::collections::BTreeMap::new();
    demo_devices.insert(
        PHONE,
        netcontrol_gui::config::DeviceConfig {
            limit_kb: 512,
            redirect: true,
            block: false,
        },
    );
    let cfg = UiConfig {
        disclaimer_dismissed: true,
        last_mode: SavedMode::Live,
        demo_interface: Some("demo-wlan0".into()),
        live_interface: Some("eth0".into()),
        demo_devices,
    };
    let parsed = UiConfig::from_ini(&cfg.to_ini());
    assert_eq!(parsed, cfg);
}

#[test]
fn settings_persist_across_restart() {
    let dir = std::env::temp_dir().join(format!("nc-test-{}", std::process::id()));
    let path = dir.join("config.ini");
    let _ = std::fs::remove_dir_all(&dir);

    // First "run": configure, which persists to disk.
    {
        let mut s = UiState::with_config_path(Some(path.clone()));
        s.toggle_redirect(PHONE);
        s.set_bandwidth_limit(PHONE, 777);
        s.dismiss_disclaimer();
    }

    // Second "run": a fresh state loads the saved config.
    let s2 = UiState::with_config_path(Some(path.clone()));
    let row = s2
        .device_rows()
        .into_iter()
        .find(|r| r.ip == PHONE)
        .unwrap();
    assert_eq!(row.bandwidth_limit_kb, 777);
    assert!(row.redirect);
    assert!(!s2.disclaimer_visible(), "dismissed disclaimer persisted");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn config_path_lives_under_d_appdata_by_default() {
    // Without the env override, config lives under D:\...\.appdata.
    std::env::remove_var("NETCONTROL_DATA_DIR");
    let p = config_path();
    let s = p.to_string_lossy().to_lowercase();
    assert!(s.starts_with("d:"), "config should live on D: — got {p:?}");
    assert!(s.contains(".appdata"));
}

// ── Start / Stop + Live unavailable ────────────────────────────────

#[test]
fn start_stop_transitions() {
    let mut s = UiState::in_memory();
    assert!(!s.capture_running());
    s.start_capture();
    assert!(s.capture_running());
    assert_eq!(s.status().1, StatusLevel::Success);
    s.stop_capture();
    assert!(!s.capture_running());
}

#[cfg(not(feature = "live-capture"))]
#[test]
fn live_capture_unavailable_without_feature() {
    let mut s = UiState::in_memory();
    s.set_mode(Mode::Live);
    s.set_live_interfaces(live_ifaces());
    s.start_capture();
    assert!(
        !s.capture_running(),
        "capture must not start without the feature"
    );
    let err = s.last_error().expect("an error is reported");
    assert!(err.contains("live capture") || err.contains("Npcap") || err.contains("live-capture"));
    assert_eq!(s.status().1, StatusLevel::Error);
}

#[test]
fn live_interface_selection_persists_by_name() {
    let mut s = UiState::in_memory();
    s.set_mode(Mode::Live);
    s.set_live_interfaces(live_ifaces());
    s.select_interface(1);
    assert_eq!(s.selected_interface_name(), "wlan0");
    // Switching away and back keeps the selected live interface.
    s.set_mode(Mode::Demonstration);
    s.set_mode(Mode::Live);
    s.set_live_interfaces(live_ifaces());
    assert_eq!(s.selected_interface_name(), "wlan0");
}

// ── Live diagnostics / unsupported indicators ──────────────────────

#[test]
fn live_diagnostics_report_passive_and_unsupported() {
    let mut s = UiState::in_memory();
    s.set_mode(Mode::Live);
    s.set_live_interfaces(live_ifaces());
    let d = s.live_diagnostics();

    // Passive-only wording and honest reasons.
    assert!(d.mode_note.to_lowercase().contains("passive"));
    assert!(!d.capture_running);
    assert_eq!(d.devices_discovered, 0);
    assert!(d.no_devices_reason.is_some());

    // The unsupported list names the non-operational features.
    let joined = d.unsupported_features.join(" ").to_lowercase();
    assert!(joined.contains("spoof"));
    assert!(joined.contains("blocking") || joined.contains("block"));
    assert!(joined.contains("enforcement"));
    assert!(joined.contains("scanning") || joined.contains("probe"));

    // In a demonstration build, capture is unsupported and says why.
    #[cfg(not(feature = "live-capture"))]
    {
        assert!(!d.capture_supported);
        assert!(d.no_devices_reason.unwrap().contains("live-capture"));
    }
}

// ── English interface ──────────────────────────────────────────────

#[test]
fn ui_strings_are_english_and_not_spanish() {
    let samples = [
        strings::INTERFACE_LABEL,
        strings::START_BUTTON,
        strings::STOP_BUTTON,
        strings::KPI_TOTAL,
        strings::KPI_SPOOF_FLAGGED,
        strings::KPI_BLOCK_FLAGGED,
        strings::KPI_GATEWAY,
        strings::EMPTY_TITLE,
        strings::EMPTY_BODY_DEMO,
        strings::EMPTY_BODY_LIVE,
        strings::COL_SPOOF,
        strings::COL_BLOCK,
    ];
    let spanish = [
        "Escanear",
        "Dispositivos",
        "DISPOSITIVOS",
        "INTERCEPTADOS",
        "BLOQUEADOS",
        "PUERTA DE ENLACE",
        "Interfaz",
        "Selecciona",
        "hay dispositivos",
    ];
    for s in samples {
        for sp in spanish {
            assert!(
                !s.contains(sp),
                "found Spanish text '{sp}' in UI string '{s}'"
            );
        }
    }
    assert_eq!(strings::INTERFACE_LABEL, "Interface:");
    assert_eq!(strings::KPI_TOTAL, "TOTAL DEVICES");
}

#[test]
fn spoof_and_block_are_labeled_non_operational() {
    // Tooltips must make clear these are planning flags, not actions.
    assert!(strings::TIP_SPOOF.contains("NOT operational"));
    assert!(strings::TIP_BLOCK.contains("NOT operational"));
    assert!(strings::TIP_CAP.to_lowercase().contains("dry-run"));
}

// ── Misc ───────────────────────────────────────────────────────────

#[test]
fn demo_start_runs_and_ticks_produce_bandwidth() {
    let mut s = UiState::in_memory();
    s.start_capture();
    for _ in 0..60 {
        s.demo_tick(1.0);
    }
    assert!(s.device_rows().iter().any(|r| r.download != "0 KB/s"));
}

#[test]
fn blocked_device_shows_no_traffic_after_ticks() {
    let mut s = UiState::in_memory();
    s.start_capture();
    s.toggle_block(PHONE);
    for _ in 0..30 {
        s.demo_tick(1.0);
    }
    let phone = s.device_rows().into_iter().find(|r| r.ip == PHONE).unwrap();
    assert_eq!(phone.download, "0 KB/s");
    assert_eq!(phone.upload, "0 KB/s");
}

#[test]
fn disclaimer_can_be_dismissed() {
    let mut s = UiState::in_memory();
    assert!(s.disclaimer_visible());
    s.dismiss_disclaimer();
    assert!(!s.disclaimer_visible());
}

// ── Live interface resolution (regression: "interface not found: Ethernet 2") ──

fn ethernet2() -> netcontrol_net::NetInterface {
    netcontrol_net::NetInterface {
        name: "Ethernet 2".into(),
        adapter_id: Some("{D9CDEFFC-4074-43FD-AD80-22E83D29E268}".into()),
        ipv4: Ipv4Addr::new(192, 168, 1, 119),
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        mac: Some([0x18, 0xc0, 0x4d, 0x01, 0x02, 0x03]),
        is_loopback: false,
    }
}

#[test]
fn live_entries_show_friendly_name_and_keep_adapter_identity() {
    let e = InterfaceEntry::from_net(ethernet2());
    assert_eq!(e.display, "Ethernet 2 — 192.168.1.119");
    assert_eq!(e.name, "Ethernet 2");
    assert!(!e.display.contains("NPF") && !e.display.contains('{'));
    assert!(!e.simulated);
    assert_eq!(
        e.iface.and_then(|i| i.adapter_id).as_deref(),
        Some("{D9CDEFFC-4074-43FD-AD80-22E83D29E268}")
    );
}

#[test]
fn selected_live_target_carries_guid_for_capture_resolution() {
    let mut s = UiState::in_memory();
    s.set_mode(Mode::Live);
    s.set_live_interfaces(vec![InterfaceEntry::from_net(ethernet2())]);
    let target = s.selected_live_target().expect("real interface selected");
    assert_eq!(target.name, "Ethernet 2");
    assert!(target.adapter_id.is_some());
}

#[test]
fn selected_live_target_reports_missing_interface() {
    let mut s = UiState::in_memory();
    s.set_mode(Mode::Live);
    s.set_live_interfaces(vec![InterfaceEntry {
        name: "NetControl-Test-Nonexistent-Adapter".into(),
        display: "gone".into(),
        simulated: false,
        iface: None,
    }]);
    match s.selected_live_target() {
        Err(Some(e)) => assert!(e.to_string().contains("Nonexistent"), "{e}"),
        other => panic!("expected a missing-interface error, got {other:?}"),
    }
}

#[test]
fn selected_live_target_requires_a_real_interface() {
    let mut s = UiState::in_memory();
    s.set_mode(Mode::Live);
    s.set_live_interfaces(Vec::new());
    assert!(matches!(s.selected_live_target(), Err(None)));
}

#[test]
fn capture_startup_error_is_surfaced_in_status_and_diagnostics() {
    let mut s = UiState::in_memory();
    s.set_mode(Mode::Live);
    s.set_live_interfaces(vec![InterfaceEntry::from_net(ethernet2())]);
    s.capture_failed(&netcontrol_net::NetError::CaptureDeviceNotFound {
        interface: "Ethernet 2".into(),
        available: Vec::new(),
    });
    assert!(!s.capture_running());
    assert_eq!(s.status().1, StatusLevel::Error);
    let d = s.live_diagnostics();
    let err = d.capture_error.expect("error kept for the Live panel");
    assert!(err.contains("Ethernet 2") && err.contains("Npcap"), "{err}");
    assert!(d.capture_device.is_none());
    assert!(!d.runtime_note.is_empty());
}

#[test]
fn saved_live_interface_restores_by_friendly_name() {
    let mut s = UiState::in_memory();
    s.set_mode(Mode::Live);
    let other = netcontrol_net::NetInterface {
        name: "Wi-Fi".into(),
        adapter_id: Some("{11111111-2222-3333-4444-555555555555}".into()),
        ipv4: Ipv4Addr::new(192, 168, 1, 50),
        ..ethernet2()
    };
    let entries = || {
        vec![
            InterfaceEntry::from_net(other.clone()),
            InterfaceEntry::from_net(ethernet2()),
        ]
    };
    s.set_live_interfaces(entries());
    s.select_interface(1);
    let cfg = s.export_config();
    assert_eq!(cfg.live_interface.as_deref(), Some("Ethernet 2"));

    let mut restored = UiState::in_memory();
    restored.apply_config(&cfg);
    restored.set_live_interfaces(entries());
    assert_eq!(restored.mode(), Mode::Live);
    assert_eq!(restored.selected_interface_name(), "Ethernet 2");
}

#[cfg(not(feature = "live-capture"))]
#[test]
fn default_build_live_start_records_capture_error() {
    let mut s = UiState::in_memory();
    s.set_mode(Mode::Live);
    s.set_live_interfaces(vec![InterfaceEntry::from_net(ethernet2())]);
    s.start_capture();
    assert!(!s.capture_running());
    let d = s.live_diagnostics();
    assert!(d.capture_error.is_some());
    assert!(d.runtime_note.contains("not compiled"));
}

// ── Data directory resolution (portable / installed / dev) ─────────

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn data_dir_env_override_wins() {
    let p = resolve_data_dir(Some(r"D:\nc-data".into()), None);
    assert_eq!(p, std::path::PathBuf::from(r"D:\nc-data"));
}

#[test]
fn portable_marker_keeps_data_beside_exe() {
    let dir = scratch("portable-empty");
    std::fs::write(dir.join(PORTABLE_MARKER), "").unwrap();
    let exe = dir.join("NetControl.exe");
    assert_eq!(resolve_data_dir(None, Some(&exe)), dir.join("data"));
}

#[test]
fn portable_marker_can_name_a_data_dir() {
    let dir = scratch("portable-custom");
    std::fs::write(dir.join(PORTABLE_MARKER), "settings\n").unwrap();
    let exe = dir.join("NetControl.exe");
    assert_eq!(resolve_data_dir(None, Some(&exe)), dir.join("settings"));
}

#[test]
fn installed_exe_without_marker_uses_per_user_default() {
    let dir = scratch("installed");
    let exe = dir.join("NetControl.exe");
    let p = resolve_data_dir(None, Some(&exe));
    assert!(
        !p.starts_with(&dir),
        "no marker → not beside the exe: {p:?}"
    );
    assert!(p.to_string_lossy().to_lowercase().contains("netcontrol"));
}

#[test]
fn diagnostics_log_records_capture_failures() {
    let dir = scratch("diaglog");
    let mut s = UiState::with_config_path(Some(dir.join("config.ini")));
    s.set_mode(Mode::Live);
    s.set_live_interfaces(vec![InterfaceEntry::from_net(ethernet2())]);
    s.capture_failed(&netcontrol_net::NetError::InterfaceNotFound(
        "Ethernet 2".into(),
    ));
    let log = std::fs::read_to_string(dir.join("netcontrol.log")).expect("log written");
    assert!(
        log.contains("Capture failed: interface not found: Ethernet 2"),
        "{log}"
    );
}
