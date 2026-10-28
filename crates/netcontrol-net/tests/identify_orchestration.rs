//! Orchestration tests for `Identifier`, driven by a synthetic in-memory
//! prober. No live network access occurs.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use netcontrol_core::{DeviceType, Pc, PcList};
use netcontrol_net::identify::{HostnameProber, Protocol};
use netcontrol_net::{CancelToken, Identifier};

/// A deterministic prober returning preset names per protocol.
#[derive(Default)]
struct MockProber {
    mdns: Option<String>,
    netbios: Option<String>,
    ssdp: Option<String>,
    llmnr: Option<String>,
    dns: Option<String>,
    calls: AtomicUsize,
    honor_cancel: bool,
}

impl MockProber {
    fn with_mdns(name: &str) -> Self {
        MockProber {
            mdns: Some(name.to_string()),
            ..Default::default()
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl HostnameProber for MockProber {
    fn probe(
        &self,
        protocol: Protocol,
        _ip: Ipv4Addr,
        _timeout: Duration,
        cancel: &CancelToken,
    ) -> Option<String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.honor_cancel && cancel.is_cancelled() {
            return None;
        }
        match protocol {
            Protocol::Mdns => self.mdns.clone(),
            Protocol::NetBios => self.netbios.clone(),
            Protocol::Ssdp => self.ssdp.clone(),
            Protocol::Llmnr => self.llmnr.clone(),
            Protocol::Dns => self.dns.clone(),
        }
    }
}

fn device(ip: [u8; 4], mac: [u8; 6]) -> Pc {
    let mut p = Pc::new();
    p.ip = Some(Ipv4Addr::from(ip));
    p.mac = Some(mac);
    p
}

const INTEL_MAC: [u8; 6] = [0xBC, 0xF1, 0x71, 0x00, 0x00, 0x01];
const APPLE_MAC: [u8; 6] = [0xA4, 0x83, 0xE7, 0x00, 0x00, 0x02];
const RANDOM_MAC: [u8; 6] = [0x72, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

// ── Layer 1 + 5 (offline) ──────────────────────────────────────────

#[test]
fn offline_sets_vendor_and_infers_type() {
    let id = Identifier::new();
    let mut d = device([192, 168, 1, 10], INTEL_MAC);
    id.identify_offline(&mut d);
    assert_eq!(d.vendor.as_deref(), Some("Intel"));
    assert_eq!(d.device_category, DeviceType::Desktop);
    assert_eq!(d.hostname, None);
}

#[test]
fn offline_flags_randomized_mac() {
    let id = Identifier::new();
    let mut d = device([192, 168, 1, 11], RANDOM_MAC);
    id.identify_offline(&mut d);
    assert_eq!(d.vendor.as_deref(), Some("Randomized MAC"));
}

// ── Active probing is disabled by default ──────────────────────────

#[test]
fn active_probes_disabled_by_default() {
    let id = Identifier::new();
    assert!(!id.active_probes_enabled());

    let mock = MockProber::with_mdns("should-not-be-used");
    let mut d = device([192, 168, 1, 20], INTEL_MAC);
    id.identify(&mut d, &mock, &CancelToken::new());

    assert_eq!(d.hostname, None, "no hostname when probing disabled");
    assert_eq!(mock.calls(), 0, "prober must not be called when disabled");
    // Vendor/category still applied.
    assert_eq!(d.vendor.as_deref(), Some("Intel"));
    assert_eq!(d.device_category, DeviceType::Desktop);
}

// ── Active probing (enabled, synthetic) ────────────────────────────

#[test]
fn mdns_hostname_sets_and_reinfers_type() {
    let id = Identifier::new().with_active_probes();
    let mock = MockProber::with_mdns("iPad-Air");
    let mut d = device([192, 168, 1, 30], APPLE_MAC);

    id.identify(&mut d, &mock, &CancelToken::new());

    assert_eq!(d.hostname.as_deref(), Some("iPad-Air"));
    // Apple vendor + "iPad" hostname -> Tablet.
    assert_eq!(d.device_category, DeviceType::Tablet);
    assert_eq!(mock.calls(), 5, "all five protocols probed");
}

#[test]
fn hostname_priority_falls_back_to_netbios() {
    let id = Identifier::new().with_active_probes();
    let mock = MockProber {
        mdns: None,
        netbios: Some("WIN-DESK".to_string()),
        ssdp: Some("ignored".to_string()),
        ..Default::default()
    };
    let mut d = device([192, 168, 1, 31], INTEL_MAC);
    id.identify(&mut d, &mock, &CancelToken::new());
    assert_eq!(d.hostname.as_deref(), Some("WIN-DESK"));
}

#[test]
fn googlecast_candidate_maps_to_label() {
    let id = Identifier::new().with_active_probes();
    let mock = MockProber::with_mdns("_googlecast");
    let mut d = device([192, 168, 1, 32], [0xF4, 0xF5, 0xE8, 0, 0, 3]); // Google OUI
    id.identify(&mut d, &mock, &CancelToken::new());
    assert_eq!(d.hostname.as_deref(), Some("Chromecast / Google Cast"));
    assert_eq!(d.device_category, DeviceType::SmartTV);
}

#[test]
fn no_valid_hostname_leaves_hostname_unset() {
    let id = Identifier::new().with_active_probes();
    let mock = MockProber::default(); // all None
    let mut d = device([192, 168, 1, 33], INTEL_MAC);
    id.identify(&mut d, &mock, &CancelToken::new());
    assert_eq!(d.hostname, None);
    assert_eq!(d.device_category, DeviceType::Desktop); // from vendor only
}

// ── Cancellation + missing IP ──────────────────────────────────────

#[test]
fn precancelled_token_skips_all_probes() {
    let id = Identifier::new().with_active_probes();
    let mock = MockProber::with_mdns("name");
    let cancel = CancelToken::new();
    cancel.cancel();

    let mut d = device([192, 168, 1, 40], INTEL_MAC);
    id.identify(&mut d, &mock, &cancel);

    assert_eq!(mock.calls(), 0, "no probes after cancellation");
    assert_eq!(d.hostname, None);
    // Offline layers still applied.
    assert_eq!(d.device_category, DeviceType::Desktop);
}

#[test]
fn device_without_ip_skips_probes() {
    let id = Identifier::new().with_active_probes();
    let mock = MockProber::with_mdns("name");
    let mut d = Pc::new();
    d.mac = Some(INTEL_MAC); // no IP

    id.identify(&mut d, &mock, &CancelToken::new());
    assert_eq!(mock.calls(), 0);
    assert_eq!(d.hostname, None);
    assert_eq!(d.vendor.as_deref(), Some("Intel"));
}

// ── Integration with core PcList (device tracking) ─────────────────

#[test]
fn identifies_device_tracked_in_pclist() {
    let list = PcList::new();
    let ip = Ipv4Addr::new(192, 168, 1, 50);
    list.add_device(device([192, 168, 1, 50], APPLE_MAC));

    let id = Identifier::new().with_active_probes();
    let mock = MockProber::with_mdns("iPhone-de-Ana");
    let cancel = CancelToken::new();

    let applied = list.update_device_by_ip(ip, |pc| {
        id.identify(pc, &mock, &cancel);
        pc.device_category
    });

    assert_eq!(applied, Some(DeviceType::Mobile));
    // The tracked device now carries the identified hostname + vendor.
    let labels = list.map_devices(|p| (p.hostname.clone(), p.vendor.clone()));
    assert_eq!(
        labels,
        vec![(Some("iPhone-de-Ana".to_string()), Some("Apple".to_string()))]
    );
    assert_eq!(list.len(), 1);
}

#[test]
fn duplicate_tracked_device_is_identified_once_per_entry() {
    let list = PcList::new();
    list.add_device(device([192, 168, 1, 60], INTEL_MAC));
    // Re-observing the same IP updates in place (no duplicate).
    list.add_device(device([192, 168, 1, 60], INTEL_MAC));
    assert_eq!(list.len(), 1);

    let id = Identifier::new().with_active_probes();
    let mock = MockProber::with_mdns("DESKTOP-ABC");
    let cancel = CancelToken::new();
    list.update_device_by_ip(Ipv4Addr::new(192, 168, 1, 60), |pc| {
        id.identify(pc, &mock, &cancel)
    });

    let hostnames = list.map_devices(|p| p.hostname.clone());
    assert_eq!(hostnames, vec![Some("DESKTOP-ABC".to_string())]);
}
