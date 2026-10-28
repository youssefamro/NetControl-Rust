//! Device-tracking tests for `PcList` (Phase 2).

use std::net::Ipv4Addr;

use netcontrol_core::{AddOutcome, Pc, PcList};

fn dev(ip: [u8; 4], mac: [u8; 6]) -> Pc {
    let mut p = Pc::new();
    p.ip = Some(Ipv4Addr::from(ip));
    p.mac = Some(mac);
    p
}

#[test]
fn add_new_device_reports_added_and_grows_list() {
    let list = PcList::new();
    assert!(list.is_empty());

    let outcome = list.add_device(dev([192, 168, 1, 10], [1, 2, 3, 4, 5, 6]));
    assert_eq!(outcome, AddOutcome::Added);
    assert!(outcome.is_new());
    assert_eq!(list.len(), 1);
    assert!(list.contains_ip(Ipv4Addr::new(192, 168, 1, 10)));
}

#[test]
fn duplicate_ip_updates_in_place_without_growing() {
    let list = PcList::new();
    assert_eq!(
        list.add_device(dev([192, 168, 1, 10], [1, 1, 1, 1, 1, 1])),
        AddOutcome::Added
    );

    // Same IP, different MAC -> Updated, length unchanged, MAC adopted.
    let outcome = list.add_device(dev([192, 168, 1, 10], [2, 2, 2, 2, 2, 2]));
    assert_eq!(outcome, AddOutcome::Updated);
    assert!(!outcome.is_new());
    assert_eq!(list.len(), 1);
    assert_eq!(
        list.mac_for_ip(Ipv4Addr::new(192, 168, 1, 10)),
        Some([2, 2, 2, 2, 2, 2])
    );
}

#[test]
fn device_without_ip_is_rejected() {
    let list = PcList::new();
    let outcome = list.add_device(Pc::new());
    assert_eq!(outcome, AddOutcome::Rejected);
    assert!(list.is_empty());
}

#[test]
fn gateway_and_local_flags_are_promoted_not_cleared() {
    let list = PcList::new();
    list.add_device(dev([10, 0, 0, 1], [9, 9, 9, 9, 9, 9]));

    // Re-observe the same IP, now flagged as gateway.
    let mut gw = dev([10, 0, 0, 1], [9, 9, 9, 9, 9, 9]);
    gw.is_gateway = true;
    assert_eq!(list.add_device(gw), AddOutcome::Updated);
    assert_eq!(list.router_ip(), Some(Ipv4Addr::new(10, 0, 0, 1)));

    // A later plain observation must not clear the gateway flag.
    assert_eq!(
        list.add_device(dev([10, 0, 0, 1], [9, 9, 9, 9, 9, 9])),
        AddOutcome::Updated
    );
    assert_eq!(list.router_ip(), Some(Ipv4Addr::new(10, 0, 0, 1)));
}

#[test]
fn router_and_local_lookups() {
    let list = PcList::new();
    let mut router = dev([192, 168, 0, 1], [0xAA; 6]);
    router.is_gateway = true;
    let mut me = dev([192, 168, 0, 50], [0xBB; 6]);
    me.is_local_pc = true;
    list.add_device(router);
    list.add_device(me);
    list.add_device(dev([192, 168, 0, 77], [0xCC; 6]));

    assert_eq!(list.router_ip(), Some(Ipv4Addr::new(192, 168, 0, 1)));
    assert_eq!(list.local_ip(), Some(Ipv4Addr::new(192, 168, 0, 50)));
    assert_eq!(
        list.ip_for_mac([0xCC; 6]),
        Some(Ipv4Addr::new(192, 168, 0, 77))
    );
    assert_eq!(list.len(), 3);
}

#[test]
fn remove_and_clear() {
    let list = PcList::new();
    list.add_device(dev([192, 168, 1, 1], [1; 6]));
    list.add_device(dev([192, 168, 1, 2], [2; 6]));

    assert!(list.remove_device_by_ip(Ipv4Addr::new(192, 168, 1, 1)));
    assert!(!list.remove_device_by_ip(Ipv4Addr::new(192, 168, 1, 1)));
    assert_eq!(list.len(), 1);

    list.clear();
    assert!(list.is_empty());
}

#[test]
fn reset_byte_counts_zeroes_all_devices() {
    let list = PcList::new();
    let pc = dev([192, 168, 1, 5], [5; 6]);
    pc.add_bytes_received(5000);
    pc.add_bytes_sent(3000);
    list.add_device(pc);

    list.reset_all_byte_counts();

    let totals = list.map_devices(|p| (p.bytes_received(), p.bytes_sent()));
    assert_eq!(totals, vec![(0, 0)]);
}

#[test]
fn last_seen_is_tracked_and_updated() {
    let list = PcList::new();
    list.add_device(dev([192, 168, 1, 9], [1; 6]));
    let first = list
        .last_seen_for_ip(Ipv4Addr::new(192, 168, 1, 9))
        .unwrap();

    list.add_device(dev([192, 168, 1, 9], [1; 6]));
    let second = list
        .last_seen_for_ip(Ipv4Addr::new(192, 168, 1, 9))
        .unwrap();
    assert!(second >= first);
}
