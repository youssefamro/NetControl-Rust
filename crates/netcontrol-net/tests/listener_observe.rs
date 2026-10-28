//! Passive ARP observation / device-learning tests, using synthetic frames.
//! No live capture is performed.

use std::net::Ipv4Addr;

use netcontrol_core::{AddOutcome, PcList};
use netcontrol_net::arp::{build_frame, ArpOperation};
use netcontrol_net::ethernet::ETHERTYPE_IPV4;
use netcontrol_net::listener::{observe_arp_frame, Observation, ObserveContext};

const LOCAL_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 42);
const ROUTER_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 1);

fn ctx() -> ObserveContext {
    ObserveContext {
        local_mac: LOCAL_MAC,
        local_ip: Some(LOCAL_IP),
        router_ip: Some(ROUTER_IP),
    }
}

/// An ARP frame as if device `dev_ip`/`dev_mac` announced itself.
fn device_frame(dev_mac: [u8; 6], dev_ip: Ipv4Addr, op: ArpOperation) -> [u8; 42] {
    build_frame(
        [0xFF; 6], // eth dst (broadcast for a request/gratuitous)
        dev_mac,   // eth src = the device
        op, dev_mac, // sender mac = device
        dev_ip,  // sender ip = device
        [0x00; 6], ROUTER_IP,
    )
}

#[test]
fn learns_device_from_arp_reply() {
    let list = PcList::new();
    let mac = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
    let ip = Ipv4Addr::new(192, 168, 1, 77);

    let obs = observe_arp_frame(&list, &device_frame(mac, ip, ArpOperation::Reply), &ctx());

    match obs {
        Observation::Learned {
            ip: oip,
            mac: omac,
            is_gateway,
            is_local,
            outcome,
            ..
        } => {
            assert_eq!(oip, ip);
            assert_eq!(omac, mac);
            assert!(!is_gateway);
            assert!(!is_local);
            assert_eq!(outcome, AddOutcome::Added);
        }
        other => panic!("expected Learned, got {other:?}"),
    }
    assert_eq!(list.len(), 1);
    assert_eq!(list.mac_for_ip(ip), Some(mac));
}

#[test]
fn learns_device_from_arp_request_too() {
    let list = PcList::new();
    let mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x09];
    let ip = Ipv4Addr::new(192, 168, 1, 23);

    let obs = observe_arp_frame(&list, &device_frame(mac, ip, ArpOperation::Request), &ctx());
    assert!(matches!(obs, Observation::Learned { .. }));
    assert!(list.contains_ip(ip));
}

#[test]
fn duplicate_frames_update_not_duplicate() {
    let list = PcList::new();
    let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    let ip = Ipv4Addr::new(192, 168, 1, 50);

    let first = observe_arp_frame(&list, &device_frame(mac, ip, ArpOperation::Reply), &ctx());
    let second = observe_arp_frame(&list, &device_frame(mac, ip, ArpOperation::Reply), &ctx());

    assert!(
        matches!(
            first,
            Observation::Learned {
                outcome: AddOutcome::Added,
                ..
            }
        ),
        "first should add"
    );
    assert!(
        matches!(
            second,
            Observation::Learned {
                outcome: AddOutcome::Updated,
                ..
            }
        ),
        "second should update"
    );
    assert_eq!(list.len(), 1);
}

#[test]
fn flags_gateway_when_sender_is_router() {
    let list = PcList::new();
    let router_mac = [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01];

    let obs = observe_arp_frame(
        &list,
        &device_frame(router_mac, ROUTER_IP, ArpOperation::Reply),
        &ctx(),
    );

    match obs {
        Observation::Learned {
            is_gateway,
            learned_gateway_mac,
            ..
        } => {
            assert!(is_gateway);
            assert_eq!(learned_gateway_mac, Some(router_mac));
        }
        other => panic!("expected Learned gateway, got {other:?}"),
    }
    assert_eq!(list.router_ip(), Some(ROUTER_IP));
}

#[test]
fn ignores_frames_from_local_host() {
    let list = PcList::new();
    // eth src == LOCAL_MAC -> our own frame.
    let frame = build_frame(
        [0xFF; 6],
        LOCAL_MAC,
        ArpOperation::Request,
        LOCAL_MAC,
        LOCAL_IP,
        [0x00; 6],
        ROUTER_IP,
    );
    assert_eq!(
        observe_arp_frame(&list, &frame, &ctx()),
        Observation::FromSelf
    );
    assert!(list.is_empty());
}

#[test]
fn ignores_short_frames() {
    let list = PcList::new();
    assert_eq!(
        observe_arp_frame(&list, &[0u8; 30], &ctx()),
        Observation::TooShort
    );
    assert!(list.is_empty());
}

#[test]
fn ignores_non_arp_frames() {
    let list = PcList::new();
    let mut frame = [0u8; 42];
    frame[6..12].copy_from_slice(&[0x99; 6]); // non-local src
    frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    assert_eq!(
        observe_arp_frame(&list, &frame, &ctx()),
        Observation::NotArp
    );
    assert!(list.is_empty());
}

#[test]
fn ignores_non_learnable_opcodes() {
    let list = PcList::new();
    let frame = device_frame(
        [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC],
        Ipv4Addr::new(192, 168, 1, 88),
        ArpOperation::Other(3), // RARP request, etc.
    );
    assert_eq!(
        observe_arp_frame(&list, &frame, &ctx()),
        Observation::NotLearnable
    );
    assert!(list.is_empty());
}
