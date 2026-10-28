//! Discovery planning, authorization gating, interface selection, and
//! cancellation tests. No live probing is performed.

use std::net::Ipv4Addr;

use netcontrol_net::arp::{ArpOperation, ArpPacket};
use netcontrol_net::discovery::{
    build_request_frames, plan_targets, AuthorizedNetwork, Discovery, DEFAULT_HOST_CAP,
};
use netcontrol_net::error::CancelToken;
use netcontrol_net::interfaces::{select_ipv4, RawIpv4Interface};

const LOCAL_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

// ── Discovery target planning ──────────────────────────────────────

#[test]
fn plan_targets_covers_usable_hosts_excluding_self_and_gateway() {
    let local = Ipv4Addr::new(192, 168, 1, 42);
    let mask = Ipv4Addr::new(255, 255, 255, 0); // /24
    let router = Ipv4Addr::new(192, 168, 1, 1);

    let targets = plan_targets(local, mask, Some(router), DEFAULT_HOST_CAP);

    // /24 has 254 usable hosts; minus self and gateway = 252.
    assert_eq!(targets.len(), 252);
    assert_eq!(targets.first(), Some(&Ipv4Addr::new(192, 168, 1, 2)));
    assert_eq!(targets.last(), Some(&Ipv4Addr::new(192, 168, 1, 254)));
    assert!(!targets.contains(&local));
    assert!(!targets.contains(&router));
    // Network and broadcast addresses are excluded.
    assert!(!targets.contains(&Ipv4Addr::new(192, 168, 1, 0)));
    assert!(!targets.contains(&Ipv4Addr::new(192, 168, 1, 255)));
}

#[test]
fn plan_targets_respects_host_cap() {
    let local = Ipv4Addr::new(10, 0, 0, 5);
    let mask = Ipv4Addr::new(255, 255, 0, 0); // /16, 65534 usable
    let targets = plan_targets(local, mask, None, 1024);
    // Capped at 1024 offsets; the local host (10.0.0.5) falls inside that window
    // and is skipped, as in the C# DiscoveryLoop.
    assert_eq!(targets.len(), 1023);
    assert!(!targets.contains(&local));
    assert_eq!(targets.first(), Some(&Ipv4Addr::new(10, 0, 0, 1)));
}

#[test]
fn build_request_frames_are_wellformed_requests() {
    let targets = [Ipv4Addr::new(192, 168, 1, 2), Ipv4Addr::new(192, 168, 1, 3)];
    let frames = build_request_frames(LOCAL_MAC, Ipv4Addr::new(192, 168, 1, 42), &targets);

    assert_eq!(frames.len(), 2);
    for (frame, target) in frames.iter().zip(targets.iter()) {
        let (_eth, arp) = ArpPacket::parse_frame(frame).expect("valid frame");
        assert_eq!(arp.op, ArpOperation::Request);
        assert_eq!(arp.sender_mac, LOCAL_MAC);
        assert_eq!(arp.target_ip, *target);
    }
}

// ── Authorization gating (active discovery disabled by default) ────

#[test]
fn discovery_is_disabled_by_default() {
    let d = Discovery::new();
    assert!(!d.is_enabled());
    assert!(!d.is_authorized_for(Ipv4Addr::new(192, 168, 1, 42)));

    let err = d
        .authorized_targets(
            Ipv4Addr::new(192, 168, 1, 42),
            Ipv4Addr::new(255, 255, 255, 0),
            None,
            DEFAULT_HOST_CAP,
        )
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        netcontrol_net::NetError::NotAuthorized.to_string()
    );
}

#[test]
fn authorized_discovery_plans_only_for_matching_subnet() {
    let mut d = Discovery::new();
    d.authorize(AuthorizedNetwork::new(
        Ipv4Addr::new(192, 168, 1, 0),
        Ipv4Addr::new(255, 255, 255, 0),
    ));
    assert!(d.is_enabled());
    assert!(d.is_authorized_for(Ipv4Addr::new(192, 168, 1, 42)));
    assert!(!d.is_authorized_for(Ipv4Addr::new(10, 0, 0, 5)));

    // Authorized subnet -> planning succeeds.
    let ok = d.authorized_targets(
        Ipv4Addr::new(192, 168, 1, 42),
        Ipv4Addr::new(255, 255, 255, 0),
        Some(Ipv4Addr::new(192, 168, 1, 1)),
        DEFAULT_HOST_CAP,
    );
    assert!(ok.is_ok());

    // A different subnet is refused even though an authorization exists.
    let refused = d.authorized_targets(
        Ipv4Addr::new(10, 0, 0, 5),
        Ipv4Addr::new(255, 255, 0, 0),
        None,
        DEFAULT_HOST_CAP,
    );
    assert!(refused.is_err());

    // Revoking disables it again.
    d.revoke();
    assert!(!d.is_enabled());
}

#[test]
fn authorized_network_membership() {
    let net = AuthorizedNetwork::new(
        Ipv4Addr::new(192, 168, 1, 123),
        Ipv4Addr::new(255, 255, 255, 0),
    );
    assert_eq!(net.network, Ipv4Addr::new(192, 168, 1, 0));
    assert!(net.contains(Ipv4Addr::new(192, 168, 1, 1)));
    assert!(net.contains(Ipv4Addr::new(192, 168, 1, 254)));
    assert!(!net.contains(Ipv4Addr::new(192, 168, 2, 1)));
}

// ── Interface selection (pure transform) ───────────────────────────

#[test]
fn select_ipv4_dedups_by_name_and_attaches_mac() {
    let raw = vec![
        RawIpv4Interface {
            name: "eth0".into(),
            adapter_id: None,
            ipv4: Ipv4Addr::new(192, 168, 1, 42),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            is_loopback: false,
        },
        // Second IPv4 on the same interface is dropped (first wins).
        RawIpv4Interface {
            name: "eth0".into(),
            adapter_id: None,
            ipv4: Ipv4Addr::new(192, 168, 1, 43),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            is_loopback: false,
        },
        RawIpv4Interface {
            name: "lo".into(),
            adapter_id: None,
            ipv4: Ipv4Addr::new(127, 0, 0, 1),
            netmask: Ipv4Addr::new(255, 0, 0, 0),
            is_loopback: true,
        },
    ];

    let macs = |name: &str| match name {
        "eth0" => Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        _ => None,
    };

    let out = select_ipv4(raw, macs);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].name, "eth0");
    assert_eq!(out[0].ipv4, Ipv4Addr::new(192, 168, 1, 42));
    assert_eq!(out[0].mac, Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
    assert!(!out[0].is_loopback);
    assert_eq!(out[1].name, "lo");
    assert!(out[1].is_loopback);
    assert_eq!(out[1].mac, None);
}

// ── Cancellation token ─────────────────────────────────────────────

#[test]
fn cancel_token_signals_across_clones() {
    let token = CancelToken::new();
    let clone = token.clone();
    assert!(!token.is_cancelled());
    assert!(!clone.is_cancelled());

    token.cancel();
    assert!(token.is_cancelled());
    assert!(clone.is_cancelled(), "cancellation is shared across clones");
}
