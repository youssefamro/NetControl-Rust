//! Golden-vector tests: Rust packet bytes vs. the C# `CArp.BuildArpPacket`
//! representation.
//!
//! The expected byte arrays are derived from the original C# layout, which was
//! independently confirmed at the CIL level with REA (the `BuildArpPacket`
//! `ldc.i4` constant stream: `newarr 42; [12]=8 [13]=6 [14]=0 [15]=1 [16]=8
//! [17]=0 [18]=6 [19]=4 [20]=0 [21]=op`, with `Array.Copy` at offsets
//! 0/6/22/28/32/38). Each test checks total length, byte ordering, header
//! fields, and address placement.

use std::net::Ipv4Addr;

use netcontrol_net::arp::{build_frame, build_request, ArpOperation, ARP_FRAME_LEN};

const LOCAL_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

#[test]
fn arp_request_matches_golden_vector() {
    // SendArpRequest(local=00:11:22:33:44:55, 192.168.1.42 -> who-has 192.168.1.1)
    let frame = build_request(
        LOCAL_MAC,
        Ipv4Addr::new(192, 168, 1, 42),
        Ipv4Addr::new(192, 168, 1, 1),
    );

    #[rustfmt::skip]
    let golden: [u8; ARP_FRAME_LEN] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // eth dst = broadcast
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // eth src = local
        0x08, 0x06,                         // ethertype ARP
        0x00, 0x01,                         // htype Ethernet
        0x08, 0x00,                         // ptype IPv4
        0x06,                               // hlen
        0x04,                               // plen
        0x00, 0x01,                         // opcode = request
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // sender mac = local
        0xC0, 0xA8, 0x01, 0x2A,             // sender ip = 192.168.1.42
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target mac = zero
        0xC0, 0xA8, 0x01, 0x01,             // target ip = 192.168.1.1
    ];

    assert_eq!(frame.len(), 42);
    assert_eq!(frame, golden);
}

#[test]
fn arp_reply_shape_matches_golden_vector() {
    // Generic build_frame with reply parameters (serialization parity only —
    // this crate never *transmits* replies).
    let frame = build_frame(
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], // eth dst (device)
        LOCAL_MAC,                            // eth src (local)
        ArpOperation::Reply,
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66], // sender mac (e.g. router)
        Ipv4Addr::new(192, 168, 1, 1),        // sender ip
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], // target mac (device)
        Ipv4Addr::new(192, 168, 1, 50),       // target ip
    );

    #[rustfmt::skip]
    let golden: [u8; ARP_FRAME_LEN] = [
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x08, 0x06,
        0x00, 0x01,
        0x08, 0x00,
        0x06,
        0x04,
        0x00, 0x02,                         // opcode = reply
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        0xC0, 0xA8, 0x01, 0x01,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0xC0, 0xA8, 0x01, 0x32,             // 192.168.1.50
    ];

    assert_eq!(frame, golden);
}

#[test]
fn header_field_offsets_and_byte_order() {
    let frame = build_request(
        LOCAL_MAC,
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(10, 0, 0, 1),
    );

    // EtherType ARP, big-endian at [12..14].
    assert_eq!(&frame[12..14], &[0x08, 0x06]);
    // Hardware type Ethernet = 1 at [14..16].
    assert_eq!(&frame[14..16], &[0x00, 0x01]);
    // Protocol type IPv4 = 0x0800 at [16..18].
    assert_eq!(&frame[16..18], &[0x08, 0x00]);
    // hlen / plen.
    assert_eq!(frame[18], 6);
    assert_eq!(frame[19], 4);
    // Opcode (low byte at offset 21, as the C# listener reads).
    assert_eq!(frame[20], 0x00);
    assert_eq!(frame[21], 0x01);
}

#[test]
fn round_trip_build_then_parse() {
    use netcontrol_net::arp::ArpPacket;

    let frame = build_request(
        LOCAL_MAC,
        Ipv4Addr::new(192, 168, 1, 42),
        Ipv4Addr::new(192, 168, 1, 254),
    );

    let (eth, arp) = ArpPacket::parse_frame(&frame).expect("valid ARP frame");
    assert_eq!(eth.src, LOCAL_MAC);
    assert_eq!(eth.dst, [0xFF; 6]);
    assert_eq!(arp.op, ArpOperation::Request);
    assert_eq!(arp.sender_mac, LOCAL_MAC);
    assert_eq!(arp.sender_ip, Ipv4Addr::new(192, 168, 1, 42));
    assert_eq!(arp.target_ip, Ipv4Addr::new(192, 168, 1, 254));
    assert_eq!(arp.htype, 1);
    assert_eq!(arp.ptype, 0x0800);
    assert_eq!(arp.hlen, 6);
    assert_eq!(arp.plen, 4);
}

#[test]
fn parse_rejects_short_and_non_arp_frames() {
    use netcontrol_net::arp::ArpPacket;
    use netcontrol_net::ethernet::ETHERTYPE_IPV4;

    // Too short.
    assert!(ArpPacket::parse_frame(&[0u8; 20]).is_none());

    // Right length but IPv4 ethertype.
    let mut frame = [0u8; ARP_FRAME_LEN];
    frame[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    assert!(ArpPacket::parse_frame(&frame).is_none());
}
