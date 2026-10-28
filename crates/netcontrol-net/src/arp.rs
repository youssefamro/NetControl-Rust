//! ARP (Address Resolution Protocol, IPv4-over-Ethernet) parsing and building.
//!
//! The frame construction mirrors `CArp.BuildArpPacket` exactly. The REA CIL
//! constant stream for that method —
//! `newarr 42; copy(0,0,6); copy(0,6,6); [12]=8 [13]=6 [14]=0 [15]=1 [16]=8
//! [17]=0 [18]=6 [19]=4 [20]=0 [21]=op; copy(22,6); copy(28,4); copy(32,6);
//! copy(38,4)` — is reproduced field-for-field by [`build_frame`].
//!
//! Only request frames are produced for discovery ([`build_request`]).
//! [`build_frame`] is a generic serializer kept for golden-vector parity; there
//! is **no** ARP-reply transmission, poisoning, or redirection in this crate.

use std::net::Ipv4Addr;

use crate::ethernet::{EthernetHeader, BROADCAST_MAC, ETHERTYPE_ARP, ETH_HEADER_LEN};

/// ARP hardware type for Ethernet.
pub const ARP_HTYPE_ETHERNET: u16 = 1;
/// ARP protocol type for IPv4.
pub const ARP_PTYPE_IPV4: u16 = 0x0800;
/// ARP hardware address length (MAC = 6).
pub const ARP_HLEN: u8 = 6;
/// ARP protocol address length (IPv4 = 4).
pub const ARP_PLEN: u8 = 4;

/// Length of the ARP payload (after the Ethernet header).
pub const ARP_PAYLOAD_LEN: usize = 28;
/// Total length of an Ethernet + ARP frame (`14 + 28`).
pub const ARP_FRAME_LEN: usize = 42;

/// ARP operation code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOperation {
    Request,
    Reply,
    Other(u16),
}

impl ArpOperation {
    pub fn from_u16(v: u16) -> Self {
        match v {
            1 => ArpOperation::Request,
            2 => ArpOperation::Reply,
            o => ArpOperation::Other(o),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            ArpOperation::Request => 1,
            ArpOperation::Reply => 2,
            ArpOperation::Other(o) => o,
        }
    }

    /// Whether this is a learnable op (request or reply), matching the C#
    /// listener's `rawPacket[21] == 1 || rawPacket[21] == 2` test.
    pub fn is_learnable(self) -> bool {
        matches!(self, ArpOperation::Request | ArpOperation::Reply)
    }
}

/// A parsed ARP packet (IPv4-over-Ethernet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPacket {
    pub htype: u16,
    pub ptype: u16,
    pub hlen: u8,
    pub plen: u8,
    pub op: ArpOperation,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

impl ArpPacket {
    /// Parses an ARP payload (the bytes after the Ethernet header). Returns
    /// `None` if shorter than [`ARP_PAYLOAD_LEN`].
    pub fn parse(payload: &[u8]) -> Option<ArpPacket> {
        if payload.len() < ARP_PAYLOAD_LEN {
            return None;
        }
        let htype = u16::from_be_bytes([payload[0], payload[1]]);
        let ptype = u16::from_be_bytes([payload[2], payload[3]]);
        let hlen = payload[4];
        let plen = payload[5];
        let op = ArpOperation::from_u16(u16::from_be_bytes([payload[6], payload[7]]));
        let mut sender_mac = [0u8; 6];
        sender_mac.copy_from_slice(&payload[8..14]);
        let sender_ip = Ipv4Addr::new(payload[14], payload[15], payload[16], payload[17]);
        let mut target_mac = [0u8; 6];
        target_mac.copy_from_slice(&payload[18..24]);
        let target_ip = Ipv4Addr::new(payload[24], payload[25], payload[26], payload[27]);
        Some(ArpPacket {
            htype,
            ptype,
            hlen,
            plen,
            op,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        })
    }

    /// Parses a full Ethernet frame, returning the header and ARP packet only
    /// when the EtherType is ARP and the payload is well-formed.
    pub fn parse_frame(frame: &[u8]) -> Option<(EthernetHeader, ArpPacket)> {
        let (eth, payload) = EthernetHeader::parse(frame)?;
        if eth.ethertype != ETHERTYPE_ARP {
            return None;
        }
        let arp = ArpPacket::parse(payload)?;
        Some((eth, arp))
    }
}

/// Builds a complete 42-byte Ethernet + ARP frame.
///
/// Field-for-field port of `CArp.BuildArpPacket`
/// `(eth_dst, eth_src, op, sha, spa, tha, tpa)`.
pub fn build_frame(
    eth_dst: [u8; 6],
    eth_src: [u8; 6],
    op: ArpOperation,
    sender_mac: [u8; 6],
    sender_ip: Ipv4Addr,
    target_mac: [u8; 6],
    target_ip: Ipv4Addr,
) -> [u8; ARP_FRAME_LEN] {
    let mut p = [0u8; ARP_FRAME_LEN];

    // Ethernet header.
    EthernetHeader {
        dst: eth_dst,
        src: eth_src,
        ethertype: ETHERTYPE_ARP,
    }
    .write_to(&mut p);

    // ARP fixed header.
    p[14..16].copy_from_slice(&ARP_HTYPE_ETHERNET.to_be_bytes()); // 00 01
    p[16..18].copy_from_slice(&ARP_PTYPE_IPV4.to_be_bytes()); // 08 00
    p[18] = ARP_HLEN; // 06
    p[19] = ARP_PLEN; // 04
    p[20..22].copy_from_slice(&op.to_u16().to_be_bytes()); // 00 op

    // ARP addresses.
    p[22..28].copy_from_slice(&sender_mac);
    p[28..32].copy_from_slice(&sender_ip.octets());
    p[32..38].copy_from_slice(&target_mac);
    p[38..42].copy_from_slice(&target_ip.octets());

    p
}

/// Builds a broadcast ARP **request** "who-has `target_ip`?" from this host.
///
/// Mirrors `CArp.SendArpRequest`: destination is broadcast, sender hardware /
/// protocol addresses are the local host's, and the target hardware address is
/// left zeroed.
pub fn build_request(
    local_mac: [u8; 6],
    local_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> [u8; ARP_FRAME_LEN] {
    build_frame(
        BROADCAST_MAC,
        local_mac,
        ArpOperation::Request,
        local_mac,
        local_ip,
        [0u8; 6],
        target_ip,
    )
}

/// Offset of the ARP opcode's low byte within a full frame (`21`), as read by
/// the original listener (`rawPacket[21]`).
pub const FRAME_OPCODE_LOW_OFFSET: usize = ETH_HEADER_LEN + 7;
