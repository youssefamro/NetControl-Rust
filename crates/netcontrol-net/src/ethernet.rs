//! Ethernet II frame header parsing and serialization.
//!
//! The byte layout is confirmed against the original C# `CArp.BuildArpPacket`
//! (REA CIL evidence: direct stores `packet[12]=8, packet[13]=6` for the ARP
//! EtherType, big-endian). Pure byte logic — no sockets.

/// EtherType for ARP (`0x0806`).
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// EtherType for IPv4 (`0x0800`).
pub const ETHERTYPE_IPV4: u16 = 0x0800;

/// Length of an Ethernet II header (6 dst + 6 src + 2 ethertype).
pub const ETH_HEADER_LEN: usize = 14;

/// The all-ones broadcast MAC address.
pub const BROADCAST_MAC: [u8; 6] = [0xFF; 6];

/// A parsed Ethernet II header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthernetHeader {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: u16,
}

impl EthernetHeader {
    /// Parses the 14-byte header, returning it together with the remaining
    /// payload slice. Returns `None` if the frame is shorter than a header.
    pub fn parse(frame: &[u8]) -> Option<(EthernetHeader, &[u8])> {
        if frame.len() < ETH_HEADER_LEN {
            return None;
        }
        let mut dst = [0u8; 6];
        let mut src = [0u8; 6];
        dst.copy_from_slice(&frame[0..6]);
        src.copy_from_slice(&frame[6..12]);
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        Some((
            EthernetHeader {
                dst,
                src,
                ethertype,
            },
            &frame[ETH_HEADER_LEN..],
        ))
    }

    /// Writes this header into the first 14 bytes of `buf`.
    ///
    /// # Panics
    /// Panics if `buf` is shorter than [`ETH_HEADER_LEN`].
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0..6].copy_from_slice(&self.dst);
        buf[6..12].copy_from_slice(&self.src);
        buf[12..14].copy_from_slice(&self.ethertype.to_be_bytes());
    }
}

/// Formats a MAC as the uppercase colon form (e.g. "AA:BB:CC:DD:EE:FF").
pub fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}
