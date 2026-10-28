//! DNS message helpers for reverse-PTR hostname resolution.
//!
//! Ports `DeviceIdentifierService.BuildDnsPtrQuery`, `ParseDnsPtrResponse`,
//! `SkipDnsName`, `ReadDnsName`, and `TryParseMdnsName`. These same helpers back
//! the mDNS (UDP 5353), LLMNR (UDP 5355), and unicast reverse-DNS probes, which
//! all issue an in-addr.arpa PTR query and parse a PTR answer.
//!
//! Pure byte logic; no sockets.

use std::net::Ipv4Addr;

use crate::hostname::clean_hostname;

/// Transaction id used by the mDNS PTR probe (`0x0000`, as in the original).
pub const MDNS_TXID: u16 = 0x0000;
/// Transaction id used by the LLMNR PTR probe (`0x1337`, as in the original).
pub const LLMNR_TXID: u16 = 0x1337;

/// DNS resource-record type for PTR.
pub const DNS_TYPE_PTR: u16 = 12;
/// DNS class IN.
pub const DNS_CLASS_IN: u16 = 1;

/// Builds a reverse-DNS PTR query for `ip`'s `in-addr.arpa` name.
///
/// Faithful port of `BuildDnsPtrQuery`: header (txid, flags 0, QD=1, AN/NS/AR=0)
/// followed by the length-prefixed labels
/// `<o4>.<o3>.<o2>.<o1>.in-addr.arpa`, a null terminator, then QTYPE=PTR,
/// QCLASS=IN.
pub fn build_ptr_query(ip: Ipv4Addr, txid: u16) -> Vec<u8> {
    let o = ip.octets();
    let labels: [String; 6] = [
        o[3].to_string(),
        o[2].to_string(),
        o[1].to_string(),
        o[0].to_string(),
        "in-addr".to_string(),
        "arpa".to_string(),
    ];

    let mut b = Vec::with_capacity(32);
    b.push((txid >> 8) as u8);
    b.push((txid & 0xFF) as u8);
    b.extend_from_slice(&[
        0x00, 0x00, // flags
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
    ]);
    for label in &labels {
        b.push(label.len() as u8);
        b.extend_from_slice(label.as_bytes());
    }
    b.push(0x00); // root terminator
    b.extend_from_slice(&DNS_TYPE_PTR.to_be_bytes());
    b.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    b
}

/// Advances past a DNS name starting at `pos`, returning the position after it.
/// Port of `SkipDnsName` (stops at a root label or a compression pointer).
pub fn skip_name(data: &[u8], mut pos: usize) -> usize {
    let mut safety = 0;
    while pos < data.len() && safety < 50 {
        safety += 1;
        let len = data[pos];
        if len == 0 {
            return pos + 1;
        }
        if (len & 0xC0) == 0xC0 {
            return pos + 2;
        }
        pos += 1 + len as usize;
    }
    pos
}

/// Reads a (possibly compressed) DNS name starting at `start`, returning the
/// dotted string. Port of `ReadDnsName`, with standard compression-pointer
/// following guarded against loops.
pub fn read_name(data: &[u8], start: usize) -> String {
    let mut out = String::new();
    let mut pos = start;
    let mut safety = 0;

    while pos < data.len() && safety < 50 {
        safety += 1;
        let len = data[pos];
        if len == 0 {
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= data.len() {
                break;
            }
            let offset = (((len & 0x3F) as usize) << 8) | data[pos + 1] as usize;
            let target = read_name(data, offset);
            if !target.is_empty() {
                if !out.is_empty() {
                    out.push('.');
                }
                out.push_str(&target);
            }
            break;
        }

        pos += 1;
        let end = pos + len as usize;
        if end > data.len() {
            break;
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(&data[pos..end]));
        pos = end;
    }

    out
}

/// Parses a DNS response and returns the first PTR answer, cleaned.
///
/// Port of `ParseDnsPtrResponse`: walks the question section, then the answers;
/// for a PTR (type 12) record, reads the target name and runs it through
/// [`clean_hostname`].
pub fn parse_ptr_response(data: &[u8]) -> Option<String> {
    if data.len() < 12 {
        return None;
    }

    let qd_count = ((data[4] as usize) << 8) | data[5] as usize;
    let an_count = ((data[6] as usize) << 8) | data[7] as usize;
    if an_count == 0 {
        return None;
    }

    let mut pos = 12;
    for _ in 0..qd_count {
        if pos >= data.len() {
            break;
        }
        pos = skip_name(data, pos);
        pos += 4; // QTYPE + QCLASS
    }

    for _ in 0..an_count {
        if pos >= data.len() {
            break;
        }
        pos = skip_name(data, pos);
        if pos + 10 > data.len() {
            break;
        }
        let rtype = ((data[pos] as u16) << 8) | data[pos + 1] as u16;
        pos += 2; // type
        pos += 2; // class
        pos += 4; // ttl
        let rdlength = ((data[pos] as usize) << 8) | data[pos + 1] as usize;
        pos += 2;

        if rtype == DNS_TYPE_PTR {
            let name = read_name(data, pos);
            if !name.is_empty() {
                return clean_hostname(&name);
            }
        }
        pos += rdlength;
    }

    None
}

/// Extracts the first name from a raw mDNS packet (Ethernet frame) at
/// `dns_offset`. Port of `TryParseMdnsName`: reads length-prefixed labels
/// (stopping at a compression pointer), rejects `.arpa`, trims the service
/// suffix at `._`, strips `.local`, and maps googlecast to the cast label.
pub fn parse_mdns_frame_name(raw: &[u8], dns_offset: usize) -> Option<String> {
    if raw.len() <= dns_offset + 12 {
        return None;
    }
    let mut pos = dns_offset + 12;
    if pos >= raw.len() {
        return None;
    }

    let mut name = String::new();
    let mut safety = 0;
    while pos < raw.len() && safety < 20 {
        safety += 1;
        let label_len = raw[pos];
        if label_len == 0 {
            break;
        }
        if (label_len & 0xC0) == 0xC0 {
            break; // compression pointer: stop (as in the original)
        }
        let end = pos + 1 + label_len as usize;
        if end > raw.len() {
            break;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(&raw[pos + 1..end]));
        pos = end;
    }

    if name.is_empty() {
        return None;
    }

    crate::hostname::clean_mdns_name(&name)
}
