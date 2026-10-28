//! NetBIOS Name Service node-status query (UDP 137).
//!
//! Ports the query bytes built in `ResolveNetBiosNameAsync` and the parser
//! `ParseNetBiosResponse`. Pure byte logic; no sockets.

/// UDP port for the NetBIOS Name Service.
pub const NETBIOS_PORT: u16 = 137;

/// Length of the fixed node-status (NBSTAT) wildcard query.
pub const NODE_STATUS_QUERY_LEN: usize = 50;

/// Builds the fixed NetBIOS node-status request for the wildcard name `*`
/// (encoded as `CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`), matching the original byte
/// array exactly: header (txid 0x0001, flags 0, QD=1), the 32-byte encoded
/// name, terminator, QTYPE=NBSTAT (0x0021), QCLASS=IN (0x0001).
pub fn build_node_status_query() -> [u8; NODE_STATUS_QUERY_LEN] {
    let mut q = [0u8; NODE_STATUS_QUERY_LEN];
    q[0] = 0x00;
    q[1] = 0x01; // transaction id
    q[2] = 0x00;
    q[3] = 0x00; // flags: query
    q[4] = 0x00;
    q[5] = 0x01; // questions: 1
                 // q[6..12] answer/authority/additional RRs = 0 (already zero)
    q[12] = 0x20; // name length (32)
    q[13] = 0x43; // 'C'
    q[14] = 0x4B; // 'K'
    for b in q.iter_mut().take(45).skip(15) {
        *b = 0x41; // 'A' x 30
    }
    q[45] = 0x00; // name terminator
    q[46] = 0x00;
    q[47] = 0x21; // type: NBSTAT
    q[48] = 0x00;
    q[49] = 0x01; // class: IN
    q
}

/// Parses a NetBIOS node-status response, returning the first workstation name.
///
/// Port of `ParseNetBiosResponse`: requires >= 75 bytes, skips the header and
/// the echoed question name (handling a `0xC0` compression pointer), advances
/// past type/class/ttl/rdlength, then reads the name table (18 bytes each:
/// 15-byte name + 1 suffix + 2 flags), returning the first non-group name with
/// suffix `0x00`.
pub fn parse_node_status_response(data: &[u8]) -> Option<String> {
    if data.len() < 75 {
        return None;
    }

    let mut pos = 12; // skip header

    // Skip the name field (compression pointer or full name).
    if pos < data.len() && (data[pos] & 0xC0) == 0xC0 {
        pos += 2;
    } else {
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        pos += 1; // skip null terminator
    }

    // Skip Type(2) + Class(2) + TTL(4) + RDLength(2).
    pos += 10;
    if pos >= data.len() {
        return None;
    }

    let num_names = data[pos] as usize;
    pos += 1;

    for _ in 0..num_names {
        if pos + 18 > data.len() {
            break;
        }
        let raw = &data[pos..pos + 15];
        let name = String::from_utf8_lossy(raw).trim_end().to_string();
        let suffix = data[pos + 15];
        let flags = ((data[pos + 16] as u16) << 8) | data[pos + 17] as u16;
        let is_group = (flags & 0x8000) != 0;
        pos += 18;

        if !is_group && suffix == 0x00 && !name.trim().is_empty() {
            return Some(name);
        }
    }

    None
}
