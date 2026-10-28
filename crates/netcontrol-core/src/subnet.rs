//! IPv4 subnet calculation utilities.
//!
//! Pure address arithmetic ported from the static helpers in the C# `CArp`
//! class. These are calculation-only functions: no sockets, no capture, no
//! packet transmission. Network operations are intentionally not part of this
//! phase.

/// Calculates the network address: `ip AND mask`.
///
/// Mirrors `CArp.GetNetworkAddress`.
pub fn network_address(ip: [u8; 4], mask: [u8; 4]) -> [u8; 4] {
    let mut result = [0u8; 4];
    for i in 0..4 {
        result[i] = ip[i] & mask[i];
    }
    result
}

/// Calculates the broadcast address: `ip OR (NOT mask)`.
///
/// Mirrors `CArp.GetBroadcastAddress`.
pub fn broadcast_address(ip: [u8; 4], mask: [u8; 4]) -> [u8; 4] {
    let mut result = [0u8; 4];
    for i in 0..4 {
        result[i] = ip[i] | !mask[i];
    }
    result
}

/// Converts a 4-byte IPv4 address to a big-endian `u32`.
///
/// Mirrors `CArp.BytesToUint`.
pub fn bytes_to_u32(bytes: [u8; 4]) -> u32 {
    ((bytes[0] as u32) << 24)
        | ((bytes[1] as u32) << 16)
        | ((bytes[2] as u32) << 8)
        | (bytes[3] as u32)
}

/// Converts a big-endian `u32` to a 4-byte IPv4 address.
///
/// Mirrors `CArp.UintToBytes`.
pub fn u32_to_bytes(value: u32) -> [u8; 4] {
    [
        (value >> 24) as u8,
        (value >> 16) as u8,
        (value >> 8) as u8,
        value as u8,
    ]
}

/// Increments an IPv4 address in place (with carry), matching `CArp.IncrementIP`.
pub fn increment_ip(ip: &mut [u8; 4]) {
    for i in (0..4).rev() {
        if ip[i] < 255 {
            ip[i] += 1;
            return;
        }
        ip[i] = 0;
    }
}

/// Number of usable host addresses in the subnet containing `ip` under `mask`,
/// capped by the original discovery limit (1024). This reproduces the host-count
/// arithmetic from `CArp.DiscoveryLoop` without performing any scanning.
pub fn host_count(ip: [u8; 4], mask: [u8; 4], cap: u32) -> u32 {
    let network = bytes_to_u32(network_address(ip, mask));
    let broadcast = bytes_to_u32(broadcast_address(ip, mask));
    let total = if broadcast > network {
        broadcast - network - 1
    } else {
        0
    };
    total.min(cap)
}
