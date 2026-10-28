//! Local network interface enumeration.
//!
//! Reads the host's interface configuration (names, IPv4 address, netmask, and
//! hardware address) via `if-addrs` + `mac_address`. This is configuration
//! inspection, **not** packet capture. The pure selection/transform step
//! ([`select_ipv4`]) is unit-tested with synthetic input so enumeration logic is
//! verified without touching the live machine.

use std::net::Ipv4Addr;

use crate::error::NetError;

/// A usable IPv4 network interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetInterface {
    /// OS display name (Windows friendly name such as `Ethernet 2`; `eth0` on Linux).
    pub name: String,
    /// Stable OS adapter identifier (Windows: the adapter GUID `{...}` that
    /// Npcap embeds in `\Device\NPF_{...}`); `None` where the OS has none.
    pub adapter_id: Option<String>,
    pub ipv4: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub mac: Option<[u8; 6]>,
    pub is_loopback: bool,
}

/// A raw IPv4 interface record prior to MAC resolution and de-duplication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawIpv4Interface {
    pub name: String,
    pub adapter_id: Option<String>,
    pub ipv4: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub is_loopback: bool,
}

/// Pure transform: de-duplicates raw records by interface name (keeping the
/// first IPv4, as the C# `LoadInterfaces` took the first IPv4 per device) and
/// attaches a MAC via `mac_lookup`. Order is preserved.
pub fn select_ipv4<F>(raw: Vec<RawIpv4Interface>, mac_lookup: F) -> Vec<NetInterface>
where
    F: Fn(&str) -> Option<[u8; 6]>,
{
    let mut seen: Vec<String> = Vec::new();
    let mut out: Vec<NetInterface> = Vec::new();
    for r in raw {
        if seen.iter().any(|n| n == &r.name) {
            continue;
        }
        seen.push(r.name.clone());
        let mac = mac_lookup(&r.name);
        out.push(NetInterface {
            name: r.name,
            adapter_id: r.adapter_id,
            ipv4: r.ipv4,
            netmask: r.netmask,
            mac,
            is_loopback: r.is_loopback,
        });
    }
    out
}

/// Enumerates the host's IPv4 interfaces.
///
/// Reads OS configuration only. Loopback interfaces are included (flagged via
/// [`NetInterface::is_loopback`]) so callers can filter as needed.
pub fn enumerate() -> Result<Vec<NetInterface>, NetError> {
    let raw: Vec<RawIpv4Interface> = if_addrs::get_if_addrs()?
        .into_iter()
        .filter_map(|iface| match iface.addr {
            if_addrs::IfAddr::V4(ref v4) => Some(RawIpv4Interface {
                is_loopback: v4.ip.is_loopback(),
                ipv4: v4.ip,
                netmask: v4.netmask,
                adapter_id: adapter_id(&iface),
                name: iface.name,
            }),
            if_addrs::IfAddr::V6(_) => None,
        })
        .collect();

    Ok(select_ipv4(raw, |name| {
        mac_address::mac_address_by_name(name)
            .ok()
            .flatten()
            .map(|m| m.bytes())
    }))
}

#[cfg(windows)]
fn adapter_id(iface: &if_addrs::Interface) -> Option<String> {
    let id = iface.adapter_name.trim();
    (!id.is_empty()).then(|| id.to_string())
}

#[cfg(not(windows))]
fn adapter_id(_iface: &if_addrs::Interface) -> Option<String> {
    None
}
