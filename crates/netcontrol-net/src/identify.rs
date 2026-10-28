//! Device identification orchestration.
//!
//! Ports `DeviceIdentifierService.IdentifyDeviceAsync`'s layered strategy:
//!
//! 1. **Layer 1 (instant):** OUI vendor + randomized-MAC detection
//!    (`netcontrol_core::oui`).
//! 2. **Layers 2–4 (active, gated):** concurrent DNS / NetBIOS / mDNS / SSDP /
//!    LLMNR probes, each with its own timeout, then best-hostname selection.
//! 3. **Layer 5:** device-type inference (`netcontrol_core::device_identifier`).
//!
//! Active probing is performed through a [`HostnameProber`], so the
//! orchestration (priority, fallback, cancellation) is tested deterministically
//! with synthetic responses. The real [`LiveUdpProber`] uses only `std::net`
//! (no pcap) and is never exercised by the test suite. Active probing is
//! **disabled by default** ([`Identifier::new`]); callers opt in explicitly.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use netcontrol_core::device_identifier::infer_device_type;
use netcontrol_core::oui;
use netcontrol_core::pc::RANDOMIZED_MAC_VENDOR;
use netcontrol_core::Pc;

use crate::dns::{build_ptr_query, parse_ptr_response, LLMNR_TXID, MDNS_TXID};
use crate::error::CancelToken;
use crate::hostname::select_best_hostname;
use crate::netbios::{build_node_status_query, parse_node_status_response, NETBIOS_PORT};
use crate::ssdp::{build_msearch, parse_server_name, SSDP_PORT};

/// mDNS UDP port.
pub const MDNS_PORT: u16 = 5353;
/// LLMNR UDP port.
pub const LLMNR_PORT: u16 = 5355;
/// Unicast reverse-DNS txid used by the live prober.
pub const DNS_TXID: u16 = 0x2020;

/// A hostname-discovery protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Mdns,
    NetBios,
    Ssdp,
    Llmnr,
    Dns,
}

/// Protocols in the original's selection-priority order (mDNS first, DNS last).
pub const PROTOCOL_PRIORITY: [Protocol; 5] = [
    Protocol::Mdns,
    Protocol::NetBios,
    Protocol::Ssdp,
    Protocol::Llmnr,
    Protocol::Dns,
];

/// Per-protocol timeouts, defaulting to the original constants.
#[derive(Debug, Clone, Copy)]
pub struct ProbeTimeouts {
    pub dns: Duration,
    pub netbios: Duration,
    pub ssdp: Duration,
    pub mdns: Duration,
    pub llmnr: Duration,
}

impl Default for ProbeTimeouts {
    fn default() -> Self {
        ProbeTimeouts {
            dns: Duration::from_millis(800),
            netbios: Duration::from_millis(1000),
            ssdp: Duration::from_millis(1000),
            mdns: Duration::from_millis(800),
            llmnr: Duration::from_millis(800),
        }
    }
}

/// Supplies a hostname for one protocol/target. Implementors must be `Sync` so
/// probes can run concurrently.
pub trait HostnameProber: Sync {
    fn probe(
        &self,
        protocol: Protocol,
        ip: Ipv4Addr,
        timeout: Duration,
        cancel: &CancelToken,
    ) -> Option<String>;
}

/// Device identifier. Active probing is disabled until explicitly enabled.
#[derive(Debug, Clone)]
pub struct Identifier {
    enable_active_probes: bool,
    timeouts: ProbeTimeouts,
}

impl Default for Identifier {
    fn default() -> Self {
        Identifier::new()
    }
}

impl Identifier {
    /// A new identifier with active probing **disabled**.
    pub fn new() -> Self {
        Identifier {
            enable_active_probes: false,
            timeouts: ProbeTimeouts::default(),
        }
    }

    /// Enables active probing (builder form).
    pub fn with_active_probes(mut self) -> Self {
        self.enable_active_probes = true;
        self
    }

    /// Enables or disables active probing.
    pub fn set_active_probes(&mut self, enabled: bool) {
        self.enable_active_probes = enabled;
    }

    /// Whether active probing is enabled.
    pub fn active_probes_enabled(&self) -> bool {
        self.enable_active_probes
    }

    /// The per-protocol timeouts in use.
    pub fn timeouts(&self) -> &ProbeTimeouts {
        &self.timeouts
    }

    fn timeout_for(&self, protocol: Protocol) -> Duration {
        match protocol {
            Protocol::Mdns => self.timeouts.mdns,
            Protocol::NetBios => self.timeouts.netbios,
            Protocol::Ssdp => self.timeouts.ssdp,
            Protocol::Llmnr => self.timeouts.llmnr,
            Protocol::Dns => self.timeouts.dns,
        }
    }

    /// Layer 1 only: sets the vendor from the OUI table, or the randomized-MAC
    /// marker. Mirrors the first block of `IdentifyDeviceAsync`.
    pub fn apply_oui(&self, device: &mut Pc) {
        if let Some(mac) = device.mac {
            if let Some(vendor) = oui::lookup(&mac) {
                device.vendor = Some(vendor.to_string());
            } else if oui::is_randomized_mac(&mac) {
                device.vendor = Some(RANDOMIZED_MAC_VENDOR.to_string());
            }
        }
    }

    /// Offline identification: OUI vendor (Layer 1) + device-type inference
    /// (Layer 5). No network access regardless of the active-probe setting.
    pub fn identify_offline(&self, device: &mut Pc) {
        self.apply_oui(device);
        device.device_category = infer_device_type(device);
    }

    /// Full identification. Applies OUI, then — when active probing is enabled
    /// and the device has an IP and cancellation has not been requested — runs
    /// the five protocol probes concurrently, selects the best hostname in
    /// priority order, and re-infers the device type.
    ///
    /// Faithful port of `IdentifyDeviceAsync`. The probes run through `prober`;
    /// no network I/O happens here directly.
    pub fn identify(&self, device: &mut Pc, prober: &dyn HostnameProber, cancel: &CancelToken) {
        self.apply_oui(device);

        let ip = match device.ip {
            Some(ip) if self.enable_active_probes && !cancel.is_cancelled() => ip,
            _ => {
                device.device_category = infer_device_type(device);
                return;
            }
        };

        // Probe concurrently; results are collected in PROTOCOL_PRIORITY order.
        let mut results: [Option<String>; 5] = [None, None, None, None, None];
        std::thread::scope(|scope| {
            let handles: Vec<_> = PROTOCOL_PRIORITY
                .iter()
                .map(|&protocol| {
                    let timeout = self.timeout_for(protocol);
                    scope.spawn(move || prober.probe(protocol, ip, timeout, cancel))
                })
                .collect();
            for (slot, handle) in results.iter_mut().zip(handles) {
                *slot = handle.join().unwrap_or(None);
            }
        });

        let refs: Vec<Option<&str>> = results.iter().map(|o| o.as_deref()).collect();
        if let Some(best) = select_best_hostname(&refs) {
            device.hostname = Some(best);
        }

        device.device_category = infer_device_type(device);
    }
}

/// A live hostname prober over `std::net::UdpSocket`.
///
/// Each probe unicasts a single query to the target and parses the first
/// response, bounded by the per-protocol timeout and the cancellation flag.
/// Reverse DNS requires a configured resolver (`dns_server`); when unset, the
/// DNS probe is skipped. **This type performs real network I/O and is never
/// used by the automated tests.**
#[derive(Debug, Clone, Default)]
pub struct LiveUdpProber {
    /// Optional resolver for unicast reverse-DNS PTR queries.
    pub dns_server: Option<SocketAddr>,
}

impl LiveUdpProber {
    pub fn new() -> Self {
        LiveUdpProber::default()
    }

    /// Sets the resolver used for the reverse-DNS probe.
    pub fn with_dns_server(mut self, server: SocketAddr) -> Self {
        self.dns_server = Some(server);
        self
    }
}

impl HostnameProber for LiveUdpProber {
    fn probe(
        &self,
        protocol: Protocol,
        ip: Ipv4Addr,
        timeout: Duration,
        cancel: &CancelToken,
    ) -> Option<String> {
        if cancel.is_cancelled() {
            return None;
        }
        let target = IpAddr::V4(ip);
        match protocol {
            Protocol::Mdns => {
                let resp = udp_query(
                    SocketAddr::new(target, MDNS_PORT),
                    &build_ptr_query(ip, MDNS_TXID),
                    timeout,
                    cancel,
                )?;
                parse_ptr_response(&resp)
            }
            Protocol::Llmnr => {
                let resp = udp_query(
                    SocketAddr::new(target, LLMNR_PORT),
                    &build_ptr_query(ip, LLMNR_TXID),
                    timeout,
                    cancel,
                )?;
                parse_ptr_response(&resp)
            }
            Protocol::NetBios => {
                let resp = udp_query(
                    SocketAddr::new(target, NETBIOS_PORT),
                    &build_node_status_query(),
                    timeout,
                    cancel,
                )?;
                parse_node_status_response(&resp)
            }
            Protocol::Ssdp => {
                let resp = udp_query(
                    SocketAddr::new(target, SSDP_PORT),
                    build_msearch(ip).as_bytes(),
                    timeout,
                    cancel,
                )?;
                parse_server_name(&String::from_utf8_lossy(&resp))
            }
            Protocol::Dns => {
                let server = self.dns_server?;
                let resp = udp_query(server, &build_ptr_query(ip, DNS_TXID), timeout, cancel)?;
                parse_ptr_response(&resp)
            }
        }
    }
}

/// Sends one UDP datagram and waits for a single reply, bounded by `timeout`
/// and `cancel`. Returns the response bytes, or `None` on any error/timeout.
/// The socket is closed when this returns (dropped).
fn udp_query(
    dst: SocketAddr,
    payload: &[u8],
    timeout: Duration,
    cancel: &CancelToken,
) -> Option<Vec<u8>> {
    if cancel.is_cancelled() {
        return None;
    }
    let bind_addr: SocketAddr = if dst.is_ipv4() {
        "0.0.0.0:0".parse().ok()?
    } else {
        "[::]:0".parse().ok()?
    };
    let socket = UdpSocket::bind(bind_addr).ok()?;
    socket.set_read_timeout(Some(timeout)).ok()?;
    socket.send_to(payload, dst).ok()?;
    if cancel.is_cancelled() {
        return None;
    }
    let mut buf = [0u8; 2048];
    let (n, _) = socket.recv_from(&mut buf).ok()?;
    Some(buf[..n].to_vec())
}
