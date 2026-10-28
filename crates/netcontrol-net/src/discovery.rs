//! Local device discovery (subnet-aware), gated behind explicit authorization.
//!
//! Ports the host-enumeration arithmetic of `CArp.DiscoveryLoop`: scan the
//! usable host range of the local subnet (network+1 .. broadcast-1), capped at
//! [`DEFAULT_HOST_CAP`], skipping the local host and the gateway.
//!
//! **Active discovery is disabled by default.** Target *planning* and request
//! *building* are pure and always available for testing, but actually *sending*
//! ARP requests requires (a) an [`AuthorizedNetwork`] that matches the local
//! subnet and (b) the `live-capture` feature. Nothing here poisons, redirects,
//! or intercepts traffic — discovery only emits standard "who-has" requests.

use std::net::Ipv4Addr;

use netcontrol_core::subnet;

use crate::arp::{build_request, ARP_FRAME_LEN};
use crate::error::NetError;

/// The original discovery host cap (`Math.Min(totalHosts, 1024)`).
pub const DEFAULT_HOST_CAP: u32 = 1024;

/// Computes the ordered list of host IPs to probe within the subnet of
/// `local_ip`/`netmask`, excluding the local host and (when known) the gateway.
///
/// Pure port of the scan-range computation in `CArp.DiscoveryLoop`.
pub fn plan_targets(
    local_ip: Ipv4Addr,
    netmask: Ipv4Addr,
    router_ip: Option<Ipv4Addr>,
    cap: u32,
) -> Vec<Ipv4Addr> {
    let ip = local_ip.octets();
    let mask = netmask.octets();
    let network = subnet::bytes_to_u32(subnet::network_address(ip, mask));
    let max_hosts = subnet::host_count(ip, mask, cap);

    let mut targets = Vec::new();
    for offset in 1..=max_hosts {
        let target = Ipv4Addr::from(subnet::u32_to_bytes(network + offset));
        if target == local_ip {
            continue;
        }
        if Some(target) == router_ip {
            continue;
        }
        targets.push(target);
    }
    targets
}

/// Builds the ARP request frames for a set of target IPs.
pub fn build_request_frames(
    local_mac: [u8; 6],
    local_ip: Ipv4Addr,
    targets: &[Ipv4Addr],
) -> Vec<[u8; ARP_FRAME_LEN]> {
    targets
        .iter()
        .map(|&t| build_request(local_mac, local_ip, t))
        .collect()
}

/// An explicitly authorized network for active discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizedNetwork {
    pub network: Ipv4Addr,
    pub mask: Ipv4Addr,
}

impl AuthorizedNetwork {
    /// Authorizes the subnet containing `any_ip` under `mask`.
    pub fn new(any_ip: Ipv4Addr, mask: Ipv4Addr) -> Self {
        let network = Ipv4Addr::from(subnet::network_address(any_ip.octets(), mask.octets()));
        AuthorizedNetwork { network, mask }
    }

    /// Whether `ip` belongs to this authorized subnet.
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        Ipv4Addr::from(subnet::network_address(ip.octets(), self.mask.octets())) == self.network
    }
}

/// Discovery controller. Disabled until a matching network is authorized.
#[derive(Debug, Default)]
pub struct Discovery {
    authorization: Option<AuthorizedNetwork>,
}

impl Discovery {
    /// A new, **disabled** discovery controller.
    pub fn new() -> Self {
        Discovery::default()
    }

    /// Authorizes active discovery for a specific network.
    pub fn authorize(&mut self, network: AuthorizedNetwork) {
        self.authorization = Some(network);
    }

    /// Revokes any authorization, disabling active discovery.
    pub fn revoke(&mut self) {
        self.authorization = None;
    }

    /// Whether active discovery is currently enabled (a network is authorized).
    pub fn is_enabled(&self) -> bool {
        self.authorization.is_some()
    }

    /// Whether `ip`'s subnet is the authorized one.
    pub fn is_authorized_for(&self, ip: Ipv4Addr) -> bool {
        self.authorization.as_ref().is_some_and(|a| a.contains(ip))
    }

    /// Returns the planned probe targets, but only when discovery is authorized
    /// for the local subnet; otherwise [`NetError::NotAuthorized`].
    pub fn authorized_targets(
        &self,
        local_ip: Ipv4Addr,
        netmask: Ipv4Addr,
        router_ip: Option<Ipv4Addr>,
        cap: u32,
    ) -> Result<Vec<Ipv4Addr>, NetError> {
        let auth = self.authorization.as_ref().ok_or(NetError::NotAuthorized)?;
        if !auth.contains(local_ip) {
            return Err(NetError::NotAuthorized);
        }
        Ok(plan_targets(local_ip, netmask, router_ip, cap))
    }

    /// Sends one discovery sweep of ARP requests on `interface_name`.
    ///
    /// Requires the `live-capture` feature and prior authorization matching the
    /// local subnet. Returns the number of requests transmitted. Respects the
    /// cancellation token between sends and cleans up the channel on return.
    #[cfg(feature = "live-capture")]
    #[allow(clippy::too_many_arguments)]
    pub fn run_once(
        &self,
        interface_name: &str,
        local_mac: [u8; 6],
        local_ip: Ipv4Addr,
        netmask: Ipv4Addr,
        router_ip: Option<Ipv4Addr>,
        cap: u32,
        cancel: &crate::error::CancelToken,
    ) -> Result<usize, NetError> {
        use pnet::datalink::{self, Channel, NetworkInterface};

        let targets = self.authorized_targets(local_ip, netmask, router_ip, cap)?;

        let iface = datalink::interfaces()
            .into_iter()
            .find(|i: &NetworkInterface| i.name == interface_name)
            .ok_or_else(|| NetError::InterfaceNotFound(interface_name.to_string()))?;

        let (mut tx, _rx) = match datalink::channel(&iface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                return Err(NetError::CaptureUnavailable(
                    "unsupported channel type".into(),
                ))
            }
            Err(e) => return Err(NetError::CaptureUnavailable(e.to_string())),
        };

        let frames = build_request_frames(local_mac, local_ip, &targets);
        let mut sent = 0usize;
        for frame in &frames {
            if cancel.is_cancelled() {
                break;
            }
            match tx.send_to(frame, None) {
                Some(Ok(())) => sent += 1,
                Some(Err(e)) => return Err(NetError::Io(e)),
                None => return Err(NetError::CaptureUnavailable("send buffer full".into())),
            }
        }
        Ok(sent)
    }
}
