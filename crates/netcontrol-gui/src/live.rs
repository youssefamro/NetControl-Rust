//! Live capture controller (compiled only with the `live-capture` feature).
//!
//! Wires the P2 passive ARP listener and the P4 traffic monitor to a shared
//! [`PcList`]. Both are read-only: they observe frames and update device state;
//! nothing is transmitted. Dropping the controller cancels and joins both
//! background threads.
//!
//! The GUI selects interfaces by their OS (friendly) name; the controller
//! resolves that once to the capture backend's device (`\Device\NPF_{GUID}` on
//! Windows) and hands the same device to both threads.

use std::sync::Arc;

use netcontrol_core::PcList;
use netcontrol_net::capture::{self, ResolvedDevice};
use netcontrol_net::listener::{ArpListener, ObserveContext};
use netcontrol_net::traffic::TrafficMonitor;
use netcontrol_net::{NetError, NetInterface};

/// Owns the live background capture threads.
pub struct CaptureController {
    listener: ArpListener,
    monitor: TrafficMonitor,
    device: ResolvedDevice,
}

impl CaptureController {
    /// Resolves `iface` to its capture device and starts passive ARP
    /// observation and traffic monitoring on it.
    pub fn start(iface: &NetInterface, list: Arc<PcList>) -> Result<Self, NetError> {
        let device = capture::resolve_live(iface)?;
        let ctx = ObserveContext {
            local_mac: iface.mac.unwrap_or([0u8; 6]),
            local_ip: Some(iface.ipv4),
            // Gateway discovery is not performed here; the router is simply
            // learned from observed ARP traffic rather than assumed.
            router_ip: None,
        };
        let listener = ArpListener::start(&device.device, list.clone(), ctx)?;
        let monitor = TrafficMonitor::start(&device.device, list)?;
        Ok(CaptureController {
            listener,
            monitor,
            device,
        })
    }

    /// The capture device in use, for diagnostics.
    pub fn device_summary(&self) -> String {
        self.device.summary()
    }

    /// The first terminal failure of either capture thread, if any.
    pub fn failure(&self) -> Option<String> {
        if self.listener.has_failed() {
            return Some(self.listener.last_error().unwrap_or_default());
        }
        if self.monitor.has_failed() {
            return Some(self.monitor.last_error().unwrap_or_default());
        }
        None
    }

    /// Stops both threads concurrently, so Stop is bounded by one grace period.
    pub fn stop(self) {
        let CaptureController {
            listener, monitor, ..
        } = self;
        std::thread::scope(|s| {
            s.spawn(|| listener.stop());
            monitor.stop();
        });
    }
}
