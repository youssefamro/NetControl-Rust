//! Passive traffic monitoring: IPv4 frame classification, per-device byte
//! accounting, and smoothed rate updates.
//!
//! Ports `CArp.TrafficMonitorLoop`. The byte offsets and constants were
//! confirmed against the compiled assembly with REA:
//!
//! - IPv4 frames only: `raw[12] == 0x08 && raw[13] == 0x00`, minimum length 34;
//! - source IP at `raw[26..30]`, destination IP at `raw[30..34]`;
//! - a source match credits the device's **upload**, a destination match its
//!   **download**;
//! - rate = `bytes / 1024 / elapsed_seconds`, smoothed with the EMA (α = 0.65)
//!   from [`netcontrol_core::throttling`].
//!
//! The classification and per-cycle aggregation are pure and fully tested with
//! synthetic frames. The live capture loop that feeds them is behind the
//! off-by-default `live-capture` feature. This is read-only monitoring — no
//! packet is transmitted, dropped, delayed, or altered.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use netcontrol_core::throttling::{bytes_to_kbps, ema_step};
use netcontrol_core::PcList;

use crate::ethernet::ETHERTYPE_IPV4;

/// Minimum frame length to classify (Ethernet header + IPv4 addresses).
pub const MIN_FRAME_LEN: usize = 34;
/// Offset of the source IPv4 address within an Ethernet frame.
pub const SRC_IP_OFFSET: usize = 26;
/// Offset of the destination IPv4 address within an Ethernet frame.
pub const DST_IP_OFFSET: usize = 30;
/// The original per-cycle capture window (1000 ms).
pub const CAPTURE_WINDOW: Duration = Duration::from_millis(1000);

/// Classified addressing info for one IPv4 frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameInfo {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    /// Full frame size in bytes (as the original counted `raw.Length`).
    pub size: usize,
}

/// Classifies an Ethernet frame as IPv4, extracting source/destination and size.
///
/// Returns `None` for frames shorter than [`MIN_FRAME_LEN`] or whose EtherType
/// is not IPv4, matching the guards in `TrafficMonitorLoop`.
pub fn classify_ipv4_frame(frame: &[u8]) -> Option<FrameInfo> {
    if frame.len() < MIN_FRAME_LEN {
        return None;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != ETHERTYPE_IPV4 {
        return None;
    }
    let src_ip = Ipv4Addr::new(
        frame[SRC_IP_OFFSET],
        frame[SRC_IP_OFFSET + 1],
        frame[SRC_IP_OFFSET + 2],
        frame[SRC_IP_OFFSET + 3],
    );
    let dst_ip = Ipv4Addr::new(
        frame[DST_IP_OFFSET],
        frame[DST_IP_OFFSET + 1],
        frame[DST_IP_OFFSET + 2],
        frame[DST_IP_OFFSET + 3],
    );
    Some(FrameInfo {
        src_ip,
        dst_ip,
        size: frame.len(),
    })
}

/// Per-cycle byte accumulation for a fixed set of tracked devices.
///
/// Seed it with the devices present at the start of a cycle, feed it the
/// captured frames, then [`apply`](CycleStats::apply) the smoothed rates to the
/// list. Devices that saw no traffic are still processed (their rate decays),
/// mirroring the original's "iterate every device each cycle" behaviour.
#[derive(Debug, Default, Clone)]
pub struct CycleStats {
    /// ip -> (download/received bytes, upload/sent bytes)
    per_ip: HashMap<Ipv4Addr, (i64, i64)>,
}

impl CycleStats {
    /// Creates a cycle seeded with the given device IPs at zero bytes.
    pub fn seeded(ips: impl IntoIterator<Item = Ipv4Addr>) -> Self {
        CycleStats {
            per_ip: ips.into_iter().map(|ip| (ip, (0i64, 0i64))).collect(),
        }
    }

    /// Records a captured frame, crediting upload to the source device and
    /// download to the destination device (only for seeded/tracked IPs).
    ///
    /// Returns `true` if the frame was attributed to at least one device.
    pub fn record(&mut self, frame: &[u8]) -> bool {
        let info = match classify_ipv4_frame(frame) {
            Some(i) => i,
            None => return false,
        };
        let size = info.size as i64;
        let mut counted = false;
        if let Some(entry) = self.per_ip.get_mut(&info.src_ip) {
            entry.1 += size; // upload (device is the sender)
            counted = true;
        }
        if let Some(entry) = self.per_ip.get_mut(&info.dst_ip) {
            entry.0 += size; // download (device is the receiver)
            counted = true;
        }
        counted
    }

    /// Directly adds download/upload byte totals for a tracked IP, bypassing
    /// frame classification. Intended for feeding pre-aggregated counts (e.g. a
    /// demonstration data source) through the same rate/EMA pipeline. Ignored
    /// for IPs not in this cycle.
    pub fn add_bytes(&mut self, ip: Ipv4Addr, download: i64, upload: i64) {
        if let Some(entry) = self.per_ip.get_mut(&ip) {
            entry.0 += download;
            entry.1 += upload;
        }
    }

    /// The `(download_bytes, upload_bytes)` recorded for an IP this cycle.
    pub fn bytes_for(&self, ip: Ipv4Addr) -> Option<(i64, i64)> {
        self.per_ip.get(&ip).copied()
    }

    /// Number of tracked IPs in this cycle.
    pub fn len(&self) -> usize {
        self.per_ip.len()
    }

    pub fn is_empty(&self) -> bool {
        self.per_ip.is_empty()
    }

    /// Applies this cycle's byte totals to the devices in `list`: stores the
    /// cycle byte counts, computes measured KB/s over `elapsed`, smooths with
    /// the EMA factor `alpha`, and updates each device's transfer rates.
    ///
    /// Faithful port of the rate-update loop in `TrafficMonitorLoop`.
    pub fn apply(&self, list: &PcList, elapsed: Duration, alpha: f64) {
        let secs = elapsed.as_secs_f64();
        for (&ip, &(down_bytes, up_bytes)) in &self.per_ip {
            list.update_device_by_ip(ip, |pc| {
                pc.set_bytes_received(down_bytes);
                pc.set_bytes_sent(up_bytes);

                let prev_down = pc.download_speed_kbps();
                let prev_up = pc.upload_speed_kbps();

                let measured_down = bytes_to_kbps(down_bytes, secs);
                let measured_up = bytes_to_kbps(up_bytes, secs);

                let smoothed_down = ema_step(measured_down, prev_down, down_bytes, alpha);
                let smoothed_up = ema_step(measured_up, prev_up, up_bytes, alpha);

                pc.update_transfer_rates(smoothed_down, smoothed_up);
            });
        }
    }
}

// ── Live capture backend (opt-in, off by default) ──────────────────

#[cfg(feature = "live-capture")]
pub use live::TrafficMonitor;

#[cfg(feature = "live-capture")]
mod live {
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::Instant;

    use netcontrol_core::throttling::TRAFFIC_EMA_ALPHA;
    use netcontrol_core::PcList;

    use super::{CycleStats, CAPTURE_WINDOW};
    use crate::capture::{self, CaptureDevice, CaptureHealth};
    use crate::error::{CancelToken, NetError};

    /// Consecutive read errors tolerated before declaring the interface failed.
    const MAX_CONSECUTIVE_ERRORS: u32 = 50;

    /// A passive, read-only per-device traffic monitor on a background thread.
    ///
    /// Each ~1s cycle it snapshots the tracked device IPs, accumulates IPv4
    /// bytes per device, and writes smoothed rates back to the shared
    /// [`PcList`]. It never transmits. Dropping it (or [`stop`](TrafficMonitor::stop))
    /// cancels the loop and joins the thread.
    pub struct TrafficMonitor {
        cancel: CancelToken,
        health: Arc<CaptureHealth>,
        handle: Option<JoinHandle<()>>,
    }

    impl TrafficMonitor {
        /// Starts monitoring IPv4 traffic on the resolved capture `device`,
        /// updating `list`.
        pub fn start(
            device: &CaptureDevice,
            list: Arc<PcList>,
        ) -> Result<TrafficMonitor, NetError> {
            let mut rx = capture::open_receiver(device)?;

            let cancel = CancelToken::new();
            let health = Arc::new(CaptureHealth::default());
            let loop_cancel = cancel.clone();
            let loop_health = health.clone();

            let handle = thread::Builder::new()
                .name("traffic-monitor".into())
                .spawn(move || {
                    while !loop_cancel.is_cancelled() {
                        // Snapshot tracked IPs for this cycle.
                        let ips: Vec<_> =
                            list.map_devices(|p| p.ip).into_iter().flatten().collect();
                        if ips.is_empty() {
                            if sleep_cancellable(&loop_cancel, CAPTURE_WINDOW) {
                                break;
                            }
                            continue;
                        }

                        let mut stats = CycleStats::seeded(ips);
                        let start = Instant::now();
                        let mut errors = 0u32;

                        while start.elapsed() < CAPTURE_WINDOW && !loop_cancel.is_cancelled() {
                            match rx.next() {
                                Ok(frame) => {
                                    errors = 0;
                                    stats.record(frame);
                                }
                                Err(e) if capture::is_idle_timeout(&e) => {}
                                Err(e) => {
                                    errors += 1;
                                    if errors >= MAX_CONSECUTIVE_ERRORS {
                                        loop_health.fail(format!("traffic monitor stopped: {e}"));
                                        return;
                                    }
                                }
                            }
                        }

                        let elapsed = start.elapsed();
                        stats.apply(&list, elapsed, TRAFFIC_EMA_ALPHA);
                    }
                })
                .map_err(NetError::Io)?;

            Ok(TrafficMonitor {
                cancel,
                health,
                handle: Some(handle),
            })
        }

        /// Whether the monitor stopped because the interface failed.
        pub fn has_failed(&self) -> bool {
            self.health.has_failed()
        }

        /// The terminal read error, if the monitor failed.
        pub fn last_error(&self) -> Option<String> {
            self.health.last_error()
        }

        /// Signals the loop to stop and joins the background thread.
        pub fn stop(mut self) {
            self.shutdown();
        }

        fn shutdown(&mut self) {
            self.cancel.cancel();
            if let Some(handle) = self.handle.take() {
                capture::join_with_grace(handle, capture::STOP_GRACE);
            }
        }
    }

    impl Drop for TrafficMonitor {
        fn drop(&mut self) {
            self.shutdown();
        }
    }

    /// Sleeps up to `dur` in small slices, returning `true` if cancelled.
    fn sleep_cancellable(cancel: &CancelToken, dur: std::time::Duration) -> bool {
        let start = Instant::now();
        while start.elapsed() < dur {
            if cancel.is_cancelled() {
                return true;
            }
            thread::sleep(std::time::Duration::from_millis(50));
        }
        cancel.is_cancelled()
    }
}
