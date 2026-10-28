//! Thread-safe device tracking.
//!
//! Port of the C# `PcList`. It owns the set of discovered [`Pc`] devices,
//! keyed by IPv4 address, and provides the same add/update/query semantics:
//! adding a device with a known IP updates the existing entry (MAC, gateway,
//! and local-host flags) in place instead of inserting a duplicate.
//!
//! The original's device-added/removed callbacks and fire-and-forget
//! identification hooks were UI/service wiring; here tracking is kept pure and
//! callback-free, and callers react to the [`AddOutcome`] returned by
//! [`PcList::add_device`].

use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::pc::Pc;

/// Result of [`PcList::add_device`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddOutcome {
    /// A new device was inserted.
    Added,
    /// An existing device (same IP) was updated in place.
    Updated,
    /// The device was rejected (no IP address).
    Rejected,
}

impl AddOutcome {
    /// True only when a brand-new device was inserted (mirrors the C#
    /// `AddDevice` boolean return used for "newly detected" logging).
    pub fn is_new(self) -> bool {
        matches!(self, AddOutcome::Added)
    }
}

struct Entry {
    pc: Pc,
    last_seen: Instant,
}

/// A thread-safe, IP-keyed collection of discovered devices.
#[derive(Default)]
pub struct PcList {
    inner: Mutex<Vec<Entry>>,
}

impl PcList {
    pub fn new() -> Self {
        PcList {
            inner: Mutex::new(Vec::new()),
        }
    }

    /// Adds a device, or updates the existing entry with the same IP.
    ///
    /// Mirrors `PcList.AddDevice`: a null/absent IP is rejected; a matching IP
    /// refreshes the last-seen timestamp, adopts a changed MAC, and promotes
    /// the gateway / local-host flags (never clearing them).
    pub fn add_device(&self, pc: Pc) -> AddOutcome {
        let ip = match pc.ip {
            Some(ip) => ip,
            None => return AddOutcome::Rejected,
        };

        let mut guard = self.inner.lock().unwrap();
        for entry in guard.iter_mut() {
            if entry.pc.ip == Some(ip) {
                entry.last_seen = Instant::now();
                if let Some(mac) = pc.mac {
                    if entry.pc.mac != Some(mac) {
                        entry.pc.mac = Some(mac);
                    }
                }
                if pc.is_gateway && !entry.pc.is_gateway {
                    entry.pc.is_gateway = true;
                }
                if pc.is_local_pc && !entry.pc.is_local_pc {
                    entry.pc.is_local_pc = true;
                }
                return AddOutcome::Updated;
            }
        }

        guard.push(Entry {
            pc,
            last_seen: Instant::now(),
        });
        AddOutcome::Added
    }

    /// Number of tracked devices.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }

    pub fn contains_ip(&self, ip: Ipv4Addr) -> bool {
        self.inner
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.pc.ip == Some(ip))
    }

    /// Removes the device with the given IP. Mirrors `PcList.RemoveDevice`.
    pub fn remove_device_by_ip(&self, ip: Ipv4Addr) -> bool {
        let mut guard = self.inner.lock().unwrap();
        if let Some(pos) = guard.iter().position(|e| e.pc.ip == Some(ip)) {
            guard.remove(pos);
            true
        } else {
            false
        }
    }

    /// IP of the first gateway device. Mirrors `PcList.GetRouter`.
    pub fn router_ip(&self) -> Option<Ipv4Addr> {
        self.inner
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.pc.is_gateway)
            .and_then(|e| e.pc.ip)
    }

    /// IP of the local host device. Mirrors `PcList.GetLocalPC`.
    pub fn local_ip(&self) -> Option<Ipv4Addr> {
        self.inner
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.pc.is_local_pc)
            .and_then(|e| e.pc.ip)
    }

    /// MAC for a given IP. Mirrors `PcList.GetDeviceByIp` (MAC projection).
    pub fn mac_for_ip(&self, ip: Ipv4Addr) -> Option<[u8; 6]> {
        self.inner
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.pc.ip == Some(ip))
            .and_then(|e| e.pc.mac)
    }

    /// IP for a given MAC. Mirrors `PcList.GetDeviceByMac` (IP projection).
    pub fn ip_for_mac(&self, mac: [u8; 6]) -> Option<Ipv4Addr> {
        self.inner
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.pc.mac == Some(mac))
            .and_then(|e| e.pc.ip)
    }

    /// When the device with this IP was last observed.
    pub fn last_seen_for_ip(&self, ip: Ipv4Addr) -> Option<Instant> {
        self.inner
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.pc.ip == Some(ip))
            .map(|e| e.last_seen)
    }

    /// Zeroes every device's byte accumulators. Mirrors `PcList.ResetAllPacketCounts`.
    pub fn reset_all_byte_counts(&self) {
        for entry in self.inner.lock().unwrap().iter() {
            entry.pc.set_bytes_received(0);
            entry.pc.set_bytes_sent(0);
        }
    }

    /// Removes devices not seen within `older_than`, returning how many were
    /// dropped. (Tracking helper; the original pruned via explicit removal.)
    pub fn remove_stale(&self, older_than: Duration) -> usize {
        let mut guard = self.inner.lock().unwrap();
        let before = guard.len();
        let now = Instant::now();
        guard.retain(|e| now.duration_since(e.last_seen) < older_than);
        before - guard.len()
    }

    /// Clears all tracked devices. Mirrors `PcList.Clear`.
    pub fn clear(&self) {
        self.inner.lock().unwrap().clear();
    }

    /// Projects each tracked device through `f`, returning the collected values.
    /// A snapshot-style accessor that avoids exposing internal locking.
    pub fn map_devices<T>(&self, f: impl Fn(&Pc) -> T) -> Vec<T> {
        self.inner
            .lock()
            .unwrap()
            .iter()
            .map(|e| f(&e.pc))
            .collect()
    }

    /// Runs `f` against the mutable device with the given IP (if present),
    /// returning its result. Used to apply device identification (vendor,
    /// hostname, category) to a tracked device in place.
    ///
    /// Note: `f` runs while the list lock is held, so a live identification that
    /// performs network I/O should be run on a detached `Pc` and the result
    /// merged, rather than probing inside this callback.
    pub fn update_device_by_ip<R>(&self, ip: Ipv4Addr, f: impl FnOnce(&mut Pc) -> R) -> Option<R> {
        let mut guard = self.inner.lock().unwrap();
        guard
            .iter_mut()
            .find(|e| e.pc.ip == Some(ip))
            .map(|e| f(&mut e.pc))
    }
}
