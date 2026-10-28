//! Bandwidth statistics: EMA smoothing and a pure in-memory token-bucket shaper.
//!
//! This module is computation-only. It decides, in memory, whether a byte
//! budget is available — it does **not** capture, drop, delay, or transmit any
//! packet. The OS-level shapers from the C# project (`LinuxTcThrottler`,
//! `MacDummynetThrottler`) are deliberately out of scope for this phase; only
//! the platform-independent `TokenBucketThrottler` logic is ported.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant;

/// EMA smoothing factor used by the traffic monitor in the original project.
pub const TRAFFIC_EMA_ALPHA: f64 = 0.65;

/// Applies one cycle of exponential-moving-average smoothing to a measured rate.
///
/// Reproduces the per-device smoothing in `CArp.TrafficMonitorLoop`:
/// - when `bytes == 0`, the previous rate decays by `(1 - alpha)` and snaps to
///   `0.0` once it drops below `0.1`;
/// - otherwise the measured rate is blended with the previous rate.
pub fn ema_step(measured_kbps: f64, previous_kbps: f64, bytes: i64, alpha: f64) -> f64 {
    if bytes == 0 {
        let decayed = (1.0 - alpha) * previous_kbps;
        if decayed < 0.1 {
            0.0
        } else {
            decayed
        }
    } else {
        (alpha * measured_kbps) + ((1.0 - alpha) * previous_kbps)
    }
}

/// Converts a byte count observed over `elapsed_seconds` into a KB/s rate,
/// matching the arithmetic in `CArp.TrafficMonitorLoop`.
pub fn bytes_to_kbps(bytes: i64, elapsed_seconds: f64) -> f64 {
    let secs = if elapsed_seconds <= 0.001 {
        1.0
    } else {
        elapsed_seconds
    };
    (bytes as f64 / 1024.0) / secs
}

/// A single-IP token bucket with explicit, injectable timing.
///
/// Port of the private `TokenBucket` in `TokenBucketThrottler`, but with the
/// clock supplied by the caller (`elapsed_secs`) so the refill/consume math is
/// deterministic and unit-testable. Refills continuously at `rate_bytes_per_sec`
/// up to `capacity`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TokenBucket {
    rate_bytes_per_sec: f64,
    capacity: f64,
    tokens: f64,
}

impl TokenBucket {
    /// Creates a full bucket with the given rate and capacity (in bytes).
    pub fn new(rate_bytes_per_sec: i64, capacity: i64) -> Self {
        TokenBucket {
            rate_bytes_per_sec: rate_bytes_per_sec as f64,
            capacity: capacity as f64,
            tokens: capacity as f64,
        }
    }

    /// Burst capacity for a rate: 1.5 s worth, floored at 4096 bytes.
    /// Mirrors `TokenBucketThrottler.SetLimit`.
    pub fn capacity_for(rate_bytes_per_sec: i64) -> i64 {
        (rate_bytes_per_sec * 3 / 2).max(4096)
    }

    /// Builds a bucket for a KB/s limit (rate = `kbps * 1024` bytes/s).
    pub fn for_kbps(limit_kbps: i32) -> Self {
        let rate = limit_kbps as i64 * 1024;
        TokenBucket::new(rate, TokenBucket::capacity_for(rate))
    }

    pub fn tokens(&self) -> f64 {
        self.tokens
    }

    pub fn rate_bytes_per_sec(&self) -> f64 {
        self.rate_bytes_per_sec
    }

    pub fn capacity(&self) -> f64 {
        self.capacity
    }

    /// Updates the rate/capacity, clamping current tokens to the new capacity.
    pub fn set_rate(&mut self, rate_bytes_per_sec: i64, capacity: i64) {
        self.rate_bytes_per_sec = rate_bytes_per_sec as f64;
        self.capacity = capacity as f64;
        if self.tokens > self.capacity {
            self.tokens = self.capacity;
        }
    }

    /// Replenishes tokens for `elapsed_secs` of elapsed time (capped at capacity).
    pub fn refill(&mut self, elapsed_secs: f64) {
        self.tokens = (self.tokens + elapsed_secs * self.rate_bytes_per_sec).min(self.capacity);
    }

    /// Refills for `elapsed_secs`, then consumes `bytes` if available.
    /// Returns whether the packet fit the budget.
    pub fn try_consume(&mut self, bytes: i64, elapsed_secs: f64) -> bool {
        self.refill(elapsed_secs);
        if self.tokens >= bytes as f64 {
            self.tokens -= bytes as f64;
            true
        } else {
            false
        }
    }
}

/// An IP-keyed bucket that tracks wall-clock time via [`Instant`] and delegates
/// the math to the pure [`TokenBucket`].
struct TimedBucket {
    bucket: TokenBucket,
    last_refill: Instant,
}

impl TimedBucket {
    fn new(rate_bytes_per_sec: i64, capacity: i64) -> Self {
        TimedBucket {
            bucket: TokenBucket::new(rate_bytes_per_sec, capacity),
            last_refill: Instant::now(),
        }
    }

    fn update_rate(&mut self, rate_bytes_per_sec: i64, capacity: i64) {
        self.bucket.set_rate(rate_bytes_per_sec, capacity);
    }

    fn try_consume(&mut self, bytes: i64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        self.bucket.try_consume(bytes, elapsed)
    }
}

/// Pure managed token-bucket traffic shaper, keyed by target IP.
///
/// Port of the C# `TokenBucketThrottler` (sans `IDisposable`). It tracks a
/// budget per IP; [`allow_packet`](Self::allow_packet) reports whether a packet
/// of a given size fits the budget. It performs no I/O.
#[derive(Default)]
pub struct TokenBucketThrottler {
    interface_name: String,
    buckets: HashMap<Ipv4Addr, TimedBucket>,
}

impl TokenBucketThrottler {
    pub fn new(interface_name: impl Into<String>) -> Self {
        TokenBucketThrottler {
            interface_name: interface_name.into(),
            buckets: HashMap::new(),
        }
    }

    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }

    /// Sets (or updates) the limit for `ip` in KB/s. A limit `<= 0` removes it.
    /// Mirrors `TokenBucketThrottler.SetLimit`, including the 1.5s burst cap.
    pub fn set_limit(&mut self, ip: Ipv4Addr, limit_kbps: i32) {
        if limit_kbps <= 0 {
            self.remove_limit(ip);
            return;
        }

        let rate_bytes_per_sec = limit_kbps as i64 * 1024;
        let max_capacity = TokenBucket::capacity_for(rate_bytes_per_sec);

        self.buckets
            .entry(ip)
            .and_modify(|b| b.update_rate(rate_bytes_per_sec, max_capacity))
            .or_insert_with(|| TimedBucket::new(rate_bytes_per_sec, max_capacity));
    }

    /// Removes any active limit for `ip`. Mirrors `TokenBucketThrottler.RemoveLimit`.
    pub fn remove_limit(&mut self, ip: Ipv4Addr) {
        self.buckets.remove(&ip);
    }

    /// Returns `true` if a packet of `packet_size_bytes` may pass (budget
    /// available or IP not throttled); `false` if it exceeds the budget.
    ///
    /// Mirrors `TokenBucketThrottler.AllowPacket`. This is an in-memory decision
    /// only; no packet is actually forwarded or dropped.
    pub fn allow_packet(&mut self, ip: Ipv4Addr, packet_size_bytes: i32) -> bool {
        match self.buckets.get_mut(&ip) {
            Some(bucket) => bucket.try_consume(packet_size_bytes as i64),
            None => true,
        }
    }

    /// Clears all limits. Mirrors `TokenBucketThrottler.ResetAll`.
    pub fn reset_all(&mut self) {
        self.buckets.clear();
    }

    /// Number of IPs currently limited (test/inspection helper).
    pub fn active_limit_count(&self) -> usize {
        self.buckets.len()
    }
}
