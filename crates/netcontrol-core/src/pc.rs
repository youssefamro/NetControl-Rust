//! The `Pc` device model.
//!
//! Ported from the C# `PC` class. The original is a WPF/Avalonia view-model
//! (`INotifyPropertyChanged`); here we keep only the data and the derived,
//! presentation-independent computed values (labels, formatted speeds, traffic
//! state). Thread-safe byte accumulators are preserved via atomics.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicI64, Ordering};

use crate::device_type::DeviceType;

/// Marker vendor string set when a MAC is detected as locally administered.
pub const RANDOMIZED_MAC_VENDOR: &str = "Randomized MAC";

const LABEL_MAX_LEN: usize = 55;

/// A discovered network device and its derived display state.
#[derive(Debug, Default)]
pub struct Pc {
    pub ip: Option<Ipv4Addr>,
    /// 6-byte hardware address.
    pub mac: Option<[u8; 6]>,
    pub name: Option<String>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub device_category: DeviceType,

    pub is_gateway: bool,
    pub is_local_pc: bool,

    redirect: bool,
    block: bool,
    bandwidth_limit_kb: i32,

    bytes_sent: AtomicI64,
    bytes_received: AtomicI64,

    download_speed_kbps: f64,
    upload_speed_kbps: f64,
    /// Combined bindable text, e.g. "↓1.0 MB/s ↑512.0 KB/s"; defaults to "—".
    download_speed: String,
}

impl Pc {
    /// Creates an empty device, matching `new PC()` in C# (name "Unknown",
    /// combined speed text "—", category Unknown).
    pub fn new() -> Self {
        Pc {
            name: Some("Unknown".to_string()),
            download_speed: "—".to_string(),
            ..Default::default()
        }
    }

    // ── MAC formatting ──────────────────────────────────────────────

    /// Upper-case MAC with no separators, matching .NET `PhysicalAddress.ToString()`.
    fn mac_plain(&self) -> Option<String> {
        self.mac
            .map(|m| m.iter().map(|b| format!("{:02X}", b)).collect::<String>())
    }

    /// Colon-delimited MAC (e.g. "74:D8:3E:6E:1B:C6"), or "—" when absent.
    ///
    /// Mirrors `PC.MacFormatted`.
    pub fn mac_formatted(&self) -> String {
        match self.mac {
            None => "—".to_string(),
            Some(m) => m
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(":"),
        }
    }

    // ── Control flags (with the C# mutual-exclusion rules) ──────────

    pub fn redirect(&self) -> bool {
        self.redirect
    }

    /// Sets redirect. Only effective when the device `can_control`; enabling
    /// redirect clears block. Mirrors the C# `Redirect` setter.
    pub fn set_redirect(&mut self, value: bool) {
        if self.can_control() && self.redirect != value {
            self.redirect = value;
            if self.redirect && self.block {
                self.block = false;
            }
        }
    }

    pub fn block(&self) -> bool {
        self.block
    }

    /// Sets block. Only effective when the device `can_control`; enabling block
    /// clears redirect. Mirrors the C# `Block` setter.
    pub fn set_block(&mut self, value: bool) {
        if self.can_control() && self.block != value {
            self.block = value;
            if self.block && self.redirect {
                self.redirect = false;
            }
        }
    }

    pub fn bandwidth_limit_kb(&self) -> i32 {
        self.bandwidth_limit_kb
    }

    /// Sets the bandwidth limit, clamped to `>= 0`. Mirrors `PC.BandwidthLimitKb`.
    pub fn set_bandwidth_limit_kb(&mut self, value: i32) {
        self.bandwidth_limit_kb = value.max(0);
    }

    /// "Unlimited" when 0, else "<n> KB/s". Mirrors `PC.BandwidthLimitDisplay`.
    pub fn bandwidth_limit_display(&self) -> String {
        if self.bandwidth_limit_kb == 0 {
            "Unlimited".to_string()
        } else {
            format!("{} KB/s", self.bandwidth_limit_kb)
        }
    }

    pub fn has_role_badge(&self) -> bool {
        self.is_local_pc || self.is_gateway
    }

    pub fn role_badge_text(&self) -> &'static str {
        if self.is_local_pc {
            "YOU"
        } else if self.is_gateway {
            "GATEWAY"
        } else {
            ""
        }
    }

    pub fn can_control(&self) -> bool {
        !self.is_local_pc && !self.is_gateway
    }

    pub fn is_throttling_enabled(&self) -> bool {
        self.can_control() && self.redirect
    }

    // ── Byte accumulators (thread-safe) ─────────────────────────────

    pub fn bytes_sent(&self) -> i64 {
        self.bytes_sent.load(Ordering::SeqCst)
    }

    pub fn bytes_received(&self) -> i64 {
        self.bytes_received.load(Ordering::SeqCst)
    }

    pub fn set_bytes_sent(&self, value: i64) {
        self.bytes_sent.store(value, Ordering::SeqCst);
    }

    pub fn set_bytes_received(&self, value: i64) {
        self.bytes_received.store(value, Ordering::SeqCst);
    }

    pub fn add_bytes_sent(&self, count: i64) {
        self.bytes_sent.fetch_add(count, Ordering::SeqCst);
    }

    pub fn add_bytes_received(&self, count: i64) {
        self.bytes_received.fetch_add(count, Ordering::SeqCst);
    }

    /// Atomically reads and zeroes both accumulators, returning `(received, sent)`.
    ///
    /// Mirrors `PC.ResetByteAccumulators` (returns `(rx, tx)`).
    pub fn reset_byte_accumulators(&self) -> (i64, i64) {
        let rx = self.bytes_received.swap(0, Ordering::SeqCst);
        let tx = self.bytes_sent.swap(0, Ordering::SeqCst);
        (rx, tx)
    }

    // ── Smoothed rate tracking ──────────────────────────────────────

    pub fn download_speed_kbps(&self) -> f64 {
        self.download_speed_kbps
    }

    pub fn set_download_speed_kbps(&mut self, value: f64) {
        self.download_speed_kbps = value;
    }

    pub fn upload_speed_kbps(&self) -> f64 {
        self.upload_speed_kbps
    }

    pub fn set_upload_speed_kbps(&mut self, value: f64) {
        self.upload_speed_kbps = value;
    }

    pub fn download_speed(&self) -> &str {
        &self.download_speed
    }

    pub fn download_speed_formatted(&self) -> String {
        format_speed(self.download_speed_kbps)
    }

    pub fn upload_speed_formatted(&self) -> String {
        format_speed(self.upload_speed_kbps)
    }

    /// Mirrors `PC.HasActiveTraffic`.
    pub fn has_active_traffic(&self) -> bool {
        self.download_speed_kbps >= 0.1
            || self.upload_speed_kbps >= 0.1
            || (!self.download_speed.is_empty()
                && self.download_speed != "—"
                && !self.download_speed.contains("0 KB/s"))
    }

    pub fn has_active_download(&self) -> bool {
        self.download_speed_kbps >= 0.1
    }

    pub fn has_active_upload(&self) -> bool {
        self.upload_speed_kbps >= 0.1
    }

    pub fn download_traffic_brush_hex(&self) -> &'static str {
        if self.has_active_download() {
            "#3FB950"
        } else {
            "#6E7681"
        }
    }

    pub fn upload_traffic_brush_hex(&self) -> &'static str {
        if self.has_active_upload() {
            "#58A6FF"
        } else {
            "#6E7681"
        }
    }

    pub fn traffic_brush_hex(&self) -> &'static str {
        if self.has_active_traffic() {
            "#3FB950"
        } else {
            "#6E7681"
        }
    }

    /// Applies new (already-smoothed) rates and rebuilds the combined text.
    ///
    /// Mirrors `PC.UpdateTransferRates`, including the `< 0.05` snap-to-zero.
    pub fn update_transfer_rates(&mut self, download_kbps: f64, upload_kbps: f64) {
        let down = if download_kbps < 0.05 {
            0.0
        } else {
            download_kbps
        };
        let up = if upload_kbps < 0.05 { 0.0 } else { upload_kbps };

        let new_down_text = format_speed(down);
        let new_up_text = format_speed(up);

        self.download_speed_kbps = down;
        self.upload_speed_kbps = up;
        self.download_speed = format!("↓{} ↑{}", new_down_text, new_up_text);
    }

    // ── Device label ────────────────────────────────────────────────

    /// Computed display label combining type, vendor and hostname, with MAC
    /// fallback. Faithful port of `PC.DeviceLabel`.
    pub fn device_label(&self) -> String {
        if self.is_local_pc {
            let host = self.hostname.as_deref().map(str::trim).unwrap_or("");
            let local_host_name = if !host.is_empty()
                && !ends_with_ignore_case(host, ".arpa")
                && host.parse::<IpAddr>().is_err()
            {
                host.to_string()
            } else {
                machine_name()
            };
            return truncate_with_ellipsis(
                &format!("{} (Local Host)", local_host_name),
                LABEL_MAX_LEN,
            );
        }

        let type_str = if self.device_category != DeviceType::Unknown {
            Some(self.device_category.as_str().to_string())
        } else {
            None
        };

        let name: Option<String> = match self.hostname.as_deref() {
            Some(h) if !h.is_empty() && !ends_with_ignore_case(h, ".arpa") => {
                Some(h.trim().to_string())
            }
            _ => None,
        };

        let is_randomized = self.vendor.as_deref() == Some(RANDOMIZED_MAC_VENDOR);
        let vendor: Option<String> = match self.vendor.as_deref() {
            Some(v) if !v.is_empty() && !is_randomized => Some(v.trim().to_string()),
            _ => None,
        };

        let mut vendor_redundant = false;
        if let (Some(n), Some(v)) = (name.as_deref(), vendor.as_deref()) {
            if contains_ignore_case(n, v) || contains_ignore_case(v, n) {
                vendor_redundant = true;
            } else {
                let first_token = v.split([' ', ',', '-', '.', '_']).find(|t| !t.is_empty());
                if let Some(tok) = first_token {
                    if tok.len() >= 3 && contains_ignore_case(n, tok) {
                        vendor_redundant = true;
                    }
                }
            }
        }

        let raw_label = match (type_str.as_deref(), name.as_deref(), vendor.as_deref()) {
            (Some(t), Some(n), Some(v)) => {
                if vendor_redundant {
                    format!("{} — {}", t, n)
                } else {
                    format!("{} — {} ({})", t, n, v)
                }
            }
            (Some(t), Some(n), None) => format!("{} — {}", t, n),
            (Some(t), None, Some(v)) => format!("{} ({})", t, v),
            (None, Some(n), Some(v)) => {
                if vendor_redundant {
                    n.to_string()
                } else {
                    format!("{} ({})", n, v)
                }
            }
            (None, Some(n), None) => n.to_string(),
            (None, None, Some(v)) => v.to_string(),
            _ => {
                // No type/name/vendor: fall back to MAC, else "Unknown Device".
                match self.mac_plain() {
                    Some(s) if s.len() == 12 => {
                        let prefix = if is_randomized { "Randomized " } else { "" };
                        format!(
                            "{}{}:{}:{}:{}:{}:{}",
                            prefix,
                            &s[0..2],
                            &s[2..4],
                            &s[4..6],
                            &s[6..8],
                            &s[8..10],
                            &s[10..12]
                        )
                    }
                    _ => "Unknown Device".to_string(),
                }
            }
        };

        truncate_with_ellipsis(&raw_label, LABEL_MAX_LEN)
    }

    /// Category display name, "Device" when Unknown. Mirrors `PC.CategoryName`.
    pub fn category_name(&self) -> String {
        if self.device_category != DeviceType::Unknown {
            self.device_category.as_str().to_string()
        } else {
            "Device".to_string()
        }
    }
}

/// Formats a KB/s rate the way `PC.FormatSpeed` does.
///
/// `< 0.1` → "0 KB/s"; `>= 1024` → "<x> MB/s"; otherwise "<x> KB/s"
/// (one decimal place).
pub fn format_speed(kbps: f64) -> String {
    if kbps < 0.1 {
        "0 KB/s".to_string()
    } else if kbps >= 1024.0 {
        format!("{:.1} MB/s", kbps / 1024.0)
    } else {
        format!("{:.1} KB/s", kbps)
    }
}

/// Truncates by character count (matching C#'s UTF-16 `string.Length` semantics
/// for the BMP text used here), appending "…" when over `max_len`.
fn truncate_with_ellipsis(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        return value.to_string();
    }
    let kept: String = value.chars().take(max_len - 1).collect();
    format!("{}…", kept)
}

fn ends_with_ignore_case(haystack: &str, suffix: &str) -> bool {
    let h = haystack.to_ascii_lowercase();
    h.ends_with(&suffix.to_ascii_lowercase())
}

fn contains_ignore_case(haystack: &str, needle: &str) -> bool {
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

/// Returns the local machine name, matching .NET `Environment.MachineName`
/// (COMPUTERNAME on Windows, HOSTNAME elsewhere), falling back to "localhost".
pub fn machine_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "localhost".to_string())
}
