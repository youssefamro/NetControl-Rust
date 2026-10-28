//! Simulated device fleet for **demonstration mode**.
//!
//! **Everything here is fake.** No packet capture, no ARP activity, no real
//! bandwidth measurement. The devices are real [`Pc`] models (classified through
//! the real OUI + heuristic pipeline), and their simulated bandwidth is fed
//! through the *real* P4 traffic/EMA pipeline (`netcontrol_net::traffic`), so the
//! demo exercises production code paths with clearly-labeled synthetic inputs.

use std::net::Ipv4Addr;

use netcontrol_core::device_identifier::infer_device_type;
use netcontrol_core::oui;
use netcontrol_core::pc::RANDOMIZED_MAC_VENDOR;
use netcontrol_core::Pc;

/// A tiny xorshift64 PRNG — deterministic, dependency-free, good enough for
/// driving cosmetic simulated traffic.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// Uniform float in `[lo, hi)`.
    pub fn range(&mut self, lo: f64, hi: f64) -> f64 {
        let unit = (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        lo + unit * (hi - lo)
    }

    /// Returns true with probability `p`.
    pub fn chance(&mut self, p: f64) -> bool {
        self.range(0.0, 1.0) < p
    }
}

/// Cosmetic traffic amplitudes for a simulated device (used only by the demo).
#[derive(Debug, Clone, Copy)]
pub struct SimProfile {
    pub down_amp_kbps: f64,
    pub up_amp_kbps: f64,
    pub activity: f64,
}

#[allow(clippy::too_many_arguments)]
fn make(
    last_octet: u8,
    mac_bytes: [u8; 6],
    hostname: &str,
    is_gateway: bool,
    is_local: bool,
    down_amp_kbps: f64,
    up_amp_kbps: f64,
    activity: f64,
) -> (Pc, SimProfile) {
    let mut pc = Pc::new();
    pc.ip = Some(Ipv4Addr::new(192, 168, 1, last_octet));
    pc.mac = Some(mac_bytes);
    pc.is_gateway = is_gateway;
    pc.is_local_pc = is_local;
    if !hostname.is_empty() {
        pc.hostname = Some(hostname.to_string());
    }

    pc.vendor = match oui::lookup(&mac_bytes) {
        Some(v) => Some(v.to_string()),
        None if oui::is_randomized_mac(&mac_bytes) => Some(RANDOMIZED_MAC_VENDOR.to_string()),
        None => None,
    };
    pc.device_category = infer_device_type(&pc);

    (
        pc,
        SimProfile {
            down_amp_kbps,
            up_amp_kbps,
            activity,
        },
    )
}

/// The default simulated fleet: a gateway, the local host, and a representative
/// mix of client devices with known OUIs.
pub fn default_fleet() -> Vec<(Pc, SimProfile)> {
    vec![
        make(
            1,
            [0x04, 0xB1, 0x67, 0x0A, 0x1B, 0x2C],
            "Gateway",
            true,
            false,
            0.0,
            0.0,
            0.0,
        ),
        make(
            42,
            [0xBC, 0xF1, 0x71, 0xA2, 0x61, 0x2E],
            "MyWorkstation",
            false,
            true,
            0.0,
            0.0,
            0.0,
        ),
        make(
            37,
            [0xA4, 0x83, 0xE7, 0x11, 0x22, 0x33],
            "iPhone-de-Carlos",
            false,
            false,
            900.0,
            180.0,
            0.55,
        ),
        make(
            23,
            [0x8C, 0x85, 0x90, 0x44, 0x55, 0x66],
            "MacBook-Pro",
            false,
            false,
            2600.0,
            420.0,
            0.6,
        ),
        make(
            51,
            [0x00, 0x15, 0x99, 0x77, 0x88, 0x99],
            "Galaxy-S23",
            false,
            false,
            700.0,
            150.0,
            0.5,
        ),
        make(
            60,
            [0xA8, 0x23, 0xFE, 0xAB, 0xCD, 0xEF],
            "LGwebOSTV",
            false,
            false,
            6200.0,
            90.0,
            0.7,
        ),
        make(
            72,
            [0x70, 0x9E, 0x29, 0x12, 0x34, 0x56],
            "PS5-Sala",
            false,
            false,
            4800.0,
            260.0,
            0.45,
        ),
        make(
            80,
            [0x00, 0x1A, 0x4B, 0x65, 0x43, 0x21],
            "HP-LaserJet",
            false,
            false,
            40.0,
            25.0,
            0.1,
        ),
        make(
            90,
            [0xF4, 0xF5, 0xE8, 0x0A, 0x0B, 0x0C],
            "Chromecast",
            false,
            false,
            3500.0,
            70.0,
            0.5,
        ),
        make(
            101,
            [0x24, 0x0A, 0xC4, 0xDE, 0xAD, 0x01],
            "esp32-temp",
            false,
            false,
            12.0,
            20.0,
            0.25,
        ),
        make(
            115,
            [0x72, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5],
            "",
            false,
            false,
            320.0,
            90.0,
            0.4,
        ),
    ]
}

/// The local subnet mask presented in the footer (simulated /24).
pub const SUBNET_MASK: &str = "255.255.255.0";
