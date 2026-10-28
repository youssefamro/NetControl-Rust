//! # netcontrol-core
//!
//! Phase 1 Rust rebuild of the NetControl core. This crate ports the pure,
//! offline logic of the original C# application:
//!
//! - [`device_type`] — the device-category enum;
//! - [`pc`] — the `Pc` device model (labels, formatted speeds, thread-safe byte
//!   accumulators, traffic state);
//! - [`pc_list`] — thread-safe, IP-keyed device tracking (Phase 2);
//! - [`oui`] — MAC-prefix → vendor lookup and randomized-MAC detection;
//! - [`device_identifier`] — vendor/hostname → device-type inference;
//! - [`subnet`] — IPv4 network/broadcast arithmetic;
//! - [`throttling`] — EMA smoothing and an in-memory token-bucket shaper
//!   (bandwidth statistics);
//! - [`privilege`] — read-only elevation detection and guidance.
//!
//! ## Scope / safety
//!
//! Network operations are intentionally **not** implemented in this phase.
//! There is no packet capture, no ARP transmission, no spoofing, interception,
//! or traffic disruption. Every function here is calculation- or
//! inspection-only.

pub mod device_identifier;
pub mod device_type;
pub mod oui;
pub mod pc;
pub mod pc_list;
pub mod privilege;
pub mod subnet;
pub mod throttling;

pub use device_type::DeviceType;
pub use pc::Pc;
pub use pc_list::{AddOutcome, PcList};
