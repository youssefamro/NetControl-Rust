//! # netcontrol-net
//!
//! Phase 2 networking layer for the NetControl Rust rebuild: Ethernet/ARP
//! packet handling, passive ARP observation, local interface enumeration, and
//! subnet-aware device discovery, integrated with `netcontrol-core`'s device
//! tracking.
//!
//! ## Modules
//!
//! - [`ethernet`] — Ethernet II header parse/serialize;
//! - [`arp`] — ARP packet parse + frame construction (port of
//!   `CArp.BuildArpPacket`);
//! - [`listener`] — passive ARP observation / device learning (port of
//!   `CArp.ArpListenerLoop`);
//! - [`interfaces`] — local IPv4 interface enumeration;
//! - [`capture`] — maps OS interfaces (friendly names) to capture devices
//!   (`\Device\NPF_{GUID}` on Windows) and probes the capture runtime;
//! - [`discovery`] — gated, subnet-aware discovery planning (port of
//!   `CArp.DiscoveryLoop`);
//! - [`dns`], [`netbios`], [`ssdp`], [`hostname`] — protocol packet build/parse
//!   and hostname cleaning/selection (port of `DeviceIdentifierService`);
//! - [`identify`] — layered device identification orchestration (port of
//!   `IdentifyDeviceAsync`), with a `std`-only live UDP prober;
//! - [`traffic`] — passive IPv4 traffic classification + per-device smoothed
//!   rate accounting (port of `CArp.TrafficMonitorLoop`);
//! - [`throttle`] — bandwidth-throttling planners (token bucket / `tc` /
//!   `dnctl`) with dry-run execution and honest enforcement reporting (port of
//!   the `Throttling` namespace);
//! - [`error`] — [`error::NetError`] and the [`error::CancelToken`].
//!
//! ## Scope / safety
//!
//! This layer observes and discovers only. **It implements no ARP poisoning,
//! interception, redirection, or traffic disruption.** Live packet capture and
//! transmission live behind the off-by-default `live-capture` feature (which
//! links Npcap/libpcap); without it, the crate still builds, parses, plans, and
//! is fully testable using synthetic frames. Active discovery additionally
//! requires an explicit [`discovery::AuthorizedNetwork`] matching the local
//! subnet, so it stays disabled until a caller opts in for a network they own.

pub mod arp;
pub mod capture;
pub mod discovery;
pub mod dns;
pub mod error;
pub mod ethernet;
pub mod hostname;
pub mod identify;
pub mod interfaces;
pub mod listener;
pub mod netbios;
pub mod ssdp;
pub mod throttle;
pub mod traffic;

pub use arp::{ArpOperation, ArpPacket};
pub use error::{CancelToken, NetError};
pub use ethernet::EthernetHeader;
pub use hostname::select_best_hostname;
pub use identify::{HostnameProber, Identifier, LiveUdpProber, Protocol};
pub use interfaces::NetInterface;
pub use listener::{observe_arp_frame, Observation, ObserveContext};
pub use throttle::{EnforcementCapability, Platform, ThrottleCommand, ThrottleKind, Throttler};
pub use traffic::{classify_ipv4_frame, CycleStats, FrameInfo};
