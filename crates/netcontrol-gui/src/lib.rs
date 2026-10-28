//! # netcontrol-gui
//!
//! Desktop front-end for the NetControl Rust rebuild. Recreates the Avalonia
//! `MainWindow` with egui/eframe and connects the P1–P5 modules:
//!
//! - P1 `netcontrol-core` — device models, classification, statistics, privilege;
//! - P2 `netcontrol-net::interfaces` / `listener` — interface enumeration and
//!   (gated) passive ARP listening;
//! - P3 `netcontrol-net::Identifier` — offline device identification;
//! - P4 `netcontrol-net::traffic` — the bandwidth/EMA pipeline (also drives the
//!   demonstration data source);
//! - P5 `netcontrol-net::throttle` — dry-run bandwidth-limit planning.
//!
//! [`state::UiState`] holds the integration logic (and is unit-tested);
//! [`app::NetControlApp`] is the egui view. Demonstration mode is the default
//! and is clearly labeled; live capture is behind the `live-capture` feature.

pub mod app;
pub mod config;
pub mod sim;
pub mod state;
pub mod strings;
pub mod theme;

#[cfg(feature = "live-capture")]
pub mod live;

pub use app::NetControlApp;
pub use state::{
    DeviceRow, InterfaceEntry, LiveDiagnostics, Mode, StatusLevel, ThrottleSummary, UiState,
};
