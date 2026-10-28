//! Centralized English UI strings.
//!
//! Keeping the user-facing text here makes the interface language consistent and
//! lets tests assert that the UI is in English. The application is English-only.

// Window / branding
pub const WINDOW_TITLE: &str = "NetControl - Network Traffic Management";
pub const APP_NAME: &str = "NetControl";
pub const APP_SUBTITLE: &str = "Network Traffic Management";

// Toolbar
pub const INTERFACE_LABEL: &str = "Interface:";
pub const START_BUTTON: &str = "Start";
pub const STOP_BUTTON: &str = "Stop";
pub const MODE_DEMO: &str = "Demonstration";
pub const MODE_LIVE: &str = "Live";

// KPI dashboard (labels reflect that spoof/block are flags, not actions)
pub const KPI_TOTAL: &str = "TOTAL DEVICES";
pub const KPI_SPOOF_FLAGGED: &str = "SPOOF-FLAGGED";
pub const KPI_BLOCK_FLAGGED: &str = "BLOCK-FLAGGED";
pub const KPI_GATEWAY: &str = "GATEWAY";

// Device table headers
pub const COL_IP: &str = "IP Address";
pub const COL_MAC: &str = "MAC Address";
pub const COL_DEVICE: &str = "Device Identification";
pub const COL_DOWNLOAD: &str = "Download";
pub const COL_UPLOAD: &str = "Upload";
pub const COL_CAP: &str = "Cap (KB/s)";
pub const COL_SPOOF: &str = "Spoof";
pub const COL_BLOCK: &str = "Block";

// Tooltips that keep non-operational features honest
pub const TIP_SPOOF: &str =
    "Planning flag only — NOT operational. No ARP redirection or interception is performed.";
pub const TIP_BLOCK: &str =
    "Planning flag only — NOT operational. No traffic blocking is performed.";
pub const TIP_CAP: &str =
    "Bandwidth cap in KB/s (0 = unlimited). Dry-run only — limits are planned, never enforced.";

// Empty state
pub const EMPTY_TITLE: &str = "No devices detected";
pub const EMPTY_BODY_DEMO: &str = "Press Start to animate the simulated device fleet.";
pub const EMPTY_BODY_LIVE: &str =
    "Select a network interface above and press Start to begin passive listening.";

// Banners
pub const DEMO_BANNER_TITLE: &str = "● DEMONSTRATION MODE";
pub const DEMO_BANNER_BODY: &str =
    "Devices and bandwidth below are simulated and clearly labeled. Packet capture, ARP \
     operations, interception, and traffic shaping are disabled.";
pub const ELEVATION_TITLE: &str = "Privilege Warning: Elevated Permissions Required";
pub const DISCLAIMER_BODY: &str =
    "Notice: NetControl is for authorized network diagnostics, lab evaluations, and education \
     only. Unauthorized ARP redirection is prohibited on non-owned infrastructure.";

// Throttling status
pub const THROTTLE_LABEL: &str = "Throttling:";
