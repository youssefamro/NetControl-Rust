//! UI state and integration logic, connecting the P1–P5 Rust modules.
//!
//! This is the testable core of the GUI. It keeps **separate device datasets**
//! for Demonstration and Live mode (so simulated and real devices never mix and
//! settings survive mode switches), persists user preferences, drives the demo
//! data source through the real P4 traffic/EMA pipeline, runs P3 offline
//! identification, plans P5 (dry-run) throttling, enumerates P2 interfaces, and
//! reports P1 privilege state plus Live-mode diagnostics.
//!
//! No ARP poisoning / redirection / interception. Live capture is gated behind
//! the `live-capture` feature; without it, live mode reports that capture is
//! unavailable rather than pretending.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use netcontrol_core::throttling::TRAFFIC_EMA_ALPHA;
use netcontrol_core::{privilege, PcList};
use netcontrol_net::throttle::{EnforcementCapability, ThrottleKind, Throttler};
use netcontrol_net::traffic::CycleStats;
use netcontrol_net::{capture, Identifier, NetError, NetInterface};

use crate::config::{self, DeviceConfig, SavedMode, UiConfig};
use crate::sim::{self, Rng, SimProfile};
use crate::strings;

/// Which data source the UI is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Clearly-labeled simulated devices and bandwidth.
    Demonstration,
    /// Real devices from live capture (requires the `live-capture` build).
    Live,
}

impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Mode::Demonstration => strings::MODE_DEMO,
            Mode::Live => strings::MODE_LIVE,
        }
    }
    fn saved(self) -> SavedMode {
        match self {
            Mode::Demonstration => SavedMode::Demonstration,
            Mode::Live => SavedMode::Live,
        }
    }
    fn from_saved(s: SavedMode) -> Self {
        match s {
            SavedMode::Demonstration => Mode::Demonstration,
            SavedMode::Live => Mode::Live,
        }
    }
}

/// Status-pill severity (mirrors the C# `SetStatus` levels).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusLevel {
    Success,
    Info,
    Warning,
    Error,
}

/// A selectable network interface entry.
///
/// `name` is the OS display name (Windows friendly name such as `Ethernet 2`)
/// and is what the UI shows and persists. The capture backend's identifier is
/// resolved from `iface` (GUID / IPv4 / MAC) only when capture starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceEntry {
    pub name: String,
    pub display: String,
    pub simulated: bool,
    /// The enumerated OS interface (`None` for simulated entries).
    pub iface: Option<NetInterface>,
}

impl InterfaceEntry {
    /// Builds a readable entry (`Ethernet 2 — 192.168.1.119`) for a real interface.
    pub fn from_net(i: NetInterface) -> Self {
        InterfaceEntry {
            display: format!(
                "{} — {}{}",
                i.name,
                i.ipv4,
                if i.is_loopback { " (loopback)" } else { "" }
            ),
            name: i.name.clone(),
            simulated: false,
            iface: Some(i),
        }
    }
}

/// A row rendered in the device table (a snapshot of one device).
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceRow {
    pub ip: Ipv4Addr,
    pub ip_display: String,
    pub mac: String,
    pub label: String,
    pub vendor: String,
    pub hostname: String,
    pub category: String,
    pub download: String,
    pub upload: String,
    pub download_hex: String,
    pub upload_hex: String,
    pub bandwidth_limit_kb: i32,
    pub redirect: bool,
    pub block: bool,
    pub is_gateway: bool,
    pub is_local: bool,
    pub can_control: bool,
    pub throttling_enabled: bool,
}

/// Honest throttling summary for the status area.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThrottleSummary {
    pub kind: String,
    /// Always conveys "Dry Run / Not Enforced" because no backend enforces here.
    pub status: String,
    pub explanation: String,
    pub last_plan: Vec<String>,
}

/// Human-readable Live-mode diagnostics shown in the Live panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveDiagnostics {
    pub interface: String,
    pub capture_supported: bool,
    pub support_note: String,
    pub elevated: bool,
    pub permission_note: String,
    pub capture_running: bool,
    /// Capture runtime (Npcap/WinPcap DLL, raw sockets) availability.
    pub runtime_note: String,
    /// The resolved capture device while running (e.g. `\Device\NPF_{GUID}`).
    pub capture_device: Option<String>,
    /// The last capture start/runtime error, if any.
    pub capture_error: Option<String>,
    pub devices_discovered: usize,
    pub no_devices_reason: Option<String>,
    pub mode_note: String,
    pub unsupported_features: Vec<String>,
}

fn kind_name(kind: ThrottleKind) -> &'static str {
    match kind {
        ThrottleKind::TokenBucket => "Token bucket (in-process)",
        ThrottleKind::LinuxTc => "Linux tc/HTB",
        ThrottleKind::MacDummynet => "macOS dnctl/dummynet",
    }
}

/// Whether this build compiled the live-capture backend.
pub const CAPTURE_SUPPORTED: bool = cfg!(feature = "live-capture");

/// The complete UI state.
pub struct UiState {
    mode: Mode,

    // Separate, never-mixed datasets.
    demo_devices: Arc<PcList>,
    live_devices: Arc<PcList>,
    profiles: Vec<(Ipv4Addr, SimProfile)>,

    // Per-mode interface selection.
    demo_interfaces: Vec<InterfaceEntry>,
    demo_selected: usize,
    live_interfaces: Vec<InterfaceEntry>,
    live_selected: usize,
    saved_live_interface: Option<String>,

    rng: Rng,
    identifier: Identifier,
    throttler: Throttler,

    status_text: String,
    status_level: StatusLevel,
    last_error: Option<String>,

    show_disclaimer: bool,
    elevation_warning: bool,
    elevation_guidance: String,
    capture_running: bool,
    capture_device: Option<String>,
    capture_error: Option<String>,
    last_plan: Vec<String>,

    config_path: Option<PathBuf>,

    #[cfg(feature = "live-capture")]
    capture: Option<crate::live::CaptureController>,
}

impl UiState {
    /// Builds the default application state, loading persisted preferences from
    /// the on-disk config (on `D:`). Capture is **never** auto-started.
    pub fn new() -> Self {
        Self::with_config_path(Some(config::config_path()))
    }

    /// Builds state without touching disk (for tests).
    pub fn in_memory() -> Self {
        Self::with_config_path(None)
    }

    /// Builds state, loading/saving preferences at `config_path` when `Some`.
    pub fn with_config_path(config_path: Option<PathBuf>) -> Self {
        let elevated = privilege::is_elevated();
        let has_caps = privilege::has_capture_capabilities();
        let elevation_warning = !elevated && !has_caps;

        let demo_interfaces = demo_interfaces();
        let throttler = make_throttler(&demo_interfaces[0].name);

        let mut state = UiState {
            mode: Mode::Demonstration,
            demo_devices: Arc::new(PcList::new()),
            live_devices: Arc::new(PcList::new()),
            profiles: Vec::new(),
            demo_interfaces,
            demo_selected: 0,
            live_interfaces: Vec::new(),
            live_selected: 0,
            saved_live_interface: None,
            rng: Rng::new(0x9E3779B97F4A7C15),
            identifier: Identifier::new(),
            throttler,
            status_text: String::new(),
            status_level: StatusLevel::Success,
            last_error: None,
            show_disclaimer: true,
            elevation_warning,
            elevation_guidance: privilege::get_elevation_guidance().to_string(),
            capture_running: false,
            capture_device: None,
            capture_error: None,
            last_plan: Vec::new(),
            config_path,
            #[cfg(feature = "live-capture")]
            capture: None,
        };

        state.seed_demo_fleet();

        if let Some(path) = &state.config_path {
            let cfg = UiConfig::load(path);
            state.apply_config(&cfg);
        }

        state.status_text = if elevation_warning {
            "Demonstration mode. (Unprivileged: live capture would need admin + Npcap.)".to_string()
        } else {
            "Demonstration mode — simulated devices. Press Start to animate.".to_string()
        };
        state.rebuild_throttler();
        state
    }

    // ── Persistence ────────────────────────────────────────────────

    /// Exports the current preferences (used for saving and for tests).
    pub fn export_config(&self) -> UiConfig {
        let mut demo_devices = std::collections::BTreeMap::new();
        for (ip, cfg) in self.demo_devices.map_devices(|p| {
            (
                p.ip,
                DeviceConfig {
                    limit_kb: p.bandwidth_limit_kb(),
                    redirect: p.redirect(),
                    block: p.block(),
                },
            )
        }) {
            if let Some(ip) = ip {
                if cfg.limit_kb != 0 || cfg.redirect || cfg.block {
                    demo_devices.insert(ip, cfg);
                }
            }
        }
        UiConfig {
            disclaimer_dismissed: !self.show_disclaimer,
            last_mode: self.mode.saved(),
            demo_interface: self
                .demo_interfaces
                .get(self.demo_selected)
                .map(|i| i.name.clone()),
            live_interface: self.saved_live_interface.clone(),
            demo_devices,
        }
    }

    /// Applies persisted preferences onto the current (seeded) state.
    pub fn apply_config(&mut self, cfg: &UiConfig) {
        self.show_disclaimer = !cfg.disclaimer_dismissed;
        self.mode = Mode::from_saved(cfg.last_mode);

        if let Some(name) = &cfg.demo_interface {
            if let Some(idx) = self.demo_interfaces.iter().position(|i| &i.name == name) {
                self.demo_selected = idx;
            }
        }
        self.saved_live_interface = cfg.live_interface.clone();

        for (ip, dc) in &cfg.demo_devices {
            self.demo_devices.update_device_by_ip(*ip, |pc| {
                pc.set_bandwidth_limit_kb(dc.limit_kb);
                if dc.block {
                    pc.set_block(true);
                } else if dc.redirect {
                    pc.set_redirect(true);
                }
            });
        }

        if self.mode == Mode::Live {
            self.load_live_interfaces();
        }
    }

    fn persist(&mut self) {
        if let Some(path) = self.config_path.clone() {
            let cfg = self.export_config();
            if let Err(e) = cfg.save(&path) {
                self.last_error = Some(format!("Could not save settings: {e}"));
            }
        }
    }

    // ── Demonstration fleet ────────────────────────────────────────

    fn seed_demo_fleet(&mut self) {
        self.demo_devices.clear();
        self.profiles.clear();
        for (mut pc, profile) in sim::default_fleet() {
            if let Some(ip) = pc.ip {
                self.identifier.identify_offline(&mut pc); // P3 offline identification
                self.profiles.push((ip, profile));
                self.demo_devices.add_device(pc);
            }
        }
    }

    /// Advances the simulated bandwidth by `dt` seconds through the real P4
    /// cycle/EMA pipeline. No-op outside demonstration mode or when stopped.
    pub fn demo_tick(&mut self, dt: f64) {
        if self.mode != Mode::Demonstration || !self.capture_running {
            return;
        }
        let dt = dt.clamp(0.05, 2.0);

        let snapshot = self.demo_devices.map_devices(|p| {
            (
                p.ip,
                p.is_gateway,
                p.is_local_pc,
                p.block(),
                p.is_throttling_enabled(),
                p.bandwidth_limit_kb(),
            )
        });

        let ips: Vec<Ipv4Addr> = snapshot.iter().filter_map(|s| s.0).collect();
        let mut stats = CycleStats::seeded(ips);

        for (ip, is_gw, is_local, blocked, throttling, cap) in snapshot {
            let ip = match ip {
                Some(ip) => ip,
                None => continue,
            };
            if is_gw || is_local {
                stats.add_bytes(ip, 0, 0);
                continue;
            }
            let profile = self
                .profiles
                .iter()
                .find(|(pip, _)| *pip == ip)
                .map(|(_, p)| *p)
                .unwrap_or(SimProfile {
                    down_amp_kbps: 0.0,
                    up_amp_kbps: 0.0,
                    activity: 0.0,
                });

            let (mut md, mut mu) = if blocked {
                (0.0, 0.0)
            } else if self.rng.chance(profile.activity) {
                (
                    self.rng.range(0.25, 1.0) * profile.down_amp_kbps,
                    self.rng.range(0.25, 1.0) * profile.up_amp_kbps,
                )
            } else {
                (0.0, 0.0)
            };

            if throttling && cap > 0 {
                let cap = cap as f64;
                md = md.min(cap);
                mu = mu.min(cap);
            }

            stats.add_bytes(ip, (md * 1024.0 * dt) as i64, (mu * 1024.0 * dt) as i64);
        }

        stats.apply(
            &self.demo_devices,
            Duration::from_secs_f64(dt),
            TRAFFIC_EMA_ALPHA,
        );
    }

    // ── Active dataset accessors ───────────────────────────────────

    fn active_devices(&self) -> &Arc<PcList> {
        match self.mode {
            Mode::Demonstration => &self.demo_devices,
            Mode::Live => &self.live_devices,
        }
    }

    fn active_interfaces(&self) -> &[InterfaceEntry] {
        match self.mode {
            Mode::Demonstration => &self.demo_interfaces,
            Mode::Live => &self.live_interfaces,
        }
    }

    fn active_selected(&self) -> usize {
        match self.mode {
            Mode::Demonstration => self.demo_selected,
            Mode::Live => self.live_selected,
        }
    }

    // ── Mode / capture control ─────────────────────────────────────

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Switches modes, stopping any running capture but **preserving** both
    /// datasets and all saved settings.
    pub fn set_mode(&mut self, mode: Mode) {
        if mode == self.mode {
            return;
        }
        self.stop_capture();
        self.mode = mode;
        self.last_error = None;
        match mode {
            Mode::Demonstration => {
                self.set_status(
                    "Demonstration mode — simulated devices. Press Start to animate.",
                    StatusLevel::Info,
                );
            }
            Mode::Live => {
                // Re-enumerate on every entry so added/removed adapters show up;
                // the saved selection is restored by name.
                self.load_live_interfaces();
                self.set_status(
                    "Live mode — select an interface and Start passive listening.",
                    StatusLevel::Info,
                );
            }
        }
        self.rebuild_throttler();
        self.persist();
    }

    /// Starts the data source for the current mode.
    pub fn start_capture(&mut self) {
        self.last_error = None;
        match self.mode {
            Mode::Demonstration => {
                self.capture_running = true;
                self.set_status(
                    "Demonstration running — simulated traffic.",
                    StatusLevel::Success,
                );
            }
            Mode::Live => self.start_live_capture(),
        }
    }

    /// Stops the current data source and cancels background work cleanly.
    pub fn stop_capture(&mut self) {
        let was_running = self.capture_running;
        self.capture_running = false;
        self.capture_device = None;
        #[cfg(feature = "live-capture")]
        if let Some(controller) = self.capture.take() {
            controller.stop();
        }
        if self.mode == Mode::Live && was_running {
            self.set_status("Capture stopped.", StatusLevel::Info);
        }
    }

    pub fn capture_running(&self) -> bool {
        self.capture_running
    }

    #[cfg(not(feature = "live-capture"))]
    fn start_live_capture(&mut self) {
        let msg = "Live capture is not available in this build. Use the Live-capable \
                   build (NetControl Live) and install Npcap on Windows."
            .to_string();
        self.capture_error = Some(msg.clone());
        self.last_error = Some(msg.clone());
        self.set_status(msg, StatusLevel::Error);
    }

    #[cfg(feature = "live-capture")]
    fn start_live_capture(&mut self) {
        let target = match self.selected_live_target() {
            Ok(t) => t,
            Err(Some(e)) => return self.capture_failed(&e),
            Err(None) => {
                self.set_status("Select a real interface first.", StatusLevel::Warning);
                return;
            }
        };
        match crate::live::CaptureController::start(&target, self.live_devices.clone()) {
            Ok(controller) => {
                self.capture_device = Some(controller.device_summary());
                self.capture_error = None;
                self.capture = Some(controller);
                self.capture_running = true;
                self.set_status(
                    format!(
                        "Passive listening on {} — {} (no scans sent).",
                        target.name, target.ipv4
                    ),
                    StatusLevel::Success,
                );
            }
            Err(e) => self.capture_failed(&e),
        }
    }

    /// Resolves the selected Live entry to an OS interface. `Err(None)` means
    /// no real interface is selected; `Err(Some(_))` means it has disappeared.
    pub fn selected_live_target(&self) -> Result<NetInterface, Option<NetError>> {
        let entry = match self.live_interfaces.get(self.live_selected) {
            Some(e) if !e.simulated => e,
            _ => return Err(None),
        };
        if let Some(iface) = &entry.iface {
            return Ok(iface.clone());
        }
        // Entries without enumeration data (e.g. restored by name): look it up.
        netcontrol_net::interfaces::enumerate()
            .map_err(Some)?
            .into_iter()
            .find(|i| i.name == entry.name)
            .ok_or_else(|| Some(NetError::InterfaceNotFound(entry.name.clone())))
    }

    /// Records a capture start/runtime failure for the status bar and Live panel.
    pub fn capture_failed(&mut self, e: &NetError) {
        let msg = format!("Capture failed: {e}");
        self.capture_error = Some(e.to_string());
        self.log_diagnostic(&msg);
        self.last_error = Some(msg.clone());
        self.set_status(msg, StatusLevel::Error);
    }

    /// Appends a line to `netcontrol.log` beside the config file (no-op for
    /// in-memory state). Failures to log are ignored.
    fn log_diagnostic(&self, line: &str) {
        use std::io::Write;
        let Some(dir) = self.config_path.as_ref().and_then(|p| p.parent()) else {
            return;
        };
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = std::fs::create_dir_all(dir);
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("netcontrol.log"))
        {
            let _ = writeln!(f, "[unix {secs}] {line}");
        }
    }

    /// Checks running capture threads; if one failed (adapter removed, driver
    /// stopped), stops capture and reports why. Call periodically from the UI.
    pub fn poll_capture_health(&mut self) {
        #[cfg(feature = "live-capture")]
        if let Some(why) = self.capture.as_ref().and_then(|c| c.failure()) {
            self.stop_capture();
            let msg = format!("Capture stopped unexpectedly: {why}");
            self.log_diagnostic(&msg);
            self.capture_error = Some(why);
            self.last_error = Some(msg.clone());
            self.set_status(msg, StatusLevel::Error);
        }
    }

    // ── Interfaces ─────────────────────────────────────────────────

    /// Loads the real host interfaces (P2 enumeration). Used by live mode.
    pub fn load_live_interfaces(&mut self) {
        match netcontrol_net::interfaces::enumerate() {
            Ok(list) => {
                let entries: Vec<InterfaceEntry> =
                    list.into_iter().map(InterfaceEntry::from_net).collect();
                let empty = entries.is_empty();
                self.set_live_interfaces(entries);
                if empty {
                    self.set_status("No IPv4 interfaces detected.", StatusLevel::Warning);
                }
            }
            Err(e) => {
                self.last_error = Some(format!("Interface enumeration failed: {e}"));
                self.set_status("Error enumerating interfaces.", StatusLevel::Error);
            }
        }
    }

    /// Sets the live interface list (used by live mode and by tests), restoring
    /// the saved selection by name when possible.
    pub fn set_live_interfaces(&mut self, interfaces: Vec<InterfaceEntry>) {
        self.live_interfaces = interfaces;
        self.live_selected = self
            .saved_live_interface
            .as_ref()
            .and_then(|name| self.live_interfaces.iter().position(|i| &i.name == name))
            .unwrap_or(0);
        self.rebuild_throttler();
    }

    pub fn interfaces(&self) -> &[InterfaceEntry] {
        self.active_interfaces()
    }

    pub fn selected_interface(&self) -> usize {
        self.active_selected()
    }

    pub fn select_interface(&mut self, index: usize) {
        match self.mode {
            Mode::Demonstration => {
                if index < self.demo_interfaces.len() {
                    self.demo_selected = index;
                }
            }
            Mode::Live => {
                if index < self.live_interfaces.len() {
                    self.live_selected = index;
                    self.saved_live_interface =
                        self.live_interfaces.get(index).map(|i| i.name.clone());
                }
            }
        }
        self.rebuild_throttler();
        self.persist();
    }

    pub fn selected_interface_name(&self) -> &str {
        self.active_interfaces()
            .get(self.active_selected())
            .map(|i| i.name.as_str())
            .unwrap_or("")
    }

    fn rebuild_throttler(&mut self) {
        let name = self
            .active_interfaces()
            .get(self.active_selected())
            .map(|i| i.name.clone())
            .unwrap_or_else(|| "none".to_string());
        self.throttler = make_throttler(&name);
    }

    // ── Device table ───────────────────────────────────────────────

    pub fn device_rows(&self) -> Vec<DeviceRow> {
        self.active_devices().map_devices(|p| DeviceRow {
            ip: p.ip.unwrap_or(Ipv4Addr::UNSPECIFIED),
            ip_display: p
                .ip
                .map(|i| i.to_string())
                .unwrap_or_else(|| "—".to_string()),
            mac: p.mac_formatted(),
            label: p.device_label(),
            vendor: p.vendor.clone().unwrap_or_default(),
            hostname: p.hostname.clone().unwrap_or_default(),
            category: p.category_name(),
            download: p.download_speed_formatted(),
            upload: p.upload_speed_formatted(),
            download_hex: p.download_traffic_brush_hex().to_string(),
            upload_hex: p.upload_traffic_brush_hex().to_string(),
            bandwidth_limit_kb: p.bandwidth_limit_kb(),
            redirect: p.redirect(),
            block: p.block(),
            is_gateway: p.is_gateway,
            is_local: p.is_local_pc,
            can_control: p.can_control(),
            throttling_enabled: p.is_throttling_enabled(),
        })
    }

    pub fn device_count(&self) -> usize {
        self.active_devices().len()
    }

    pub fn demo_device_count(&self) -> usize {
        self.demo_devices.len()
    }

    pub fn live_device_count(&self) -> usize {
        self.live_devices.len()
    }

    /// (total, spoof-flagged, block-flagged, gateway-ip-string)
    pub fn dashboard(&self) -> (usize, usize, usize, String) {
        let devices = self.active_devices();
        let total = devices.len();
        let redirect = devices
            .map_devices(|p| p.redirect())
            .into_iter()
            .filter(|r| *r)
            .count();
        let blocked = devices
            .map_devices(|p| p.block())
            .into_iter()
            .filter(|b| *b)
            .count();
        let gateway = devices
            .router_ip()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "—".to_string());
        (total, redirect, blocked, gateway)
    }

    pub fn local_ip(&self) -> String {
        self.active_devices()
            .local_ip()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "—".to_string())
    }

    // ── Per-device controls ────────────────────────────────────────

    pub fn set_bandwidth_limit(&mut self, ip: Ipv4Addr, kbps: i32) {
        self.active_devices()
            .update_device_by_ip(ip, |pc| pc.set_bandwidth_limit_kb(kbps));
        self.sync_throttle(ip);
        self.persist();
    }

    pub fn toggle_redirect(&mut self, ip: Ipv4Addr) {
        self.active_devices().update_device_by_ip(ip, |pc| {
            let v = !pc.redirect();
            pc.set_redirect(v);
        });
        self.sync_throttle(ip);
        self.persist();
    }

    pub fn toggle_block(&mut self, ip: Ipv4Addr) {
        self.active_devices().update_device_by_ip(ip, |pc| {
            let v = !pc.block();
            pc.set_block(v);
        });
        self.sync_throttle(ip);
        self.persist();
    }

    /// Reconciles a device's limit with the P5 (dry-run) throttler and records
    /// the planned commands. This never enforces anything.
    fn sync_throttle(&mut self, ip: Ipv4Addr) {
        let state = self.active_devices().update_device_by_ip(ip, |pc| {
            (pc.redirect(), pc.can_control(), pc.bandwidth_limit_kb())
        });
        if let Some((redirect, can_control, limit)) = state {
            if let Ok(cmds) = self.throttler.sync_device(ip, redirect, can_control, limit) {
                self.last_plan = cmds.iter().map(|c| c.display()).collect();
            }
        }
    }

    /// An honest summary of what throttling would do (always "Not Enforced").
    pub fn throttle_summary(&self) -> ThrottleSummary {
        let cap = self.throttler.enforcement();
        debug_assert!(!cap.is_operational());
        let status = match cap {
            EnforcementCapability::CalculationOnly => "Dry Run — Not Enforced (calculation only)",
            EnforcementCapability::PathDependent => {
                "Dry Run — Not Enforced (host not on peer path)"
            }
            EnforcementCapability::IncompletePathDependent => {
                "Dry Run — Not Enforced (adapter incomplete)"
            }
        };
        ThrottleSummary {
            kind: kind_name(self.throttler.kind()).to_string(),
            status: status.to_string(),
            explanation: cap.explain().to_string(),
            last_plan: self.last_plan.clone(),
        }
    }

    // ── Live diagnostics ───────────────────────────────────────────

    /// Human-readable Live-mode diagnostics for the Live panel.
    pub fn live_diagnostics(&self) -> LiveDiagnostics {
        let interface = self
            .live_interfaces
            .get(self.live_selected)
            .map(|i| i.display.clone())
            .unwrap_or_else(|| "(none selected)".to_string());

        let support_note = if CAPTURE_SUPPORTED {
            "Live capture compiled in. Requires Npcap on Windows; root/CAP_NET_RAW on Linux/macOS."
                .to_string()
        } else {
            "This is a demonstration build — live capture is not compiled in.".to_string()
        };

        let elevated = privilege::is_elevated() || privilege::has_capture_capabilities();
        let permission_note = if elevated {
            "Capture privileges detected (admin/root or capture capability).".to_string()
        } else {
            self.elevation_guidance.clone()
        };

        let devices_discovered = self.live_devices.len();
        let no_devices_reason = if !CAPTURE_SUPPORTED {
            Some(
                "This build cannot capture. Use the Live-capable build (`--features live-capture`) and install \
                 Npcap."
                    .to_string(),
            )
        } else if !self.capture_running {
            Some("Capture is not started. Press Start.".to_string())
        } else if devices_discovered == 0 {
            Some(
                "Passive listening is active but no ARP traffic has been observed yet. NetControl \
                 does not send scans or probes, so devices appear only as they announce themselves."
                    .to_string(),
            )
        } else {
            None
        };

        LiveDiagnostics {
            interface,
            capture_supported: CAPTURE_SUPPORTED,
            support_note,
            elevated,
            permission_note,
            capture_running: self.capture_running && self.mode == Mode::Live,
            runtime_note: capture::runtime_status().describe(),
            capture_device: self.capture_device.clone(),
            capture_error: self.capture_error.clone(),
            devices_discovered,
            no_devices_reason,
            mode_note: "Passive listening only — NetControl observes ARP/IP traffic and never \
                        sends ARP scans, probes, or replies."
                .to_string(),
            unsupported_features: vec![
                "Active ARP scanning / discovery probes (listening is passive only)".to_string(),
                "ARP spoofing / redirection / interception (not implemented)".to_string(),
                "Traffic blocking (the Block flag is a marker only — nothing is dropped)"
                    .to_string(),
                "Bandwidth enforcement (throttling is dry-run only — nothing is applied)"
                    .to_string(),
                "Gateway auto-detection (the router is learned passively from traffic)".to_string(),
            ],
        }
    }

    // ── Status / banners ───────────────────────────────────────────

    pub fn set_status(&mut self, text: impl Into<String>, level: StatusLevel) {
        self.status_text = text.into();
        self.status_level = level;
    }

    pub fn status(&self) -> (&str, StatusLevel) {
        (&self.status_text, self.status_level)
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    pub fn elevation_warning(&self) -> bool {
        self.elevation_warning
    }

    pub fn elevation_guidance(&self) -> &str {
        &self.elevation_guidance
    }

    pub fn disclaimer_visible(&self) -> bool {
        self.show_disclaimer
    }

    pub fn dismiss_disclaimer(&mut self) {
        self.show_disclaimer = false;
        self.persist();
    }

    pub fn subnet_mask(&self) -> &str {
        sim::SUBNET_MASK
    }
}

impl Default for UiState {
    fn default() -> Self {
        UiState::in_memory()
    }
}

fn demo_interfaces() -> Vec<InterfaceEntry> {
    [
        ("demo-eth0", "demo-eth0 — Ethernet (simulated)"),
        ("demo-wlan0", "demo-wlan0 — Wi-Fi (simulated)"),
    ]
    .iter()
    .map(|(name, display)| InterfaceEntry {
        name: name.to_string(),
        display: display.to_string(),
        simulated: true,
        iface: None,
    })
    .collect()
}

fn make_throttler(interface: &str) -> Throttler {
    let name = if interface.trim().is_empty() {
        "none"
    } else {
        interface
    };
    Throttler::new(name).unwrap_or_else(|_| Throttler::new("none").expect("non-empty name"))
}
