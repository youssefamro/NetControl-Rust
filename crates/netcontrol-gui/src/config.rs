//! Persistent user preferences.
//!
//! A tiny line-based config (no external serializer) storing the preferences
//! that should survive mode switches and application restarts: the dismissed
//! disclaimer, the last mode, the per-mode interface selection, and the
//! user-defined **demonstration** device settings (bandwidth cap, spoof/block
//! flags). Live captures are never persisted or auto-restored.
//!
//! The data directory is resolved by [`resolve_data_dir`]: `NETCONTROL_DATA_DIR`,
//! then a portable marker next to the executable, then (for development runs)
//! this workspace's gitignored `.appdata` on `D:`, then the per-user OS default.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

/// Which mode the app was last in (persisted, but capture is never auto-started).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SavedMode {
    Demonstration,
    Live,
}

impl SavedMode {
    fn as_str(self) -> &'static str {
        match self {
            SavedMode::Demonstration => "demo",
            SavedMode::Live => "live",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        match s {
            "demo" => Some(SavedMode::Demonstration),
            "live" => Some(SavedMode::Live),
            _ => None,
        }
    }
}

/// Saved per-device demonstration settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeviceConfig {
    pub limit_kb: i32,
    pub redirect: bool,
    pub block: bool,
}

/// The full persisted configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiConfig {
    pub disclaimer_dismissed: bool,
    pub last_mode: SavedMode,
    pub demo_interface: Option<String>,
    pub live_interface: Option<String>,
    /// Demo device settings keyed by IP (BTreeMap for stable serialization).
    pub demo_devices: BTreeMap<Ipv4Addr, DeviceConfig>,
}

impl Default for UiConfig {
    fn default() -> Self {
        UiConfig {
            disclaimer_dismissed: false,
            last_mode: SavedMode::Demonstration,
            demo_interface: None,
            live_interface: None,
            demo_devices: BTreeMap::new(),
        }
    }
}

impl UiConfig {
    /// Serializes to the line-based format.
    pub fn to_ini(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "disclaimer_dismissed={}\n",
            self.disclaimer_dismissed as u8
        ));
        out.push_str(&format!("last_mode={}\n", self.last_mode.as_str()));
        if let Some(i) = &self.demo_interface {
            out.push_str(&format!("demo_interface={i}\n"));
        }
        if let Some(i) = &self.live_interface {
            out.push_str(&format!("live_interface={i}\n"));
        }
        for (ip, cfg) in &self.demo_devices {
            out.push_str(&format!(
                "dev={ip}|{}|{}|{}\n",
                cfg.limit_kb, cfg.redirect as u8, cfg.block as u8
            ));
        }
        out
    }

    /// Parses the line-based format, ignoring unknown/malformed lines.
    pub fn from_ini(text: &str) -> Self {
        let mut cfg = UiConfig::default();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = match line.split_once('=') {
                Some(kv) => kv,
                None => continue,
            };
            match key {
                "disclaimer_dismissed" => cfg.disclaimer_dismissed = value == "1",
                "last_mode" => {
                    if let Some(m) = SavedMode::parse(value) {
                        cfg.last_mode = m;
                    }
                }
                "demo_interface" => cfg.demo_interface = Some(value.to_string()),
                "live_interface" => cfg.live_interface = Some(value.to_string()),
                "dev" => {
                    if let Some((ip, dc)) = parse_device(value) {
                        cfg.demo_devices.insert(ip, dc);
                    }
                }
                _ => {}
            }
        }
        cfg
    }

    /// Loads the config from `path`, returning defaults if it is missing or
    /// unreadable (never fails).
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(text) => UiConfig::from_ini(&text),
            Err(_) => UiConfig::default(),
        }
    }

    /// Saves the config to `path`, creating parent directories. Errors are
    /// returned so callers can surface them, but are non-fatal.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, self.to_ini())
    }
}

fn parse_device(value: &str) -> Option<(Ipv4Addr, DeviceConfig)> {
    let mut parts = value.split('|');
    let ip: Ipv4Addr = parts.next()?.parse().ok()?;
    let limit_kb: i32 = parts.next()?.parse().ok()?;
    let redirect = parts.next()? == "1";
    let block = parts.next()? == "1";
    Some((
        ip,
        DeviceConfig {
            limit_kb,
            redirect,
            block,
        },
    ))
}

/// Marker file next to the executable that selects portable data storage.
/// Empty: data lives in `<exe dir>\data`. Otherwise its first line is the data
/// directory (absolute, or relative to the executable's directory).
pub const PORTABLE_MARKER: &str = "netcontrol.portable";

/// The application-data directory. See [`resolve_data_dir`].
pub fn data_dir() -> PathBuf {
    resolve_data_dir(
        std::env::var("NETCONTROL_DATA_DIR").ok(),
        std::env::current_exe().ok().as_deref(),
    )
}

/// Resolves the data directory, in priority order:
///
/// 1. `env_override` (`NETCONTROL_DATA_DIR`), if non-empty;
/// 2. a [`PORTABLE_MARKER`] next to the executable (portable ZIP / installer
///    choice);
/// 3. a development build run from this workspace's `target\` directory: the
///    workspace's gitignored `.appdata` (keeps dev settings on `D:`);
/// 4. the per-user OS default (`%LOCALAPPDATA%\NetControl`,
///    `$XDG_CONFIG_HOME/netcontrol`, `~/Library/Application Support/NetControl`).
pub fn resolve_data_dir(env_override: Option<String>, exe: Option<&Path>) -> PathBuf {
    if let Some(dir) = env_override.filter(|d| !d.trim().is_empty()) {
        return PathBuf::from(dir.trim());
    }

    if let Some(exe_dir) = exe.and_then(Path::parent) {
        let marker = exe_dir.join(PORTABLE_MARKER);
        if let Ok(text) = std::fs::read_to_string(&marker) {
            let line = text.lines().next().unwrap_or("").trim();
            return if line.is_empty() {
                exe_dir.join("data")
            } else {
                exe_dir.join(line)
            };
        }

        if let Some(ws) = exe_dir
            .ancestors()
            .find(|a| a.file_name().is_some_and(|n| n == "target"))
            .and_then(Path::parent)
            .filter(|ws| ws.join("Cargo.toml").is_file() && ws.join("crates").is_dir())
        {
            return ws.join(".appdata");
        }
    }

    os_default_data_dir()
}

fn os_default_data_dir() -> PathBuf {
    let env_dir = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    if cfg!(windows) {
        env_dir("LOCALAPPDATA")
            .or_else(|| env_dir("APPDATA"))
            .map(|d| d.join("NetControl"))
            .unwrap_or_else(|| PathBuf::from(".netcontrol"))
    } else if cfg!(target_os = "macos") {
        env_dir("HOME")
            .map(|h| h.join("Library/Application Support/NetControl"))
            .unwrap_or_else(|| PathBuf::from(".netcontrol"))
    } else {
        env_dir("XDG_CONFIG_HOME")
            .or_else(|| env_dir("HOME").map(|h| h.join(".config")))
            .map(|d| d.join("netcontrol"))
            .unwrap_or_else(|| PathBuf::from(".netcontrol"))
    }
}

/// The diagnostics log within [`data_dir`] (capture start/runtime failures).
pub fn diagnostics_log_path() -> PathBuf {
    data_dir().join("netcontrol.log")
}

/// The config file path within [`data_dir`].
pub fn config_path() -> PathBuf {
    data_dir().join("config.ini")
}
