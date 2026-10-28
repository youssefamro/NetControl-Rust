//! Capture-device resolution and capture-runtime health.
//!
//! The GUI lists interfaces from the OS ([`crate::interfaces`]), but the
//! capture backend names them differently. On Windows the OS reports a friendly
//! name (`Ethernet 2`) plus an adapter GUID, while Npcap/WinPcap expose the same
//! adapter as `\Device\NPF_{GUID}`, so a lookup by display name never matches.
//! [`resolve_capture_device`] bridges the two, in priority order:
//!
//! 1. exact name (Linux/macOS, where both layers use `eth0`/`en0`);
//! 2. adapter GUID contained in the capture-device name (Windows);
//! 3. a **unique** IPv4 address match;
//! 4. a **unique** hardware (MAC) address match.
//!
//! The original C# app avoided the problem by binding SharpPcap's capture
//! devices (`\Device\NPF_{...}`) straight to the interface combo box. This port
//! keeps readable names in the GUI and resolves the capture identifier here.
//!
//! Resolution is pure and tested with synthetic device lists. The live backend
//! (`pnet`) and the Windows runtime probe are behind the `live-capture` feature.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use crate::error::NetError;
use crate::interfaces::NetInterface;

/// A device as reported by the capture backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureDevice {
    /// Backend identifier used to open the device (`\Device\NPF_{GUID}`, `eth0`).
    pub name: String,
    /// Backend description (e.g. the adapter model on Windows); may be empty.
    pub description: String,
    pub mac: Option<[u8; 6]>,
    pub ipv4: Vec<Ipv4Addr>,
}

/// How an OS interface was matched to a capture device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchedBy {
    Name,
    AdapterGuid,
    Ipv4,
    Mac,
}

impl MatchedBy {
    pub fn label(self) -> &'static str {
        match self {
            MatchedBy::Name => "name",
            MatchedBy::AdapterGuid => "adapter GUID",
            MatchedBy::Ipv4 => "IPv4 address",
            MatchedBy::Mac => "MAC address",
        }
    }
}

/// An OS interface resolved to its capture device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedDevice {
    pub device: CaptureDevice,
    pub matched_by: MatchedBy,
}

impl ResolvedDevice {
    /// One-line description for diagnostics.
    pub fn summary(&self) -> String {
        format!(
            "{} (matched by {})",
            self.device.name,
            self.matched_by.label()
        )
    }
}

/// Resolves `target` (an OS interface) to one of the backend `devices`.
pub fn resolve_capture_device(
    target: &NetInterface,
    devices: &[CaptureDevice],
) -> Result<ResolvedDevice, NetError> {
    let found = |d: &CaptureDevice, by| {
        Ok(ResolvedDevice {
            device: d.clone(),
            matched_by: by,
        })
    };

    if let Some(d) = devices.iter().find(|d| d.name == target.name) {
        return found(d, MatchedBy::Name);
    }

    if let Some(guid) = target
        .adapter_id
        .as_deref()
        .map(normalize_guid)
        .filter(|g| !g.is_empty())
    {
        if let Some(d) = devices
            .iter()
            .find(|d| normalize_guid(&d.name).ends_with(&guid))
        {
            return found(d, MatchedBy::AdapterGuid);
        }
    }

    if !target.ipv4.is_unspecified() {
        if let Some(d) = unique(devices, |d| d.ipv4.contains(&target.ipv4)) {
            return found(d, MatchedBy::Ipv4);
        }
    }

    if let Some(mac) = target.mac.filter(is_usable_mac) {
        if let Some(d) = unique(devices, |d| d.mac == Some(mac)) {
            return found(d, MatchedBy::Mac);
        }
    }

    Err(NetError::CaptureDeviceNotFound {
        interface: target.name.clone(),
        available: devices.iter().map(describe).collect(),
    })
}

fn unique(
    devices: &[CaptureDevice],
    pred: impl Fn(&CaptureDevice) -> bool,
) -> Option<&CaptureDevice> {
    let mut it = devices.iter().filter(|d| pred(d));
    let first = it.next()?;
    it.next().is_none().then_some(first)
}

/// Upper-cases and strips braces so `{d9cd...}` and `D9CD...` compare equal.
fn normalize_guid(s: &str) -> String {
    s.trim()
        .trim_end_matches('}')
        .to_ascii_uppercase()
        .replace('{', "")
}

fn is_usable_mac(mac: &[u8; 6]) -> bool {
    *mac != [0u8; 6] && *mac != [0xffu8; 6]
}

fn describe(d: &CaptureDevice) -> String {
    if d.description.is_empty() {
        d.name.clone()
    } else {
        format!("{} [{}]", d.name, d.description)
    }
}

/// Shared health flags for a capture thread, surfaced in the GUI diagnostics.
#[derive(Debug, Default)]
pub struct CaptureHealth {
    failed: AtomicBool,
    last_error: Mutex<Option<String>>,
}

impl CaptureHealth {
    /// Records a terminal failure; the thread stops after reporting it.
    pub fn fail(&self, why: impl Into<String>) {
        *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(why.into());
        self.failed.store(true, Ordering::SeqCst);
    }

    pub fn has_failed(&self) -> bool {
        self.failed.load(Ordering::SeqCst)
    }

    pub fn last_error(&self) -> Option<String> {
        self.last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// Availability of the packet-capture runtime on this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeStatus {
    /// The runtime is loadable; the string describes it (e.g. the DLL path).
    Available(String),
    /// The runtime is missing; capture must not be attempted.
    Missing(String),
    /// This build does not include live capture.
    NotCompiled,
}

impl RuntimeStatus {
    pub fn is_available(&self) -> bool {
        matches!(self, RuntimeStatus::Available(_))
    }

    pub fn describe(&self) -> String {
        match self {
            RuntimeStatus::Available(what) => what.clone(),
            RuntimeStatus::Missing(why) => why.clone(),
            RuntimeStatus::NotCompiled => "live capture is not compiled into this build".into(),
        }
    }
}

/// Classifies a loaded `Packet.dll` path (Windows) for diagnostics.
pub fn describe_packet_dll(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    if lower.contains("\\npcap\\") {
        format!("Npcap runtime loaded ({path})")
    } else {
        format!(
            "WinPcap-compatible runtime loaded ({path}). Npcap is recommended; legacy WinPcap \
             is unmaintained and may not capture on current Windows versions"
        )
    }
}

/// Probes the capture runtime. Without `live-capture` this is always
/// [`RuntimeStatus::NotCompiled`].
#[cfg(not(feature = "live-capture"))]
pub fn runtime_status() -> RuntimeStatus {
    RuntimeStatus::NotCompiled
}

#[cfg(feature = "live-capture")]
pub use live::{capture_devices, open_receiver, resolve_live, runtime_status};

#[cfg(feature = "live-capture")]
mod live {
    use std::time::Duration;

    use pnet::datalink::{self, Channel, DataLinkReceiver};
    use pnet::ipnetwork::IpNetwork;

    use super::{resolve_capture_device, CaptureDevice, ResolvedDevice, RuntimeStatus};
    use crate::error::NetError;
    use crate::interfaces::NetInterface;

    /// Read timeout so loops can observe cancellation. Honoured on Linux/macOS;
    /// pnet's Windows backend ignores it, so stop is also bounded by the caller.
    pub(crate) const READ_TIMEOUT: Duration = Duration::from_millis(250);

    /// Probes (once) whether the capture runtime can be loaded.
    pub fn runtime_status() -> RuntimeStatus {
        static STATUS: std::sync::OnceLock<RuntimeStatus> = std::sync::OnceLock::new();
        STATUS.get_or_init(probe).clone()
    }

    #[cfg(windows)]
    fn probe() -> RuntimeStatus {
        use windows_sys::Win32::System::LibraryLoader::{
            GetModuleFileNameW, LoadLibraryW, SetDllDirectoryW,
        };

        fn wide(s: &str) -> Vec<u16> {
            s.encode_utf16().chain(std::iter::once(0)).collect()
        }

        // Npcap (without WinPcap-compatibility mode) installs Packet.dll only in
        // System32\Npcap. Packet.dll is delay-loaded by the GUI binary, so adding
        // this directory before the first capture call lets it resolve there.
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let npcap_dir = std::path::Path::new(&system_root).join(r"System32\Npcap");
        if npcap_dir.is_dir() {
            let w = wide(&npcap_dir.to_string_lossy());
            // SAFETY: `w` is a valid NUL-terminated UTF-16 string.
            unsafe { SetDllDirectoryW(w.as_ptr()) };
        }

        let name = wide("Packet.dll");
        // SAFETY: valid NUL-terminated UTF-16 module name. The handle is kept
        // loaded for the life of the process (capture uses it).
        let module = unsafe { LoadLibraryW(name.as_ptr()) };
        if module.is_null() {
            return RuntimeStatus::Missing(
                "Packet.dll could not be loaded: Npcap is not installed. Install Npcap from \
                 https://npcap.com/ and restart NetControl"
                    .into(),
            );
        }
        let mut buf = [0u16; 520];
        // SAFETY: buffer pointer/length are valid for writes.
        let len = unsafe { GetModuleFileNameW(module, buf.as_mut_ptr(), buf.len() as u32) };
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        RuntimeStatus::Available(super::describe_packet_dll(&path))
    }

    #[cfg(not(windows))]
    fn probe() -> RuntimeStatus {
        RuntimeStatus::Available(if cfg!(target_os = "linux") {
            "raw packet sockets (AF_PACKET); requires root or CAP_NET_RAW".into()
        } else {
            "BPF devices (/dev/bpf*); requires root".into()
        })
    }

    fn ensure_runtime() -> Result<(), NetError> {
        match runtime_status() {
            RuntimeStatus::Available(_) => Ok(()),
            other => Err(NetError::CaptureUnavailable(other.describe())),
        }
    }

    fn backend_interfaces() -> Result<Vec<datalink::NetworkInterface>, NetError> {
        ensure_runtime()?;
        // pnet panics on Windows if the driver refuses to list adapters.
        std::panic::catch_unwind(datalink::interfaces).map_err(|_| {
            NetError::CaptureUnavailable(
                "the capture driver failed to list adapters (is the Npcap service running?)".into(),
            )
        })
    }

    /// Lists the backend's capture devices.
    pub fn capture_devices() -> Result<Vec<CaptureDevice>, NetError> {
        Ok(backend_interfaces()?
            .into_iter()
            .map(|i| CaptureDevice {
                ipv4: i
                    .ips
                    .iter()
                    .filter_map(|n| match n {
                        IpNetwork::V4(v4) => Some(v4.ip()),
                        IpNetwork::V6(_) => None,
                    })
                    .collect(),
                mac: i.mac.map(|m| m.octets()),
                name: i.name,
                description: i.description,
            })
            .collect())
    }

    /// Resolves an OS interface against the live backend device list.
    pub fn resolve_live(target: &NetInterface) -> Result<ResolvedDevice, NetError> {
        resolve_capture_device(target, &capture_devices()?)
    }

    /// Opens a read-only receiver on a resolved backend device.
    pub fn open_receiver(device: &CaptureDevice) -> Result<Box<dyn DataLinkReceiver>, NetError> {
        let iface = backend_interfaces()?
            .into_iter()
            .find(|i| i.name == device.name)
            .ok_or_else(|| NetError::CaptureDeviceNotFound {
                interface: device.name.clone(),
                available: Vec::new(),
            })?;
        let config = datalink::Config {
            read_timeout: Some(READ_TIMEOUT),
            ..Default::default()
        };
        match datalink::channel(&iface, config) {
            Ok(Channel::Ethernet(_tx, rx)) => Ok(rx),
            Ok(_) => Err(NetError::CaptureUnavailable(
                "unsupported channel type".into(),
            )),
            Err(error) => Err(NetError::CaptureOpenFailed {
                device: device.name.clone(),
                error,
            }),
        }
    }
}

/// Whether a receive error is just the read timeout (not a failure).
pub fn is_idle_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

/// How long Stop waits for a capture thread before detaching it.
pub const STOP_GRACE: std::time::Duration = std::time::Duration::from_millis(1500);

/// Joins `handle` if the thread finishes within `grace`; otherwise detaches it.
///
/// pnet's Windows backend blocks in `PacketReceivePacket` until a frame arrives
/// (it ignores the read timeout), so Stop must not hang the UI on a quiet link.
/// A detached thread has already been cancelled and exits on its next frame.
pub fn join_with_grace(handle: std::thread::JoinHandle<()>, grace: std::time::Duration) {
    let start = std::time::Instant::now();
    while !handle.is_finished() {
        if start.elapsed() >= grace {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let _ = handle.join();
}
