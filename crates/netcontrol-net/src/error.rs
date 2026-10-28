//! Error type and cooperative cancellation for the networking layer.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Errors produced by the networking layer.
#[derive(Debug)]
pub enum NetError {
    /// Active discovery was attempted on a network that has not been authorized.
    NotAuthorized,
    /// The requested network interface could not be found.
    InterfaceNotFound(String),
    /// The OS interface exists, but the capture backend (Npcap/WinPcap on
    /// Windows, raw sockets/BPF elsewhere) reports no matching capture device.
    CaptureDeviceNotFound {
        /// The interface as the user selected it (friendly name).
        interface: String,
        /// Capture-device names the backend did report (may be empty).
        available: Vec<String>,
    },
    /// The capture device was found but could not be opened.
    CaptureOpenFailed {
        /// The backend device name (e.g. `\Device\NPF_{GUID}`).
        device: String,
        error: std::io::Error,
    },
    /// Live packet capture is not available (feature disabled or backend error).
    CaptureUnavailable(String),
    /// An underlying I/O error.
    Io(std::io::Error),
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetError::NotAuthorized => write!(
                f,
                "active discovery is not authorized for this network (disabled by default)"
            ),
            NetError::InterfaceNotFound(name) => write!(
                f,
                "interface not found: {name} (it may have been disconnected; refresh the interface list)"
            ),
            NetError::CaptureDeviceNotFound {
                interface,
                available,
            } => {
                if available.is_empty() {
                    write!(
                        f,
                        "no capture devices are available for interface {interface}: the capture driver reported none. On Windows, install Npcap and make sure its service is running; on Linux/macOS, run with capture privileges"
                    )
                } else {
                    write!(
                        f,
                        "interface {interface} has no matching capture device (the capture driver reports: {})",
                        available.join(", ")
                    )
                }
            }
            NetError::CaptureOpenFailed { device, error } => write!(
                f,
                "could not open capture device {device}: {error}. {}",
                capture_error_hint(error)
            ),
            NetError::CaptureUnavailable(why) => write!(f, "live capture unavailable: {why}"),
            NetError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for NetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NetError::Io(e) => Some(e),
            NetError::CaptureOpenFailed { error, .. } => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for NetError {
    fn from(e: std::io::Error) -> Self {
        NetError::Io(e)
    }
}

/// A user-facing remedy for a capture-device open failure.
///
/// Windows codes come from `PacketOpenAdapter`'s `GetLastError`; Unix errors
/// come from opening a raw socket / BPF device.
pub fn capture_error_hint(error: &std::io::Error) -> &'static str {
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_PATH_NOT_FOUND: i32 = 3;
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_GEN_FAILURE: i32 = 31;
    const EPERM: i32 = 1;
    const EACCES: i32 = 13;

    let code = error.raw_os_error();
    if cfg!(windows) {
        match code {
            Some(ERROR_ACCESS_DENIED) => {
                return "Permission denied: run NetControl as Administrator (Npcap may be installed in administrator-only mode).";
            }
            Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND | ERROR_GEN_FAILURE) => {
                return "The capture driver could not open this adapter: check that Npcap is installed, its service is running, and the adapter is enabled.";
            }
            _ => {}
        }
    } else if matches!(code, Some(EPERM | EACCES)) {
        return "Permission denied: run as root, or grant the binary CAP_NET_RAW (Linux: sudo setcap cap_net_raw,cap_net_admin=eip <binary>).";
    }
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        return "Permission denied: run NetControl with administrator/root privileges.";
    }
    "Check that the capture runtime is installed and that you have capture privileges."
}

/// A cheap, clonable cooperative-cancellation flag shared across threads.
///
/// Long-running loops (the live ARP listener and discovery sender) poll
/// [`is_cancelled`](CancelToken::is_cancelled) and stop promptly when
/// [`cancel`](CancelToken::cancel) is called.
#[derive(Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        CancelToken(Arc::new(AtomicBool::new(false)))
    }

    /// Requests cancellation.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}
