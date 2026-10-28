//! Privilege / elevation detection.
//!
//! Ported from the C# `PrivilegeDetector`. These checks are read-only: they
//! report whether the current process is elevated and give platform-specific
//! guidance. They never attempt packet capture or any network operation.

/// Determines whether the current process is running with root or
/// administrative privileges. Best-effort; never panics.
///
/// Mirrors `PrivilegeDetector.IsElevated`.
pub fn is_elevated() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }

    #[cfg(windows)]
    {
        windows_is_elevated().unwrap_or(false)
    }

    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

#[cfg(windows)]
fn windows_is_elevated() -> Option<bool> {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return None;
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret_len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);

        if ok == 0 {
            None
        } else {
            Some(elevation.TokenIsElevated != 0)
        }
    }
}

/// Verifies whether the process either has superuser privileges or packet
/// capture capabilities.
///
/// Mirrors `PrivilegeDetector.HasCaptureCapabilities`. Live capture-device
/// enumeration is out of scope for this phase (no pcap bindings), so this
/// reduces to the elevation check and always executes safely.
pub fn has_capture_capabilities() -> bool {
    is_elevated()
}

/// Returns contextual instructions guiding the user on how to elevate
/// permissions on the current OS.
///
/// Mirrors `PrivilegeDetector.GetElevationGuidance`.
pub fn get_elevation_guidance() -> &'static str {
    if cfg!(windows) {
        "Please restart NetControl with 'Run as administrator' to enable packet capture and ARP redirection."
    } else {
        "Launch with 'pkexec' or 'sudo -E ./NetControl', or grant raw socket capabilities via 'sudo setcap cap_net_raw,cap_net_admin=eip <binary>'."
    }
}
