//! Mirrors the C# `PrivilegeDetectorTests`.

use netcontrol_core::privilege;

#[test]
fn get_elevation_guidance_should_return_platform_guidance() {
    let guidance = privilege::get_elevation_guidance();
    assert!(!guidance.trim().is_empty());
    assert!(
        guidance.contains("pkexec")
            || guidance.contains("administrator")
            || guidance.contains("sudo"),
        "Guidance must contain platform elevation instructions: {guidance}"
    );
}

#[test]
fn is_elevated_should_execute_without_panicking() {
    // Verifies that the OS privilege check executes safely across platforms.
    let _elevated = privilege::is_elevated();
}

#[test]
fn has_capture_capabilities_should_execute_safely() {
    let _caps = privilege::has_capture_capabilities();
}
