//! Mirrors the C# `CArpCalculationTests`.

use netcontrol_core::subnet::{broadcast_address, network_address};

#[test]
fn get_network_address_should_calculate_correct_subnet_base() {
    let ip = [192, 168, 1, 150];
    let mask = [255, 255, 255, 0];
    assert_eq!(network_address(ip, mask), [192, 168, 1, 0]);
}

#[test]
fn get_broadcast_address_should_calculate_correct_broadcast() {
    let ip = [192, 168, 1, 150];
    let mask = [255, 255, 255, 0];
    assert_eq!(broadcast_address(ip, mask), [192, 168, 1, 255]);
}

#[test]
fn subnet_mask_slash23_should_calculate_correct_bounds() {
    let ip = [10, 0, 1, 45];
    let mask = [255, 255, 254, 0]; // /23
    assert_eq!(network_address(ip, mask), [10, 0, 0, 0]);
    assert_eq!(broadcast_address(ip, mask), [10, 0, 1, 255]);
}
