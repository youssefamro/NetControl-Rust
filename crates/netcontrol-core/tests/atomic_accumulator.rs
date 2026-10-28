//! Mirrors the C# `AtomicAccumulatorTests`.

mod common;

use std::net::Ipv4Addr;
use std::thread;

use netcontrol_core::Pc;

#[test]
fn atomic_accumulators_should_accumulate_bytes_correctly_under_concurrency() {
    let mut pc = Pc::new();
    pc.ip = Some(Ipv4Addr::new(192, 168, 1, 100));
    pc.mac = Some(common::parse_mac("001122334455"));

    // 10 parallel threads each adding 1000 packets of 1500 bytes.
    thread::scope(|scope| {
        for _ in 0..10 {
            scope.spawn(|| {
                for _ in 0..1000 {
                    pc.add_bytes_received(1500);
                    pc.add_bytes_sent(1500);
                }
            });
        }
    });

    assert_eq!(pc.bytes_received(), 15_000_000);
    assert_eq!(pc.bytes_sent(), 15_000_000);

    let (down, up) = pc.reset_byte_accumulators();
    assert_eq!(down, 15_000_000);
    assert_eq!(up, 15_000_000);
    assert_eq!(pc.bytes_received(), 0);
    assert_eq!(pc.bytes_sent(), 0);
}
