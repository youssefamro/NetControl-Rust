//! Deterministic token-bucket rate-control tests (time injected explicitly).

use netcontrol_core::throttling::TokenBucket;

#[test]
fn capacity_is_one_and_a_half_seconds_floored_at_4096() {
    // 100 KB/s -> 102400 B/s -> capacity 153600.
    assert_eq!(TokenBucket::capacity_for(102_400), 153_600);
    // Tiny rate floored at 4096.
    assert_eq!(TokenBucket::capacity_for(1000), 4096);
    assert_eq!(TokenBucket::capacity_for(0), 4096);
}

#[test]
fn for_kbps_sets_rate_and_full_tokens() {
    let b = TokenBucket::for_kbps(100);
    assert_eq!(b.rate_bytes_per_sec(), 102_400.0);
    assert_eq!(b.capacity(), 153_600.0);
    assert_eq!(b.tokens(), 153_600.0); // starts full
}

#[test]
fn consume_within_budget_succeeds_and_depletes() {
    let mut b = TokenBucket::new(1000, 1000);
    // Full bucket: consume all 1000 with no time passing.
    assert!(b.try_consume(1000, 0.0));
    assert_eq!(b.tokens(), 0.0);
    // Nothing left this instant.
    assert!(!b.try_consume(1, 0.0));
}

#[test]
fn boundary_exact_budget_passes_one_more_byte_fails() {
    let mut b = TokenBucket::new(1000, 1000);
    assert!(b.try_consume(999, 0.0));
    assert!(b.try_consume(1, 0.0)); // exactly empties
    assert!(!b.try_consume(1, 0.0));
}

#[test]
fn tokens_replenish_over_time() {
    let mut b = TokenBucket::new(1000, 1000); // 1000 B/s, cap 1000
    assert!(b.try_consume(1000, 0.0)); // empty
    assert_eq!(b.tokens(), 0.0);

    // Half a second -> +500 tokens; consume 400 leaves 100.
    assert!(b.try_consume(400, 0.5));
    assert!((b.tokens() - 100.0).abs() < 1e-9);

    // Not enough yet for a 300-byte packet with no further time.
    assert!(!b.try_consume(300, 0.0));
}

#[test]
fn refill_is_capped_at_capacity() {
    let mut b = TokenBucket::new(1000, 1000);
    b.try_consume(1000, 0.0); // empty
    b.refill(100.0); // way more than capacity worth of time
    assert_eq!(b.tokens(), 1000.0); // capped
}

#[test]
fn set_rate_clamps_tokens_to_new_capacity() {
    let mut b = TokenBucket::new(1000, 10_000);
    assert_eq!(b.tokens(), 10_000.0);
    b.set_rate(500, 2000);
    assert_eq!(b.capacity(), 2000.0);
    assert_eq!(b.tokens(), 2000.0); // clamped down
}

#[test]
fn throttler_enforces_per_ip_budget() {
    use netcontrol_core::throttling::TokenBucketThrottler;
    use std::net::Ipv4Addr;

    let mut t = TokenBucketThrottler::new("eth0");
    let ip = Ipv4Addr::new(192, 168, 1, 50);

    // Un-limited IPs always pass.
    assert!(t.allow_packet(ip, 1500));

    // After a limit, a packet within the (large initial) burst passes.
    t.set_limit(ip, 100);
    assert_eq!(t.active_limit_count(), 1);
    assert!(t.allow_packet(ip, 1500));

    // Removing the limit returns the IP to always-pass.
    t.remove_limit(ip);
    assert_eq!(t.active_limit_count(), 0);
    assert!(t.allow_packet(ip, 1_000_000));
}
