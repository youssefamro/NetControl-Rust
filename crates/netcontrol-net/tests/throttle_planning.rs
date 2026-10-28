//! Throttle command-generation, dry-run, validation, and cleanup tests.
//! No OS shaping rules are applied; execution is dry-run or mocked.

use std::net::Ipv4Addr;

use netcontrol_net::throttle::{
    controls_path_for_peer, planner_for, CommandExecutor, DryRunExecutor, EnforcementCapability,
    ExecutorMode, Platform, ThrottleCommand, ThrottleError, ThrottleKind, ThrottlePlanner,
    Throttler, TokenBucketPlanner,
};

const IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);

fn lines(cmds: &[ThrottleCommand]) -> Vec<String> {
    cmds.iter().map(|c| c.display()).collect()
}

// ── Linux tc command generation ────────────────────────────────────

#[test]
fn tc_init_matches_original_commands() {
    let mut p = netcontrol_net::throttle::TcPlanner::new("eth0");
    assert_eq!(
        lines(&p.initialize()),
        vec![
            "tc qdisc del dev eth0 root",
            "tc qdisc add dev eth0 root handle 1: htb default 9999",
            "tc class add dev eth0 parent 1: classid 1:9999 htb rate 1000mbit ceil 1000mbit",
        ]
    );
}

#[test]
fn tc_set_limit_generates_class_and_filters() {
    let mut p = netcontrol_net::throttle::TcPlanner::new("eth0");
    // 100 KB/s -> 800 kbit/s; first class id = 10; src filter handle = 10010.
    assert_eq!(
        lines(&p.set_limit(IP, 100)),
        vec![
            "tc class replace dev eth0 parent 1: classid 1:10 htb rate 800kbit ceil 800kbit",
            "tc filter replace dev eth0 protocol ip parent 1: prio 1 handle 10 u32 match ip dst 192.168.1.50 flowid 1:10",
            "tc filter replace dev eth0 protocol ip parent 1: prio 1 handle 10010 u32 match ip src 192.168.1.50 flowid 1:10",
        ]
    );
}

#[test]
fn tc_class_id_progression_matches_original_formula() {
    let mut p = netcontrol_net::throttle::TcPlanner::new("eth0");
    // _nextClassId = (_nextClassId + 1) % 9000 + 10, starting at 10 -> 10, 21, 32.
    let ids: Vec<i32> = [10u8, 11, 12]
        .iter()
        .map(|o| {
            let cmds = p.set_limit(Ipv4Addr::new(10, 0, 0, *o), 100);
            // The classid "1:<id>" is the arg right after "classid".
            let args = &cmds[0].args;
            let pos = args.iter().position(|a| a == "classid").unwrap();
            args[pos + 1]
                .strip_prefix("1:")
                .unwrap()
                .parse::<i32>()
                .unwrap()
        })
        .collect();
    assert_eq!(ids, vec![10, 21, 32]);
}

#[test]
fn tc_rate_is_floored_at_8_kbit() {
    let mut p = netcontrol_net::throttle::TcPlanner::new("eth0");
    // 0 KB/s would remove; 1 KB/s -> 8 kbit; a sub-unit is impossible (int), so
    // the floor matters for the max(8, kbps*8) guard at kbps such as... use 1.
    let cmds = p.set_limit(IP, 1);
    assert!(cmds[0].display().contains("rate 8kbit ceil 8kbit"));
}

#[test]
fn tc_remove_limit_tears_down_filters_and_class() {
    let mut p = netcontrol_net::throttle::TcPlanner::new("eth0");
    p.set_limit(IP, 100); // allocate class id 10
    assert_eq!(
        lines(&p.remove_limit(IP)),
        vec![
            "tc filter del dev eth0 protocol ip parent 1: prio 1 handle 10 u32",
            "tc filter del dev eth0 protocol ip parent 1: prio 1 handle 10010 u32",
            "tc class del dev eth0 parent 1: classid 1:10",
        ]
    );
    // Removing an unknown IP yields no commands.
    assert!(p.remove_limit(Ipv4Addr::new(10, 10, 10, 10)).is_empty());
}

#[test]
fn tc_set_limit_zero_is_a_removal() {
    let mut p = netcontrol_net::throttle::TcPlanner::new("eth0");
    p.set_limit(IP, 100);
    let removal = p.set_limit(IP, 0);
    assert_eq!(removal.len(), 3);
    assert!(removal[0].display().starts_with("tc filter del"));
}

// ── macOS dnctl command generation ─────────────────────────────────

#[test]
fn dummynet_commands_match_original_and_are_incomplete() {
    let mut p = netcontrol_net::throttle::DummynetPlanner::new("en0");
    assert_eq!(lines(&p.initialize()), vec!["dnctl -q flush"]);
    assert_eq!(
        lines(&p.set_limit(IP, 250)),
        vec!["dnctl pipe 100 config bw 250KByte/s"]
    );
    assert_eq!(lines(&p.remove_limit(IP)), vec!["dnctl pipe 100 delete"]);
    // Faithful to the original's incompleteness: no pfctl binding is emitted.
    assert_eq!(
        p.enforcement(),
        EnforcementCapability::IncompletePathDependent
    );
}

// ── Token-bucket planner emits no OS commands ──────────────────────

#[test]
fn token_bucket_planner_emits_no_commands() {
    let mut p = TokenBucketPlanner::new("Ethernet 2");
    assert!(p.initialize().is_empty());
    assert!(p.set_limit(IP, 500).is_empty());
    assert_eq!(p.active_count(), 1);
    assert!(p.bucket(IP).is_some());
    assert!(p.remove_limit(IP).is_empty());
    assert_eq!(p.active_count(), 0);
    assert_eq!(p.enforcement(), EnforcementCapability::CalculationOnly);
}

// ── Platform selection (factory) ───────────────────────────────────

#[test]
fn platform_selection_matches_factory() {
    assert_eq!(
        planner_for(Platform::Linux, "eth0").unwrap().kind(),
        ThrottleKind::LinuxTc
    );
    assert_eq!(
        planner_for(Platform::MacOs, "en0").unwrap().kind(),
        ThrottleKind::MacDummynet
    );
    assert_eq!(
        planner_for(Platform::Windows, "Ethernet").unwrap().kind(),
        ThrottleKind::TokenBucket
    );
    assert_eq!(
        planner_for(Platform::Other, "any").unwrap().kind(),
        ThrottleKind::TokenBucket
    );
}

#[test]
fn empty_interface_is_rejected() {
    assert!(matches!(
        planner_for(Platform::Linux, "   "),
        Err(ThrottleError::EmptyInterface)
    ));
    assert!(matches!(
        Throttler::with_platform("", Platform::Linux),
        Err(ThrottleError::EmptyInterface)
    ));
}

// ── Throttler: dry-run default, validation, cancellation, cleanup ──

#[test]
fn throttler_is_dry_run_by_default_and_records_commands() {
    let mut t = Throttler::with_platform("eth0", Platform::Linux).unwrap();
    assert!(t.is_dry_run());
    assert_eq!(t.kind(), ThrottleKind::LinuxTc);
    assert_eq!(t.enforcement(), EnforcementCapability::PathDependent);

    let init = t.initialize().unwrap();
    assert_eq!(init.len(), 3);
    let set = t.set_limit(IP, 100).unwrap();
    assert_eq!(set.len(), 3);
}

#[test]
fn throttler_rejects_negative_rate() {
    let mut t = Throttler::with_platform("eth0", Platform::Linux).unwrap();
    assert!(matches!(
        t.set_limit(IP, -5),
        Err(ThrottleError::NegativeRate(-5))
    ));
}

#[test]
fn throttler_sync_device_sets_or_removes() {
    let mut t = Throttler::with_platform("eth0", Platform::Linux).unwrap();
    // redirect + controllable + positive limit -> set (class + 2 filters).
    assert_eq!(t.sync_device(IP, true, true, 100).unwrap().len(), 3);
    // not redirected -> removal (filters + class teardown).
    assert_eq!(t.sync_device(IP, false, true, 100).unwrap().len(), 3);
    // redirected but zero limit -> removal (no active id now -> empty).
    assert!(t.sync_device(IP, true, true, 0).unwrap().is_empty());
}

#[test]
fn throttler_reset_all_is_cleanup() {
    let mut t = Throttler::with_platform("eth0", Platform::Linux).unwrap();
    t.set_limit(IP, 100).unwrap();
    assert_eq!(
        lines(&t.reset_all().unwrap()),
        vec!["tc qdisc del dev eth0 root"]
    );
}

#[test]
fn throttler_cancellation_stops_execution() {
    let mut t = Throttler::with_platform("eth0", Platform::Linux).unwrap();
    t.cancel();
    assert!(t.is_cancelled());
    assert!(matches!(
        t.set_limit(IP, 100),
        Err(ThrottleError::Cancelled)
    ));
}

// A mock executor that fails, to exercise error propagation.
struct FailingExecutor;
impl CommandExecutor for FailingExecutor {
    fn mode(&self) -> ExecutorMode {
        ExecutorMode::System
    }
    fn execute(&mut self, command: &ThrottleCommand) -> Result<(), ThrottleError> {
        Err(ThrottleError::ExecutionFailed {
            command: command.display(),
            detail: "mock failure".into(),
        })
    }
}

#[test]
fn throttler_propagates_execution_errors() {
    let mut t = Throttler::with_platform("eth0", Platform::Linux)
        .unwrap()
        .with_executor(Box::new(FailingExecutor));
    assert!(!t.is_dry_run());
    assert!(matches!(
        t.initialize(),
        Err(ThrottleError::ExecutionFailed { .. })
    ));
}

#[test]
fn dry_run_executor_records_without_running() {
    let mut ex = DryRunExecutor::new();
    assert_eq!(ex.mode(), ExecutorMode::DryRun);
    let cmd = ThrottleCommand {
        program: "tc".into(),
        args: vec!["qdisc".into(), "del".into()],
        ignore_errors: true,
    };
    ex.execute(&cmd).unwrap();
    assert_eq!(ex.log(), &["tc qdisc del".to_string()]);
}

// ── Honest enforcement reporting ───────────────────────────────────

#[test]
fn no_backend_claims_operational_enforcement() {
    for cap in [
        EnforcementCapability::CalculationOnly,
        EnforcementCapability::PathDependent,
        EnforcementCapability::IncompletePathDependent,
    ] {
        assert!(!cap.is_operational(), "{cap:?} must not claim enforcement");
        assert!(!cap.explain().is_empty());
    }
}

#[test]
fn path_control_requires_being_the_peers_gateway() {
    // This host controls a peer's path only if it is that peer's gateway.
    assert!(!controls_path_for_peer(false));
    assert!(controls_path_for_peer(true));
}
