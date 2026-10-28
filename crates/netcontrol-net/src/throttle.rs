//! Bandwidth-throttling framework.
//!
//! Ports `IBandwidthThrottler`, `BandwidthThrottlerFactory`, `TokenBucketThrottler`,
//! `LinuxTcThrottler`, and `MacDummynetThrottler`, with three deliberate design
//! changes driven by the task's honesty requirement:
//!
//! 1. **Command generation is separated from execution.** A [`ThrottlePlanner`]
//!    turns an operation into the exact OS [`ThrottleCommand`]s (verified against
//!    the C# strings via REA); a [`CommandExecutor`] decides what to do with them.
//! 2. **Dry-run is the default** on every platform ([`DryRunExecutor`]) — the
//!    commands are generated and recorded but never run.
//! 3. **Enforcement capability is reported honestly** ([`EnforcementCapability`]).
//!    The token bucket is a calculator the original never consulted on the data
//!    path; `tc`/`dnctl` rules only affect traffic that actually traverses this
//!    host; and the macOS adapter is incomplete (it configures a dummynet pipe
//!    but, like the original, never binds it to traffic via `pfctl`).
//!
//! No ARP poisoning, interception, or redirection is used to seize another
//! device's traffic. Whether a limit can take effect at all depends on the host
//! genuinely being on that device's path (see [`controls_path_for_peer`]).

use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;

use netcontrol_core::throttling::TokenBucket;

use crate::error::CancelToken;

/// The host OS family (for planner selection), independent of the build target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Windows,
    Linux,
    MacOs,
    Other,
}

impl Platform {
    /// The platform this binary is running on.
    pub fn current() -> Platform {
        if cfg!(target_os = "linux") {
            Platform::Linux
        } else if cfg!(target_os = "macos") {
            Platform::MacOs
        } else if cfg!(target_os = "windows") {
            Platform::Windows
        } else {
            Platform::Other
        }
    }
}

/// Which throttling backend is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleKind {
    /// In-process token bucket (Windows / other): calculation only.
    TokenBucket,
    /// Linux `tc` HTB queueing disciplines.
    LinuxTc,
    /// macOS `dnctl` dummynet pipes (incomplete: no `pfctl` binding).
    MacDummynet,
}

/// An honest statement of what a backend can actually enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementCapability {
    /// Computes per-IP byte budgets in process, but nothing consumes them on a
    /// data path — the original `IBandwidthThrottler` never exposed
    /// `AllowPacket`, so `CArp` never called it. Cannot limit a peer's
    /// bandwidth without forwarding that peer's packets (not implemented).
    CalculationOnly,
    /// Emits real OS shaping rules, but they only affect traffic traversing
    /// *this* host. Effective against a peer device only if this host is that
    /// device's gateway/router. Requires elevated privileges. Dry-run by default.
    PathDependent,
    /// Path-dependent *and* incomplete as written: the macOS adapter configures
    /// a dummynet pipe but never attaches it to any flow via `pfctl`, so it
    /// shapes nothing even when executed.
    IncompletePathDependent,
}

impl EnforcementCapability {
    /// Whether this backend can ever enforce a real limit as implemented.
    pub fn is_operational(self) -> bool {
        // None of the backends enforce against a peer as wired here: the token
        // bucket is never consulted, and the shapers need the host to be on the
        // peer's path (which this project never seizes). PathDependent *can*
        // shape genuinely-routed traffic, but not a peer's by default.
        false
    }

    /// A human-readable explanation.
    pub fn explain(self) -> &'static str {
        match self {
            EnforcementCapability::CalculationOnly => {
                "token-bucket budgets are computed in process but never applied to a data path; \
                 limiting a peer would require forwarding its packets (not implemented)"
            }
            EnforcementCapability::PathDependent => {
                "generates real OS shaping rules that only affect traffic traversing this host; \
                 effective against a peer only if this host is its gateway/router, and only when \
                 executed with privileges (dry-run by default)"
            }
            EnforcementCapability::IncompletePathDependent => {
                "configures a dummynet pipe but, like the original, never binds it to traffic via \
                 pfctl; shapes nothing even when executed"
            }
        }
    }
}

/// A single OS command the planner would run (program + argument vector).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThrottleCommand {
    pub program: String,
    pub args: Vec<String>,
    /// Whether a non-zero exit is tolerated (mirrors the C# `ignoreErrors`).
    pub ignore_errors: bool,
}

impl ThrottleCommand {
    fn new(program: &str, args: &[&str], ignore_errors: bool) -> Self {
        ThrottleCommand {
            program: program.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            ignore_errors,
        }
    }

    /// The command as a shell-style line, for logging / dry-run output.
    pub fn display(&self) -> String {
        if self.args.is_empty() {
            self.program.clone()
        } else {
            format!("{} {}", self.program, self.args.join(" "))
        }
    }
}

impl fmt::Display for ThrottleCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display())
    }
}

/// Errors from configuration, validation, or execution.
#[derive(Debug)]
pub enum ThrottleError {
    /// The interface name was empty/blank (mirrors the factory's `ArgumentException`).
    EmptyInterface,
    /// A rate was negative (callers should pass `0` to mean "remove / unlimited").
    NegativeRate(i32),
    /// The operation was cancelled before completing.
    Cancelled,
    /// A command failed during (non-dry-run) execution.
    ExecutionFailed { command: String, detail: String },
}

impl fmt::Display for ThrottleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThrottleError::EmptyInterface => write!(f, "interface name cannot be null or empty"),
            ThrottleError::NegativeRate(r) => {
                write!(f, "invalid rate {r} KB/s (use 0 to remove a limit)")
            }
            ThrottleError::Cancelled => write!(f, "throttle operation cancelled"),
            ThrottleError::ExecutionFailed { command, detail } => {
                write!(f, "command failed: `{command}`: {detail}")
            }
        }
    }
}

impl std::error::Error for ThrottleError {}

/// Validates an interface name (non-empty, non-blank).
pub fn validate_interface(name: &str) -> Result<(), ThrottleError> {
    if name.trim().is_empty() {
        Err(ThrottleError::EmptyInterface)
    } else {
        Ok(())
    }
}

/// Validates a requested rate. Negative rates are rejected; `0` is valid and
/// means "remove the limit".
pub fn validate_kbps(kbps: i32) -> Result<(), ThrottleError> {
    if kbps < 0 {
        Err(ThrottleError::NegativeRate(kbps))
    } else {
        Ok(())
    }
}

// ── Planners (pure command generation) ─────────────────────────────

/// Generates the OS commands for throttle operations. No execution.
pub trait ThrottlePlanner: Send {
    fn kind(&self) -> ThrottleKind;
    fn enforcement(&self) -> EnforcementCapability;
    /// One-time setup commands (root qdisc, pipe flush, …).
    fn initialize(&mut self) -> Vec<ThrottleCommand>;
    /// Commands to set (or, for `kbps <= 0`, remove) a per-IP limit.
    fn set_limit(&mut self, ip: Ipv4Addr, kbps: i32) -> Vec<ThrottleCommand>;
    /// Commands to remove a per-IP limit.
    fn remove_limit(&mut self, ip: Ipv4Addr) -> Vec<ThrottleCommand>;
    /// Commands to clear all limits (cleanup).
    fn reset_all(&mut self) -> Vec<ThrottleCommand>;
}

/// Linux `tc`/HTB planner. Faithful port of `LinuxTcThrottler` command strings.
#[derive(Debug)]
pub struct TcPlanner {
    interface: String,
    class_ids: HashMap<Ipv4Addr, i32>,
    next_class_id: i32,
}

impl TcPlanner {
    pub fn new(interface: impl Into<String>) -> Self {
        TcPlanner {
            interface: interface.into(),
            class_ids: HashMap::new(),
            next_class_id: 10,
        }
    }

    /// Allocates (or reuses) a class id for `ip`, reproducing the original
    /// `_nextClassId = (_nextClassId + 1) % 9000 + 10` progression.
    fn class_id_for(&mut self, ip: Ipv4Addr) -> i32 {
        if let Some(id) = self.class_ids.get(&ip) {
            return *id;
        }
        let id = self.next_class_id;
        self.next_class_id = (self.next_class_id + 1) % 9000 + 10;
        self.class_ids.insert(ip, id);
        id
    }
}

impl ThrottlePlanner for TcPlanner {
    fn kind(&self) -> ThrottleKind {
        ThrottleKind::LinuxTc
    }

    fn enforcement(&self) -> EnforcementCapability {
        EnforcementCapability::PathDependent
    }

    fn initialize(&mut self) -> Vec<ThrottleCommand> {
        let dev = self.interface.clone();
        vec![
            ThrottleCommand::new("tc", &["qdisc", "del", "dev", &dev, "root"], true),
            ThrottleCommand::new(
                "tc",
                &[
                    "qdisc", "add", "dev", &dev, "root", "handle", "1:", "htb", "default", "9999",
                ],
                false,
            ),
            ThrottleCommand::new(
                "tc",
                &[
                    "class", "add", "dev", &dev, "parent", "1:", "classid", "1:9999", "htb",
                    "rate", "1000mbit", "ceil", "1000mbit",
                ],
                false,
            ),
        ]
    }

    fn set_limit(&mut self, ip: Ipv4Addr, kbps: i32) -> Vec<ThrottleCommand> {
        if kbps <= 0 {
            return self.remove_limit(ip);
        }
        let class_id = self.class_id_for(ip);
        let dev = self.interface.clone();
        let ip_str = ip.to_string();
        // KB/s -> kbit/s (1 KB/s = 8 kbit/s), floored at 8.
        let rate_kbit = (kbps * 8).max(8);
        let classid = format!("1:{class_id}");
        let rate = format!("{rate_kbit}kbit");
        let dst_handle = class_id.to_string();
        let src_handle = (class_id + 10000).to_string();

        vec![
            ThrottleCommand::new(
                "tc",
                &[
                    "class", "replace", "dev", &dev, "parent", "1:", "classid", &classid, "htb",
                    "rate", &rate, "ceil", &rate,
                ],
                false,
            ),
            ThrottleCommand::new(
                "tc",
                &[
                    "filter",
                    "replace",
                    "dev",
                    &dev,
                    "protocol",
                    "ip",
                    "parent",
                    "1:",
                    "prio",
                    "1",
                    "handle",
                    &dst_handle,
                    "u32",
                    "match",
                    "ip",
                    "dst",
                    &ip_str,
                    "flowid",
                    &classid,
                ],
                false,
            ),
            ThrottleCommand::new(
                "tc",
                &[
                    "filter",
                    "replace",
                    "dev",
                    &dev,
                    "protocol",
                    "ip",
                    "parent",
                    "1:",
                    "prio",
                    "1",
                    "handle",
                    &src_handle,
                    "u32",
                    "match",
                    "ip",
                    "src",
                    &ip_str,
                    "flowid",
                    &classid,
                ],
                false,
            ),
        ]
    }

    fn remove_limit(&mut self, ip: Ipv4Addr) -> Vec<ThrottleCommand> {
        let class_id = match self.class_ids.remove(&ip) {
            Some(id) => id,
            None => return Vec::new(),
        };
        let dev = self.interface.clone();
        let classid = format!("1:{class_id}");
        let dst_handle = class_id.to_string();
        let src_handle = (class_id + 10000).to_string();
        vec![
            ThrottleCommand::new(
                "tc",
                &[
                    "filter",
                    "del",
                    "dev",
                    &dev,
                    "protocol",
                    "ip",
                    "parent",
                    "1:",
                    "prio",
                    "1",
                    "handle",
                    &dst_handle,
                    "u32",
                ],
                true,
            ),
            ThrottleCommand::new(
                "tc",
                &[
                    "filter",
                    "del",
                    "dev",
                    &dev,
                    "protocol",
                    "ip",
                    "parent",
                    "1:",
                    "prio",
                    "1",
                    "handle",
                    &src_handle,
                    "u32",
                ],
                true,
            ),
            ThrottleCommand::new(
                "tc",
                &[
                    "class", "del", "dev", &dev, "parent", "1:", "classid", &classid,
                ],
                true,
            ),
        ]
    }

    fn reset_all(&mut self) -> Vec<ThrottleCommand> {
        self.class_ids.clear();
        let dev = self.interface.clone();
        vec![ThrottleCommand::new(
            "tc",
            &["qdisc", "del", "dev", &dev, "root"],
            true,
        )]
    }
}

/// macOS `dnctl`/dummynet planner. Faithful port of `MacDummynetThrottler`,
/// **including its incompleteness**: it never binds pipes to traffic via `pfctl`.
#[derive(Debug)]
pub struct DummynetPlanner {
    #[allow(dead_code)]
    interface: String,
    pipe_ids: HashMap<Ipv4Addr, i32>,
    next_pipe_id: i32,
}

impl DummynetPlanner {
    pub fn new(interface: impl Into<String>) -> Self {
        DummynetPlanner {
            interface: interface.into(),
            pipe_ids: HashMap::new(),
            next_pipe_id: 100,
        }
    }

    fn pipe_id_for(&mut self, ip: Ipv4Addr) -> i32 {
        if let Some(id) = self.pipe_ids.get(&ip) {
            return *id;
        }
        let id = self.next_pipe_id;
        self.next_pipe_id += 1;
        self.pipe_ids.insert(ip, id);
        id
    }
}

impl ThrottlePlanner for DummynetPlanner {
    fn kind(&self) -> ThrottleKind {
        ThrottleKind::MacDummynet
    }

    fn enforcement(&self) -> EnforcementCapability {
        EnforcementCapability::IncompletePathDependent
    }

    fn initialize(&mut self) -> Vec<ThrottleCommand> {
        // The C# ctor calls ResetAll().
        self.reset_all()
    }

    fn set_limit(&mut self, ip: Ipv4Addr, kbps: i32) -> Vec<ThrottleCommand> {
        if kbps <= 0 {
            return self.remove_limit(ip);
        }
        let pipe_id = self.pipe_id_for(ip);
        let bw = format!("{kbps}KByte/s");
        let pipe = pipe_id.to_string();
        vec![ThrottleCommand::new(
            "dnctl",
            &["pipe", &pipe, "config", "bw", &bw],
            false,
        )]
    }

    fn remove_limit(&mut self, ip: Ipv4Addr) -> Vec<ThrottleCommand> {
        match self.pipe_ids.remove(&ip) {
            Some(id) => {
                let pipe = id.to_string();
                vec![ThrottleCommand::new(
                    "dnctl",
                    &["pipe", &pipe, "delete"],
                    true,
                )]
            }
            None => Vec::new(),
        }
    }

    fn reset_all(&mut self) -> Vec<ThrottleCommand> {
        self.pipe_ids.clear();
        vec![ThrottleCommand::new("dnctl", &["-q", "flush"], true)]
    }
}

/// In-process token-bucket planner (Windows / other). Emits no OS commands; it
/// maintains per-IP buckets purely for rate *calculation*.
#[derive(Debug, Default)]
pub struct TokenBucketPlanner {
    #[allow(dead_code)]
    interface: String,
    buckets: HashMap<Ipv4Addr, TokenBucket>,
}

impl TokenBucketPlanner {
    pub fn new(interface: impl Into<String>) -> Self {
        TokenBucketPlanner {
            interface: interface.into(),
            buckets: HashMap::new(),
        }
    }

    /// The configured bucket for `ip`, if any (for inspection/calculation).
    pub fn bucket(&self, ip: Ipv4Addr) -> Option<TokenBucket> {
        self.buckets.get(&ip).copied()
    }

    /// Number of IPs with a configured bucket.
    pub fn active_count(&self) -> usize {
        self.buckets.len()
    }
}

impl ThrottlePlanner for TokenBucketPlanner {
    fn kind(&self) -> ThrottleKind {
        ThrottleKind::TokenBucket
    }

    fn enforcement(&self) -> EnforcementCapability {
        EnforcementCapability::CalculationOnly
    }

    fn initialize(&mut self) -> Vec<ThrottleCommand> {
        Vec::new()
    }

    fn set_limit(&mut self, ip: Ipv4Addr, kbps: i32) -> Vec<ThrottleCommand> {
        if kbps <= 0 {
            self.buckets.remove(&ip);
        } else {
            self.buckets.insert(ip, TokenBucket::for_kbps(kbps));
        }
        Vec::new()
    }

    fn remove_limit(&mut self, ip: Ipv4Addr) -> Vec<ThrottleCommand> {
        self.buckets.remove(&ip);
        Vec::new()
    }

    fn reset_all(&mut self) -> Vec<ThrottleCommand> {
        self.buckets.clear();
        Vec::new()
    }
}

/// Selects a planner for a platform, mirroring `BandwidthThrottlerFactory.Create`
/// (Linux → tc, macOS → dummynet, everything else → token bucket).
pub fn planner_for(
    platform: Platform,
    interface: &str,
) -> Result<Box<dyn ThrottlePlanner>, ThrottleError> {
    validate_interface(interface)?;
    Ok(match platform {
        Platform::Linux => Box::new(TcPlanner::new(interface)),
        Platform::MacOs => Box::new(DummynetPlanner::new(interface)),
        Platform::Windows | Platform::Other => Box::new(TokenBucketPlanner::new(interface)),
    })
}

// ── Executors (what to do with generated commands) ─────────────────

/// How a [`CommandExecutor`] treats commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorMode {
    /// Commands are recorded, never run.
    DryRun,
    /// Commands are executed against the system.
    System,
}

/// Decides what happens to each generated command.
pub trait CommandExecutor {
    fn mode(&self) -> ExecutorMode;
    fn execute(&mut self, command: &ThrottleCommand) -> Result<(), ThrottleError>;
}

/// The **default** executor: records commands without running them.
#[derive(Debug, Default)]
pub struct DryRunExecutor {
    log: Vec<String>,
}

impl DryRunExecutor {
    pub fn new() -> Self {
        DryRunExecutor::default()
    }

    /// The recorded command lines, in order.
    pub fn log(&self) -> &[String] {
        &self.log
    }
}

impl CommandExecutor for DryRunExecutor {
    fn mode(&self) -> ExecutorMode {
        ExecutorMode::DryRun
    }

    fn execute(&mut self, command: &ThrottleCommand) -> Result<(), ThrottleError> {
        self.log.push(command.display());
        Ok(())
    }
}

/// Runs commands against the system via `std::process::Command`.
///
/// This is **never** the default and is never used by the test suite. It is
/// provided so a caller that has verified it genuinely controls the traffic path
/// (e.g. the host is the gateway) and holds the needed privileges can opt in.
pub struct SystemExecutor;

impl CommandExecutor for SystemExecutor {
    fn mode(&self) -> ExecutorMode {
        ExecutorMode::System
    }

    fn execute(&mut self, command: &ThrottleCommand) -> Result<(), ThrottleError> {
        use std::process::Command;
        let result = Command::new(&command.program).args(&command.args).status();
        match result {
            Ok(status) if status.success() || command.ignore_errors => Ok(()),
            Ok(status) => Err(ThrottleError::ExecutionFailed {
                command: command.display(),
                detail: format!("exit status {status}"),
            }),
            Err(_) if command.ignore_errors => Ok(()),
            Err(e) => Err(ThrottleError::ExecutionFailed {
                command: command.display(),
                detail: e.to_string(),
            }),
        }
    }
}

// ── Throttler (planner + executor + state) ─────────────────────────

/// Ties a platform planner to an executor. Generates commands, validates input,
/// runs commands through the executor (dry-run by default), and reports what it
/// can genuinely enforce.
pub struct Throttler {
    interface: String,
    planner: Box<dyn ThrottlePlanner>,
    executor: Box<dyn CommandExecutor>,
    cancel: CancelToken,
}

impl Throttler {
    /// Builds a throttler for the current platform with the **dry-run** executor.
    pub fn new(interface: &str) -> Result<Self, ThrottleError> {
        Throttler::with_platform(interface, Platform::current())
    }

    /// Builds a throttler for a specific platform (dry-run executor).
    pub fn with_platform(interface: &str, platform: Platform) -> Result<Self, ThrottleError> {
        let planner = planner_for(platform, interface)?;
        Ok(Throttler {
            interface: interface.to_string(),
            planner,
            executor: Box::new(DryRunExecutor::new()),
            cancel: CancelToken::new(),
        })
    }

    /// Replaces the executor (e.g. an opt-in `SystemExecutor`, or a test mock).
    pub fn with_executor(mut self, executor: Box<dyn CommandExecutor>) -> Self {
        self.executor = executor;
        self
    }

    pub fn interface(&self) -> &str {
        &self.interface
    }

    pub fn kind(&self) -> ThrottleKind {
        self.planner.kind()
    }

    pub fn is_dry_run(&self) -> bool {
        self.executor.mode() == ExecutorMode::DryRun
    }

    /// What this backend can genuinely enforce (honest report).
    pub fn enforcement(&self) -> EnforcementCapability {
        self.planner.enforcement()
    }

    /// Access the executor (e.g. to read a dry-run log). Downcast as needed.
    pub fn executor(&self) -> &dyn CommandExecutor {
        self.executor.as_ref()
    }

    fn run(
        &mut self,
        commands: Vec<ThrottleCommand>,
    ) -> Result<Vec<ThrottleCommand>, ThrottleError> {
        for command in &commands {
            if self.cancel.is_cancelled() {
                return Err(ThrottleError::Cancelled);
            }
            self.executor.execute(command)?;
        }
        Ok(commands)
    }

    /// Emits and runs setup commands. Returns the commands that were generated.
    pub fn initialize(&mut self) -> Result<Vec<ThrottleCommand>, ThrottleError> {
        let cmds = self.planner.initialize();
        self.run(cmds)
    }

    /// Sets a per-IP limit in KB/s (`0` removes it). Returns the commands.
    pub fn set_limit(
        &mut self,
        ip: Ipv4Addr,
        kbps: i32,
    ) -> Result<Vec<ThrottleCommand>, ThrottleError> {
        validate_kbps(kbps)?;
        let cmds = self.planner.set_limit(ip, kbps);
        self.run(cmds)
    }

    /// Removes a per-IP limit. Returns the commands.
    pub fn remove_limit(&mut self, ip: Ipv4Addr) -> Result<Vec<ThrottleCommand>, ThrottleError> {
        let cmds = self.planner.remove_limit(ip);
        self.run(cmds)
    }

    /// Clears all limits (cleanup). Returns the commands.
    pub fn reset_all(&mut self) -> Result<Vec<ThrottleCommand>, ThrottleError> {
        let cmds = self.planner.reset_all();
        self.run(cmds)
    }

    /// Reconciles a single device's limit with its control state, mirroring
    /// `CArp.UpdateDeviceBandwidthLimit`: a redirected, controllable device with
    /// a positive limit gets that limit; otherwise the limit is removed.
    ///
    /// Note: `redirect` here reflects the device model's flag only. This project
    /// does not perform the ARP redirection that would place the host on the
    /// peer's path, so a `true` flag does not imply genuine enforcement — see
    /// [`enforcement`](Self::enforcement).
    pub fn sync_device(
        &mut self,
        ip: Ipv4Addr,
        redirect: bool,
        can_control: bool,
        limit_kbps: i32,
    ) -> Result<Vec<ThrottleCommand>, ThrottleError> {
        if redirect && can_control && limit_kbps > 0 {
            self.set_limit(ip, limit_kbps)
        } else {
            self.remove_limit(ip)
        }
    }

    /// Cancels in-flight command execution; subsequent `run` calls fail fast.
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Whether execution has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }
}

/// Whether this host can shape a peer's bandwidth at all.
///
/// Bandwidth shaping only affects traffic that traverses this host. A peer's
/// traffic traverses this host only when this host is the peer's gateway/router
/// (`host_is_peer_gateway`). This project never performs ARP redirection to
/// insert itself into a path it does not already occupy, so for an ordinary LAN
/// host this is `false` — the throttler is a dry-run planner, not an enforcer.
pub fn controls_path_for_peer(host_is_peer_gateway: bool) -> bool {
    host_is_peer_gateway
}
