# NetControl — Rust rebuild

A Rust reimplementation of [NetControl](https://github.com/nov0caina/NetControl)
(C# / .NET 8 / Avalonia, MIT) by Abel Meza Enriquez. NetControl shows the
devices on a local network and their bandwidth use, in a desktop GUI built with
egui.

**Version 0.1.0.** Windows x64 is built, packaged, and smoke-tested. Linux and
macOS have build scripts but are **untested**.

## What works, and what does not

| Feature | Status |
| --- | --- |
| Demonstration mode (simulated devices, real classification/EMA pipeline) | Working |
| Live mode: passive ARP device discovery | Working on Windows with Npcap¹ |
| Live mode: per-device upload/download rates | Working on Windows with Npcap¹ |
| Interface selection by readable name (`Ethernet 2 — 192.168.1.119`) | Working |
| Device identification (OUI vendor, device type) | Working (offline) |
| Settings persistence | Working |
| Bandwidth limits | **Dry run only** — planned commands are shown, never applied |
| ARP redirection / spoofing, interception | **Not implemented** |
| Blocking devices | **Not implemented** (the Block flag is a marker) |
| Active scanning / probing | **Not used** by the GUI (listening is passive) |
| Linux / macOS | **Untested** |

¹ Capture start-up, interface resolution, and runtime detection were verified on
the development machine; sustained live capture results depend on the network
and are verified manually.

**Install and use:** see [docs/INSTALL.md](docs/INSTALL.md) — Windows installer
and portable ZIP, Npcap, administrator rights, selecting an interface,
Demonstration vs. Live, troubleshooting, and known limitations.

## Workspace

| Crate | Contents |
| --- | --- |
| `netcontrol-core` | Device model, OUI table, device classification, subnet math, privilege detection, EMA and token-bucket math (no I/O) |
| `netcontrol-net` | Ethernet/ARP, passive listener, interface enumeration, capture-device resolution, discovery planning, hostname probes, traffic accounting, dry-run throttle planning |
| `netcontrol-gui` | egui application (`UiState` holds the tested logic; `app.rs` the view) |

Live packet capture (`pnet`) is behind the off-by-default `live-capture`
feature. Without it everything builds and tests with no capture library.

```
NetControl-Rust/
  crates/netcontrol-core/        # P1 core logic + tests
  crates/netcontrol-net/         # P2–P5 networking + tests
    src/capture.rs               # OS interface -> capture device; runtime probe
    build.rs                     # finds the Npcap SDK (Packet.lib) for live builds
    examples/list_capture_devices.rs
  crates/netcontrol-gui/         # P6 GUI + tests
    assets/                      # application icon (from the original project)
    build.rs                     # icon/version resources; delay-loads Packet.dll
  packaging/windows/             # build-release.ps1, install/uninstall, Inno Setup
  packaging/linux/, macos/       # untested build scripts
  docs/INSTALL.md                # user documentation
  docs/releases/                 # release notes
  scripts/test-app.ps1           # check + launch workflow for development
```

## Building from source

Requirements:

- Rust stable with the MSVC toolchain (`x86_64-pc-windows-msvc`) and Visual
  Studio Build Tools (C++).
- For the Live-capable build only: the [Npcap SDK](https://npcap.com/#download).
  `crates/netcontrol-net/build.rs` looks in `NPCAP_SDK_DIR` (or `NPCAP_SDK`),
  then `D:\DevTools\NpcapSDK`, `C:\Program Files\NpcapSDK`, `C:\NpcapSDK`,
  `C:\npcap-sdk`.
- Optional: the Windows SDK `rc.exe` (embeds the icon and version info; found
  automatically, or set `RC`). Without it the build succeeds without an icon.

```powershell
# Demonstration-only GUI
cargo build --release -p netcontrol-gui
# Live-capable GUI
cargo build --release -p netcontrol-gui --features live-capture
# Run
cargo run --release -p netcontrol-gui --features live-capture
```

### Verification

```powershell
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --features netcontrol-gui/live-capture -- -D warnings
cargo build --release -p netcontrol-gui --features live-capture
```

Read-only check of how this machine's interfaces map to capture devices (opens
no device, captures nothing):

```powershell
cargo run -p netcontrol-net --features live-capture --example list_capture_devices
```

`scripts\test-app.ps1` runs the checks and launches the GUI in Demonstration
mode (`-Live` for the live build, `-NoLaunch` for checks only); it never starts
capture.

### Packaging (Windows)

```powershell
powershell -ExecutionPolicy Bypass -File packaging\windows\build-release.ps1
```

Produces in `dist\`:

- `NetControl-<ver>-windows-x64\` — staged files (`NetControl.exe` Live-capable,
  `NetControl-Demo.exe` demonstration-only, icon, docs, license, scripts);
- `NetControl-<ver>-windows-x64-portable.zip`;
- `NetControl-<ver>-windows-x64-setup.exe` (Inno Setup 6, if `ISCC.exe` is
  installed) or `NetControl-<ver>-windows-x64-user-setup.exe` (Windows
  IExpress wrapper around `install.ps1`);
- `SHA256SUMS.txt`.

The script checks that every required file is present in the stage and ZIP and
that both executables carry `NetControl <ver>` version metadata.

## Settings location

`NETCONTROL_DATA_DIR` → `netcontrol.portable` next to the executable → this
workspace's gitignored `.appdata\` (development runs from `target\`) →
`%LOCALAPPDATA%\NetControl` (Linux `~/.config/netcontrol`, macOS
`~/Library/Application Support/NetControl`). `config.ini` holds preferences;
`netcontrol.log` records capture errors.

## Networking layer (Phase P2)

`netcontrol-net` ports the packet/discovery logic of the C# `CArp`, verified
byte-for-byte against the compiled assembly with REA (see below):

| Capability | Source (C#) | Rust |
| --- | --- | --- |
| Ethernet frame parse/serialize | implicit in `BuildArpPacket` | `ethernet::EthernetHeader` |
| ARP request/reply parse | `ArpListenerLoop` | `arp::ArpPacket::parse(_frame)` |
| ARP frame construction | `BuildArpPacket` | `arp::build_frame` / `build_request` |
| Passive ARP listening | `ArpListenerLoop` | `listener::observe_arp_frame` (+ gated live loop) |
| Interface enumeration | `LoadInterfaces` | `interfaces::enumerate` / `select_ipv4` |
| Subnet device discovery | `DiscoveryLoop` | `discovery::plan_targets` / `Discovery` |
| Device tracking | `PcList` | `netcontrol_core::pc_list::PcList` |
| Cancellation / cleanup | thread flags + `Dispose` | `error::CancelToken` + `Drop` |

**Safety posture.** No ARP poisoning, interception, redirection, or disruption
is implemented. Live packet capture/transmission is behind the off-by-default
`live-capture` feature (links Npcap/libpcap); without it the crate still builds,
parses, plans, and is fully tested with synthetic frames. Active discovery
additionally requires a `discovery::AuthorizedNetwork` matching the local
subnet, so it stays disabled until a caller opts in for a network they own.

## Device identification (Phase P3)

Ports `DeviceIdentifierService`'s layered strategy to `netcontrol-net`:

| Capability | Source (C#) | Rust |
| --- | --- | --- |
| Reverse-DNS PTR build/parse | `BuildDnsPtrQuery` / `ParseDnsPtrResponse` | `dns::build_ptr_query` / `parse_ptr_response` |
| mDNS (UDP 5353) | `ProbeMdnsAsync` / `TryParseMdnsName` | `dns` + `identify` (`Protocol::Mdns`) |
| LLMNR (UDP 5355) | `ProbeLlmnrAsync` | `identify` (`Protocol::Llmnr`, txid `0x1337`) |
| NetBIOS (UDP 137) | `ResolveNetBiosNameAsync` / `ParseNetBiosResponse` | `netbios::build_node_status_query` / `parse_node_status_response` |
| SSDP (UDP 1900) | `ProbeSsdpAsync` / `ParseSsdpFriendlyName` | `ssdp::build_msearch` / `parse_server_name` |
| OUI vendor lookup | `OuiDatabase.Lookup` | `netcontrol_core::oui::lookup` (P1) |
| Randomized-MAC detection | `OuiDatabase.IsRandomizedMac` | `netcontrol_core::oui::is_randomized_mac` (P1) |
| Device-type inference | `InferDeviceType` | `netcontrol_core::device_identifier` (P1) |
| Hostname clean/select | `CleanHostname` / `SelectBestHostname` | `hostname` module |
| Orchestration + timeouts | `IdentifyDeviceAsync` | `identify::Identifier` (+ `HostnameProber`) |

The five probes run **concurrently** (`std::thread::scope`), each with the
original per-protocol timeout, and the best hostname is chosen in priority order
(mDNS → NetBIOS → SSDP → LLMNR → DNS). Active probing is **off by default**; the
`LiveUdpProber` performs real `std::net` UDP I/O and is never run by the tests.
No ARP poisoning, interception, redirection, or disruption is introduced.

## Traffic monitoring (Phase P4)

Ports `CArp.TrafficMonitorLoop` to `netcontrol-net::traffic` (offsets/constants
confirmed via REA):

| Capability | Source (C#) | Rust |
| --- | --- | --- |
| IPv4 frame classification | `raw[12..14]==0x0800`, len ≥ 34 | `traffic::classify_ipv4_frame` |
| Per-device up/down bytes | src\@26 → sent, dst\@30 → received | `traffic::CycleStats::record` |
| Rate = bytes/1024/elapsed | per-cycle rate math | `netcontrol_core::throttling::bytes_to_kbps` |
| EMA smoothing (α = 0.65) | `TrafficEmaAlpha` blend/decay | `netcontrol_core::throttling::ema_step` |
| Periodic updates → `PcList` | 1 s capture cycle | `CycleStats::apply` (+ gated `TrafficMonitor` loop) |
| Cancellation / cleanup | thread flag + handle join | `CancelToken` + `Drop` |
| Interface-failure handling | `HandleNetworkInterruption` | `TrafficMonitor::has_failed` (consecutive-error threshold) |

A cycle seeds `CycleStats` with the currently tracked device IPs, classifies
each captured IPv4 frame (source → upload, destination → download), then
`apply`s measured-and-smoothed KB/s to every device (idle devices decay toward
zero). The live `TrafficMonitor` loop is `live-capture`-only and never runs in
the test suite; monitoring is read-only — no packet is transmitted, dropped, or
altered.

## Bandwidth throttling (Phase P5)

Ports the `Throttling` namespace to `netcontrol-net::throttle`, restructured so
command generation is separate from execution and nothing enforces silently:

| Capability | Source (C#) | Rust |
| --- | --- | --- |
| Rate-control math (token bucket) | `TokenBucketThrottler` + `TokenBucket` | `netcontrol_core::throttling::TokenBucket` (time-injectable) |
| Platform selection | `BandwidthThrottlerFactory.Create` | `throttle::planner_for` |
| Linux `tc`/HTB commands | `LinuxTcThrottler` | `throttle::TcPlanner` |
| macOS `dnctl` commands | `MacDummynetThrottler` | `throttle::DummynetPlanner` |
| Windows / other | `TokenBucketThrottler` | `throttle::TokenBucketPlanner` |
| Command execution | `Process.Start` inside each adapter | `CommandExecutor` (`DryRunExecutor` default, `SystemExecutor` opt-in) |
| Device-limit reconciliation | `CArp.UpdateDeviceBandwidthLimit` | `Throttler::sync_device` |
| — | (implicit / unstated) | `EnforcementCapability` honest reporting |

**Dry-run is the default** on every platform: `Throttler::new` records the exact
OS commands it *would* run and never executes them. Command strings were
verified against the compiled assembly via REA. Each backend reports an
`EnforcementCapability`, and **none report `is_operational()`**:

- **Token bucket** (Windows/other) — `CalculationOnly`: the original's
  `AllowPacket` is not part of `IBandwidthThrottler`, so `CArp` never consulted
  it; budgets are computed but never applied to a data path.
- **`tc`** (Linux) — `PathDependent`: emits real HTB rules, but they only shape
  traffic traversing this host (effective against a peer only if this host is
  that peer's gateway), require privileges, and run only in the opt-in system
  executor.
- **`dnctl`** (macOS) — `IncompletePathDependent`: configures a dummynet pipe
  but, exactly like the original, never binds it to traffic via `pfctl`.

`controls_path_for_peer(host_is_peer_gateway)` encodes the rule that a limit can
only take effect when the host genuinely controls the peer's path. This project
never performs ARP redirection to seize a path it does not occupy.

To build with live capture (requires Npcap SDK on Windows):

```powershell
cargo build -p netcontrol-net --features live-capture
```


## Test mapping

Each C# test class has a corresponding Rust integration test file:

| C# test class | Rust test file |
| --- | --- |
| `CArpCalculationTests` | `tests/subnet_calculation.rs` |
| `AtomicAccumulatorTests` | `tests/atomic_accumulator.rs` |
| `DeviceCategorizationTests` | `tests/device_categorization.rs` |
| `DeviceLabelTests` | `tests/device_label.rs` |
| `OuiAndIdentificationTests` | `tests/oui_and_identification.rs` |
| `PrivilegeDetectorTests` | `tests/privilege_detector.rs` |
| `TrafficRateTests` | `tests/traffic_rate.rs` |

## Live capture and interface resolution (P6 fix)

Windows reports adapters by friendly name (`Ethernet 2`) and GUID; Npcap names
the same adapter `\Device\NPF_{GUID}`. The GUI lists friendly names, and
`netcontrol_net::capture::resolve_capture_device` maps the selection to the
capture device by **exact name** (Linux/macOS), then **adapter GUID**, then a
**unique IPv4**, then a **unique MAC**. The resolved device is shared by the ARP
listener and the traffic monitor and shown in the Live panel. The original C#
app bound SharpPcap's capture devices directly to its combo box (confirmed with
REA on the compiled `MainWindow.LoadInterfaces`), so it never needed this step.

`Packet.dll` is delay-loaded by the Live-capable executable and located at
runtime (`System32\Npcap` first), so the program starts without Npcap and Live
mode reports the missing runtime instead.

## License

MIT — see [LICENSE](LICENSE). This is a derivative of the MIT-licensed original
NetControl; its copyright notice is retained. Attribution and third-party
notices: [NOTICE](NOTICE). Changes: [CHANGELOG.md](CHANGELOG.md).
