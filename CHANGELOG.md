# Changelog

All notable changes to the NetControl Rust rebuild. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-10-28

First packaged release of the Rust rebuild of NetControl.

### Added
- `netcontrol-core`: device model, OUI vendor table, device classification,
  subnet math, privilege detection, EMA smoothing, token-bucket math (P1).
- `netcontrol-net`: Ethernet/ARP parsing and frame building, passive ARP
  observation, interface enumeration, gated discovery planning (P2); DNS /
  NetBIOS / mDNS / SSDP / LLMNR hostname identification (P3); passive per-device
  traffic accounting (P4); dry-run bandwidth-throttle planning for token
  bucket, Linux `tc`, and macOS `dnctl` with honest enforcement reporting (P5).
- `netcontrol-gui`: egui recreation of the original window with Demonstration
  and Live modes, separate datasets per mode, persisted preferences, and a Live
  diagnostics panel (P6).
- `netcontrol-net::capture`: maps OS interfaces to capture devices and probes
  the capture runtime (Npcap/WinPcap `Packet.dll`).
- Windows packaging (P7): optimized x64 executables with icon and version
  metadata, a demonstration-only executable, portable ZIP, per-user installer
  with Start Menu shortcuts and uninstaller, Inno Setup script, checksums.
- Linux and macOS packaging scripts (untested).
- Portable / per-user data directory resolution and a `netcontrol.log`
  diagnostics log for capture errors.

### Fixed
- Live capture on Windows failed with `interface not found: Ethernet 2`: the GUI
  passed the Windows friendly name to pnet, whose Npcap backend names adapters
  `\Device\NPF_{GUID}`. Interfaces are now resolved by adapter GUID (then unique
  IPv4, then unique MAC), for both the ARP listener and the traffic monitor.
- The Live-capable executable would not start on machines with Npcap installed
  without WinPcap-compatibility mode, because `Packet.dll` lives in
  `System32\Npcap`. `Packet.dll` is now delay-loaded and located at runtime;
  if it is missing, Live mode reports it instead of the program failing to
  launch.
- Linking the live-capture build required manually setting `LIB` to the Npcap
  SDK; the build script now finds it (`NPCAP_SDK_DIR` or standard locations).
- Stop could hang indefinitely on a silent link (pnet's Windows backend blocks
  until the next frame); it now returns within ~1.5 s.
- Read timeouts on Linux/macOS were counted as errors and would mark the
  traffic monitor failed.
- The Live interface list was enumerated only once; it now refreshes each time
  Live mode is entered.
- Settings were hard-coded to a developer path on `D:`; they now follow
  `NETCONTROL_DATA_DIR`, a portable marker, the development workspace, or the
  per-user OS default.

### Not implemented
- ARP redirection/spoofing, interception, and blocking.
- Enforcement of bandwidth limits (dry-run only).

