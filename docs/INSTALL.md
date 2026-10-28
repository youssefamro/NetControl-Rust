# Installing and using NetControl

NetControl shows the devices on your local network and their bandwidth use. It
has two modes:

- **Demonstration mode** (default): clearly-labeled simulated devices. Needs no
  drivers and no administrator rights.
- **Live mode**: passively listens to ARP and IPv4 traffic on one network
  interface to discover devices and measure their traffic. It **never sends**
  scans, probes, or ARP packets.

> **What NetControl does not do (in this version).** ARP redirection
> ("spoofing"), traffic interception, and blocking are **not implemented** — the
> Spoof/Block checkboxes are markers only. Bandwidth limits are **dry-run**: the
> commands that would be used are shown, but nothing is applied.

## Windows

### Requirements

| | Demonstration | Live capture |
| --- | --- | --- |
| Windows 10/11, 64-bit | required | required |
| [Npcap](https://npcap.com/) runtime | — | required |
| Administrator rights | — | required if Npcap was installed with *"Restrict Npcap driver's access to Administrators only"* |
| Rust / Cargo / .NET | not needed | not needed |

Install Npcap with its default options. WinPcap API-compatible mode is **not**
required: NetControl finds Npcap's `Packet.dll` in `System32\Npcap` itself.
Without Npcap the Live-capable build still starts; Live mode then explains that
the capture runtime is missing.

### Release files

| File | What it is |
| --- | --- |
| `NetControl-<ver>-windows-x64-portable.zip` | Portable copy; settings stay in the extracted folder |
| `NetControl-<ver>-windows-x64-user-setup.exe` | Per-user installer (built with Windows IExpress) |
| `NetControl-<ver>-windows-x64-setup.exe` | Inno Setup installer (only when built with Inno Setup 6) |
| `SHA256SUMS.txt` | Checksums for the files above |

Each package contains two programs:

- `NetControl.exe` — the full application (Demonstration + Live).
- `NetControl-Demo.exe` — demonstration only; contains no capture code and never
  loads Npcap. Use it if `NetControl.exe` will not start.

The executables are not code-signed, so Windows SmartScreen may warn on first
launch (*More info → Run anyway*). Verify downloads against `SHA256SUMS.txt`:

```powershell
Get-FileHash .\NetControl-0.1.0-windows-x64-portable.zip -Algorithm SHA256
```

### Portable use

1. Extract the ZIP to any folder you can write to (e.g. `D:\Apps\NetControl`).
2. Run `NetControl.exe`.

The included `netcontrol.portable` file tells NetControl to keep its settings
and diagnostics in a `data` folder next to the executable. To keep them
elsewhere, put a folder path on the first line of `netcontrol.portable`
(absolute, or relative to the executable).

### Installer

Run `NetControl-<ver>-windows-x64-user-setup.exe`. It installs for the current
user only (no administrator prompt is needed for installation) and asks for:

- the install folder (default `%LOCALAPPDATA%\Programs\NetControl`);
- the settings folder (default `%LOCALAPPDATA%\NetControl`; enter e.g.
  `D:\NetControl\data` to keep settings on another drive).

It creates Start Menu shortcuts — **NetControl**, **NetControl
(Administrator)**, **NetControl Demo (no capture)**, **Uninstall NetControl** —
and registers NetControl in *Settings → Apps → Installed apps*, from where it
can be uninstalled. Uninstalling keeps your settings; run
`uninstall.ps1 -RemoveData` from the install folder to remove them too.

The installer script can also be run directly from an extracted ZIP:

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1 -InstallDir D:\Apps\NetControl -DataDir D:\Apps\NetControl\data
```

### Administrator rights

NetControl does not request elevation itself. Run it as Administrator (use the
**NetControl (Administrator)** shortcut, or right-click → *Run as
administrator*) only when Live capture reports *Permission denied*, which
happens when Npcap is restricted to administrators. Demonstration mode never
needs it.

## Using NetControl

### Selecting a network interface

Switch to **Live** (top-right toggle). The interface list shows each adapter's
Windows name and IPv4 address, e.g. `Ethernet 2 — 192.168.1.119`. Pick the
adapter connected to the network you want to observe (usually the one with your
LAN address). VPN/TUN adapters (e.g. `nekoray-tun`) and loopback generally have
no capture device; choosing one produces a clear error listing the adapters the
capture driver does support.

Internally, NetControl maps the readable name to Npcap's device
(`\Device\NPF_{GUID}`) by adapter GUID, falling back to a unique IPv4 or MAC
match. The device actually used appears as **Capture device** in the Live panel.

### Demonstration vs. Live

| | Demonstration | Live |
| --- | --- | --- |
| Devices | 11 simulated devices | Devices seen on the network |
| Traffic numbers | Simulated | Measured from captured frames |
| Spoof / Block / Cap | Markers; affect simulated numbers only | Markers only; nothing is enforced |
| Needs Npcap / admin | No | Yes (see above) |

Each mode keeps its own device list; switching modes stops any running capture
but keeps your selections.

### Starting and stopping passive monitoring

1. In Live mode, select the interface and press **Start**.
2. The status bar shows `Passive listening on <interface> — <IP> (no scans
   sent).` and the Live panel shows the capture device.
3. Devices appear as they send ARP traffic; this can take from seconds to a few
   minutes because NetControl does not scan.
4. Press **Stop** to end capture. Stopping returns within about 1.5 seconds even
   on a quiet network.

Capture is never started automatically, including after a restart.

### Settings persistence

NetControl saves `config.ini` (dismissed disclaimer, last mode, selected
interface per mode, demonstration device settings) and appends capture errors
to `netcontrol.log` in its data folder:

1. `NETCONTROL_DATA_DIR`, if set;
2. otherwise the folder named by `netcontrol.portable` next to the executable
   (portable ZIP: `.\data`);
3. otherwise `%LOCALAPPDATA%\NetControl` (Linux: `~/.config/netcontrol`,
   macOS: `~/Library/Application Support/NetControl`).

Live device lists are not saved.

## Troubleshooting

| Message / symptom | Cause and fix |
| --- | --- |
| `Live capture is not available in this build` | You are running `NetControl-Demo.exe` or a default developer build. Use `NetControl.exe`. |
| Live panel *Capture runtime*: `Packet.dll could not be loaded: Npcap is not installed` | Install Npcap from https://npcap.com/ and restart NetControl. |
| *Capture runtime* mentions `WinPcap-compatible runtime` | An old WinPcap `Packet.dll` was found. It may work, but WinPcap is unmaintained; install Npcap. |
| `interface X has no matching capture device (the capture driver reports: …)` | The selected adapter is not captured by Npcap (VPN/TUN, Wi-Fi Direct, virtual adapters). Pick an adapter from the list in the message. |
| `no capture devices are available for interface X` | Npcap reports no adapters: the Npcap service is stopped or the install is broken. Reinstall Npcap or run `sc query npcap`. |
| `could not open capture device … Permission denied` | Npcap is restricted to administrators. Use the **NetControl (Administrator)** shortcut. |
| `interface not found: X (it may have been disconnected…)` | The adapter was removed or renamed since the list was loaded. Switch to Demonstration and back to Live to refresh. |
| `Capture stopped unexpectedly: …` | The adapter went down or the driver stopped during capture. Fix the adapter and press Start again. |
| Capture running, no devices | Normal on a quiet network: NetControl only listens. Devices appear when they send ARP (e.g. when reconnecting). |
| SmartScreen warning | The binaries are unsigned. Verify the checksum, then *More info → Run anyway*. |

Errors are also appended to `netcontrol.log` in the data folder.

## Linux and macOS

Linux and macOS builds have **not been built or tested** for this release, and
no binaries are provided. Build scripts are included as a starting point:

- `packaging/linux/build.sh` — builds and creates a `.tar.gz` with a `.desktop`
  entry and icon. Needs Rust plus the X11/Wayland/OpenGL development packages
  used by eframe (Debian/Ubuntu: `libxkbcommon-dev libgl1-mesa-dev
  libx11-dev libxcursor-dev libxrandr-dev libxi-dev libwayland-dev`). Live
  capture uses raw `AF_PACKET` sockets (no libpcap); grant the binary
  `cap_net_raw,cap_net_admin` with `setcap` or run it as root.
- `packaging/macos/build.sh` — builds a `NetControl.app` bundle. Live capture
  uses BPF devices (`/dev/bpf*`) and requires running as root.

## Known limitations

- ARP redirection/spoofing, interception, and blocking are not implemented.
- Bandwidth limits are dry-run only; nothing is enforced on any platform.
- Live discovery is passive; silent devices may not appear.
- On a switched network this computer only sees its own traffic plus
  broadcasts, so other devices usually show 0 KB/s, and the router shows 0 KB/s
  because traffic through it carries the remote server's address. Per-device
  rates are meaningful only for traffic that actually reaches this adapter.
- The gateway is not auto-detected; it is learned only if it sends ARP.
- Windows: pnet's Npcap backend ignores read timeouts, so a capture thread on a
  completely silent link is detached on Stop and exits at the next frame.
- Linux/macOS builds are untested.
- Binaries are not code-signed.
