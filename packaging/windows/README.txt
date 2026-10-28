NetControl for Windows (x64)
============================

NetControl.exe       Full application: Demonstration + Live (passive) capture.
NetControl-Demo.exe  Demonstration only. No capture code, no Npcap needed.

Quick start
-----------
1. Run NetControl.exe. It opens in Demonstration mode (simulated devices).
2. For real devices: install Npcap from https://npcap.com/ (default options),
   switch to Live (top right), pick your adapter, e.g.
   "Ethernet 2 - 192.168.1.119", and press Start.
3. If Live reports "Permission denied", run NetControl as Administrator.

NetControl only listens. It never sends scans, probes, or ARP packets.
Not implemented in this version: ARP redirection/spoofing, interception,
blocking. Bandwidth limits are dry-run only (shown, never applied).

Portable use: settings are stored in .\data next to the executable
(controlled by the netcontrol.portable file).
Install for the current user: run install.ps1 (or the -user-setup.exe).

Full documentation: INSTALL.md. License: LICENSE.txt (MIT). Attribution:
NOTICE.txt. Changes: CHANGELOG.md.
