#!/usr/bin/env bash
# Builds a Linux x86_64/aarch64 release tarball of NetControl.
#
# UNTESTED: this script has not been run for the 0.1.0 release.
#
# Requirements (build machine): Rust (stable) and eframe's system libraries,
#   Debian/Ubuntu: sudo apt install build-essential pkg-config libxkbcommon-dev \
#     libgl1-mesa-dev libx11-dev libxcursor-dev libxrandr-dev libxi-dev libwayland-dev
# Live capture uses raw AF_PACKET sockets via pnet (no libpcap needed); at run
# time it needs root or: sudo setcap cap_net_raw,cap_net_admin=eip ./netcontrol
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
VERSION="$(sed -n 's/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -1)"
ARCH="$(uname -m)"
NAME="NetControl-${VERSION}-linux-${ARCH}"
STAGE="dist/${NAME}"

cargo build --release -p netcontrol-gui --features live-capture

rm -rf "$STAGE" && mkdir -p "$STAGE"
install -m 0755 target/release/netcontrol-gui "$STAGE/netcontrol"
install -m 0644 crates/netcontrol-gui/assets/app_icon.png "$STAGE/netcontrol.png"
install -m 0644 LICENSE NOTICE CHANGELOG.md docs/INSTALL.md "$STAGE/"
install -m 0755 packaging/linux/install.sh "$STAGE/install.sh"
cat > "$STAGE/netcontrol.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=NetControl
Comment=Network device and bandwidth monitor (passive)
Exec=netcontrol
Icon=netcontrol
Terminal=false
Categories=Network;Monitor;
EOF

tar -C dist -czf "dist/${NAME}.tar.gz" "$NAME"
(cd dist && sha256sum "${NAME}.tar.gz" > "${NAME}.tar.gz.sha256")
echo "Built dist/${NAME}.tar.gz"
