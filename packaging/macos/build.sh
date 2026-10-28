#!/usr/bin/env bash
# Builds NetControl.app and a zip for macOS (run on macOS).
#
# UNTESTED: this script has not been run for the 0.1.0 release.
#
# Requirements: Xcode command-line tools and Rust. Live capture uses BPF devices
# (/dev/bpf*) via pnet and must run as root:
#   sudo /Applications/NetControl.app/Contents/MacOS/netcontrol
# The bundle is unsigned; Gatekeeper will require right-click > Open.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
VERSION="$(sed -n 's/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -1)"
ARCH="$(uname -m)"
APP="dist/NetControl.app"

cargo build --release -p netcontrol-gui --features live-capture

rm -rf "$APP" && mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
install -m 0755 target/release/netcontrol-gui "$APP/Contents/MacOS/netcontrol"

# Icon: build an .icns from the 512px PNG with sips + iconutil.
ICONSET="$(mktemp -d)/NetControl.iconset"
mkdir -p "$ICONSET"
for s in 16 32 128 256 512; do
  sips -z $s $s crates/netcontrol-gui/assets/app_icon.png --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/NetControl.icns"

cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>NetControl</string>
  <key>CFBundleDisplayName</key><string>NetControl</string>
  <key>CFBundleIdentifier</key><string>io.github.netcontrol-rust</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleExecutable</key><string>netcontrol</string>
  <key>CFBundleIconFile</key><string>NetControl</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
EOF
cp LICENSE NOTICE "$APP/Contents/Resources/"

(cd dist && ditto -c -k --keepParent NetControl.app "NetControl-${VERSION}-macos-${ARCH}.zip")
echo "Built dist/NetControl-${VERSION}-macos-${ARCH}.zip"
