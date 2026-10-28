#!/usr/bin/env bash
# Installs NetControl for the current user (~/.local), or system-wide with
# --system (requires sudo). Optionally grants capture capabilities.
# UNTESTED for the 0.1.0 release.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

if [[ "${1:-}" == "--system" ]]; then
  BIN=/usr/local/bin; APPS=/usr/local/share/applications; ICONS=/usr/local/share/icons/hicolor/512x512/apps
else
  BIN="$HOME/.local/bin"; APPS="$HOME/.local/share/applications"; ICONS="$HOME/.local/share/icons/hicolor/512x512/apps"
fi
mkdir -p "$BIN" "$APPS" "$ICONS"
install -m 0755 "$HERE/netcontrol" "$BIN/netcontrol"
install -m 0644 "$HERE/netcontrol.png" "$ICONS/netcontrol.png"
install -m 0644 "$HERE/netcontrol.desktop" "$APPS/netcontrol.desktop"
echo "Installed to $BIN/netcontrol"
echo "For Live capture without root, run:"
echo "  sudo setcap cap_net_raw,cap_net_admin=eip $BIN/netcontrol"
