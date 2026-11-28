#!/bin/bash
# Runner-local fresh prefix only. Original signed runtime is never modified.
set -euo pipefail
PREFIX="$RUNNER_TEMP/netfx40-msxml3-prefix"
test -f "$PREFIX/.swcompat-netfx481-disposable"
test ! -L "$PREFIX/.swcompat-webview2-disposable"
test ! -e "$PREFIX/.swcompat-webview2-disposable"
test ! -e "$1"
python3 -m swcompat --wine "$SWCOMPAT_WINE" --prefix "$PREFIX" \
  --logs-dir "$RUNNER_TEMP/ipd-webview-first-logs" set-winver win11
touch "$PREFIX/.swcompat-webview2-disposable"
python3 -m scripts.webview2_runtime_trial --wine "$SWCOMPAT_WINE" --prefix "$PREFIX" \
  --installer build/MicrosoftEdgeWebView2RuntimeInstallerX64.exe --sha256-file build/evergreen-installer.sha256 \
  --probe build/webview2_controller_probe.exe --output "$1" \
  --timeout-seconds 240 --agree-disposable-prefix --experiment-full-win32-exit build/webview2_win32_launch.exe
python3 -m scripts.netfx481_webview2_restart_gate --wine "$SWCOMPAT_WINE" --prefix "$PREFIX" \
  --probe build/webview2_controller_probe.exe --initial "$1" --output build/solidworks-webview2-restart.json
