#!/usr/bin/env bash
# setup-gui.sh — run once to bootstrap the Wails GUI project
set -e

REPO="$(cd "$(dirname "$0")" && pwd)"
GUI="$REPO/gui"

echo "==> 1/4  Adding Wails Go dependency…"
cd "$REPO"
go get github.com/wailsapp/wails/v2@latest
go mod tidy

echo "==> 2/4  Installing frontend npm packages…"
cd "$GUI/frontend"
npm install

echo "==> 3/4  Installing icons…"
SRC_LOGO="/Users/kimo/Desktop/kmoz000/ISPApp-TunnelHub/cmd/web/portal/app/public/logo/512.png"
if [ -f "$SRC_LOGO" ]; then
  mkdir -p "$GUI/build"
  mkdir -p "$GUI/frontend/public"
  cp "$SRC_LOGO" "$GUI/build/appicon.png"
  cp "$SRC_LOGO" "$GUI/frontend/public/logo.png"
  echo "    Icons installed."
else
  echo "    WARNING: source logo not found at $SRC_LOGO"
  echo "    Place a 512×512 PNG at gui/build/appicon.png and gui/frontend/public/logo.png"
fi

echo "==> 4/4  Run the unified desktop client:"
echo ""
echo "    make gui-dev"
echo ""
echo "    Or build GUI-enabled binary:"
echo "    make build-gui"
echo ""
echo "Done ✓"
