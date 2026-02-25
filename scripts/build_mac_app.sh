#!/bin/bash
set -e

APP_NAME="Wantastic"
APP_DIR="../tmp/${APP_NAME}.app"
CONTENTS_DIR="${APP_DIR}/Contents"
MACOS_DIR="${CONTENTS_DIR}/MacOS"

echo "Building ${APP_NAME}.app..."

# 1. Create directory structure
mkdir -p "${MACOS_DIR}"

# 2. Build the Go binary (with CGO enabled)
echo "Compiling wantasticd..."
TMPDIR=/tmp GOCACHE=/tmp/go-cache CGO_ENABLED=1 go build -v -o "${MACOS_DIR}/wantasticd" ./cmd/wantasticd

# 3. Create Info.plist with Location Services permission request
echo "Creating Info.plist..."
cat << 'EOF' > "${CONTENTS_DIR}/Info.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>wantasticd</string>
    <key>CFBundleIdentifier</key>
    <string>app.wantastic.agent</string>
    <key>CFBundleName</key>
    <string>Wantastic</string>
    <key>CFBundleDisplayName</key>
    <string>Wantastic</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.15</string>
    <!-- Privacy prompts for macOS to allow Wi-Fi SSID reading -->
    <key>NSLocationWhenInUseUsageDescription</key>
    <string>Wantastic requires Location Services to accurately read the Wi-Fi SSID and optimize your connection.</string>
    <key>NSLocationUsageDescription</key>
    <string>Wantastic requires Location Services to accurately read the Wi-Fi SSID and optimize your connection.</string>
    <key>NSLocationAlwaysAndWhenInUseUsageDescription</key>
    <string>Wantastic requires Location Services to accurately read the Wi-Fi SSID and optimize your connection.</string>
</dict>
</plist>
EOF

echo "Done! You can now run the app bundle:"
echo "sudo ./${APP_NAME}.app/Contents/MacOS/wantasticd connect -config traditional.conf"
echo ""
echo "Note: Running from within the .app bundle allows macOS to prompt for Location Services"
echo "so it can read the SSID on Ventura+."
