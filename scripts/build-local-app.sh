#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

swift build --configuration debug
bin_path="$(swift build --show-bin-path)"

app=".build/local/Wantastic.app"
contents="$app/Contents"
mkdir -p "$contents/MacOS" "$contents/Resources" "$contents/Library/LaunchDaemons"
cp "$bin_path/Wantastic" "$contents/MacOS/Wantastic"
cp "$bin_path/WantasticLocalAccessHelper" "$contents/MacOS/WantasticLocalAccessHelper"
cp Config/app.wantastic.desktop.local-access-helper.plist \
  "$contents/Library/LaunchDaemons/app.wantastic.desktop.local-access-helper.plist"

resource_bundle="$bin_path/WantasticMac_WantasticApp.bundle"
if [ ! -d "$resource_bundle" ] || {
  [ ! -s "$resource_bundle/WantasticLogoSwiftPM.png" ] &&
  [ ! -s "$resource_bundle/Contents/Resources/WantasticLogoSwiftPM.png" ]
}; then
  echo "SwiftPM app resource bundle or standalone logo is missing: $resource_bundle" >&2
  exit 1
fi
cp -R "$resource_bundle" "$contents/Resources/"

/usr/libexec/PlistBuddy -c 'Clear dict' "$contents/Info.plist" 2>/dev/null || true
/usr/libexec/PlistBuddy -c 'Add :CFBundleExecutable string Wantastic' "$contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Add :CFBundleIdentifier string app.wantastic.desktop' "$contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Add :CFBundleName string Wantastic' "$contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Add :CFBundlePackageType string APPL' "$contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Add :CFBundleVersion string 0.1.0' "$contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Add :CFBundleShortVersionString string 0.1.0' "$contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Add :LSMinimumSystemVersion string 14.0' "$contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Add :LSUIElement bool true' "$contents/Info.plist"

# Prefer the local self-signed identity after the user trusts it for Code
# Signing in Keychain Access. Untrusted or absent identities fall back to
# ad-hoc signing. An explicit override is honored for developer/CI workflows.
local_identity='Wantastic Local Code Signing (kimo)'
if [ -n "${WANTASTIC_CODESIGN_IDENTITY:-}" ]; then
  signing_identity="$WANTASTIC_CODESIGN_IDENTITY"
elif command -v security >/dev/null 2>&1 && \
  security find-identity -p codesigning -v 2>/dev/null | grep -Fq "\"$local_identity\""; then
  signing_identity="$local_identity"
else
  signing_identity='-'
fi
codesign --force --sign "$signing_identity" \
  --identifier app.wantastic.desktop.local-access-helper \
  "$contents/MacOS/WantasticLocalAccessHelper"
codesign --force --deep --sign "$signing_identity" "$app"
codesign --verify --deep --strict "$app"
printf 'Built local app signed with %s: %s/%s\n' "$signing_identity" "$PWD" "$app"
