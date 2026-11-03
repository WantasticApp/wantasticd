#!/bin/sh
# Builds dist/wantastic-macos.pkg: one installer for Intel and Apple silicon,
# from the binaries scripts/build-darwin.sh left in build/darwin-{arm64,amd64}.
#
#   scripts/build-darwin-pkg.sh <version-tag>
set -eu

TAG="$1"
VERSION=$(printf '%s' "$TAG" | sed -E 's/^v//; s/[^0-9.].*$//')
case "$VERSION" in *.*.*) ;; *) VERSION="0.0.0" ;; esac
WORK=build/pkg
mkdir -p dist
rm -rf "$WORK"
mkdir -p "$WORK/scripts" "$WORK/resources"

# One binary for both architectures; Apple silicon needs a signature.
lipo -create -output "$WORK/scripts/wantasticd" build/darwin-arm64/wantasticd build/darwin-amd64/wantasticd
if [ -n "${MACOS_APP_IDENTITY:-}" ]; then
  codesign --force --options runtime --timestamp --sign "$MACOS_APP_IDENTITY" --identifier app.wantastic.wantasticd "$WORK/scripts/wantasticd"
else
  codesign --force --sign - --identifier app.wantastic.wantasticd "$WORK/scripts/wantasticd"
fi
codesign --verify "$WORK/scripts/wantasticd"
lipo -archs "$WORK/scripts/wantasticd"

cp install.sh "$WORK/scripts/install.sh"
cp installer/macos/scripts/postinstall "$WORK/scripts/postinstall"
chmod 755 "$WORK/scripts/postinstall" "$WORK/scripts/install.sh" "$WORK/scripts/wantasticd"
cp installer/macos/resources/* "$WORK/resources/"
sed "s/version=\"VERSION\"/version=\"$VERSION\"/" installer/macos/distribution.xml > "$WORK/distribution.xml"

# Extended attributes (com.apple.provenance cannot be cleared) would ship
# as ._ AppleDouble files; tell the archivers not to write them.
xattr -cr "$WORK" 2>/dev/null || true
export COPYFILE_DISABLE=1

# No payload: the postinstall script installs everything, the same way
# install.sh does from the network.
pkgbuild --nopayload --scripts "$WORK/scripts" --identifier app.wantastic.wantasticd \
  --version "$VERSION" "$WORK/wantasticd.pkg"
if [ -n "${MACOS_INSTALLER_IDENTITY:-}" ]; then
  productbuild --distribution "$WORK/distribution.xml" --resources "$WORK/resources" \
    --package-path "$WORK" --sign "$MACOS_INSTALLER_IDENTITY" --timestamp "dist/wantastic-macos.pkg"
else
  productbuild --distribution "$WORK/distribution.xml" --resources "$WORK/resources" \
    --package-path "$WORK" "dist/wantastic-macos.pkg"
fi

# Notarize when credentials are provided: Apple scans the package and the
# ticket is stapled to it, so macOS opens it without the "could not verify
# ... free of malware" warning (or "Move to Trash"), even offline. CI uses an
# App Store Connect API key (NOTARY_KEY_PATH); a Mac uses a keychain profile
# saved with `xcrun notarytool store-credentials` (NOTARY_PROFILE).
NOTARIZE=""
if [ -n "${NOTARY_KEY_PATH:-}" ]; then
  NOTARIZE="--key $NOTARY_KEY_PATH --key-id ${NOTARY_KEY_ID:-} --issuer ${NOTARY_ISSUER:-}"
elif [ -n "${NOTARY_PROFILE:-}" ]; then
  NOTARIZE="--keychain-profile $NOTARY_PROFILE"
fi
if [ -n "${MACOS_INSTALLER_IDENTITY:-}" ] && [ -n "$NOTARIZE" ]; then
  # shellcheck disable=SC2086 # NOTARIZE is a list of flags
  xcrun notarytool submit dist/wantastic-macos.pkg $NOTARIZE --wait --timeout 30m
  xcrun stapler staple dist/wantastic-macos.pkg
  xcrun stapler validate dist/wantastic-macos.pkg
  spctl --assess --type install --verbose=2 dist/wantastic-macos.pkg
fi
pkgutil --check-signature dist/wantastic-macos.pkg || true # unsigned until the Apple certificates are set up
ls -l dist/wantastic-macos.pkg
