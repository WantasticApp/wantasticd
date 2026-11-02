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
codesign --force --sign - --identifier app.wantastic.wantasticd "$WORK/scripts/wantasticd"
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
productbuild --distribution "$WORK/distribution.xml" --resources "$WORK/resources" \
  --package-path "$WORK" "dist/wantastic-macos.pkg"

pkgutil --check-signature dist/wantastic-macos.pkg || true # unsigned until a Developer ID Installer certificate is set up
ls -l dist/wantastic-macos.pkg
