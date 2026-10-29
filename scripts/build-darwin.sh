#!/bin/sh
# Build, sign, verify and package both macOS release archives into dist/.
# Runs on any macOS runner (Apple silicon or Intel): the other architecture is
# cross-compiled with clang, and smoke-tested only where the CPU can run it.
#
#   scripts/build-darwin.sh <version-tag>
set -eu

TAG="$1"
SHA=$(git rev-parse --short HEAD)
# Go 1.25 supports macOS 12 and later.
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-12.0}"
LDFLAGS="-s -w -X wantastic-agent/pkg/version.Version=${TAG}+${SHA} -X wantastic-agent/pkg/version.Commit=${SHA} -X wantastic-agent/pkg/version.BuildDate=$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
HOST_ARCH=$(uname -m)
mkdir -p dist

for GOARCH in arm64 amd64; do
  CLANG_ARCH=arm64
  [ "$GOARCH" = "amd64" ] && CLANG_ARCH=x86_64
  OUT="build/darwin-$GOARCH"
  mkdir -p "$OUT"
  echo "== darwin/$GOARCH"

  # cgo: the menu-bar app links Cocoa.
  GOOS=darwin GOARCH=$GOARCH CGO_ENABLED=1 \
    CC="clang -arch ${CLANG_ARCH}" \
    CGO_CFLAGS="-mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET}" \
    CGO_LDFLAGS="-mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET}" \
    go build -trimpath -ldflags="$LDFLAGS" -o "$OUT/wantasticd" ./cmd/wantasticd

  # Apple silicon refuses to run unsigned code; ad-hoc sign both builds.
  codesign --force --sign - --identifier app.wantastic.wantasticd "$OUT/wantasticd"
  codesign --verify --verbose=2 "$OUT/wantasticd"

  ARCHS=$(lipo -archs "$OUT/wantasticd")
  [ "$ARCHS" = "$CLANG_ARCH" ] || { echo "expected $CLANG_ARCH, got $ARCHS"; exit 1; }
  # Only system libraries: a Homebrew dylib would not exist on users' Macs.
  if otool -L "$OUT/wantasticd" | tail -n +2 | grep -vE '^[[:space:]]*(/usr/lib/|/System/Library/)'; then
    echo "non-system library linked"; exit 1
  fi
  otool -l "$OUT/wantasticd" | grep -A4 LC_BUILD_VERSION | grep minos

  if [ "$CLANG_ARCH" = "$HOST_ARCH" ]; then
    "$OUT/wantasticd" version | grep -F "$TAG"
  elif [ "$CLANG_ARCH" = "x86_64" ] && arch -x86_64 /usr/bin/true 2>/dev/null; then
    arch -x86_64 "$OUT/wantasticd" version | grep -F "$TAG"
  else
    echo "this runner cannot execute $CLANG_ARCH; skipping the smoke test"
  fi

  cp README.md "$OUT/"
  tar -czvf "dist/wantasticd-darwin-${GOARCH}.tar.gz" -C "$OUT" wantasticd README.md
done
