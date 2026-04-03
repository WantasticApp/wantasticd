#!/bin/sh
# Wantasticd Self-Update Script
# Safe atomic binary replacement + service-managed restart.
# Usage: ./self-update.sh [version] [target-binary-path]
set -e

BASE_URL="https://get.wantastic.app"

# ── platform ─────────────────────────────────────────────────────────────────
UNAME_S="$(uname -s)"
case "$UNAME_S" in
  Linux*)  OS="linux"  ;;
  Darwin*) OS="darwin" ;;
  *) echo "Unsupported OS: $UNAME_S"; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64)         ARCH="amd64"    ;;
  aarch64|arm64)  ARCH="arm64"    ;;
  armv7*|armv6*)  ARCH="arm"      ;;
  i386|i686)      ARCH="386"      ;;
  mips64)         ARCH="mips64"   ;;
  mips64el)       ARCH="mips64le" ;;
  mipsle|mipsel)  ARCH="mipsle"   ;;
  mips)           ARCH="mips"     ;;
  riscv64)        ARCH="riscv64"  ;;
  ppc64le)        ARCH="ppc64le"  ;;
  *) echo "Unsupported arch: $(uname -m)"; exit 1 ;;
esac

# ── service restart ───────────────────────────────────────────────────────────
# After the binary is replaced on disk the running process keeps its old inode.
# We ask the service manager to restart so a fresh exec picks up the new binary.
restart_service() {
  # systemd
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet wantasticd 2>/dev/null; then
    echo "Restarting via systemd…"
    systemctl restart wantasticd
    return 0
  fi
  # procd (OpenWrt)
  if [ -x /etc/init.d/wantasticd ] && command -v procd >/dev/null 2>&1; then
    echo "Restarting via procd…"
    /etc/init.d/wantasticd restart
    return 0
  fi
  # OpenRC
  if command -v rc-service >/dev/null 2>&1; then
    echo "Restarting via OpenRC…"
    rc-service wantasticd restart
    return 0
  fi
  # generic init.d
  if [ -x /etc/init.d/wantasticd ]; then
    echo "Restarting via init.d…"
    /etc/init.d/wantasticd restart
    return 0
  fi
  # launchd (macOS)
  if [ "$OS" = "darwin" ] && command -v launchctl >/dev/null 2>&1; then
    echo "Restarting via launchctl…"
    launchctl stop  com.wantastic.wantasticd 2>/dev/null || true
    launchctl start com.wantastic.wantasticd
    return 0
  fi
  # Fallback: exec new binary directly (replaces running process)
  echo "No service manager found — exec'ing new binary directly…"
  exec "$TARGET_BIN" "$@"
}

# ── main ─────────────────────────────────────────────────────────────────────
main() {
  VERSION="$1"
  TARGET_BIN="$2"

  # Resolve target binary path
  if [ -z "$TARGET_BIN" ]; then
    if   command -v wantasticd >/dev/null 2>&1; then TARGET_BIN="$(command -v wantasticd)"
    elif [ -f "/usr/local/bin/wantasticd" ];    then TARGET_BIN="/usr/local/bin/wantasticd"
    elif [ -f "/usr/bin/wantasticd" ];          then TARGET_BIN="/usr/bin/wantasticd"
    elif [ -f "/bin/wantasticd" ];              then TARGET_BIN="/bin/wantasticd"
    else echo "Error: cannot find wantasticd binary"; exit 1
    fi
  fi

  # Fetch latest version tag if not supplied
  if [ -z "$VERSION" ]; then
    echo "Fetching latest version…"
    VERSION=$(curl -sSL "${BASE_URL}/latest" | tr -d '[:space:]')
  fi
  [ -z "$VERSION" ] && { echo "Error: could not determine latest version"; exit 1; }

  echo "Target binary:  $TARGET_BIN"
  echo "Target version: $VERSION"
  echo "Platform:       $OS-$ARCH"

  DOWNLOAD_URL="${BASE_URL}/latest/wantasticd-${OS}-${ARCH}.tar.gz"
  echo "Downloading $DOWNLOAD_URL…"

  TMP_DIR=$(mktemp -d)
  trap 'rm -rf "$TMP_DIR"' EXIT

  CODE=$(curl -sSL -w "%{http_code}" -o "$TMP_DIR/pkg.tar.gz" "$DOWNLOAD_URL")
  [ "$CODE" = "200" ] || { echo "Error: download failed (HTTP $CODE)"; exit 1; }

  tar -xzf "$TMP_DIR/pkg.tar.gz" -C "$TMP_DIR"

  if [ "$OS" = "darwin" ]; then
    NEW_BIN=$(find "$TMP_DIR" -name "wantasticd" -type f -perm +111 2>/dev/null | head -n 1)
  else
    NEW_BIN=$(find "$TMP_DIR" -name "wantasticd" -type f 2>/dev/null | head -n 1)
  fi
  [ -n "$NEW_BIN" ] || { echo "Error: binary not found in archive"; ls -la "$TMP_DIR"; exit 1; }

  chmod +x "$NEW_BIN"

  # ── atomic replacement ────────────────────────────────────────────────────
  # Stage in the same directory so mv is rename(2) — atomic on same filesystem.
  # The running process keeps its old inode open; the new inode is exec'd by
  # the service manager on restart.
  DEST_DIR="$(dirname "$TARGET_BIN")"
  STAGING="${DEST_DIR}/.wantasticd.update.$$"

  cp "$NEW_BIN" "$STAGING" || { echo "Error: cannot write to $DEST_DIR (check permissions)"; exit 1; }
  chmod +x "$STAGING"
  mv -f "$STAGING" "$TARGET_BIN"
  echo "Binary updated: $TARGET_BIN"

  # ── trigger service restart ───────────────────────────────────────────────
  restart_service
  echo "Update complete — running version: $VERSION"
}

main "$@"
