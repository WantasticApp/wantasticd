#!/bin/sh
# Wantasticd Self-Update Script
# Safe atomic binary replacement + service-managed restart.
# Usage: ./self-update.sh [version] [target-binary-path]
set -e

BASE_URL="https://get.wantastic.app"
CONNECT_TIMEOUT="${WANTASTIC_UPDATE_CONNECT_TIMEOUT:-15}"
DOWNLOAD_TIMEOUT="${WANTASTIC_UPDATE_DOWNLOAD_TIMEOUT:-300}"
VERIFY_TIMEOUT="${WANTASTIC_UPDATE_VERIFY_TIMEOUT:-20}"
SERVICE_MANAGER=""

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
    SERVICE_MANAGER="systemd"
    return 0
  fi
  # procd (OpenWrt)
  if [ -x /etc/init.d/wantasticd ] && command -v procd >/dev/null 2>&1; then
    echo "Restarting via procd…"
    /etc/init.d/wantasticd restart
    SERVICE_MANAGER="procd"
    return 0
  fi
  # OpenRC
  if command -v rc-service >/dev/null 2>&1; then
    echo "Restarting via OpenRC…"
    rc-service wantasticd restart
    SERVICE_MANAGER="openrc"
    return 0
  fi
  # generic init.d
  if [ -x /etc/init.d/wantasticd ]; then
    echo "Restarting via init.d…"
    /etc/init.d/wantasticd restart
    SERVICE_MANAGER="initd"
    return 0
  fi
  # launchd (macOS)
  if [ "$OS" = "darwin" ] && command -v launchctl >/dev/null 2>&1; then
    echo "Restarting via launchctl…"
    launchctl stop  com.wantastic.wantasticd 2>/dev/null || true
    launchctl start com.wantastic.wantasticd
    SERVICE_MANAGER="launchd"
    return 0
  fi
  echo "Error: no supported service manager found; refusing an unverifiable update"
  return 1
}

service_is_running() {
  case "$SERVICE_MANAGER" in
    systemd) systemctl is-active --quiet wantasticd ;;
    procd)
      if command -v ubus >/dev/null 2>&1; then
        _service_state=$(ubus call service list '{"name":"wantasticd"}' 2>/dev/null || true)
        echo "$_service_state" | grep -q '"running"[[:space:]]*:[[:space:]]*true'
      else
        pidof wantasticd >/dev/null 2>&1
      fi
      ;;
    initd) /etc/init.d/wantasticd status >/dev/null 2>&1 ;;
    openrc) rc-service wantasticd status >/dev/null 2>&1 ;;
    launchd) launchctl list com.wantastic.wantasticd >/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}

binary_reports_version() {
  _expected="$1"
  _output=$("$TARGET_BIN" version 2>/dev/null || true)
  case "$_output" in
    *"$_expected"*) return 0 ;;
    *) return 1 ;;
  esac
}

verify_update() {
  _elapsed=0
  while [ "$_elapsed" -lt "$VERIFY_TIMEOUT" ]; do
    if service_is_running && binary_reports_version "$VERSION"; then
      return 0
    fi
    sleep 1
    _elapsed=$((_elapsed + 1))
  done
  return 1
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
    VERSION=$(curl -sSL --connect-timeout "$CONNECT_TIMEOUT" --max-time 30 \
      "${BASE_URL}/latest" | tr -d '[:space:]')
  fi
  [ -z "$VERSION" ] && { echo "Error: could not determine latest version"; exit 1; }

  echo "Target binary:  $TARGET_BIN"
  echo "Target version: $VERSION"
  echo "Platform:       $OS-$ARCH"

  # The version endpoint includes build metadata (for example
  # v1.0.5+abcdef0), while immutable release objects use the tag directory.
  # Never download binaries through /latest: that path can remain cached at
  # an edge after the small version marker has already changed.
  RELEASE_TAG="${VERSION%%+*}"
  case "$RELEASE_TAG" in
    ""|*[!A-Za-z0-9._-]*)
      echo "Error: invalid release version: $VERSION"
      exit 1
      ;;
  esac
  DOWNLOAD_URL="${BASE_URL}/${RELEASE_TAG}/wantasticd-${OS}-${ARCH}.tar.gz"
  echo "Downloading $DOWNLOAD_URL…"

  TMP_DIR=$(mktemp -d)
  trap 'rm -rf "$TMP_DIR"' EXIT

  CODE=$(curl -sSL \
    --connect-timeout "$CONNECT_TIMEOUT" \
    --max-time "$DOWNLOAD_TIMEOUT" \
    --retry 2 \
    --retry-delay 2 \
    --retry-connrefused \
    -w "%{http_code}" \
    -o "$TMP_DIR/pkg.tar.gz" \
    "$DOWNLOAD_URL")
  [ "$CODE" = "200" ] || { echo "Error: download failed (HTTP $CODE)"; exit 1; }

  tar -xzf "$TMP_DIR/pkg.tar.gz" -C "$TMP_DIR"

  if [ "$OS" = "darwin" ]; then
    NEW_BIN=$(find "$TMP_DIR" -name "wantasticd" -type f -perm +111 2>/dev/null | head -n 1)
  else
    NEW_BIN=$(find "$TMP_DIR" -name "wantasticd" -type f 2>/dev/null | head -n 1)
  fi
  [ -n "$NEW_BIN" ] || { echo "Error: binary not found in archive"; ls -la "$TMP_DIR"; exit 1; }

  chmod +x "$NEW_BIN"

  # Refuse a corrupt archive, wrong architecture, or incorrectly-versioned
  # build before touching the running installation.
  NEW_VERSION_OUTPUT=$("$NEW_BIN" version 2>/dev/null || true)
  case "$NEW_VERSION_OUTPUT" in
    *"$VERSION"*) ;;
    *)
      echo "Error: downloaded binary does not report target version $VERSION"
      [ -n "$NEW_VERSION_OUTPUT" ] && echo "Reported: $NEW_VERSION_OUTPUT"
      exit 1
      ;;
  esac

  # ── atomic replacement ────────────────────────────────────────────────────
  # Stage in the same directory so mv is rename(2) — atomic on same filesystem.
  # The running process keeps its old inode open; the new inode is exec'd by
  # the service manager on restart.
  DEST_DIR="$(dirname "$TARGET_BIN")"
  STAGING="${DEST_DIR}/.wantasticd.update.$$"
  BACKUP="$TMP_DIR/wantasticd.previous"

  [ ! -f "$TARGET_BIN" ] || cp -p "$TARGET_BIN" "$BACKUP"
  cp "$NEW_BIN" "$STAGING" || { echo "Error: cannot write to $DEST_DIR (check permissions)"; exit 1; }
  chmod +x "$STAGING"
  mv -f "$STAGING" "$TARGET_BIN"
  echo "Binary updated: $TARGET_BIN"

  # ── trigger service restart ───────────────────────────────────────────────
  if ! restart_service || ! verify_update; then
    echo "Error: updated service failed health verification; restoring previous binary"
    if [ -f "$BACKUP" ]; then
      ROLLBACK_STAGING="${DEST_DIR}/.wantasticd.rollback.$$"
      cp -p "$BACKUP" "$ROLLBACK_STAGING"
      chmod +x "$ROLLBACK_STAGING"
      mv -f "$ROLLBACK_STAGING" "$TARGET_BIN"
      restart_service || true
    fi
    exit 1
  fi
  echo "Update complete — running version: $VERSION"
}

main "$@"
