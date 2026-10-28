#!/bin/sh
# Wantasticd Self-Update Script
# Safe atomic binary replacement + service-managed restart.
# Usage: ./self-update.sh [version] [target-binary-path] [downloaded-archive]
# The agent downloads the archive itself and passes it as the third argument;
# manual runs fall back to curl, wget or uclient-fetch.
set -e

BASE_URL="https://get.wantastic.app"
CONNECT_TIMEOUT="${WANTASTIC_UPDATE_CONNECT_TIMEOUT:-15}"
DOWNLOAD_TIMEOUT="${WANTASTIC_UPDATE_DOWNLOAD_TIMEOUT:-300}"
VERIFY_TIMEOUT="${WANTASTIC_UPDATE_VERIFY_TIMEOUT:-20}"
SERVICE_MANAGER=""
LAUNCHD_LABEL="com.wantastic.wantasticd"
TRAY_LABEL="com.wantastic.tray"
TRAY_PLIST="/Library/LaunchAgents/${TRAY_LABEL}.plist"
NO_TRAY_MARKER="/Library/Application Support/Wantastic/no-tray"
OLD_PID=""

run_initd() {
  if [ -x /etc/init.d/wantasticd ]; then
    /etc/init.d/wantasticd "$1"
  elif [ -f /etc/init.d/wantasticd ]; then
    /bin/sh /etc/init.d/wantasticd "$1"
  else
    return 1
  fi
}

# fetch URL DEST — prints the HTTP status (200 on success). BusyBox wget and
# uclient-fetch do not report a status code, so success maps to 200.
fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -sSL \
      --connect-timeout "$CONNECT_TIMEOUT" \
      --max-time "$DOWNLOAD_TIMEOUT" \
      --retry 2 \
      --retry-delay 2 \
      --retry-connrefused \
      -w "%{http_code}" \
      -o "$2" \
      "$1"
    return 0
  fi
  for _fetcher in wget uclient-fetch; do
    if command -v "$_fetcher" >/dev/null 2>&1; then
      if "$_fetcher" -q -T "$CONNECT_TIMEOUT" -O "$2" "$1" >/dev/null 2>&1 && [ -s "$2" ]; then
        printf 200
      else
        printf 000
      fi
      return 0
    fi
  done
  echo "Error: no downloader available (curl, wget or uclient-fetch)" >&2
  printf 000
}

# ── platform ─────────────────────────────────────────────────────────────────
UNAME_S="$(uname -s)"
case "$UNAME_S" in
  Linux*)  OS="linux"  ;;
  Darwin*) OS="darwin" ;;
  *) echo "Unsupported OS: $UNAME_S"; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64)
    ARCH="amd64"
    # A shell under Rosetta reports x86_64 on Apple silicon; install native.
    if [ "$OS" = "darwin" ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null)" = "1" ]; then
      ARCH="arm64"
    fi
    ;;
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
launchd_pid() {
  launchctl print "system/$LAUNCHD_LABEL" 2>/dev/null | awk '$1 == "pid" { print $3; exit }'
}

restart_service() {
  # launchd (macOS). Checked first so a stray /etc/init.d entry cannot shadow
  # it. kickstart -k replaces the job in one step; stop/start raced KeepAlive.
  if [ "$OS" = "darwin" ] && command -v launchctl >/dev/null 2>&1 &&
     launchctl print "system/$LAUNCHD_LABEL" >/dev/null 2>&1; then
    echo "Restarting via launchd…"
    OLD_PID=$(launchd_pid)
    launchctl kickstart -k "system/$LAUNCHD_LABEL"
    SERVICE_MANAGER="launchd"
    return 0
  fi
  # systemd
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet wantasticd 2>/dev/null; then
    echo "Restarting via systemd…"
    systemctl restart wantasticd
    SERVICE_MANAGER="systemd"
    return 0
  fi
  # procd (OpenWrt)
  if [ -f /etc/init.d/wantasticd ] && command -v procd >/dev/null 2>&1; then
    echo "Restarting via procd…"
    run_initd restart
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
  if [ -f /etc/init.d/wantasticd ]; then
    echo "Restarting via init.d…"
    run_initd restart
    SERVICE_MANAGER="initd"
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
    initd)
      if run_initd status >/dev/null 2>&1; then
        return 0
      fi
      if command -v ubus >/dev/null 2>&1; then
        _service_state=$(ubus call service list '{"name":"wantasticd"}' 2>/dev/null || true)
        echo "$_service_state" | grep -q '"running"[[:space:]]*:[[:space:]]*true'
      else
        pidof wantasticd >/dev/null 2>&1
      fi
      ;;
    openrc) rc-service wantasticd status >/dev/null 2>&1 ;;
    launchd)
      # "launchctl list" succeeds for a loaded but crashed job; require a
      # running process that is not the one we replaced.
      _pid=$(launchd_pid)
      [ -n "$_pid" ] && [ "$_pid" != "$OLD_PID" ] && kill -0 "$_pid" 2>/dev/null
      ;;
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

# macOS kills unsigned arm64 binaries and refuses quarantined ones.
prepare_darwin_binary() {
  [ "$OS" = "darwin" ] || return 0
  xattr -d com.apple.quarantine "$1" 2>/dev/null || true
  if ! codesign -v "$1" >/dev/null 2>&1; then
    codesign -f -s - "$1" >/dev/null 2>&1 || echo "Warning: could not ad-hoc sign $1"
  fi
}

# The menu-bar app runs per user from the same binary. Install its agent when
# missing (installs from before the tray existed) and restart it on the new
# binary, unless the admin opted out with the no-tray marker.
refresh_darwin_tray() {
  [ "$SERVICE_MANAGER" = "launchd" ] || return 0
  [ -f "$NO_TRAY_MARKER" ] && return 0
  if [ ! -f "$TRAY_PLIST" ]; then
    mkdir -p /Library/LaunchAgents 2>/dev/null || return 0
    cat > "$TRAY_PLIST" <<PLIST || return 0
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>${TRAY_LABEL}</string>
  <key>ProgramArguments</key>
  <array><string>${TARGET_BIN}</string><string>tray</string></array>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
  <key>ProcessType</key><string>Interactive</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>10</integer>
</dict></plist>
PLIST
    chmod 644 "$TRAY_PLIST"
    echo "Installed menu-bar agent $TRAY_PLIST"
  fi
  _uid=$(stat -f %u /dev/console 2>/dev/null || true)
  case "$_uid" in ""|0) return 0 ;; esac
  if launchctl print "gui/$_uid/$TRAY_LABEL" >/dev/null 2>&1; then
    launchctl kickstart -k "gui/$_uid/$TRAY_LABEL" >/dev/null 2>&1 || true
  else
    launchctl bootstrap "gui/$_uid" "$TRAY_PLIST" >/dev/null 2>&1 || true
  fi
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
  ARCHIVE="${3:-}"

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
    _latest_file=$(mktemp)
    [ "$(fetch "${BASE_URL}/latest" "$_latest_file")" = "200" ] && VERSION=$(tr -d '[:space:]' < "$_latest_file")
    rm -f "$_latest_file"
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

  TMP_DIR=$(mktemp -d)
  # WANTASTIC_UPDATE_WORKDIR is the agent's download directory (holding this
  # script and the archive); the agent may have exited, so clean it here too.
  trap 'rm -rf "$TMP_DIR" ${WANTASTIC_UPDATE_WORKDIR:+"$WANTASTIC_UPDATE_WORKDIR"}' EXIT

  if [ -n "$ARCHIVE" ] && [ -s "$ARCHIVE" ]; then
    echo "Using downloaded archive $ARCHIVE"
    cp "$ARCHIVE" "$TMP_DIR/pkg.tar.gz"
  else
    echo "Downloading $DOWNLOAD_URL…"
    CODE=$(fetch "$DOWNLOAD_URL" "$TMP_DIR/pkg.tar.gz")
    [ "$CODE" = "200" ] || { echo "Error: download failed (HTTP $CODE)"; exit 1; }
  fi

  tar -xzf "$TMP_DIR/pkg.tar.gz" -C "$TMP_DIR"

  if [ "$OS" = "darwin" ]; then
    NEW_BIN=$(find "$TMP_DIR" -name "wantasticd" -type f -perm +111 2>/dev/null | head -n 1)
  else
    NEW_BIN=$(find "$TMP_DIR" -name "wantasticd" -type f 2>/dev/null | head -n 1)
  fi
  [ -n "$NEW_BIN" ] || { echo "Error: binary not found in archive"; ls -la "$TMP_DIR"; exit 1; }

  chmod +x "$NEW_BIN"
  prepare_darwin_binary "$NEW_BIN"

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
  # Kept next to the binary after a successful update for manual rollback;
  # each update replaces it, so backups never accumulate.
  BACKUP="${TARGET_BIN}.previous"

  # Leftovers from an update that was killed half-way.
  rm -f "${DEST_DIR}"/.wantasticd.update.* "${DEST_DIR}"/.wantasticd.rollback.* 2>/dev/null || true
  if [ -f "$TARGET_BIN" ]; then
    { cp -p "$TARGET_BIN" "${BACKUP}.tmp" && mv -f "${BACKUP}.tmp" "$BACKUP"; } ||
      { echo "Error: cannot back up $TARGET_BIN"; exit 1; }
  fi
  cp "$NEW_BIN" "$STAGING" || { echo "Error: cannot write to $DEST_DIR (check permissions)"; exit 1; }
  chmod +x "$STAGING"
  # Always a new inode, never an in-place overwrite: macOS caches code
  # signatures per vnode and kills a binary whose pages change underneath.
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
  refresh_darwin_tray
  echo "Update complete — running version: $VERSION"
}

main "$@"
