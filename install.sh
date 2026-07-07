#!/bin/sh
# Wantastic Agent — Universal Install Script
# Platforms: Linux (systemd / procd-OpenWrt / OpenRC-Alpine / SysV / BusyBox), macOS
# Windows:   irm https://get.wantastic.app/install.ps1 | iex
#
# Usage:
#   curl -sSL https://get.wantastic.app/install.sh | sh
#   curl -sSL https://get.wantastic.app/install.sh | sh -s -- --token <TOKEN>
#   curl -sSL https://get.wantastic.app/install.sh | sh -s -- --portal-url https://console.wantastic.app --token <TOKEN>
set -e

BASE_URL="https://get.wantastic.app"
INSTALL_TOKEN=""
INSTALL_PORTAL_URL=""
INSTALL_SERVER=""
DO_LOGIN=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --token|-t) INSTALL_TOKEN="$2"; DO_LOGIN=1; shift 2 ;;
    --portal-url|-u) INSTALL_PORTAL_URL="$2"; shift 2 ;;
    --server) INSTALL_SERVER="$2"; shift 2 ;;
    --login)    DO_LOGIN=1; shift ;;
    *) shift ;;
  esac
done

# ── platform ─────────────────────────────────────────────────────────────────
UNAME_S="$(uname -s 2>/dev/null || echo unknown)"
case "$UNAME_S" in
  Linux*)  OS="linux"  ;;
  Darwin*) OS="darwin" ;;
  *)
    echo "Unsupported OS: $UNAME_S"
    echo "For Windows run: irm https://get.wantastic.app/install.ps1 | iex"
    exit 1 ;;
esac

case "$(uname -m 2>/dev/null || echo unknown)" in
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
  *)
    echo "Unsupported architecture: $(uname -m)"
    echo "Download manually from $BASE_URL"
    exit 1 ;;
esac

echo "Platform: $OS/$ARCH"

# ── readonly filesystem (OpenWrt / embedded) ──────────────────────────────────
NEED_REMOUNT_RO=0
if [ "$OS" = "linux" ]; then
  if grep -qE " / .*\bro\b" /proc/mounts 2>/dev/null; then
    echo "Root filesystem is read-only — remounting rw…"
    if mount -o remount,rw / 2>/dev/null; then
      NEED_REMOUNT_RO=1
    else
      echo "  Warning: remount failed, install may fail"
    fi
  fi
fi

# ── download helpers ──────────────────────────────────────────────────────────
have() { command -v "$1" >/dev/null 2>&1; }

http_get() {
  _url="$1"; _dest="$2"
  if have curl; then
    _code=$(curl -sSL -w "%{http_code}" -o "$_dest" "$_url")
    [ "$_code" = "200" ] && return 0
    echo "HTTP $_code downloading $_url"; return 1
  elif have wget; then
    wget -qO "$_dest" "$_url" && return 0
    echo "wget failed: $_url"; return 1
  else
    echo "Error: curl or wget required"; exit 1
  fi
}

http_text() {
  if have curl; then curl -sSL "$1"
  elif have wget; then wget -qO- "$1"
  else echo "Error: curl or wget required"; exit 1
  fi
}

# ── download binary ───────────────────────────────────────────────────────────
echo "Fetching latest version…"
VERSION=$(http_text "${BASE_URL}/latest" | tr -d '[:space:]')
[ -n "$VERSION" ] || { echo "Error: could not determine latest version"; exit 1; }
echo "Version: $VERSION"

TMP_DIR=$(mktemp -d 2>/dev/null || { mkdir -p /tmp/wantastic_install; printf '/tmp/wantastic_install'; })
trap 'rm -rf "$TMP_DIR"' EXIT

ARCHIVE_URL="${BASE_URL}/latest/wantasticd-${OS}-${ARCH}.tar.gz"
echo "Downloading $ARCHIVE_URL…"
http_get "$ARCHIVE_URL" "$TMP_DIR/pkg.tar.gz"
tar -xzf "$TMP_DIR/pkg.tar.gz" -C "$TMP_DIR"

if [ "$OS" = "darwin" ]; then
  EXTRACTED=$(find "$TMP_DIR" -name "wantasticd" -type f -perm +111 2>/dev/null | head -n 1)
else
  EXTRACTED=$(find "$TMP_DIR" -name "wantasticd" -type f 2>/dev/null | head -n 1)
fi
[ -n "$EXTRACTED" ] || { echo "Error: binary not found in archive"; ls -la "$TMP_DIR"; exit 1; }

# ── install binary (atomic) ───────────────────────────────────────────────────
if   [ -d "/usr/local/bin" ] && echo "$PATH" | grep -q "/usr/local/bin"; then
  INSTALL_DIR="/usr/local/bin"
elif [ -d "/usr/bin" ]; then
  INSTALL_DIR="/usr/bin"
else
  INSTALL_DIR="/bin"
fi
INSTALL_PATH="${INSTALL_DIR}/wantasticd"

echo "Installing to $INSTALL_PATH…"
cp "$EXTRACTED" "${INSTALL_PATH}.new"
chmod +x "${INSTALL_PATH}.new"
mv -f "${INSTALL_PATH}.new" "$INSTALL_PATH"
echo "wantasticd $VERSION installed."

# ── config (never overwritten if it exists) ──────────────────────────────────
if [ -n "${WANTASTIC_CONFIG:-}" ]; then
  CONFIG_FILE="$WANTASTIC_CONFIG"
elif [ -n "${WANTASTIC_CONFIG_DIR:-}" ]; then
  CONFIG_FILE="${WANTASTIC_CONFIG_DIR%/}/config.conf"
elif [ "$OS" = "linux" ] && [ -f "/etc/wantastic" ] && [ ! -d "/etc/wantastic" ]; then
  CONFIG_FILE="/etc/wantastic"
elif [ "$OS" = "linux" ] && [ -d "/usrdata" ]; then
  CONFIG_FILE="/usrdata/wantastic/etc/config.conf"
elif [ "$OS" = "darwin" ]; then
  CONFIG_FILE="/Library/Application Support/Wantastic/config.conf"
else
  CONFIG_FILE="/etc/wantastic/config.conf"
fi

CONFIG_DIR=$(dirname "$CONFIG_FILE")
mkdir -p "$CONFIG_DIR" 2>/dev/null || true
quote_sh() {
  printf "'%s'" "$(printf "%s" "$1" | sed "s/'/'\\\\''/g")"
}
INSTALL_PATH_Q=$(quote_sh "$INSTALL_PATH")
CONFIG_FILE_Q=$(quote_sh "$CONFIG_FILE")

if [ ! -f "$CONFIG_FILE" ]; then
  touch "$CONFIG_FILE" 2>/dev/null && chmod 600 "$CONFIG_FILE" 2>/dev/null || true
fi

if [ "$DO_LOGIN" = "1" ]; then
  if [ -s "$CONFIG_FILE" ]; then
    echo "Config already exists at $CONFIG_FILE — skipping login."
  else
    echo ""
    echo "=== Logging in ==="
    run_login() {
      if [ -n "$INSTALL_SERVER" ] && [ -n "$INSTALL_PORTAL_URL" ]; then
        echo "Warning: both --server and --portal-url were provided; using --portal-url."
      fi
      if [ -n "$INSTALL_PORTAL_URL" ] && [ -n "$INSTALL_TOKEN" ]; then
        "$INSTALL_PATH" login --portal-url "$INSTALL_PORTAL_URL" --token "$INSTALL_TOKEN"
      elif [ -n "$INSTALL_PORTAL_URL" ]; then
        "$INSTALL_PATH" login --portal-url "$INSTALL_PORTAL_URL"
      elif [ -n "$INSTALL_SERVER" ] && [ -n "$INSTALL_TOKEN" ]; then
        "$INSTALL_PATH" login --server "$INSTALL_SERVER" --token "$INSTALL_TOKEN"
      elif [ -n "$INSTALL_SERVER" ]; then
        "$INSTALL_PATH" login --server "$INSTALL_SERVER"
      elif [ -n "$INSTALL_TOKEN" ]; then
        "$INSTALL_PATH" login --token "$INSTALL_TOKEN"
      else
        "$INSTALL_PATH" login
      fi
    }

    if run_login; then
      echo "Login successful. Config saved to $CONFIG_FILE"
    else
      echo ""
      echo "Login failed — $CONFIG_FILE is empty. Edit it and re-run: wantasticd login"
    fi
  fi
else
  echo "Skipping login. Run 'wantasticd login' to authenticate."
fi

# ── init system detection ─────────────────────────────────────────────────────
detect_init() {
  if [ -d /run/systemd/private ] || \
     { command -v systemctl >/dev/null 2>&1 && systemctl --version >/dev/null 2>&1; }; then
    echo systemd; return
  fi
  if command -v procd >/dev/null 2>&1 || [ -f /etc/openwrt_release ]; then
    echo procd; return
  fi
  if command -v rc-update >/dev/null 2>&1; then
    echo openrc; return
  fi
  if [ -d /etc/init.d ]; then
    if command -v update-rc.d >/dev/null 2>&1 || command -v chkconfig >/dev/null 2>&1; then
      echo sysv; return
    fi
    echo busybox; return
  fi
  echo unknown
}

# ── service installation ──────────────────────────────────────────────────────
install_service_systemd() {
  cat > /etc/systemd/system/wantasticd.service <<EOF
[Unit]
Description=Wantastic Overlay Networking Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_PATH} connect --config "${CONFIG_FILE}"
Restart=on-failure
RestartSec=5
KillMode=process

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable wantasticd
  systemctl restart wantasticd
  echo "Service registered with systemd and started."
}

install_service_procd() {
  # procd init script (OpenWrt / embedded)
  cat > /etc/init.d/wantasticd <<EOF
#!/bin/sh /etc/rc.common
START=99
STOP=10
USE_PROCD=1
start_service() {
  procd_open_instance
  procd_set_param command ${INSTALL_PATH_Q} connect --config ${CONFIG_FILE_Q}
  procd_set_param respawn 3600 5 0
  procd_set_param stdout 1
  procd_set_param stderr 1
  procd_close_instance
}
EOF
  chmod +x /etc/init.d/wantasticd
  /etc/init.d/wantasticd enable
  /etc/init.d/wantasticd stop 2>/dev/null || true
  /etc/init.d/wantasticd start
  echo "Service registered with procd and started."
}

install_service_openrc() {
  cat > /etc/init.d/wantasticd <<EOF
#!/sbin/openrc-run
description="Wantastic Overlay Networking Daemon"
command="${INSTALL_PATH}"
command_args="connect --config ${CONFIG_FILE_Q}"
command_background=true
pidfile=/run/wantasticd.pid
depend() { need net; }
EOF
  chmod +x /etc/init.d/wantasticd
  rc-update add wantasticd default
  rc-service wantasticd restart
  echo "Service registered with OpenRC and started."
}

install_service_sysv() {
  cat > /etc/init.d/wantasticd <<EOF
#!/bin/sh
### BEGIN INIT INFO
# Provides: wantasticd
# Required-Start: \$network
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
### END INIT INFO
PIDFILE=/var/run/wantasticd.pid
case "\$1" in
  start) start-stop-daemon --start --background --make-pidfile \
           --pidfile \$PIDFILE --exec ${INSTALL_PATH_Q} -- connect --config ${CONFIG_FILE_Q} ;;
  stop)  start-stop-daemon --stop --pidfile \$PIDFILE; rm -f \$PIDFILE ;;
  restart) \$0 stop; sleep 1; \$0 start ;;
  *) echo "Usage: \$0 {start|stop|restart}"; exit 1 ;;
esac
EOF
  chmod +x /etc/init.d/wantasticd
  if command -v update-rc.d >/dev/null 2>&1; then
    update-rc.d wantasticd defaults
  elif command -v chkconfig >/dev/null 2>&1; then
    chkconfig --add wantasticd
  fi
  /etc/init.d/wantasticd restart
  echo "Service registered with SysV init and started."
}

install_service_busybox() {
  # Minimal embedded: respawn via /etc/inittab
  INIT_SCRIPT=/etc/init.d/wantasticd
  printf '#!/bin/sh\nexec %s connect --config %s\n' \
    "$INSTALL_PATH_Q" "$CONFIG_FILE_Q" > "$INIT_SCRIPT"
  chmod +x "$INIT_SCRIPT"
  if ! grep -q "wantasticd" /etc/inittab 2>/dev/null; then
    printf '::respawn:%s\n' "$INIT_SCRIPT" >> /etc/inittab
    echo "Added respawn entry to /etc/inittab."
    # Signal init to re-read inittab (BusyBox init responds to SIGHUP)
    kill -HUP 1 2>/dev/null || true
  fi
  # Also start it now in the background
  "$INSTALL_PATH" connect --config "$CONFIG_FILE" &
  echo "Service started in background (BusyBox respawn configured)."
}

install_service_launchd() {
  PLIST=/Library/LaunchDaemons/com.wantastic.wantasticd.plist
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.wantastic.wantasticd</string>
  <key>ProgramArguments</key>
  <array>
    <string>${INSTALL_PATH}</string>
    <string>connect</string>
    <string>--config</string><string>${CONFIG_FILE}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/wantasticd.log</string>
  <key>StandardErrorPath</key><string>/var/log/wantasticd.log</string>
</dict></plist>
EOF
  launchctl bootout system "$PLIST" 2>/dev/null || true
  launchctl bootstrap system "$PLIST"
  echo "Service registered with launchd and started."
}

if [ "$OS" = "darwin" ]; then
  INIT_SYS="launchd"
else
  INIT_SYS=$(detect_init)
fi

echo ""
echo "=== Installing as system service (init: $INIT_SYS) ==="
case "$INIT_SYS" in
  systemd) install_service_systemd ;;
  procd)   install_service_procd   ;;
  openrc)  install_service_openrc  ;;
  sysv)    install_service_sysv    ;;
  busybox) install_service_busybox ;;
  launchd) install_service_launchd ;;
  *)
    echo "Unknown init system — start manually: wantasticd connect --config $CONFIG_FILE"
    ;;
esac

# ── restore read-only filesystem ──────────────────────────────────────────────
if [ "$NEED_REMOUNT_RO" = "1" ]; then
  echo "Restoring read-only filesystem…"
  mount -o remount,ro / 2>/dev/null || echo "  Warning: could not remount ro"
fi

echo ""
echo "Done. wantasticd $VERSION is installed and running."
