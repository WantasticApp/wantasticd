#!/bin/sh
# --- DNS: prefer the core server reachable through the WG tunnel ---
# wg.conf declares `DNS = 10.0.0.1` (the wantasticd core server inside the
# tunnel). Docker overwrites /etc/resolv.conf at container start, so we have
# to (re)write it here. The fallback to 8.8.8.8 lets early-boot lookups work
# before the handshake completes; once the tunnel is up, queries go to the
# core server first. `options timeout:1 attempts:1` keeps fallback fast when
# the tunnel is briefly down.
#
# /etc/resolv.conf is a symlink in OpenWrt rootfs — replace it with a
# regular file so our writes stick.
WG_CORE_DNS="10.0.0.1"
# Docker may bind-mount /etc/resolv.conf (rm fails with EBUSY). If it's a
# symlink (OpenWrt default), swap it for a regular file; otherwise overwrite
# the bind-mounted file in place — both work.
if [ -L /etc/resolv.conf ]; then
    rm -f /etc/resolv.conf
fi
cat > /etc/resolv.conf <<EOF
# Primary: wantasticd core server (reachable through WG tunnel)
nameserver ${WG_CORE_DNS}
# Bootstrap fallback (used until the tunnel is up, and for non-tunneled lookups)
nameserver 8.8.8.8
nameserver 1.1.1.1
options timeout:1 attempts:1
EOF

# --- SSH (dropbear) ---
rm -rf /etc/dropbear
mkdir -p /etc/dropbear
# Some dropbear builds in OpenWrt drop ecdsa support — generate only the
# universally-supported types.
dropbearkey -t rsa     -f /etc/dropbear/dropbear_rsa_host_key     2>/dev/null
dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key 2>/dev/null
echo -e "root\nroot" | passwd root
/usr/sbin/dropbear -B -p 22

# --- LuCI runtime prerequisites ---
# We can't use procd as PID 1 (we need to run wantasticd via air). So we
# manually replicate what procd's /etc/init.d/{ubusd,rpcd,uhttpd,system}
# would normally do:
#   • ubusd  → IPC bus
#   • rpcd   → registers session/login/file/luci/iwinfo with ubus
#              (without it, LuCI's runtime.uc:133 nulls and 500's the page)
#   • board.json → static fallback so `ubus call system board` works
#   • LuCI cache/session dirs in /tmp
# We deliberately do NOT start netifd: it would clobber Docker's eth0 by
# applying the stock OpenWrt /etc/config/network.
mkdir -p /var/run/ubus /var/run /var/lock /var/state /tmp/state /tmp/run \
         /tmp/luci-modulecache /tmp/luci-indexcache /tmp/luci-sessions \
         /tmp/.uci

# Static board.json (procd's /etc/init.d/boot would normally generate this).
if [ ! -s /etc/board.json ]; then
    cat > /etc/board.json <<EOF
{
  "model": { "id": "wantasticd-dev", "name": "WantastiC Dev Container" },
  "release": {
    "distribution": "OpenWrt",
    "version": "23.05",
    "revision": "container",
    "target": "armvirt/64",
    "description": "OpenWrt 23.05 (WantastiC dev container)"
  },
  "hostname": "$(hostname)",
  "system": "container",
  "led": {},
  "network": {
    "lan": { "ifname": "eth0", "protocol": "dhcp" }
  }
}
EOF
fi

# Set hostname inside the container's UCI so LuCI shows something sensible.
[ -f /etc/config/system ] && \
    uci -q set system.@system[0].hostname="$(hostname)" && \
    uci -q commit system

# Disable init scripts that would otherwise reconfigure Docker's eth0 or
# fight with the host. procd will start everything else for us.
for svc in network firewall firewall4 odhcpd dnsmasq miniupnpd umdns ucitrack \
           sysntpd urandom_seed boot done; do
    [ -x /etc/init.d/$svc ] && /etc/init.d/$svc disable 2>/dev/null
done

# Start ubusd first (procd needs it).
[ -x /sbin/ubusd ] && /sbin/ubusd &
for i in 1 2 3 4 5; do
    [ -S /var/run/ubus/ubus.sock ] && break
    sleep 1
done

# Start procd in user mode (not as PID 1). It registers the `system` and
# `service` ubus namespaces — `system.board` etc. — that LuCI calls during
# request dispatch. Without it, runtime.uc:133 hits a null and 500's the page.
# It also runs the remaining (non-disabled) init.d scripts: rpcd, uhttpd,
# dropbear, log, ...
[ -x /sbin/procd ] && /sbin/procd &

# Wait until `system` is registered on ubus, or 8 s, whichever comes first.
for i in 1 2 3 4 5 6 7 8; do
    if ubus -t 1 list 2>/dev/null | grep -q '^system$'; then
        echo "✅ procd registered system+service on ubus"
        break
    fi
    sleep 1
done

# Belt-and-suspenders: if procd didn't autostart rpcd (e.g. enable symlinks
# missing), kick it manually. Without rpcd, LuCI session/luci/file ubus
# methods are absent.
if ! ubus -t 1 list 2>/dev/null | grep -q '^session$'; then
    [ -x /sbin/rpcd ] && /sbin/rpcd &
    sleep 1
fi

# --- WiFi simulator ---
# Change radios=N to create more fake phys
modprobe mac80211_hwsim radios=2 || echo "mac80211_hwsim failed to load (check --privileged and host kernel module)"

# Wait for phys to register in sysfs
for i in 1 2 3 4 5; do
    [ -d /sys/class/ieee80211/phy0 ] && break
    sleep 1
done

# --- Generate /etc/config/wireless from detected phys ---
# OpenWrt's netifd matches `option path` against the device's sysfs path,
# so we resolve it dynamically instead of using 'virtual'.
: > /etc/config/wireless
phy_idx=0
for phy_path in /sys/class/ieee80211/*; do
    [ -e "$phy_path" ] || continue
    phy=$(basename "$phy_path")
    dev_link=$(readlink -f "$phy_path/device" 2>/dev/null)
    rel_path=${dev_link#/sys/devices/}
    rel_path=${rel_path%/ieee80211/$phy}

    cat >> /etc/config/wireless <<UCI

config wifi-device 'radio${phy_idx}'
    option type 'mac80211'
    option path '${rel_path}'
    option channel '6'
    option band '2g'
    option htmode 'HT20'
    option disabled '0'

config wifi-iface 'default_radio${phy_idx}'
    option device 'radio${phy_idx}'
    option network 'lan'
    option mode 'ap'
    option ssid "WantastiC-Sim-${phy_idx}"
    option encryption 'none'
    option disabled '0'
UCI
    phy_idx=$((phy_idx + 1))
done

if [ "$phy_idx" -eq 0 ]; then
    echo "⚠️  mac80211_hwsim not available (host kernel doesn't expose the module);"
    echo "    writing a static fake wireless UCI so WUSP still reports radios."
    cat > /etc/config/wireless <<'UCI'

config wifi-device 'radio0'
    option type 'mac80211'
    option path 'platform/fake-radio0'
    option channel '6'
    option band '2g'
    option htmode 'HT20'
    option disabled '0'

config wifi-iface 'default_radio0'
    option device 'radio0'
    option network 'lan'
    option mode 'ap'
    option ssid 'WantastiC-Fake-0'
    option encryption 'none'
    option disabled '0'

config wifi-device 'radio1'
    option type 'mac80211'
    option path 'platform/fake-radio1'
    option channel '36'
    option band '5g'
    option htmode 'VHT80'
    option disabled '0'

config wifi-iface 'default_radio1'
    option device 'radio1'
    option network 'lan'
    option mode 'ap'
    option ssid 'WantastiC-Fake-1'
    option encryption 'none'
    option disabled '0'
UCI
    phy_idx=2
fi
echo "✅ ${phy_idx} radio(s) in /etc/config/wireless"

# Note: no `wifi up` — that requires netifd, which we deliberately don't run
# (see comment above). The wireless UCI config above is purely for the WUSP
# agent's UCI-based radio enumeration.

# --- HTTP server on port 80 (LuCI when available, busybox httpd otherwise) ---
# Bound to 0.0.0.0 so the WireGuard TUN (wantastic0, 10.0.0.x) is covered,
# making port 80 discoverable by the core-server port scanner over the tunnel.
# /etc/init.d/uhttpd uses procd which we don't run, so we bypass it.
mkdir -p /www
if [ ! -f /www/index.html ]; then
    cat > /www/index.html <<'HTML'
<!doctype html><html><head><title>WantastiC client</title></head>
<body><h1>WantastiC client</h1>
<p>This client is reachable on port 80 via the WireGuard overlay.</p>
</body></html>
HTML
fi

# --- uhttpd (LuCI web UI) ---
# Same arguments OpenWrt's /etc/init.d/uhttpd builds from /etc/config/uhttpd
# default 'main' instance, plus -p 0.0.0.0:80 explicitly. Bound to 0.0.0.0 so
# the WireGuard TUN (wantastic0) is also covered, making port 80 discoverable
# by the core port scanner over the tunnel.
pkill -f "uhttpd.*0.0.0.0:80" 2>/dev/null
if [ -x /usr/sbin/uhttpd ]; then
    /usr/sbin/uhttpd \
        -h /www -r OpenWrt -x /cgi-bin -i .ucode=/usr/bin/ucode \
        -t 60 -T 30 -k 20 -A 1 -n 3 -N 100 -R \
        -p 0.0.0.0:80
    sleep 1
    if netstat -lnt 2>/dev/null | grep -q ':80 ' || ss -lnt 2>/dev/null | grep -q ':80 '; then
        echo "✅ uhttpd listening on 0.0.0.0:80 (LuCI ready)"
    else
        echo "❌ uhttpd did not bind to :80"
    fi
else
    # Fallback: tiny Go HTTP server for at least port-scan discoverability.
    mkdir -p /www
    [ -f /www/index.html ] || echo "<h1>WantastiC client</h1>" > /www/index.html
    cat > /tmp/httpd-fallback.go <<'GO'
package main
import ("log"; "net/http")
func main() {
    log.Println("[go-httpd] serving /www on :80")
    http.Handle("/", http.FileServer(http.Dir("/www")))
    log.Fatal(http.ListenAndServe(":80", nil))
}
GO
    CGO_ENABLED=0 go build -trimpath -o /usr/local/bin/httpd-fallback /tmp/httpd-fallback.go && \
        /usr/local/bin/httpd-fallback >/var/log/httpd-fallback.log 2>&1 &
    echo "⚠️  uhttpd missing — using Go fallback HTTP server on :80"
fi

# --- Pre-flight diagnostics (logged once before handing off to wantasticd) ---
echo "=== Pre-flight diagnostics ==="
echo "-- /dev/net/tun --"
ls -l /dev/net/tun 2>&1 || echo "MISSING /dev/net/tun (TUN mode will fail)"
echo "-- eth0 / routes --"
ip -br addr 2>/dev/null || ifconfig 2>/dev/null
ip route 2>/dev/null || route -n 2>/dev/null
echo "-- /etc/resolv.conf --"
cat /etc/resolv.conf 2>/dev/null
echo "-- listening sockets --"
netstat -lnt 2>/dev/null | head -20 || ss -lnt 2>/dev/null | head -20
echo "-- WG endpoint resolves --"
getent ahosts wg.wantastic.local 2>/dev/null || nslookup wg.wantastic.local 2>/dev/null || echo "(no resolver tool)"
echo "==============================="

# --- Execute the main command (wantasticd / air) ---
exec "$@"
