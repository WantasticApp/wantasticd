#!/bin/sh
rm -rf /etc/dropbear
mkdir -p /etc/dropbear
dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key
dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key
dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key

# Set root password to "root" by editing the shadow file
echo -e "root\nroot" | passwd root

# Start dropbear in the background
/usr/sbin/dropbear -B -p 22
# Load the WiFi simulator (you can change radios=2/3/... to create more fake radios)
modprobe mac80211_hwsim radios=2 || echo "mac80211_hwsim failed to load (check --privileged)"

# Optional: auto-create a basic fake AP in UCI so LuCI shows something immediately
uci -q batch << EOF
set wireless.radio0=wifi-device
set wireless.radio0.type='mac80211'
set wireless.radio0.channel='6'
set wireless.radio0.hwmode='11g'
set wireless.radio0.path='virtual'

set wireless.@wifi-iface[0]=wifi-iface
set wireless.@wifi-iface[0].device='radio0'
set wireless.@wifi-iface[0].mode='ap'
set wireless.@wifi-iface[0].ssid='Fake-WiFi-Sim'
set wireless.@wifi-iface[0].encryption='none'
set wireless.@wifi-iface[0].network='lan'

commit wireless
EOF

wifi reload || true

echo "✅ mac80211_hwsim loaded — fake WiFi ready"
# Execute the main command (wantasticd)
exec "$@"
