#!/bin/bash
# Deploy wantasticd agent + firmware to ONU (PTF2164Q / EN7528)
# Run from the wantasticd repo root after confirming ONU is reachable.
#
# Usage:
#   ./scripts/deploy-onu.sh [onu-ip]
#
# Default ONU IP: 192.168.1.1
# Requires: curl, sshpass or SSH key access to the ONU
set -euo pipefail

ONU_IP="${1:-192.168.1.1}"
ONU_USER="${ONU_USER:-root}"
ONU_PASS="${ONU_PASS:-}"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
AGENT_BIN="$REPO_DIR/bin/fiberagent-tiny"
FW_IMAGE="/Users/kimo/olt-work/onu-fw/onu-fs-new.bin"
BRAND_DIR="/Users/kimo/olt-work/onu-fw/rootfs-extracted/usr/osgi/wantastic/brand"
DEPLOY_DIR="/usr/osgi/wantastic"

echo "=== ONU Deployment ==="
echo "ONU:       $ONU_IP"
echo "Agent:     $AGENT_BIN ($(wc -c < "$AGENT_BIN" | tr -d ' ') bytes)"
echo "Firmware:  $FW_IMAGE ($(wc -c < "$FW_IMAGE" | tr -d ' ') bytes)"
echo ""

# Check prerequisites
for f in "$AGENT_BIN" "$FW_IMAGE"; do
    [ -f "$f" ] || { echo "ERROR: $f not found"; exit 1; }
done

ping -c 1 -W 3 "$ONU_IP" >/dev/null 2>&1 || { echo "ERROR: $ONU_IP unreachable"; exit 1; }
echo "[OK] ONU reachable"

# Build SSH/SCP command with legacy cipher support (EN7528 dropbear)
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
SSH_OPTS="$SSH_OPTS -o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
SSH_OPTS="$SSH_OPTS -o HostKeyAlgorithms=+ssh-rsa,ssh-dss"
SSH_OPTS="$SSH_OPTS -o PubkeyAcceptedKeyTypes=+ssh-rsa"
SSH_OPTS="$SSH_OPTS -o Ciphers=+aes128-cbc,aes256-cbc,3des-cbc"

do_ssh() { ssh $SSH_OPTS "$ONU_USER@$ONU_IP" "$@"; }
do_scp() { scp $SSH_OPTS "$@"; }

echo ""
echo "--- Step 1: Deploy agent binary ---"
do_ssh "mkdir -p $DEPLOY_DIR" 2>/dev/null || true
do_scp "$AGENT_BIN" "$ONU_USER@$ONU_IP:$DEPLOY_DIR/wantasticd"
do_ssh "chmod +x $DEPLOY_DIR/wantasticd"
echo "[OK] Agent deployed to $DEPLOY_DIR/wantasticd"

# Deploy brand logos
if [ -d "$BRAND_DIR" ]; then
    do_ssh "mkdir -p $DEPLOY_DIR/brand" 2>/dev/null || true
    do_scp "$BRAND_DIR/logo_oem.png" "$ONU_USER@$ONU_IP:$DEPLOY_DIR/brand/"
    do_scp "$BRAND_DIR/titlelogo_oem.png" "$ONU_USER@$ONU_IP:$DEPLOY_DIR/brand/"
    echo "[OK] Brand logos deployed"
fi

echo ""
echo "--- Step 2: Verify agent runs ---"
AGENT_VER=$(do_ssh "$DEPLOY_DIR/wantasticd status 2>/dev/null || $DEPLOY_DIR/wantasticd --version 2>/dev/null || echo unknown")
echo "Agent version: $AGENT_VER"

echo ""
echo "--- Step 3: Flash firmware ---"
echo "Uploading firmware to ONU web interface..."
# The ONU's boa web server accepts firmware uploads via /cgi-bin/upgrade.asp
# Method 1: HTTP multipart upload to the CGI endpoint
curl -s -o /dev/null -w "%{http_code}" \
    -F "tools_FW_UploadFile=@$FW_IMAGE" \
    "http://$ONU_IP/cgi-bin/upgrade.asp" && echo " [OK] Firmware uploaded" || {
    echo "HTTP upload failed. Trying SCP fallback..."
    # Method 2: SCP to /tmp and trigger flash via CLI
    do_scp "$FW_IMAGE" "$ONU_USER@$ONU_IP:/tmp/firmware.bin"
    do_ssh "mtd write /tmp/firmware.bin rootfs && echo '[OK] Flash complete' || echo '[FAIL] Flash failed'"
}

echo ""
echo "--- Step 4: Post-flash verification ---"
echo "The ONU will reboot after firmware flash."
echo "After reboot, verify:"
echo "  1. Web UI at http://$ONU_IP — should show CyberAntennas branding"
echo "  2. Menu should have 'CyberAntennas' tab under Network"
echo "  3. http://$ONU_IP/wantastic.html — should load the dashboard"
echo "  4. Agent at http://$ONU_IP:9043/status — onboarding status"
echo ""
echo "To test WUSP getters:"
echo "  curl http://$ONU_IP:9043/api/wusp/telemetry | python3 -m json.tool"
echo ""
echo "To test WUSP setters:"
echo '  curl -X POST http://'$ONU_IP':9043/api/wusp/set -d '"'"'{"path":"Device.WUSP_ONU.Network.DNS.Server.1.Address","value":"8.8.8.8"}'"'"
echo ""
echo "To test WUSP operate:"
echo '  curl -X POST http://'$ONU_IP':9043/api/wusp/operate -d '"'"'{"command":"Device.WUSP_ONU.Network.BackupNetworkConfig()"}'"'"
echo ""
echo "=== Done ==="
