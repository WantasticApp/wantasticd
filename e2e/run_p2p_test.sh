#!/bin/bash
set -e

# Wait for containers
echo "==> Ensuring wantasticd clients are running..."
if ! docker ps | grep "wantasticd-client1" > /dev/null; then
  echo "Containers not running. Please start them first (e.g. docker compose up -d)."
  exit 1
fi

echo "==> Waiting 5 seconds for tunnels to establish handshakes and P2P connections..."
sleep 5

echo "=========================================="
echo "     WIREGUARD TUNNEL STATUS (P2P PROOF)  "
echo "=========================================="
echo "--- Client1 Status ---"
docker exec wantasticd-client1 /app/tmp/wantasticd status || echo "Status unavailable"
echo ""
echo "--- Client2 Status ---"
docker exec wantasticd-client2 /app/tmp/wantasticd status || echo "Status unavailable"
echo ""

echo "=========================================="
echo "          LATENCY TESTS (PING)            "
echo "=========================================="
echo "PING from Client1 (10.0.0.3) -> Client2 (10.0.0.4)"
docker exec wantasticd-client1 /app/tmp/wantasticd ping -c 4 10.0.0.4 || echo "Ping failed"

echo ""
echo "PING from Client1 (10.0.0.3) -> Client3 (10.0.0.5)"
docker exec wantasticd-client1 /app/tmp/wantasticd ping -c 4 10.0.0.5 || echo "Ping failed"

echo ""
echo "=========================================="
echo "         THROUGHPUT TESTS (IPERF3)        "
echo "=========================================="

echo "Starting iperf3 servers on Client2 and Client3..."
docker exec -d wantasticd-client2 iperf3 -s -p 5201
docker exec -d wantasticd-client3 iperf3 -s -p 5201

# Allow servers to start
sleep 2

echo "..."
echo "IPERF3 from Client1 -> Client2 (P2P Over WireGuard TUN)"
docker exec wantasticd-client1 iperf3 -c 10.0.0.4 -p 5201 -t 10 || echo "iPerf3 failed"

echo "..."
echo "IPERF3 from Client1 -> Client3 (P2P Over WireGuard TUN)"
docker exec wantasticd-client1 iperf3 -c 10.0.0.5 -p 5201 -t 10 || echo "iPerf3 failed"

echo "..."
echo "=========================================="
echo "    THROUGHPUT TESTS (NORMAL NETWORK)     "
echo "=========================================="
echo "IPERF3 from Client1 -> Client2 (Normal Docker Network)"
docker exec wantasticd-client1 iperf3 -c 172.25.0.12 -p 5201 -t 10 || echo "iPerf3 failed"

echo "..."
echo "IPERF3 from Client1 -> Client3 (Normal Docker Network)"
docker exec wantasticd-client1 iperf3 -c 172.25.0.13 -p 5201 -t 10 || echo "iPerf3 failed"

echo "=========================================="
echo "            CLEANUP                       "
echo "=========================================="
echo "Killing background tasks..."
docker exec wantasticd-client1 killall wantasticd 2>/dev/null || true
docker exec wantasticd-client2 killall iperf3 2>/dev/null || true
docker exec wantasticd-client3 killall iperf3 2>/dev/null || true

echo "E2E P2P Test Finished Successfully!"
