#!/bin/bash
# e2e/run_oauth2_test.sh
# End-to-end test for the OAuth2 / device-registration flow.
#
# What it tests:
#   1. Mock portal starts and serves OAuth2 + register endpoints
#   2. `wantasticd login --token` path: HMAC signed register, ChaCha20 decrypt, config save, agent starts
#   3. `wantasticd login` device flow path: RFC 8628 poll → token → register → config save, agent starts
#   4. `wantasticd connect` starts the agent from a saved config and TUN interface comes up
#   5. /api/status HTTP endpoint returns running=true
#   6. Mock portal rejects requests with invalid HMAC (401)
#
# Prerequisites: Docker + docker compose v2

set -euo pipefail

COMPOSE="docker compose -f e2e/docker-compose/docker-compose.oauth2.yml"
PASS=0
FAIL=0

pass() { echo "  [PASS] $*"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL + 1)); }
section() {
  echo ""
  echo "=========================================="
  echo "  $*"
  echo "=========================================="
}

cleanup() {
  echo ""
  echo "==> Cleaning up containers and volumes..."
  $COMPOSE down --remove-orphans --volumes 2>/dev/null || true
}
trap cleanup EXIT

# Wait for a string to appear in container logs (with timeout)
wait_for_log() {
  local container="$1"
  local pattern="$2"
  local timeout_sec="${3:-30}"
  for i in $(seq 1 "$timeout_sec"); do
    if docker logs "$container" 2>&1 | grep -q "$pattern"; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# ── 1. Build images ──────────────────────────────────────────────────────────
section "BUILDING IMAGES"
$COMPOSE build mockportal builder auth-token auth-device-flow auth-connect
pass "Docker images built"

# ── 2. Start mock portal ─────────────────────────────────────────────────────
section "STARTING MOCK PORTAL"
$COMPOSE up -d mockportal

echo "==> Waiting for mockportal health check..."
for i in $(seq 1 30); do
  STATUS=$(docker inspect --format='{{.State.Health.Status}}' wantasticd-mockportal 2>/dev/null || echo "")
  if [ "$STATUS" = "healthy" ]; then
    break
  fi
  sleep 1
  if [ "$i" -eq 30 ]; then
    fail "mockportal did not become healthy in time"
    docker logs wantasticd-mockportal 2>&1 || true
    exit 1
  fi
done
pass "Mock portal is healthy"

# ── 3. Build the wantasticd binary (cached in named volume) ─────────────────
section "BUILDING wantasticd BINARY"
echo "==> Running builder service (go build inside container)..."
set +e
$COMPOSE run --rm --no-deps builder > /tmp/build_output.txt 2>&1
BUILD_EXIT=$?
set -e

if [ "$BUILD_EXIT" -eq 0 ] && grep -q "Build OK" /tmp/build_output.txt; then
  pass "wantasticd binary built successfully"
else
  echo "--- build output ---"
  cat /tmp/build_output.txt
  fail "wantasticd binary build failed (exit $BUILD_EXIT)"
  exit 1
fi

# ── 4. Test: --token path ────────────────────────────────────────────────────
section "TEST 1: LOGIN WITH --token FLAG"
echo "==> Running: wantasticd login --portal-url http://mockportal:8080 --token e2e-test-token"

$COMPOSE up -d --no-deps auth-token

# Wait for agent start (max 30s)
if wait_for_log wantasticd-auth-token "Wantastic agent started successfully" 30; then
  TOKEN_LOG=$(docker logs wantasticd-auth-token 2>&1)
  pass "Login (--token) succeeded and agent started"

  if echo "$TOKEN_LOG" | grep -q "Configuration saved\|Login successful"; then
    pass "Config file was saved successfully"
  else
    fail "Config file save not confirmed in output"
  fi

  if echo "$TOKEN_LOG" | grep -qi "console\|handoff\|confirm\|mockportal"; then
    pass "Handoff/confirmation URL was printed"
  else
    fail "Handoff URL not found in output"
  fi

  if echo "$TOKEN_LOG" | grep -q "TUN mode initialized\|wantastic0\|Created TUN"; then
    pass "TUN interface came up after login"
  else
    fail "TUN interface did not come up after login"
  fi
else
  TOKEN_LOG=$(docker logs wantasticd-auth-token 2>&1)
  echo "--- auth-token logs ---"
  echo "$TOKEN_LOG" | tail -20
  fail "Login (--token) did not start agent within 30s"
  fail "Config file save check skipped"
  fail "Handoff URL check skipped"
  fail "TUN interface check skipped"
fi

$COMPOSE stop auth-token 2>/dev/null || true

# ── 5. Test: device flow path ────────────────────────────────────────────────
section "TEST 2: DEVICE FLOW (RFC 8628)"
echo "==> Running: wantasticd login --portal-url http://mockportal:8080 (full RFC 8628 poll flow)"

$COMPOSE up -d --no-deps auth-device-flow

# Device flow: credentials fetch → device code → poll (1 pending, 1 approve) → register → agent start
if wait_for_log wantasticd-auth-device "Wantastic agent started successfully" 45; then
  DEVICE_LOG=$(docker logs wantasticd-auth-device 2>&1)
  pass "Login (device flow) succeeded and agent started"

  if echo "$DEVICE_LOG" | grep -qi "E2E-TEST\|verification\|device\|Wantastic Device Authorization"; then
    pass "Device auth UI was displayed"
  else
    fail "Device auth UI not found in output"
  fi

  if echo "$DEVICE_LOG" | grep -q "Configuration saved\|Login successful"; then
    pass "Config saved after device flow"
  else
    fail "Config save not confirmed after device flow"
  fi

  if echo "$DEVICE_LOG" | grep -q "TUN mode initialized\|wantastic0\|Created TUN"; then
    pass "Agent TUN came up after device flow"
  else
    fail "TUN did not come up after device flow"
  fi
else
  DEVICE_LOG=$(docker logs wantasticd-auth-device 2>&1)
  echo "--- auth-device-flow logs ---"
  echo "$DEVICE_LOG" | tail -20
  fail "Login (device flow) did not start agent within 45s"
  fail "Device auth UI check skipped"
  fail "Config save check skipped"
  fail "Agent TUN check skipped"
fi

$COMPOSE stop auth-device-flow 2>/dev/null || true

# ── 6. Test: connect + agent status ─────────────────────────────────────────
section "TEST 3: CONNECT — AGENT STARTS FROM SAVED CONFIG"
echo "==> Starting auth-connect container (wantasticd connect from pre-baked client1.conf)..."

$COMPOSE up -d --no-deps auth-connect

if wait_for_log wantasticd-auth-connect "Wantastic agent started successfully" 20; then
  pass "Agent started via connect command"
else
  echo "(timed out waiting for agent start)"
  docker logs wantasticd-auth-connect 2>&1 | tail -20 || true
  fail "Agent did not start via connect within 20s"
fi

echo "--- TUN interface status ---"
if docker exec wantasticd-auth-connect ip addr show wantastic0 2>/dev/null; then
  pass "TUN interface wantastic0 is up"
else
  fail "TUN interface wantastic0 not found"
fi

echo ""
echo "--- /api/status (port 9034) ---"
IPC_RESP=$(docker exec wantasticd-auth-connect \
  wget -qO- "http://127.0.0.1:9034/api/status" 2>/dev/null || echo "")
echo "$IPC_RESP"

if echo "$IPC_RESP" | grep -q '"running":true'; then
  pass "/api/status reports running=true"
else
  fail "/api/status did not report running=true (got: $IPC_RESP)"
fi

if echo "$IPC_RESP" | grep -q '"tun_mode":true'; then
  pass "/api/status reports tun_mode=true"
else
  fail "/api/status did not report tun_mode=true"
fi

# ── 7. Test: HMAC rejection ──────────────────────────────────────────────────
section "TEST 4: HMAC REJECTION"
echo "==> Sending a request with bad HMAC to /api/agent/register..."

# Send bad request from within the wantastic-oauth2 network using the connect container
# (which has wget available via Dockerfile.oauth2)
HMAC_OUT=$(docker exec wantasticd-auth-connect sh -c \
  'wget -q -O /dev/null \
     --method=POST \
     --body-data='"'"'{"hostname":"x","os":"linux","arch":"amd64","nonce":1}'"'"' \
     --header='"'"'Authorization: Bearer faketoken'"'"' \
     --header='"'"'Content-Type: application/json'"'"' \
     --header='"'"'x-wantastic-ts: 0'"'"' \
     --header='"'"'x-wantastic-device: baddevice'"'"' \
     --header='"'"'x-wantastic-sig: badsig'"'"' \
     http://172.26.0.10:8080/api/agent/register 2>&1; echo "exit:$?"' 2>/dev/null || echo "")
echo "$HMAC_OUT"

# The portal rejects with 401; wget exits non-zero (6 = auth failure, or other)
# Check the mockportal logs for the rejection instead
if docker logs wantasticd-mockportal 2>&1 | grep -q "HMAC validation failed\|invalid signature"; then
  pass "Mock portal correctly rejected bad HMAC (logged rejection)"
else
  # Fallback: non-zero wget exit (auth rejected = non-200)
  if echo "$HMAC_OUT" | grep -q "exit:[^0]"; then
    pass "Mock portal rejected bad HMAC (wget non-zero exit)"
  else
    fail "HMAC rejection not confirmed"
  fi
fi

# ── 8. Check mock portal logs ────────────────────────────────────────────────
section "MOCK PORTAL LOGS"
docker logs wantasticd-mockportal 2>&1 | grep -E "\[mockportal\]|Register|HMAC|credentials" | tail -20 || true

# ── Summary ──────────────────────────────────────────────────────────────────
section "RESULTS"
TOTAL=$((PASS + FAIL))
echo "  Passed: $PASS / $TOTAL"
echo "  Failed: $FAIL / $TOTAL"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "E2E OAuth2 Test FAILED"
  exit 1
else
  echo "E2E OAuth2 Test PASSED"
  exit 0
fi
