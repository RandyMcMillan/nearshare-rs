#!/bin/bash
# Test that two NearShare instances discover each other via libp2p mDNS.
set -e

pkill -f nearshare-rs 2>/dev/null || true
sleep 1

BIN="${CARGO_TARGET_DIR:-$(cargo metadata --format-version 1 2>/dev/null | grep -o '"target_directory":"[^"]*"' | cut -d'"' -f4)}"/release/nearshare-rs

if [ ! -f "$BIN" ]; then
    echo "Building release binary..."
    cargo build --release
fi

echo "=== Starting instance 1 on port 8080 ==="
$BIN > /tmp/nearshare-test-1.log 2>&1 &
PID1=$!
sleep 4

echo "=== Starting instance 2 on port 8081 ==="
PORT=8081 $BIN > /tmp/nearshare-test-2.log 2>&1 &
PID2=$!
sleep 8

function cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    kill $PID1 $PID2 2>/dev/null || true
    wait $PID1 $PID2 2>/dev/null || true
}
trap cleanup EXIT

echo ""
echo "=== Instance 1 logs ==="
cat /tmp/nearshare-test-1.log

echo ""
echo "=== Instance 2 logs ==="
cat /tmp/nearshare-test-2.log

echo ""
echo "=== Auth on instance 1 ==="
TOK1=$(curl -s -X POST http://localhost:8080/api/auth \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"password"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

echo "=== Peers via instance 1 HTTP API ==="
PEERS=$(curl -s http://localhost:8080/api/peers -H "Authorization: Bearer $TOK1")
echo "$PEERS"

echo ""
if [ "$PEERS" != "[]" ]; then
    echo "✅ Discovery test PASSED — peers found"
else
    echo "❌ Discovery test FAILED — no peers found"
    exit 1
fi
