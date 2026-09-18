#!/bin/bash
# End-to-end test: upload a file on instance 1, send it to instance 2 via P2P, verify it arrives.
set -e

pkill -f nearshare-rs 2>/dev/null || true
sleep 1

BIN="${CARGO_TARGET_DIR:-$(cargo metadata --format-version 1 2>/dev/null | grep -o '"target_directory":"[^"]*"' | cut -d'"' -f4)}"/release/nearshare-rs

if [ ! -f "$BIN" ]; then
    echo "Building release binary..."
    cargo build --release
fi

echo "=== Starting instance 1 on port 8080 ==="
$BIN > /tmp/nearshare-send-1.log 2>&1 &
PID1=$!
sleep 4

echo "=== Starting instance 2 on port 8081 ==="
PORT=8081 $BIN > /tmp/nearshare-send-2.log 2>&1 &
PID2=$!
sleep 8

function cleanup() {
    echo ""
    echo "=== Cleaning up ==="
    kill $PID1 $PID2 2>/dev/null || true
    wait $PID1 $PID2 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Auth on instance 1 ==="
TOK1=$(curl -s -X POST http://localhost:8080/api/auth \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"password"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

echo "=== Auth on instance 2 ==="
TOK2=$(curl -s -X POST http://localhost:8081/api/auth \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"password"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

echo "=== Create test file ==="
echo "hello from p2p test $(date +%s)" > /tmp/nearshare-test.txt

echo "=== Upload to instance 1 ==="
curl -s -X POST http://localhost:8080/api/upload \
    -H "Authorization: Bearer $TOK1" \
    -F "files=@/tmp/nearshare-test.txt"
echo ""

echo "=== List files on instance 1 ==="
curl -s http://localhost:8080/api/files -H "Authorization: Bearer $TOK1"
echo ""

echo "=== Get peer ID of instance 2 ==="
PEER2=$(curl -s http://localhost:8081/api/peer_id | python3 -c "import sys,json; print(json.load(sys.stdin)['peer_id'])")
echo "$PEER2"

echo "=== Send file to instance 2 ==="
curl -s -X POST "http://localhost:8080/api/send?peer_id=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PEER2'))")&path=nearshare-test.txt" \
    -H "Authorization: Bearer $TOK1"
echo ""

sleep 3

echo "=== Incoming files on instance 2 ==="
INCOMING=$(curl -s http://localhost:8081/api/incoming -H "Authorization: Bearer $TOK2")
echo "$INCOMING"

echo ""
if [ "$INCOMING" != "[]" ]; then
    echo "✅ Send test PASSED — file arrived at peer"
else
    echo "❌ Send test FAILED — no incoming files on instance 2"
    echo ""
    echo "=== Instance 1 logs ==="
    cat /tmp/nearshare-send-1.log
    echo ""
    echo "=== Instance 2 logs ==="
    cat /tmp/nearshare-send-2.log
    exit 1
fi
