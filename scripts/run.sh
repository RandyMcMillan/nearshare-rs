#!/bin/bash
# Run NearShare-rs. Set PORT=8081 to run on a different port.
set -e

BIN="${CARGO_TARGET_DIR:-$(cargo metadata --format-version 1 2>/dev/null | grep -o '"target_directory":"[^"]*"' | cut -d'"' -f4)}"/release/nearshare-rs

if [ ! -f "$BIN" ]; then
    echo "Binary not found at $BIN"
    echo "Building release binary..."
    cargo build --release
fi

PORT="${PORT:-8080}"
echo "Starting NearShare-rs on port $PORT..."
exec "$BIN"
