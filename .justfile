# NearShare-rs — justfile
# Install `just`: https://github.com/casey/just

set dotenv-load := false

# Default recipe: show available commands
default:
    @just --list

# Build debug binary
build:
    cargo build

# Build release binary
release:
    cargo build --release

# Fast type-check
check:
    cargo check

# Run the app on default port 8080
run:
    cargo run --release

# Run on a custom port (e.g. just run-port 8081)
run-port PORT:
    PORT={{PORT}} cargo run --release

# Run with cargo watch (auto-restart on changes; installs cargo-watch if missing)
watch:
    @cargo watch --version > /dev/null 2>&1 || cargo install cargo-watch
    cargo watch -x "run --release"

# Run lint + type-check
lint:
    cargo clippy --all-targets --all-features -- -D warnings
    cargo check

# Format code
fmt:
    cargo fmt

# Run the discovery test (two nodes find each other)
test-discovery:
    ./scripts/test-discovery.sh

# Run the end-to-end file-send test
test-send:
    ./scripts/test-send.sh

# Run all tests
test: test-discovery test-send

# Clean build artifacts
clean:
    cargo clean
