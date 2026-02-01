#!/usr/bin/env bash
# setup.sh — install dependencies, build, and run the vanity Ed25519 key search.

# Usage: ./setup.sh [<target>] [--input <file>] [--output <file>] [--threads N]
# All arguments are passed through to the vanity-ed25519 binary.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# --- dependencies ---------------------------------------------------------

if ! command -v cc &>/dev/null; then
    echo "[setup] Installing build-essential..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq build-essential
fi

if ! command -v rustup &>/dev/null; then
    echo "[setup] Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi

export PATH="$HOME/.cargo/bin:$PATH"

echo "[setup] Building..."

# --- build (native) -------------------------------------------------------
echo "[setup] Building native Linux binary..."
cd "$SCRIPT_DIR"
cargo build --release 2>&1

# --- build (windows) ------------------------------------------------------
echo "[setup] Building Windows binary (x86_64-pc-windows-gnu)..."
rustup target add x86_64-pc-windows-gnu 2>/dev/null || true
cargo build --release --target x86_64-pc-windows-gnu 2>&1
echo "[setup] Windows binary at: $SCRIPT_DIR/target/x86_64-pc-windows-gnu/release/vanity-ed25519.exe"

# --- benchmark -----------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "[setup] Running benchmark (bench.sh) before setup..."
"$SCRIPT_DIR/bench.sh"

# --- run ------------------------------------------------------------------

echo "[setup] Launching vanity-ed25519..."
echo
./target/release/vanity-ed25519 "$@"
