#!/usr/bin/env bash
# setup.sh — install dependencies, build, and run the vanity Ed25519 key search.
# Usage: ./setup.sh <vanity-target>
# Example: ./setup.sh alfie
set -euo pipefail

TARGET="${1:?Usage: $0 <vanity-target>}"
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

# --- build ----------------------------------------------------------------

echo "[setup] Building..."
cd "$SCRIPT_DIR"
cargo build --release 2>&1

# --- run ------------------------------------------------------------------

echo "[setup] Searching for vanity target: $TARGET"
echo
./target/release/vanity-ed25519 "$TARGET"
