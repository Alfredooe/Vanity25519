#!/usr/bin/env bash
# bench.sh — performance benchmark for vanity-ed25519
# Usage: ./bench.sh [output_file]
# Default output: perf_results.txt

set -euo pipefail

BIN="$(dirname "$0")/target/release/vanity-ed25519"
OUT="${1:-$(dirname "$0")/perf_results.txt}"

if [[ ! -f "$BIN" ]]; then
    echo "Binary not found: $BIN"
    exit 1
fi

{
    cpus=$(nproc)
    for threads in 1 "$cpus"; do
        for run in 1 2 3; do
            start_ns=$(date +%s%N)
            output=$(timeout 30 "$BIN" ab --threads "$threads" 2>&1 || true)
            end_ns=$(date +%s%N)

            # Extract attempt count and average rate from output
            attempts=$(echo "$output" | grep -oP 'Attempts: ~\K[0-9]+' | tail -1 || echo "0")
            avg_rate=$(echo "$output" | grep -oP 'Average rate: \K[0-9.]+(?= keys/sec)' | tail -1 || echo "0")

            elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))
            echo "Run $run (threads=$threads): ~$attempts attempts in ${elapsed_ms}ms, avg rate: $avg_rate keys/sec"
        done
        echo ""
    done
} | tee "$OUT"

echo "Results saved to: $OUT"
