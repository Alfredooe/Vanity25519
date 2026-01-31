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
    echo "============================================================"
    echo "     vanity-ed25519 Performance Benchmark"
    echo "============================================================"
    echo ""

    for threads in 1 4; do
        export RAYON_NUM_THREADS=$threads
        for run in 1 2; do
            start_ns=$(date +%s%N)
            output=$(timeout 30 "$BIN" "ab" 2>&1 || true)
            end_ns=$(date +%s%N)

            # Extract attempt count from output
            attempts=$(echo "$output" | grep -oP '(?<=Attempts: )[^$]*' | tail -1 || echo "0")
            if [[ -z "$attempts" ]]; then
                attempts=$(echo "$output" | grep -oP '(?<=Attempts: ~)[^$]*' | tail -1 || echo "0")
            fi

            elapsed_ms=$(( (end_ns - start_ns) / 1_000_000 ))
            if (( elapsed_ms > 0 )); then
                throughput=$(( (attempts * 1000) / elapsed_ms ))
            else
                throughput=0
            fi

            echo "Run $run (threads=$threads): ~$attempts attempts in ${elapsed_ms}ms = $throughput keys/sec"
        done
        echo ""
    done
} | tee "$OUT"

echo "Results saved to: $OUT"
