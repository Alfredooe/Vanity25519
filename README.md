# vanity-ed25519

Generates Ed25519 SSH keypairs until the base64-encoded public key contains a target word, bounded by `+` or `/` delimiters (the natural word boundaries in base64 SSH keys).

## Build

```sh
cargo build --release
```

Or run `./setup.sh` to install dependencies, build, benchmark, and launch in one step.

## Usage

```sh
# Single target
./target/release/vanity-ed25519 hello

# Multiple targets from a file (one per line, # comments and blank lines ignored)
./target/release/vanity-ed25519 --input targets.txt

# Combine positional and file targets; write results to a file (append mode)
./target/release/vanity-ed25519 hello --input targets.txt --output results.txt

# Limit thread count
./target/release/vanity-ed25519 hello --threads 4
```

When multiple targets are provided, all are searched simultaneously in a single parallel pass. The search exits once every target has a match.

## Match rule

A key matches target `foo` if its base64 public key contains any of: `+foo+`, `+foo/`, `/foo+`, `/foo/`.

## Benchmark

Run `./bench.sh` to measure key generation throughput. Results are saved to `perf_results.txt`.
