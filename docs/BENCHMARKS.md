# Benchmarks

Performance measurement for algod-rust and comparison against go-algorand (v4.5.1-stable).

## Overview

The benchmark suite has two tiers:

1. **Micro benchmarks** -- Criterion (Rust) and testing.B (Go) benchmarks that decode the _same fixture files_ from disk, eliminating network variance entirely.
2. **Macro benchmarks** -- Mixed-cluster comparison where both a Rust relay and a Go non-relay sync blocks from a Go relay node under real consensus, measuring time-to-round-N, peak RSS, and average CPU.

Additionally, there are **single-implementation profiling tools** (`bench decode`, `bench replay`, `bench-go`) that fetch blocks over HTTP. These measure end-to-end throughput including network latency and are NOT suitable for Go-vs-Rust comparison.

## Quick Start

```bash
# Fair comparison: micro benchmarks on same fixture data
make benchmark            # runs bench-micro (Rust) + bench-micro-go (Go)

# Fair comparison: macro cluster benchmark (requires Docker)
make bench-cluster        # starts mixed cluster, samples stats, reports comparison

# Single-implementation profiling (NOT for comparison)
make bench-decode         # Rust decode throughput (includes HTTP fetch)
make bench-rust           # Rust decode + validate throughput (includes HTTP fetch)
```

## Fair Comparison: Micro Benchmarks

Both Rust and Go decode the same msgpack fixture files from `crates/core/algo-codec/tests/fixtures/` (e.g., `block_1.msgpack`, `block_6.msgpack`). These are raw REST responses captured from a Go algod node.

### Rust (`make bench-micro`)

Runs `cargo bench --workspace`, which executes Criterion benchmarks across multiple crates:

| Crate | Benchmarks |
| --- | --- |
| `algo-codec` | Decode/encode block, round-trip, block digest, txn ID, raw payset extraction |
| `algo-validate` | SHA-512/256 (various sizes), ed25519 verification, Merkle root (1-64 txns), vector commitment (SHA-256/SHA-512), full block validation |
| `algo-avm` | TEAL bytecode parsing (simple/large), arithmetic execution, concat, sha256/keccak256 chained hashing |
| `algo-ledger` | SQLite open, account read/write, block storage put/get, apply_pay (SQLite vs in-memory) |

Criterion automatically handles warm-up, statistical sampling, and outlier detection. Results are saved to `target/criterion/` with HTML reports.

### Go (`make bench-micro-go`)

Runs Go `testing.B` benchmarks in `benchmarks/go-decode/` that read the same fixture files and decode them with go-algorand's msgpack decoder (`protocol.Decode`):

| Benchmark | Description |
| --- | --- |
| `BenchmarkDecodeBlockResponse` | Full REST response (block+cert) into `rpcs.EncodedBlockCert` |
| `BenchmarkDecodeBlock` | Block portion only into `bookkeeping.Block` |

Each benchmark reports ns/op, bytes/op, allocs/op, and throughput (MB/s via `b.SetBytes`).

```bash
# Run Go benchmarks with 5 iterations
cd benchmarks/go-decode && go test -bench=. -benchmem -count=5
```

### Why This Is Fair

Both implementations:
- Read the same bytes from disk (no network variance)
- Decode the same msgpack format (go-algorand's canonical encoding)
- Use their native benchmark frameworks (Criterion / testing.B) with proper warm-up and statistical rigor
- Report comparable metrics (ns/op, throughput)

## Fair Comparison: Mixed Cluster (`make bench-cluster`)

The mixed-cluster benchmark runs both implementations as real nodes syncing blocks from a Go relay under actual consensus:

**Topology:**
- `go-relay` -- Go algod relay node, block producer (real agreement protocol)
- `rust-relay` -- Rust relay node, syncs from go-relay via gossip
- `go-nonrelay` -- Go algod non-relay, syncs from rust-relay (validates rust-relay's block serving)

**What it measures:**
- Time for each node to reach round N (default: 50)
- Peak RSS (memory) via `docker stats`
- Average CPU via `docker stats`
- Blocks/sec throughput

**Usage:**
```bash
# Default: wait for round 50
make bench-cluster

# Custom target round
TARGET_ROUND=100 make bench-cluster

# With custom output path
bash docker/scripts/bench-cluster.sh --target-round 200 --output my-results/cluster.json
```

**Output:** A JSON file with side-by-side metrics for both implementations.

## Single-Implementation Profiling

These tools fetch blocks over HTTP. Network latency dominates (~99% of wall time), so they should NOT be used for Go-vs-Rust comparison. They are useful for:
- Profiling the Rust implementation in isolation
- Measuring REST endpoint throughput
- Identifying decode/validate bottlenecks within a single implementation

### `make bench-decode` / `make bench-rust`

Fetches N blocks from a REST endpoint, decodes (and optionally validates) each one, and reports throughput.

```bash
make bench-decode BENCH_START=40000000 BENCH_COUNT=100
make bench-rust   BENCH_START=40000000 BENCH_COUNT=100
```

### `make bench-go`

Fetches N blocks via `curl` and measures wall-clock time. Only measures HTTP fetch throughput (no in-process decode).

```bash
make bench-go BENCH_START=40000000 BENCH_COUNT=100
```

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `BENCH_START` | `40000000` | First mainnet round (for profiling tools) |
| `BENCH_COUNT` | `100` | Number of blocks (for profiling tools) |
| `BENCH_OUTPUT` | `bench-results` | Directory for JSON result files |
| `TARGET_ROUND` | `50` | Target round for cluster benchmark |

## Criterion Output

Microbenchmark results go to `target/criterion/<benchmark_name>/`. Each contains:

- `report/index.html` -- interactive plots (violin, line, PDF)
- `new/estimates.json` -- raw statistical data (mean, median, std dev, confidence intervals)
- `change/estimates.json` -- regression/improvement vs previous baseline (if available)

```bash
# View Criterion HTML reports (macOS)
open target/criterion/report/index.html
```

## Why HTTP-Fetch Benchmarks Are Not Useful for Comparison

The CLI `bench decode` and `bench replay` commands (and the `bench-go.sh` script) fetch blocks over HTTP from a REST endpoint. The wall-clock time is dominated by:

1. Network round-trip latency to the REST endpoint
2. CDN/server response time
3. TCP connection overhead

The actual decode + validate work is a tiny fraction of the total time. Comparing "Rust fetching via reqwest" against "Go fetching via curl" tells you about HTTP client performance and network conditions, not about the decode/validate implementations.

The micro benchmarks (Criterion + testing.B) and the mixed-cluster benchmark eliminate this problem by either removing the network entirely (fixture files) or using the same network for both (Docker bridge network).
