# Benchmarks

Performance comparison of algod-rust against go-algorand (v4.5.1-stable).

## Overview

This benchmark suite measures three things:

1. **Block decode throughput** (`bench decode`) -- how fast the Rust implementation can fetch and decode (msgpack to struct) mainnet blocks over REST, with no validation. Always runnable, useful for measuring pure serialization performance.
2. **Block replay throughput** (`bench replay`) -- how fast each implementation can fetch, decode, and validate mainnet blocks over REST. This is the primary Rust-vs-Go comparison. Validation is properly chained: each block validates against its predecessor's timestamp, and genesis fields are extracted from the blocks themselves.
3. **Microbenchmarks** -- Criterion-based benchmarks for hot-path operations (codec, validation, AVM execution, ledger I/O). These track regressions within the Rust codebase.

## Quick Start

```bash
# Run decode-only benchmark (no validation, always works)
make bench-decode

# Run the full Rust-vs-Go comparison (fetches 100 mainnet blocks by default)
make bench-compare

# Run Criterion microbenchmarks only
make bench-micro

# Run everything
make benchmark
```

## Benchmark Scenarios

### Decode Only (`make bench-decode`)

Measures pure msgpack decode throughput. Fetches N blocks from a REST endpoint and decodes each from msgpack to the Rust `Block` struct. No validation is performed. This is useful for isolating serialization performance from validation overhead.

```bash
# Decode 100 blocks starting at round 40000000
make bench-decode BENCH_START=40000000 BENCH_COUNT=100
```

### Block Replay (`make bench-compare`)

Replays a range of mainnet blocks through the full decode-and-validate pipeline. Both implementations fetch blocks from the same REST endpoint (default: Nodely public API) and process them sequentially.

**Rust side** (`make bench-rust`): Runs `algod-rust bench replay`, which first fetches the block at `start_round - 1` to obtain the previous timestamp and genesis context. Then for each block in the range, it decodes msgpack, extracts raw payset blobs, runs stateless validation (`algo_validate::validate_block`) with proper chained context, and collects resource metrics via a background sampling thread (100ms interval using `sysinfo`). Validation pass/fail counts are reported in the summary.

**Go side** (`make bench-go`): Runs `docker/scripts/bench-go.sh`, which fetches blocks via `curl` and measures wall-clock time and bytes downloaded. RSS and CPU are reported as 0 since they reflect `curl` overhead, not the Go node itself.

The `bench compare` subcommand then loads both JSON result files and prints a side-by-side table showing elapsed time, blocks/sec, peak RSS, average CPU, and the delta between them.

### Microbenchmarks (`make bench-micro`)

Runs `cargo bench --workspace`, which executes Criterion benchmarks across four crates:

| Crate | Benchmarks |
| --- | --- |
| `algo-codec` | Decode/encode block, round-trip, block digest, txn ID, raw payset extraction |
| `algo-validate` | SHA-512/256 (various sizes), ed25519 verification, Merkle root (1-64 txns), vector commitment (SHA-256/SHA-512), full block validation |
| `algo-avm` | TEAL bytecode parsing (simple/large), arithmetic execution, concat, sha256/keccak256 chained hashing |
| `algo-ledger` | SQLite open, account read/write, block storage put/get, apply_pay (SQLite vs in-memory) |

Criterion automatically handles warm-up, statistical sampling, and outlier detection. Results are saved to `target/criterion/` with HTML reports.

## Metrics Collected

| Metric | Rust | Go | Unit |
| --- | --- | --- | --- |
| Wall-clock time | `std::time::Instant` | `date`/`gdate`/`python3 time.time()` | seconds |
| Peak RSS | `sysinfo` crate, sampled every 100ms | Not measured (0) | bytes |
| Avg CPU | `sysinfo` process snapshot at finish | Not measured (0) | percent |
| Blocks/sec | blocks processed / elapsed | blocks fetched / elapsed | blocks/s |
| Txns/sec | total txns in payset / elapsed | Not measured | txns/s |
| Disk I/O | Not measured | `curl` `size_download` sum | bytes |

## Methodology

**Controlled comparison.** Both implementations fetch from the same REST endpoint during the same run (`make bench-compare` runs them sequentially). Network variance is the primary noise source; use `BENCH_COUNT=500` or higher for more stable results.

**Warm-up.** The first run against a given block range may be slower due to CDN caching at the REST endpoint. For reproducible numbers, run `make bench-rust` once as a warm-up before the timed comparison, or use a local archival node (`make archival-up`).

**Deterministic replay.** Block replay is deterministic -- the same block range always produces the same decode/validate workload. No consensus participation or networking is involved.

**Microbenchmark rigor.** Criterion runs each benchmark through a configurable number of iterations with automatic warm-up, reports mean/median/stddev, and detects performance regressions between runs via saved baselines in `target/criterion/`.

## Configuration

All configuration is via Makefile variables, overridable on the command line:

| Variable | Default | Description |
| --- | --- | --- |
| `BENCH_START` | `40000000` | First mainnet round to replay |
| `BENCH_COUNT` | `100` | Number of blocks to replay |
| `BENCH_OUTPUT` | `bench-results` | Directory for JSON result files |

Examples:

```bash
# Replay 500 blocks starting at round 45000000
make bench-compare BENCH_START=45000000 BENCH_COUNT=500

# Save results to a custom directory
make bench-compare BENCH_OUTPUT=my-results

# Use a local archival node instead of public API
make bench-rust BENCH_START=1000 BENCH_COUNT=50 \
  ALGOD_URL=http://localhost:4001 \
  ALGOD_TOKEN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

## Output Format

### Block Replay JSON

Both Rust and Go produce a `BenchRun` JSON file with this schema:

```json
{
  "scenario": "Block Replay: 100 mainnet blocks (40000000-40000099)",
  "implementation": "Rust",
  "metrics": {
    "wall_clock_secs": 12.34,
    "peak_rss_bytes": 52428800,
    "avg_cpu_pct": 45.2,
    "disk_io_bytes": null,
    "blocks_per_sec": 8.1,
    "txns_per_sec": 486.0
  },
  "timestamp": "2026-03-14T12:00:00Z",
  "git_sha": "abc1234",
  "config": {
    "block_range": "40000000-40000099",
    "block_count": 100,
    "duration_secs": null,
    "custom": {}
  }
}
```

### Comparison Table

`bench compare` prints a terminal table by default:

```
Block Replay: 100 mainnet blocks (40000000-40000099)
────────────────────────────────────────────────────────────
                    Go (4.5.1)    Rust (abc1234)            D
Elapsed                142.0s            38.0s   3.7x faster
Peak RSS               1.7 GB          200.0 MB   8.6x less
Avg CPU                 87.0%            62.0%      40% less
Blocks/sec                 70              263       3.8x
Txns/sec              4,200           15,800        3.8x
```

Pass `--markdown` to `bench compare` for a Markdown table suitable for PRs.

### Criterion Output

Microbenchmark results go to `target/criterion/<benchmark_name>/`. Each contains:

- `report/index.html` -- interactive plots (violin, line, PDF)
- `new/estimates.json` -- raw statistical data (mean, median, std dev, confidence intervals)
- `change/estimates.json` -- regression/improvement vs previous baseline (if available)

## Interpreting Results

**Speedup column (D).** Computed as `go_value / rust_value`. A value > 1 means Rust is faster (for time-based metrics) or uses fewer resources (for RSS/CPU). For throughput metrics (blocks/sec, txns/sec), the ratio is `rust_value / go_value`, so > 1 still means Rust is better.

**Caveats.**
- The Go benchmark only measures REST fetch time via `curl`, not full in-process decode+validate. The Rust benchmark does full decode+validate. This makes the comparison conservative for Rust (Rust does more work in the measured window).
- Peak RSS for Go is reported as 0 since the script measures `curl`, not the Go node process.
- Network latency dominates when fetching from public APIs. Use a local node or increase `BENCH_COUNT` to amortize.

## Reproducing Results

1. Ensure prerequisites are installed:
   ```bash
   # Rust toolchain
   rustup update stable
   # jq and curl (for Go benchmark script)
   brew install jq curl   # macOS
   ```

2. Build in release mode:
   ```bash
   cargo build --release
   ```

3. Run the comparison:
   ```bash
   make bench-compare BENCH_START=40000000 BENCH_COUNT=100
   ```

4. Results appear in `bench-results/`:
   - `bench-replay-rust.json` -- Rust metrics
   - `bench-replay-go.json` -- Go metrics
   - Comparison table printed to stdout

5. Run microbenchmarks:
   ```bash
   make bench-micro
   open target/criterion/report/index.html   # macOS
   ```

6. For a local comparison (avoids network variance):
   ```bash
   make archival-up        # start local archival Go node
   # Wait for it to sync enough blocks, then:
   make bench-compare BENCH_START=1000 BENCH_COUNT=200
   make archival-down
   ```
