#!/usr/bin/env bash
# Benchmark Go algod's block fetch performance via REST API (HTTP fetch only).
#
# WARNING: This script measures HTTP fetch throughput via curl, NOT in-process
# Go decode+validate performance. Network latency dominates the results (~99%
# of wall time), making this unsuitable for Go-vs-Rust comparison.
#
# For fair comparison, use:
#   - `make bench-micro-go`  — Go testing.B benchmarks on same fixture files
#   - `make bench-cluster`   — side-by-side mixed-cluster node comparison
#
# This script is retained for single-implementation profiling (e.g., measuring
# REST endpoint throughput from a particular node).
#
# Usage:
#   ./bench-go.sh --start-round 40000000 --count 100
#   ./bench-go.sh --start-round 40000000 --count 500 --algod-url http://localhost:4001 \
#                 --token aaaa... --output results.json

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────
ALGOD_URL="http://mainnet-api.4160.nodely.dev"
TOKEN=""
START_ROUND=""
COUNT=100
OUTPUT="bench-replay-go.json"

# ── Parse arguments ───────────────────────────────────────────────────
usage() {
    cat <<USAGE
Usage: $0 --start-round <ROUND> [OPTIONS]

Required:
  --start-round <ROUND>   First round to fetch

Options:
  --algod-url <URL>       Algod REST endpoint (default: $ALGOD_URL)
  --token <TOKEN>         X-Algo-API-Token value (default: empty)
  --count <N>             Number of blocks to fetch (default: $COUNT)
  --output <PATH>         Output JSON file path (default: $OUTPUT)
  -h, --help              Show this help message
USAGE
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --algod-url)  ALGOD_URL="$2";   shift 2 ;;
        --token)      TOKEN="$2";       shift 2 ;;
        --start-round) START_ROUND="$2"; shift 2 ;;
        --count)      COUNT="$2";       shift 2 ;;
        --output)     OUTPUT="$2";      shift 2 ;;
        -h|--help)    usage ;;
        *)            echo "ERROR: Unknown argument: $1"; usage ;;
    esac
done

if [[ -z "${START_ROUND}" ]]; then
    echo "ERROR: --start-round is required"
    usage
fi

# ── Check required tools ─────────────────────────────────────────────
for tool in curl jq; do
    if ! command -v "${tool}" &>/dev/null; then
        echo "ERROR: '${tool}' is required but not found in PATH"
        exit 1
    fi
done

# ── Compute range ─────────────────────────────────────────────────────
END_ROUND=$((START_ROUND + COUNT))
BLOCK_RANGE="${START_ROUND}-$((END_ROUND - 1))"

echo "Go Block Replay Benchmark"
echo "  URL:         ${ALGOD_URL}"
echo "  Rounds:      ${START_ROUND} .. $((END_ROUND - 1))"
echo "  Block count: ${COUNT}"
echo "  Output:      ${OUTPUT}"
echo ""

# ── Run benchmark ─────────────────────────────────────────────────────
TOTAL_BYTES=0
BLOCKS_FETCHED=0

# Record start time.
# macOS date does not support %N, so try gdate first, then fall back to
# python, then to second-precision date.
if command -v gdate &>/dev/null; then
    TIME_CMD="gdate"
elif date +%s.%N 2>/dev/null | grep -q '\.'; then
    TIME_CMD="date"
else
    # Fallback: use python for sub-second precision
    TIME_CMD="python_time"
fi

now_secs() {
    case "${TIME_CMD}" in
        python_time) python3 -c 'import time; print(f"{time.time():.6f}")' ;;
        *)           ${TIME_CMD} +%s.%N ;;
    esac
}

START_TIME=$(now_secs)

for (( round = START_ROUND; round < END_ROUND; round++ )); do
    BYTES=$(curl -s \
        -H "X-Algo-API-Token: ${TOKEN}" \
        "${ALGOD_URL}/v2/blocks/${round}?format=msgpack" \
        -o /dev/null \
        -w "%{size_download}")

    if [[ "${BYTES}" == "0" ]]; then
        echo "WARNING: round ${round} returned 0 bytes (may not exist or server error)"
    fi

    TOTAL_BYTES=$((TOTAL_BYTES + BYTES))
    BLOCKS_FETCHED=$((BLOCKS_FETCHED + 1))

    # Progress indicator every 10 blocks
    if (( BLOCKS_FETCHED % 10 == 0 )); then
        echo "  Fetched ${BLOCKS_FETCHED}/${COUNT} blocks..."
    fi
done

END_TIME=$(now_secs)

# ── Compute metrics ──────────────────────────────────────────────────
# Use awk for floating-point arithmetic (portable).
ELAPSED=$(awk "BEGIN { printf \"%.6f\", ${END_TIME} - ${START_TIME} }")
BLOCKS_PER_SEC=$(awk "BEGIN { if (${ELAPSED} > 0) printf \"%.2f\", ${BLOCKS_FETCHED} / ${ELAPSED}; else print \"0\" }")

# REST-only benchmark: RSS and CPU are client-side curl overhead, not meaningful.
PEAK_RSS=0
AVG_CPU=0.0

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# ── Write JSON output ────────────────────────────────────────────────
jq -n \
    --arg scenario "replay" \
    --arg implementation "Go" \
    --argjson wall_clock "${ELAPSED}" \
    --argjson peak_rss "${PEAK_RSS}" \
    --argjson avg_cpu "${AVG_CPU}" \
    --argjson blocks_per_sec "${BLOCKS_PER_SEC}" \
    --arg timestamp "${TIMESTAMP}" \
    --arg git_sha "4.5.1-stable" \
    --arg block_range "${BLOCK_RANGE}" \
    --argjson block_count "${BLOCKS_FETCHED}" \
    --argjson total_bytes "${TOTAL_BYTES}" \
    '{
        scenario: $scenario,
        implementation: $implementation,
        metrics: {
            wall_clock_secs: $wall_clock,
            peak_rss_bytes: $peak_rss,
            avg_cpu_pct: $avg_cpu,
            disk_io_bytes: $total_bytes,
            blocks_per_sec: $blocks_per_sec,
            txns_per_sec: null
        },
        timestamp: $timestamp,
        git_sha: $git_sha,
        config: {
            block_range: $block_range,
            block_count: $block_count,
            duration_secs: null,
            custom: {}
        }
    }' > "${OUTPUT}"

# ── Print summary ────────────────────────────────────────────────────
echo ""
echo "Go Block Replay: ${BLOCKS_FETCHED} blocks (rounds ${BLOCK_RANGE})"
echo "Elapsed: ${ELAPSED}s"
echo "Blocks/sec: ${BLOCKS_PER_SEC}"
echo "Total bytes: ${TOTAL_BYTES}"
echo "Output: ${OUTPUT}"
