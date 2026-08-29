#!/usr/bin/env bash

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# bench-cluster.sh — Mixed-cluster Go-vs-Rust side-by-side comparison.
#
# Starts the mixed cluster (go-relay producing blocks, rust-observer syncing
# via gossip, go-nonrelay syncing via rust-relay), then samples RSS and CPU
# for both observer containers every 2 seconds until both reach round N.
#
# Outputs a JSON comparison file in the BenchRun schema.
#
# Usage:
#   bash docker/scripts/bench-cluster.sh
#   bash docker/scripts/bench-cluster.sh --target-round 100 --output bench-results/cluster.json

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────
TARGET_ROUND="${TARGET_ROUND:-50}"
OUTPUT="${OUTPUT:-bench-results/bench-cluster.json}"
SAMPLE_INTERVAL=2
ALGOD_TOKEN="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
COMPOSE="docker compose -f docker/docker-compose.mixed-cluster.yml"

# ── Parse arguments ───────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target-round) TARGET_ROUND="$2"; shift 2 ;;
        --output)       OUTPUT="$2";       shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--target-round N] [--output PATH]"
            echo ""
            echo "Options:"
            echo "  --target-round N   Wait until both nodes reach this round (default: 50)"
            echo "  --output PATH      Output JSON file (default: bench-results/bench-cluster.json)"
            exit 0
            ;;
        *) echo "ERROR: Unknown argument: $1"; exit 1 ;;
    esac
done

# ── Check required tools ─────────────────────────────────────────────
for tool in docker jq curl; do
    if ! command -v "${tool}" &>/dev/null; then
        echo "ERROR: '${tool}' is required but not found in PATH"
        exit 1
    fi
done

mkdir -p "$(dirname "${OUTPUT}")"

echo "Mixed-Cluster Benchmark"
echo "  Target round: ${TARGET_ROUND}"
echo "  Output:       ${OUTPUT}"
echo ""

# ── Start the cluster ────────────────────────────────────────────────
echo "==> Starting mixed cluster..."
${COMPOSE} build --quiet 2>/dev/null || true
${COMPOSE} up -d go-relay
echo "Waiting for go-relay to be healthy..."
until docker inspect --format='{{.State.Health.Status}}' mc-go-relay 2>/dev/null | grep -q healthy; do
    sleep 1
done
echo "go-relay is healthy. Starting remaining services..."
${COMPOSE} up -d

# Start background transaction generator
echo "Starting background transaction generator..."
(
    sleep 10  # Let services settle
    ACCOUNTS=$(docker exec mc-go-relay goal account list -d /algod/data 2>/dev/null | awk '{print $2}')
    FROM=$(echo "$ACCOUNTS" | head -1)
    TO=$(echo "$ACCOUNTS" | tail -1)
    if [ -z "$FROM" ] || [ -z "$TO" ]; then
        echo "WARNING: no accounts found for txn generation"
        exit 0
    fi
    SEQ=0
    while docker inspect --format='{{.State.Status}}' mc-go-relay 2>/dev/null | grep -q running; do
        SEQ=$((SEQ + 1))
        docker exec mc-go-relay goal clerk send -a 1000 -f "$FROM" -t "$TO" -d /algod/data -n "bench-txn-$SEQ" >/dev/null 2>&1 || true
        sleep 3
    done
) &
TXN_PID=$!
trap 'kill ${TXN_PID} 2>/dev/null || true; ${COMPOSE} down -v 2>/dev/null || true' EXIT

# Wait for services to start producing blocks
echo "Waiting for services to settle..."
sleep 15

# ── Helper: get current round from a container ───────────────────────
get_round() {
    local url="$1"
    curl -sf -H "X-Algo-API-Token: ${ALGOD_TOKEN}" "${url}/v2/status" 2>/dev/null \
        | jq -r '.["last-round"] // 0' 2>/dev/null || echo "0"
}

# ── Helper: sample docker stats ──────────────────────────────────────
# Returns: container_name mem_usage_bytes cpu_pct
sample_stats() {
    local container="$1"
    docker stats --no-stream --format '{{.Name}} {{.MemUsage}} {{.CPUPerc}}' "${container}" 2>/dev/null | head -1
}

parse_mem_bytes() {
    # Input like "12.5MiB" or "1.2GiB" — convert to bytes
    local raw="$1"
    local num unit
    num=$(echo "$raw" | sed 's/[A-Za-z]*$//')
    unit=$(echo "$raw" | sed 's/[0-9.]*//g')
    case "$unit" in
        KiB|kB) awk "BEGIN { printf \"%.0f\", ${num} * 1024 }" ;;
        MiB|MB) awk "BEGIN { printf \"%.0f\", ${num} * 1024 * 1024 }" ;;
        GiB|GB) awk "BEGIN { printf \"%.0f\", ${num} * 1024 * 1024 * 1024 }" ;;
        *)      echo "0" ;;
    esac
}

# ── Sample loop ──────────────────────────────────────────────────────
echo "==> Sampling stats every ${SAMPLE_INTERVAL}s until both reach round ${TARGET_ROUND}..."

RUST_PEAK_RSS=0
RUST_CPU_SUM=0
RUST_SAMPLES=0
GO_PEAK_RSS=0
GO_CPU_SUM=0
GO_SAMPLES=0
RUST_REACHED=""
GO_REACHED=""

# Time tracking
if command -v gdate &>/dev/null; then
    TIME_CMD="gdate"
elif date +%s.%N 2>/dev/null | grep -q '\.'; then
    TIME_CMD="date"
else
    TIME_CMD="python_time"
fi

now_secs() {
    case "${TIME_CMD}" in
        python_time) python3 -c 'import time; print(f"{time.time():.6f}")' ;;
        *)           ${TIME_CMD} +%s.%N ;;
    esac
}

START_TIME=$(now_secs)

MAX_WAIT=600  # 10 minutes
ELAPSED_INT=0

while true; do
    # Sample rust-observer (no REST port exposed; check go-relay for reference)
    # rust-observer has no REST API, so we track its container stats only.
    # We use go-nonrelay's round as a proxy for rust-relay's throughput (it syncs through rust-relay).

    # Get rounds
    GO_RELAY_ROUND=$(get_round "http://localhost:4001")
    GO_NONRELAY_ROUND=$(get_round "http://localhost:4002")
    # Query rust-relay's ledger round directly via sqlite. Since TASK-100
    # the round metadata lives in the tracker DB
    # (`<prefix>.tracker.sqlite`); G6 part 3 (TASK-107) retired the
    # Rust-only `algod_rust_meta` cache, so we read `acctrounds.acctbase`
    # (Go's `accountsRound` — the same row both Go and Rust agree on).
    RUST_RELAY_ROUND=$(docker exec mc-rust-relay sqlite3 /app/ledger.tracker.sqlite "SELECT rnd FROM acctrounds WHERE id='acctbase'" 2>/dev/null || echo "?")

    # Sample container stats
    RUST_STATS=$(sample_stats "mc-rust-relay" 2>/dev/null || echo "")
    GO_NR_STATS=$(sample_stats "mc-go-nonrelay" 2>/dev/null || echo "")

    if [ -n "$RUST_STATS" ]; then
        # Parse: "mc-rust-relay 12.5MiB / 16GiB 0.50%"
        RUST_MEM_RAW=$(echo "$RUST_STATS" | awk '{print $2}')
        RUST_CPU_RAW=$(echo "$RUST_STATS" | awk '{print $NF}' | tr -d '%')
        RUST_MEM=$(parse_mem_bytes "$RUST_MEM_RAW")
        RUST_SAMPLES=$((RUST_SAMPLES + 1))
        RUST_CPU_SUM=$(awk "BEGIN { printf \"%.2f\", ${RUST_CPU_SUM} + ${RUST_CPU_RAW} }")
        if [ "$RUST_MEM" -gt "$RUST_PEAK_RSS" ] 2>/dev/null; then
            RUST_PEAK_RSS=$RUST_MEM
        fi
    fi

    if [ -n "$GO_NR_STATS" ]; then
        GO_MEM_RAW=$(echo "$GO_NR_STATS" | awk '{print $2}')
        GO_CPU_RAW=$(echo "$GO_NR_STATS" | awk '{print $NF}' | tr -d '%')
        GO_MEM=$(parse_mem_bytes "$GO_MEM_RAW")
        GO_SAMPLES=$((GO_SAMPLES + 1))
        GO_CPU_SUM=$(awk "BEGIN { printf \"%.2f\", ${GO_CPU_SUM} + ${GO_CPU_RAW} }")
        if [ "$GO_MEM" -gt "$GO_PEAK_RSS" ] 2>/dev/null; then
            GO_PEAK_RSS=$GO_MEM
        fi
    fi

    # Check if target reached
    if [ -z "$RUST_REACHED" ] && [ "$GO_NONRELAY_ROUND" -ge "$TARGET_ROUND" ] 2>/dev/null; then
        RUST_REACHED=$(now_secs)
        echo "  rust-relay chain reached round ${TARGET_ROUND} (via go-nonrelay) at t=$(awk "BEGIN { printf \"%.1f\", ${RUST_REACHED} - ${START_TIME} }")s"
    fi
    if [ -z "$GO_REACHED" ] && [ "$GO_RELAY_ROUND" -ge "$TARGET_ROUND" ] 2>/dev/null; then
        GO_REACHED=$(now_secs)
        echo "  go-relay reached round ${TARGET_ROUND} at t=$(awk "BEGIN { printf \"%.1f\", ${GO_REACHED} - ${START_TIME} }")s"
    fi

    # Progress
    echo "  [t=${ELAPSED_INT}s] go-relay=${GO_RELAY_ROUND} rust-relay=${RUST_RELAY_ROUND} go-nonrelay(via rust)=${GO_NONRELAY_ROUND}"

    # Both reached target?
    if [ -n "$RUST_REACHED" ] && [ -n "$GO_REACHED" ]; then
        echo ""
        echo "Both nodes have reached round ${TARGET_ROUND}."
        break
    fi

    ELAPSED_INT=$((ELAPSED_INT + SAMPLE_INTERVAL))
    if [ "$ELAPSED_INT" -ge "$MAX_WAIT" ]; then
        echo ""
        echo "WARNING: Timed out after ${MAX_WAIT}s. Reporting partial results."
        [ -z "$RUST_REACHED" ] && RUST_REACHED=$(now_secs)
        [ -z "$GO_REACHED" ] && GO_REACHED=$(now_secs)
        break
    fi

    sleep "$SAMPLE_INTERVAL"
done

END_TIME=$(now_secs)

# ── Compute metrics ──────────────────────────────────────────────────
RUST_ELAPSED=$(awk "BEGIN { printf \"%.3f\", ${RUST_REACHED} - ${START_TIME} }")
GO_ELAPSED=$(awk "BEGIN { printf \"%.3f\", ${GO_REACHED} - ${START_TIME} }")

RUST_AVG_CPU=0
if [ "$RUST_SAMPLES" -gt 0 ]; then
    RUST_AVG_CPU=$(awk "BEGIN { printf \"%.1f\", ${RUST_CPU_SUM} / ${RUST_SAMPLES} }")
fi

GO_AVG_CPU=0
if [ "$GO_SAMPLES" -gt 0 ]; then
    GO_AVG_CPU=$(awk "BEGIN { printf \"%.1f\", ${GO_CPU_SUM} / ${GO_SAMPLES} }")
fi

RUST_BPS=$(awk "BEGIN { if (${RUST_ELAPSED} > 0) printf \"%.2f\", ${TARGET_ROUND} / ${RUST_ELAPSED}; else print \"0\" }")
GO_BPS=$(awk "BEGIN { if (${GO_ELAPSED} > 0) printf \"%.2f\", ${TARGET_ROUND} / ${GO_ELAPSED}; else print \"0\" }")

TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# ── Write JSON output ────────────────────────────────────────────────
jq -n \
    --arg timestamp "${TIMESTAMP}" \
    --argjson target_round "${TARGET_ROUND}" \
    --argjson rust_elapsed "${RUST_ELAPSED}" \
    --argjson rust_peak_rss "${RUST_PEAK_RSS}" \
    --argjson rust_avg_cpu "${RUST_AVG_CPU}" \
    --argjson rust_bps "${RUST_BPS}" \
    --argjson go_elapsed "${GO_ELAPSED}" \
    --argjson go_peak_rss "${GO_PEAK_RSS}" \
    --argjson go_avg_cpu "${GO_AVG_CPU}" \
    --argjson go_bps "${GO_BPS}" \
    '{
        scenario: "mixed-cluster",
        timestamp: $timestamp,
        config: {
            target_round: $target_round
        },
        rust: {
            implementation: "Rust",
            metrics: {
                wall_clock_secs: $rust_elapsed,
                peak_rss_bytes: $rust_peak_rss,
                avg_cpu_pct: $rust_avg_cpu,
                blocks_per_sec: $rust_bps,
                txns_per_sec: null,
                disk_io_bytes: null
            }
        },
        go: {
            implementation: "Go",
            metrics: {
                wall_clock_secs: $go_elapsed,
                peak_rss_bytes: $go_peak_rss,
                avg_cpu_pct: $go_avg_cpu,
                blocks_per_sec: $go_bps,
                txns_per_sec: null,
                disk_io_bytes: null
            }
        }
    }' > "${OUTPUT}"

# ── Print summary ────────────────────────────────────────────────────
echo ""
echo "=== Mixed-Cluster Benchmark Results ==="
echo "Target round:        ${TARGET_ROUND}"
echo ""
echo "                     Go (relay)       Rust (relay)"
echo "Time to round N:     ${GO_ELAPSED}s          ${RUST_ELAPSED}s"
echo "Peak RSS:            $(awk "BEGIN { printf \"%.1f\", ${GO_PEAK_RSS} / 1048576 }") MB         $(awk "BEGIN { printf \"%.1f\", ${RUST_PEAK_RSS} / 1048576 }") MB"
echo "Avg CPU:             ${GO_AVG_CPU}%            ${RUST_AVG_CPU}%"
echo "Blocks/sec:          ${GO_BPS}             ${RUST_BPS}"
echo ""
echo "Output: ${OUTPUT}"

# ── Save logs before tear down ────────────────────────────────────────
echo ""
echo "==> Saving container logs..."
docker logs mc-rust-relay > bench-results/rust-relay.log 2>&1 || true
docker logs mc-go-nonrelay > bench-results/go-nonrelay.log 2>&1 || true

# ── Tear down ─────────────────────────────────────────────────────────
echo ""
echo "==> Stopping mixed cluster..."
kill ${TXN_PID} 2>/dev/null || true
${COMPOSE} down -v 2>/dev/null || true
trap - EXIT
echo "Done."
