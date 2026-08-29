#!/usr/bin/env bash

# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# bench-stress.sh — issue #100 mixed-cluster stress benchmark.
#
# Brings up the 6-node topology in docker-compose.stress-test.yml (1 Go relay +
# 1 Rust relay, fully meshed; 2 Go + 2 Rust participation nodes each dialing
# both relays), drives it with `algod-rust loadgen` at a configurable sustained
# rate, samples per-container CPU/RSS and per-node round every 2s, and writes a
# structured JSON report comparing the Go and Rust nodes.
#
# Phases (issue #100 "Benchmark Phases"):
#   startup   — bootstrap netroot, start all six nodes, wait healthy + syncing
#   warmup    — light load, verify every node advances
#   ramp      — linear ramp to the target rate
#   sustained — full blast at the target rate
#   cooldown  — stop submitting, let the pools drain
#   report    — aggregate and emit bench-results/bench-stress.json
#
# Usage:
#   bash docker/scripts/bench-stress.sh
#   bash docker/scripts/bench-stress.sh --target-tps 500 --sustained-secs 180
#   bash docker/scripts/bench-stress.sh --group-size 16 --keep-up
#
# Defaults are a short smoke-sized run so the harness is usable on a laptop;
# the issue's aspirational numbers are --target-tps 1000 --sustained-secs 300.
#
# ── History: the round-0 limitation is fixed ───────────────────────────
#
# The first run of this harness (issue #100, before #478/#469/#482) found the
# three Rust nodes stuck at round 0: they never accepted a Go proposal and
# never recovered via catchup, so every transaction aimed at a Rust endpoint
# was rejected with "transaction round window [N, N+1000] does not cover block
# round 1" and the achieved TPS came entirely from the Go half of the
# round-robin. That is no longer the case — all six nodes advance in lockstep
# and all six REST endpoints accept submissions — so the CPU/RSS comparison is
# now like-for-like (every node is validating and committing the same chain).
#
# ── Participation evidence ─────────────────────────────────────────────
#
# Whether the Rust nodes propose and vote used to be inferred by grepping
# their logs for message text, which silently reported zero once the log
# strings changed. It now comes from the real counters that issue #473 added:
# `GET /v2/participation/status` on any `participate` node. The raw JSON is
# saved per node into the sample dir and folded into the report.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCKER_DIR="$(cd "${HERE}/.." && pwd)"
ROOT="$(cd "${DOCKER_DIR}/.." && pwd)"

# ── Defaults ──────────────────────────────────────────────────────────
TARGET_TPS="${TARGET_TPS:-200}"
WARMUP_TPS="${WARMUP_TPS:-25}"
WARMUP_SECS="${WARMUP_SECS:-30}"
RAMP_SECS="${RAMP_SECS:-30}"
SUSTAINED_SECS="${SUSTAINED_SECS:-120}"
COOLDOWN_SECS="${COOLDOWN_SECS:-30}"
GROUP_SIZE="${GROUP_SIZE:-1}"
ACCOUNTS="${ACCOUNTS:-16}"
FUND_MICROALGOS="${FUND_MICROALGOS:-1000000000}"
CONCURRENCY="${CONCURRENCY:-8}"
# >1 by default: under sustained load the pool's fee floor climbs above the
# protocol minimum between params polls, and a stale-by-one-poll fee is
# rejected outright. See `effective_fee` in bin/algod-rust/src/commands/loadgen.rs.
FEE_MULTIPLIER="${FEE_MULTIPLIER:-4}"
OUTPUT="${OUTPUT:-bench-results/bench-stress.json}"
SAMPLE_INTERVAL=2
STARTUP_TIMEOUT="${STARTUP_TIMEOUT:-240}"
KEEP_UP=0
PURGE=1

ALGOD_TOKEN="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
COMPOSE_FILE="${DOCKER_DIR}/docker-compose.stress-test.yml"
COMPOSE="docker compose -f ${COMPOSE_FILE}"

# Node name → container, host REST port. Keep these three lists aligned.
NODE_NAMES="go-relay rust-relay go-part-1 go-part-2 rust-part-1 rust-part-2"
GO_NODES="go-relay go-part-1 go-part-2"
RUST_NODES="rust-relay rust-part-1 rust-part-2"

container_for() { echo "stress-$1"; }
port_for() {
    case "$1" in
        go-relay)    echo 4101 ;;
        rust-relay)  echo 4102 ;;
        go-part-1)   echo 4103 ;;
        go-part-2)   echo 4104 ;;
        rust-part-1) echo 4105 ;;
        rust-part-2) echo 4106 ;;
        *) echo "" ;;
    esac
}

# ── Parse arguments ───────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target-tps)     TARGET_TPS="$2";     shift 2 ;;
        --warmup-tps)     WARMUP_TPS="$2";     shift 2 ;;
        --warmup-secs)    WARMUP_SECS="$2";    shift 2 ;;
        --ramp-secs)      RAMP_SECS="$2";      shift 2 ;;
        --sustained-secs) SUSTAINED_SECS="$2"; shift 2 ;;
        --cooldown-secs)  COOLDOWN_SECS="$2";  shift 2 ;;
        --group-size)     GROUP_SIZE="$2";     shift 2 ;;
        --accounts)       ACCOUNTS="$2";       shift 2 ;;
        --concurrency)    CONCURRENCY="$2";    shift 2 ;;
        --fee-multiplier) FEE_MULTIPLIER="$2"; shift 2 ;;
        --output)         OUTPUT="$2";         shift 2 ;;
        --keep-up)        KEEP_UP=1;           shift   ;;
        --no-purge)       PURGE=0;             shift   ;;
        -h|--help)
            cat <<'USAGE'
Usage: bench-stress.sh [options]

  --target-tps N       Sustained transactions/sec target      (default 200)
  --warmup-tps N       Warmup-phase rate                      (default 25)
  --warmup-secs N      Warmup duration                        (default 30)
  --ramp-secs N        Linear ramp duration                   (default 30)
  --sustained-secs N   Full-rate duration                     (default 120)
  --cooldown-secs N    Drain window after submissions stop    (default 30)
  --group-size N       Txns per atomic group, 1-16            (default 1)
  --accounts N         Pre-funded generator accounts          (default 16)
  --concurrency N      Submitter tasks per endpoint           (default 8)
  --fee-multiplier N   Headroom over the congestion fee       (default 4)
  --output PATH        JSON report path    (default bench-results/bench-stress.json)
  --keep-up            Leave the cluster running after the report
  --no-purge           Reuse an existing docker/stress-netroot tree
USAGE
            exit 0
            ;;
        *) echo "ERROR: unknown argument: $1" >&2; exit 1 ;;
    esac
done

for tool in docker python3 curl; do
    command -v "${tool}" >/dev/null 2>&1 || { echo "ERROR: '${tool}' not found in PATH" >&2; exit 1; }
done

cd "${ROOT}"
mkdir -p "$(dirname "${OUTPUT}")"
RESULTS_DIR="$(cd "$(dirname "${OUTPUT}")" && pwd)"
SAMPLE_DIR="${RESULTS_DIR}/stress-samples"
rm -rf "${SAMPLE_DIR}"
mkdir -p "${SAMPLE_DIR}"

echo "=========================================="
echo " Mixed-cluster stress benchmark (issue #100)"
echo "   target TPS:      ${TARGET_TPS}"
echo "   warmup:          ${WARMUP_SECS}s @ ${WARMUP_TPS} TPS"
echo "   ramp:            ${RAMP_SECS}s"
echo "   sustained:       ${SUSTAINED_SECS}s"
echo "   cooldown:        ${COOLDOWN_SECS}s"
echo "   group size:      ${GROUP_SIZE}"
echo "   fee multiplier:  ${FEE_MULTIPLIER}"
echo "   gen accounts:    ${ACCOUNTS}"
echo "   output:          ${OUTPUT}"
echo "=========================================="

# ── Helpers ───────────────────────────────────────────────────────────
# A native-Windows `python3` writes CRLF to stdout, and `$(...)` only strips
# the trailing newline — leaving a bare CR glued to every captured value.
# That CR then travels into `goal clerk send -t <addr>` (rejected as a
# "non-canonical" address) and into every numeric comparison. Strip it once,
# here, so no caller has to remember.
py() { python3 "$@" | tr -d '\r'; }

now_secs() { py -c 'import time; print(f"{time.time():.6f}")'; }

# Under Git Bash the `python3` on PATH is a native Windows build that cannot
# open MSYS-style `/c/...` paths, so translate before handing it one. Elsewhere
# this is the identity. Where a *file's contents* will do, we pipe those in
# instead and skip the translation entirely.
pypath() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else echo "$1"; fi
}

# Any docker invocation whose arguments are *container-side* paths (/out/...,
# /algod/data) must run with MSYS path conversion disabled, or Git Bash
# rewrites them to `C:/Program Files/Git/out/...` on the way into the Windows
# docker binary. `docker build`, whose argument is a genuine host path, must
# NOT be wrapped. No-op off Windows.
dockerc() { MSYS_NO_PATHCONV=1 docker "$@"; }

# With conversion off, the *host*-side `-f <compose file>` argument has to be
# native already, so pre-translate it once.
COMPOSE_FILE_NATIVE="$(pypath "${COMPOSE_FILE}")"

api() {
    # api <node> <path> — GET against a node's REST API, empty on failure.
    local port; port="$(port_for "$1")"
    curl -sf --max-time 4 -H "X-Algo-API-Token: ${ALGOD_TOKEN}" \
        "http://127.0.0.1:${port}$2" 2>/dev/null || true
}

node_round() {
    local body; body="$(api "$1" /v2/status)"
    [ -z "${body}" ] && { echo ""; return; }
    py -c "
import json,sys
try:
    print(json.loads(sys.argv[1]).get('last-round',''))
except Exception:
    print('')
" "${body}"
}

wait_healthy() {
    local container="$1" deadline=$((SECONDS + STARTUP_TIMEOUT))
    while [ "${SECONDS}" -lt "${deadline}" ]; do
        local st
        st="$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
              "${container}" 2>/dev/null || echo "missing")"
        case "${st}" in
            healthy) return 0 ;;
            exited|dead) echo "ERROR: ${container} exited during startup" >&2; return 1 ;;
        esac
        sleep 2
    done
    echo "ERROR: ${container} not healthy within ${STARTUP_TIMEOUT}s" >&2
    return 1
}

teardown() {
    local rc=$?
    [ -n "${SAMPLER_PID:-}" ] && kill "${SAMPLER_PID}" 2>/dev/null || true
    if [ "${KEEP_UP}" = "0" ]; then
        echo "==> collecting container logs"
        for n in ${NODE_NAMES}; do
            docker logs "$(container_for "${n}")" > "${RESULTS_DIR}/stress-${n}.log" 2>&1 || true
        done
        echo "==> tearing down"
        ${COMPOSE} down -v --remove-orphans >/dev/null 2>&1 || true
    else
        echo "==> --keep-up: cluster left running (tear down with:"
        echo "    ${COMPOSE} down -v)"
    fi
    exit "${rc}"
}

# ══════════════════════════════════════════════════════════════════════
# PHASE 1 — startup
# ══════════════════════════════════════════════════════════════════════
echo ""
echo "### PHASE 1/6: startup"

if [ "${PURGE}" = "1" ]; then
    ${COMPOSE} down -v --remove-orphans >/dev/null 2>&1 || true
    # shellcheck source=./stress-bootstrap.sh
    source "${HERE}/stress-bootstrap.sh" --purge
else
    # shellcheck source=./stress-bootstrap.sh
    source "${HERE}/stress-bootstrap.sh"
fi
export STRESS_GENESIS_ID STRESS_RUST1_PARTKEY STRESS_RUST2_PARTKEY
export STRESS_GENESIS_HASH=""

trap teardown EXIT INT TERM

echo "==> building algod-rust:stress"
docker build -q -f "${DOCKER_DIR}/Dockerfile" --target runtime -t algod-rust:stress "${ROOT}" >/dev/null

echo "==> starting go-relay"
${COMPOSE} up -d go-relay
wait_healthy "$(container_for go-relay)"

# The Rust nodes need the genesis hash as hex on the command line, and the only
# way to obtain it without reimplementing canonical-msgpack hashing in shell is
# to ask a running node.
PARAMS="$(api go-relay /v2/transactions/params)"
STRESS_GENESIS_HASH="$(py -c "
import base64, json, sys
print(base64.b64decode(json.loads(sys.argv[1])['genesis-hash']).hex())
" "${PARAMS}")"
export STRESS_GENESIS_HASH
if [ -z "${STRESS_GENESIS_HASH}" ]; then
    echo "ERROR: could not read genesis hash from go-relay" >&2
    exit 1
fi
echo "==> genesis hash: ${STRESS_GENESIS_HASH}"

echo "==> starting the remaining five nodes"
${COMPOSE} up -d go-part-1 go-part-2 rust-relay rust-part-1 rust-part-2

STARTUP_FAILED=""
for n in ${NODE_NAMES}; do
    if ! wait_healthy "$(container_for "${n}")"; then
        STARTUP_FAILED="${STARTUP_FAILED} ${n}"
    fi
done
if [ -n "${STARTUP_FAILED}" ]; then
    echo "ERROR: node(s) failed to become healthy:${STARTUP_FAILED}" >&2
    for n in ${STARTUP_FAILED}; do
        echo "--- last 40 lines of $(container_for "${n}") ---" >&2
        docker logs --tail 40 "$(container_for "${n}")" >&2 2>&1 || true
    done
    exit 1
fi
echo "==> all six nodes healthy"

# ── Generator accounts: create, then fund from WalletGo1 via go-part-1 ──
KEYS_HOST="${RESULTS_DIR}/stress-loadgen-keys.json"
echo "==> generating ${ACCOUNTS} load-generator accounts"
dockerc compose -f "${COMPOSE_FILE_NATIVE}" run --rm --entrypoint algod-rust loadgen \
    loadgen gen-accounts --count "${ACCOUNTS}" --out /out/stress-loadgen-keys.json >/dev/null
[ -f "${KEYS_HOST}" ] || { echo "ERROR: key file not produced at ${KEYS_HOST}" >&2; exit 1; }

FUNDER="$(py -c "
import json, sys
g = json.loads(sys.argv[1])
print(next(a['addr'] for a in g['alloc'] if a.get('comment') == 'WalletGo1'))
" "$(cat "${DOCKER_DIR}/stress-netroot/genesis.json")")"
echo "==> funding generator accounts from ${FUNDER} (${FUND_MICROALGOS} µAlgo each)"
GEN_ADDRS="$(py -c "
import json, sys
for a in json.loads(sys.argv[1])['accounts']:
    print(a['address'])
" "$(cat "${KEYS_HOST}")")"
# The algod image starts kmd asynchronously after algod itself reports
# healthy, so `goal clerk send` (which needs the wallet) can fail for a while
# after the health gate opens. Wait for kmd rather than losing the funding
# round — an unfunded generator produces nothing but `overspend` rejections
# and a benchmark that measures an idle cluster.
#
# A second, Docker-Desktop-specific hazard: bootstrap deletes and recreates
# `docker/stress-netroot/`, and the host-filesystem share occasionally serves
# the container a stale view of the recreated directory. `goal` then fails
# with `could not make cachedir: ... no such file or directory` even though
# the data dir is plainly there on the host. Restarting the container
# re-establishes the mount, so fall back to that once before giving up.
echo "==> waiting for kmd on go-part-1"
goal_ready() {
    dockerc exec "$(container_for go-part-1)" goal account list -d /algod/data >/dev/null 2>&1
}
wait_goal_ready() {
    local tries="$1"
    for _ in $(seq 1 "${tries}"); do
        goal_ready && return 0
        sleep 2
    done
    return 1
}
KMD_READY=0
if wait_goal_ready 20; then
    KMD_READY=1
else
    echo "==> goal still unusable on go-part-1; restarting it and retrying"
    ${COMPOSE} restart go-part-1 >/dev/null 2>&1 || true
    wait_healthy "$(container_for go-part-1)" || true
    wait_goal_ready 20 && KMD_READY=1
fi
[ "${KMD_READY}" = "1" ] || echo "WARNING: goal/kmd never became usable on go-part-1" >&2

for addr in ${GEN_ADDRS}; do
    if ! FUND_OUT="$(dockerc exec "$(container_for go-part-1)" goal clerk send \
            -a "${FUND_MICROALGOS}" -f "${FUNDER}" -t "${addr}" \
            -d /algod/data -N 2>&1)"; then
        echo "WARNING: funding ${addr} failed: ${FUND_OUT}" >&2
    fi
done

# Funding used -N (no wait), so poll until the balances actually appear.
# Proceeding with unfunded accounts silently would make every later number
# meaningless, so this is a hard gate.
echo "==> waiting for funding to commit"
FUNDED=0
for _ in $(seq 1 30); do
    FUNDED=0
    for addr in ${GEN_ADDRS}; do
        bal="$(api go-relay "/v2/accounts/${addr}")"
        if [ -n "${bal}" ] && python3 -c "
import json, sys
sys.exit(0 if json.loads(sys.argv[1]).get('amount', 0) > 0 else 1)
" "${bal}" 2>/dev/null; then
            FUNDED=$((FUNDED + 1))
        fi
    done
    [ "${FUNDED}" -ge 1 ] && break
    sleep 2
done
echo "==> ${FUNDED}/${ACCOUNTS} generator accounts funded"
if [ "${FUNDED}" -eq 0 ]; then
    echo "ERROR: no generator account was funded; the load phase would submit only" >&2
    echo "       overspend-rejected transactions. Aborting." >&2
    exit 1
fi

# ── Background metric sampler (every 2s, per node) ────────────────────
# One `docker stats --no-stream` call covering all six containers per tick
# (six separate calls would cost ~6s and blow the 2s cadence).
sample_loop() {
    while true; do
        local ts stats
        ts="$(now_secs)"
        stats="$(docker stats --no-stream --format '{{.Name}} {{.MemUsage}} {{.CPUPerc}}' 2>/dev/null || true)"
        # Poll every node's round concurrently. Rounds advance every ~2.5s
        # under load and six sequential curl+python round-trips take a
        # comparable amount of time, so a sequential sample manufactures an
        # apparent one-to-two-round gap between the first node polled and the
        # last — an artefact exactly the size of the ≤2-round sync criterion it
        # would be used to judge.
        for n in ${NODE_NAMES}; do
            node_round "${n}" > "${SAMPLE_DIR}/.round.${n}" &
        done
        wait
        for n in ${NODE_NAMES}; do
            local c line mem cpu rnd
            c="$(container_for "${n}")"
            line="$(echo "${stats}" | grep -E "^${c} " | head -1)"
            mem="$(echo "${line}" | awk '{print $2}')"
            cpu="$(echo "${line}" | awk '{print $NF}' | tr -d '%')"
            rnd="$(tr -d '\r\n' < "${SAMPLE_DIR}/.round.${n}" 2>/dev/null || true)"
            echo "${ts},${mem:-},${cpu:-},${rnd:-}" >> "${SAMPLE_DIR}/${n}.csv"
        done
        sleep "${SAMPLE_INTERVAL}"
    done
}
sample_loop &
SAMPLER_PID=$!

record_phase() {
    echo "$1,$(now_secs),$(node_round go-relay)" >> "${SAMPLE_DIR}/phases.csv"
}

# Snapshot every node's `/v2/participation/status` counters (issue #473). Go
# nodes and any non-participating process answer 404, which curl -f turns into
# an empty body — the report treats "no file / empty file" as "no counters",
# which is exactly right for the Go half of the cluster.
#
# Taken twice (before the load starts and after cooldown) because the counters
# are cumulative from process start: the delta is what the measured window
# actually did, while the raw end-of-run totals also include warmup.
capture_partstatus() {
    local label="$1" n
    for n in ${NODE_NAMES}; do
        api "${n}" /v2/participation/status > "${SAMPLE_DIR}/${n}.partstatus.${label}.json" || true
    done
}

# ══════════════════════════════════════════════════════════════════════
# PHASE 2 — warmup
# ══════════════════════════════════════════════════════════════════════
echo ""
echo "### PHASE 2/6: warmup — ${WARMUP_SECS}s @ ${WARMUP_TPS} TPS"
record_phase warmup_start

ENDPOINTS="http://go-relay:8080,http://rust-relay:8080,http://go-part-1:8080,http://go-part-2:8080,http://rust-part-1:8080,http://rust-part-2:8080"

run_loadgen() {
    # run_loadgen <tps> <duration> <ramp> <report-name>
    dockerc compose -f "${COMPOSE_FILE_NATIVE}" run --rm --entrypoint algod-rust loadgen \
        loadgen run \
        --algod-urls "${ENDPOINTS}" \
        --token "${ALGOD_TOKEN}" \
        --keys /out/stress-loadgen-keys.json \
        --target-tps "$1" \
        --duration-secs "$2" \
        --ramp-secs "$3" \
        --group-size "${GROUP_SIZE}" \
        --concurrency "${CONCURRENCY}" \
        --fee-multiplier "${FEE_MULTIPLIER}" \
        --output "/out/$4" >/dev/null 2>&1 \
        || echo "WARNING: loadgen phase '$4' exited non-zero" >&2
}

run_loadgen "${WARMUP_TPS}" "${WARMUP_SECS}" 0 stress-loadgen-warmup.json
record_phase warmup_end

echo "==> per-node rounds after warmup:"
WARMUP_SYNC_OK=1
for n in ${NODE_NAMES}; do
    r="$(node_round "${n}")"
    printf '    %-12s round=%s\n' "${n}" "${r:-n/a}"
    [ -z "${r}" ] && WARMUP_SYNC_OK=0
done
[ "${WARMUP_SYNC_OK}" = "0" ] && echo "WARNING: a node did not report a round after warmup" >&2

# ══════════════════════════════════════════════════════════════════════
# PHASES 3+4 — ramp then sustained (one loadgen invocation; the generator
# does the linear ramp internally, so the two phases are contiguous with no
# submission gap between them).
# ══════════════════════════════════════════════════════════════════════
echo ""
echo "### PHASE 3/6: ramp — ${RAMP_SECS}s to ${TARGET_TPS} TPS"
echo "### PHASE 4/6: sustained — ${SUSTAINED_SECS}s @ ${TARGET_TPS} TPS"
record_phase load_start
capture_partstatus before
run_loadgen "${TARGET_TPS}" "$((RAMP_SECS + SUSTAINED_SECS))" "${RAMP_SECS}" stress-loadgen-main.json
record_phase load_end

# ══════════════════════════════════════════════════════════════════════
# PHASE 5 — cooldown
# ══════════════════════════════════════════════════════════════════════
echo ""
echo "### PHASE 5/6: cooldown — ${COOLDOWN_SECS}s"
sleep "${COOLDOWN_SECS}"
record_phase cooldown_end

# ══════════════════════════════════════════════════════════════════════
# PHASE 6 — report
# ══════════════════════════════════════════════════════════════════════
echo ""
echo "### PHASE 6/6: report"

kill "${SAMPLER_PID}" 2>/dev/null || true
SAMPLER_PID=""

# Per-node final round, real participation counters, and crash/restart counts.
for n in ${NODE_NAMES}; do
    node_round "${n}" > "${SAMPLE_DIR}/${n}.final-round" || true
done
capture_partstatus after

# `restart: unless-stopped` means an OOM-killed or panicking node comes back
# silently and the round samples barely notice. Docker's own RestartCount and
# the last exit code are the only unambiguous evidence, so record them for
# every node — this is the "no OOM crashes" acceptance criterion.
for n in ${NODE_NAMES}; do
    docker inspect --format '{{.RestartCount}},{{.State.ExitCode}},{{.State.OOMKilled}}' \
        "$(container_for "${n}")" > "${SAMPLE_DIR}/${n}.restarts" 2>/dev/null \
        || echo "0,0,false" > "${SAMPLE_DIR}/${n}.restarts"
done
for n in ${RUST_NODES}; do
    docker logs "$(container_for "${n}")" 2>&1 \
        | grep -ciE '\bERROR\b|panicked' \
        > "${SAMPLE_DIR}/${n}.errors" || echo 0 > "${SAMPLE_DIR}/${n}.errors"
    docker logs "$(container_for "${n}")" 2>&1 \
        | grep -ciE '\bWARN\b' \
        > "${SAMPLE_DIR}/${n}.warns" || echo 0 > "${SAMPLE_DIR}/${n}.warns"
done

# Block-level aggregates come from go-relay, which has the full chain.
# Fetching every block in the measured window is the only way to get real
# per-block txn counts and byte sizes (the /v2/status endpoint carries neither).
LOAD_START_ROUND="$(py -c "
import csv, io, sys
rows = {r[0]: r for r in csv.reader(io.StringIO(sys.argv[1])) if r}
row = rows.get('load_start')
print((row[2] if row and len(row) > 2 else '') or 0)
" "$(cat "${SAMPLE_DIR}/phases.csv")")"
FINAL_ROUND="$(node_round go-relay)"

python3 "$(pypath "${HERE}/stress-report.py")" \
    --sample-dir "$(pypath "${SAMPLE_DIR}")" \
    --results-dir "$(pypath "${RESULTS_DIR}")" \
    --output "$(pypath "${ROOT}/${OUTPUT}")" \
    --nodes "${NODE_NAMES}" \
    --go-nodes "${GO_NODES}" \
    --rust-nodes "${RUST_NODES}" \
    --target-tps "${TARGET_TPS}" \
    --group-size "${GROUP_SIZE}" \
    --warmup-secs "${WARMUP_SECS}" \
    --ramp-secs "${RAMP_SECS}" \
    --sustained-secs "${SUSTAINED_SECS}" \
    --cooldown-secs "${COOLDOWN_SECS}" \
    --load-start-round "${LOAD_START_ROUND:-0}" \
    --final-round "${FINAL_ROUND:-0}" \
    --algod-url "http://127.0.0.1:$(port_for go-relay)" \
    --algod-token "${ALGOD_TOKEN}"

echo ""
echo "Report: ${OUTPUT}"
echo "Logs:   ${RESULTS_DIR}/stress-<node>.log"
echo "Samples:${SAMPLE_DIR}/"
