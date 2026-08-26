#!/usr/bin/env bash
# verify-soak.sh — issue #596 (P2P analogue of ops/mixed-cluster's
# verify-soak.sh, issue #470 §2 / TASK-88 / TASK-95).
#
# Ports the WS-gossip harness's verifier wrapper to this harness's
# container names (p2pinterop-*) and host ports (5001-5004 rather than
# 4001-4004). The verifier tools themselves
# (`algo-fork-detector`, `algo-cert-crossverify`, `tools/cert-authenticate`)
# are unmodified — they operate on exported ledger/block facts over
# REST + SQLite, not on the gossip/P2P transport, so nothing about them
# is WS-gossip-specific. See docs/P2P_SOAK_METHODOLOGY.md.
#
#   1. algo-fork-detector — pulls /v2/blocks/{r} from every Go REST node
#      in the P2P cluster and asserts identical block digests per round.
#   2. algo-cert-crossverify — cross-verifies certs the Go nodes produced
#      by authenticating them against an algod-rust ledger. The P2P
#      harness's rust-node-4 also runs `--ledger-path=/app/ledger`
#      (docker-compose.yml), producing the same
#      `ledger.tracker.sqlite` + `ledger.block.sqlite` pair the
#      WS-gossip harness's rust-node-4 does, extracted via the same
#      SQLite backup-API `docker exec` + `docker cp` pattern.
#   3. tools/cert-authenticate — the inverse direction. Combined with
#      step 2, every sampled certificate is proven to authenticate under
#      BOTH implementations.
#
# Usage:
#   verify-soak.sh [--from-round N] [--to-round M] [--stride S]
#                  [--tools-dir PATH] [--out-dir PATH]
#                  [--no-cert-crossverify] [--cert-ledger PATH]
#                  [--skip-preflight] [--rust-account ADDR]
#                  [--min-rust-vote-rounds N] [--no-go-authenticate]
#
# Exit codes: identical semantics to ops/mixed-cluster/scripts/verify-soak.sh
#   0 — every tool that ran reported clean
#   1 — the fork detector exited with its degraded-coverage code
#   2 — a real fork was detected, OR cert cross-verify / go-authenticate failed
#   3 — preflight failed (cluster not healthy, no token file, etc.)
#   4 — extracting the Rust ledger failed
#
# Notes:
# - The script does not start or stop the cluster. Run start.sh / stop.sh
#   around it.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/../.." && pwd)"

FROM_ROUND=""
TO_ROUND=""
STRIDE=20
TOOLS_DIR="${TOOLS_DIR:-$REPO_ROOT/target/debug}"
SKIP_PREFLIGHT=0
OUT_DIR="${OUT_DIR:-$ROOT}"
RUN_CERT=1
CERT_LEDGER_OVERRIDE=""
RUST_ACCOUNT="${RUST_ACCOUNT:-}"
MIN_RUST_VOTE_ROUNDS="${MIN_RUST_VOTE_ROUNDS:-1}"
RUN_GO_AUTH=1

RUST_CONTAINER=p2pinterop-rust-node-4
ALGOD_TOKEN="${ALGOD_TOKEN:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"

usage() {
    cat <<EOF
usage: $(basename "$0") [--from-round N] [--to-round M] [--stride S]
                        [--tools-dir PATH] [--out-dir PATH]
                        [--no-cert-crossverify] [--cert-ledger PATH]
                        [--skip-preflight] [--rust-account ADDR]
                        [--min-rust-vote-rounds N] [--no-go-authenticate]

Options:
  --from-round N         First round to verify (default: 1).
  --to-round M           Last round to verify (default: cluster's current
                         max round at preflight time).
  --stride S             Sample every S'th round for cert cross-verify
                         (fork detection always runs every round).
                         Default: 20.
  --tools-dir PATH       Directory containing algo-fork-detector and
                         algo-cert-crossverify binaries. Default:
                         \$REPO_ROOT/target/debug.
  --out-dir PATH         Where to write verifier JSONL output (default:
                         the mixed-cluster-p2p root).
  --no-cert-crossverify  Skip the cert cross-verify step entirely.
  --cert-ledger PATH     Use an externally-prepared SQLite ledger prefix
                         instead of docker cp'ing from
                         p2pinterop-rust-node-4:/app/ledger.*.sqlite.
  --skip-preflight       Skip the status.sh health check.
  --rust-account ADDR    Address of the Rust participant. Enables the
                         vote-in-certificate assertion and the Go-side
                         re-authentication step.
  --min-rust-vote-rounds N
                         Fail unless at least N sampled certificates
                         contain a vote from --rust-account (default 1).
  --no-go-authenticate   Skip the go-algorand-side authentication even
                         when --rust-account is given.
  -h, --help             Show this help.

Artifacts written:
  \$OUT_DIR/verify-fork-<ts>.jsonl
  \$OUT_DIR/verify-cert-<ts>.jsonl (unless --no-cert-crossverify)
  \$OUT_DIR/verify-go-input-<ts>.json  (with --rust-account)
  \$OUT_DIR/verify-go-report-<ts>.json (with --rust-account)
EOF
}

need_arg() {
    if [ $# -lt 2 ] || [ -z "$2" ] || [ "${2:0:2}" = "--" ]; then
        echo "error: flag '$1' requires a value" >&2
        usage >&2
        exit 2
    fi
}

while [ $# -gt 0 ]; do
    case "$1" in
        --from-round)             need_arg "$@"; FROM_ROUND="$2"; shift 2 ;;
        --to-round)               need_arg "$@"; TO_ROUND="$2"; shift 2 ;;
        --stride)                 need_arg "$@"; STRIDE="$2"; shift 2 ;;
        --tools-dir)              need_arg "$@"; TOOLS_DIR="$2"; shift 2 ;;
        --out-dir)                need_arg "$@"; OUT_DIR="$2"; shift 2 ;;
        --cert-ledger)            need_arg "$@"; CERT_LEDGER_OVERRIDE="$2"; shift 2 ;;
        --rust-account)           need_arg "$@"; RUST_ACCOUNT="$2"; shift 2 ;;
        --min-rust-vote-rounds)   need_arg "$@"; MIN_RUST_VOTE_ROUNDS="$2"; shift 2 ;;
        --no-go-authenticate)     RUN_GO_AUTH=0; shift ;;
        --no-cert-crossverify)    RUN_CERT=0; shift ;;
        --skip-preflight)         SKIP_PREFLIGHT=1; shift ;;
        -h|--help)                usage; exit 0 ;;
        *)
            echo "unknown arg: $1" >&2
            usage >&2
            exit 2 ;;
    esac
done

FORK_BIN="$TOOLS_DIR/algo-fork-detector"
CERT_BIN="$TOOLS_DIR/algo-cert-crossverify"
[ -x "$FORK_BIN" ] || FORK_BIN="$TOOLS_DIR/algo-fork-detector.exe"
[ -x "$CERT_BIN" ] || CERT_BIN="$TOOLS_DIR/algo-cert-crossverify.exe"

if [ ! -x "$FORK_BIN" ]; then
    echo "error: $FORK_BIN not found or not executable" >&2
    echo "       rebuild with:" >&2
    echo "         cargo build -p algo-fork-detector" >&2
    exit 2
fi
if [ "$RUN_CERT" = "1" ] && [ ! -x "$CERT_BIN" ]; then
    echo "error: $CERT_BIN not found or not executable" >&2
    echo "       cert cross-verify needs it; rebuild with:" >&2
    echo "         cargo build -p algo-cert-crossverify" >&2
    echo "       (or pass --no-cert-crossverify to skip this step)" >&2
    exit 2
fi

mkdir -p "$OUT_DIR"

NETROOT="$ROOT/netroot"
TOKEN_FILE="$NETROOT/Node1/algod.token"
if [ ! -f "$TOKEN_FILE" ]; then
    echo "error: algod token file $TOKEN_FILE missing" >&2
    echo "       did you run scripts/start.sh?" >&2
    exit 3
fi

# -- Preflight --------------------------------------------------------------
if [ "$SKIP_PREFLIGHT" = "0" ]; then
    echo "==> preflight: status.sh"
    if ! "$HERE/status.sh" >/dev/null 2>&1; then
        echo "error: cluster not healthy — run start.sh first." >&2
        exit 3
    fi
    echo "    cluster healthy"
fi

# Derive --to-round from the cluster's current max round if unspecified.
# status.sh's per-row output doesn't carry a single "max round" summary
# line the way ops/mixed-cluster's does, so read go-node-1's round
# directly instead of scraping status.sh's text.
if [ -z "$TO_ROUND" ]; then
    TO_ROUND="$(curl -sf -H "X-Algo-API-Token: $ALGOD_TOKEN" \
        "http://127.0.0.1:5001/v2/status" 2>/dev/null | python3 -c "
import json, sys
try:
    print(json.load(sys.stdin).get('last-round', ''))
except Exception:
    print('')
" | tr -d '\r')"
    if [ -z "$TO_ROUND" ]; then
        echo "error: could not derive --to-round from go-node-1's /v2/status" >&2
        exit 3
    fi
    # Leave a small buffer so the verifier doesn't race the node tip.
    TO_ROUND=$((TO_ROUND - 2))
fi
if [ -z "$FROM_ROUND" ]; then
    FROM_ROUND=1
fi
echo "    verify range: $FROM_ROUND..$TO_ROUND (stride $STRIDE for cert)"

# -- 1. Fork detector ------------------------------------------------------
FORK_OUT="$OUT_DIR/verify-fork-$(date +%s).jsonl"
echo "==> fork detector: $FROM_ROUND..$TO_ROUND"
set +e
"$FORK_BIN" \
    --nodes "go-node-1=http://127.0.0.1:5001,go-node-2=http://127.0.0.1:5002,go-node-3=http://127.0.0.1:5003" \
    --from-round "$FROM_ROUND" \
    --to-round "$TO_ROUND" \
    --token-file "$TOKEN_FILE" \
    --jsonl-out "$FORK_OUT"
fork_rc=$?
set -e
echo "    fork-detector exit: $fork_rc (output: $FORK_OUT)"

# -- 2. Cert cross-verify (Go → Rust) ---------------------------------------
cert_rc=0
WORKDIR=""
cleanup_workdir() {
    if [ -n "$WORKDIR" ] && [ -d "$WORKDIR" ]; then
        rm -rf "$WORKDIR"
    fi
}
trap cleanup_workdir EXIT

if [ "$RUN_CERT" = "1" ]; then
    CERT_OUT="$OUT_DIR/verify-cert-$(date +%s).jsonl"
    if [ -n "$CERT_LEDGER_OVERRIDE" ]; then
        CERT_PREFIX_CANDIDATE="${CERT_LEDGER_OVERRIDE%.tracker.sqlite}"
        CERT_PREFIX_CANDIDATE="${CERT_PREFIX_CANDIDATE%.block.sqlite}"
        CERT_PREFIX_CANDIDATE="${CERT_PREFIX_CANDIDATE%.sqlite}"
        if [ ! -s "${CERT_PREFIX_CANDIDATE}.tracker.sqlite" ]; then
            echo "error: --cert-ledger path $CERT_LEDGER_OVERRIDE is not a split-layout" >&2
            echo "       ledger (no non-empty ${CERT_PREFIX_CANDIDATE}.tracker.sqlite)." >&2
            exit 4
        fi
        if [ ! -s "${CERT_PREFIX_CANDIDATE}.block.sqlite" ]; then
            echo "error: --cert-ledger split prefix $CERT_PREFIX_CANDIDATE is missing the" >&2
            echo "       block database (no non-empty ${CERT_PREFIX_CANDIDATE}.block.sqlite)." >&2
            exit 4
        fi
        CERT_LEDGER_PATH="$CERT_PREFIX_CANDIDATE"
        echo "==> cert cross-verify (Go-produced → Rust verifier), stride $STRIDE"
        echo "    ledger: $CERT_LEDGER_PATH (--cert-ledger override)"
    else
        WORKDIR="$(mktemp -d -t verify-soak-p2p.XXXXXX)"
        CERT_LEDGER_PREFIX="$WORKDIR/ledger"
        CERT_LEDGER_PATH="$CERT_LEDGER_PREFIX"
        TRACKER_PATH="${CERT_LEDGER_PREFIX}.tracker.sqlite"
        BLOCK_PATH="${CERT_LEDGER_PREFIX}.block.sqlite"
        echo "==> cert cross-verify (Go-produced → Rust verifier), stride $STRIDE"
        echo "    snapshotting Rust tracker + block databases via SQLite backup API"
        if docker exec "$RUST_CONTAINER" sqlite3 /app/ledger.tracker.sqlite \
                    ".backup '/app/verify-soak-tracker.sqlite'" >/dev/null 2>&1 \
                && docker exec "$RUST_CONTAINER" sqlite3 /app/ledger.block.sqlite \
                    ".backup '/app/verify-soak-block.sqlite'" >/dev/null 2>&1; then
            if ! docker cp "$RUST_CONTAINER:/app/verify-soak-tracker.sqlite" \
                    "$TRACKER_PATH" 2>/dev/null; then
                echo "error: failed to docker cp the tracker snapshot." >&2
                exit 4
            fi
            if ! docker cp "$RUST_CONTAINER:/app/verify-soak-block.sqlite" \
                    "$BLOCK_PATH" 2>/dev/null; then
                echo "error: failed to docker cp the block snapshot." >&2
                exit 4
            fi
            docker exec "$RUST_CONTAINER" rm -f \
                    /app/verify-soak-tracker.sqlite \
                    /app/verify-soak-block.sqlite \
                >/dev/null 2>&1 || true
        else
            echo "    warning: sqlite3 .backup unavailable in container;" >&2
            echo "    falling back to raw docker cp (may be racy under heavy writes)" >&2
            if ! docker cp "$RUST_CONTAINER:/app/ledger.tracker.sqlite" \
                    "$TRACKER_PATH" 2>/dev/null; then
                echo "error: failed to docker cp the tracker DB." >&2
                echo "       is $RUST_CONTAINER running?" >&2
                exit 4
            fi
            if ! docker cp "$RUST_CONTAINER:/app/ledger.block.sqlite" \
                    "$BLOCK_PATH" 2>/dev/null; then
                echo "error: failed to docker cp the block DB." >&2
                echo "       is $RUST_CONTAINER running?" >&2
                exit 4
            fi
            for sidecar in \
                    ledger.tracker.sqlite-wal ledger.tracker.sqlite-shm \
                    ledger.block.sqlite-wal ledger.block.sqlite-shm; do
                docker cp "$RUST_CONTAINER:/app/$sidecar" "$WORKDIR/$sidecar" \
                    2>/dev/null || true
            done
        fi
        if [ ! -s "$TRACKER_PATH" ] || [ ! -s "$BLOCK_PATH" ]; then
            echo "error: extracted ledger pair under $WORKDIR is empty" >&2
            exit 4
        fi
        echo "    ledger size: tracker=$(du -h "$TRACKER_PATH" | awk '{print $1}') block=$(du -h "$BLOCK_PATH" | awk '{print $1}')"
    fi
    CERT_EXTRA_ARGS=()
    if [ -n "$RUST_ACCOUNT" ]; then
        GO_INPUT="$OUT_DIR/verify-go-input-$(date +%s).json"
        CERT_EXTRA_ARGS+=(--rust-account "$RUST_ACCOUNT")
        CERT_EXTRA_ARGS+=(--min-rust-vote-rounds "$MIN_RUST_VOTE_ROUNDS")
        CERT_EXTRA_ARGS+=(--export-go-input "$GO_INPUT")
        echo "    rust participant: $RUST_ACCOUNT (>= $MIN_RUST_VOTE_ROUNDS cert(s) must carry its vote)"
    fi
    set +e
    "$CERT_BIN" \
        --node http://127.0.0.1:5001 \
        --token-file "$TOKEN_FILE" \
        --ledger-sqlite "$CERT_LEDGER_PATH" \
        --from-round "$FROM_ROUND" \
        --to-round "$TO_ROUND" \
        --stride "$STRIDE" \
        --jsonl-out "$CERT_OUT" \
        "${CERT_EXTRA_ARGS[@]+"${CERT_EXTRA_ARGS[@]}"}"
    cert_rc=$?
    set -e
    echo "    cert-crossverify exit: $cert_rc (output: $CERT_OUT)"
else
    echo "==> cert cross-verify: SKIPPED (--no-cert-crossverify)"
fi

# -- 3. Go-side certificate authentication (Rust → Go) ----------------------
go_auth_rc=0
if [ -n "$RUST_ACCOUNT" ] && [ "$RUN_CERT" = "1" ] && [ "$RUN_GO_AUTH" = "1" ]; then
    GO_REPORT="$OUT_DIR/verify-go-report-$(date +%s).json"
    echo "==> go-algorand cert authentication (Rust-participating certs -> Go verifier)"
    if [ ! -s "${GO_INPUT:-/nonexistent}" ]; then
        echo "error: cert-crossverify did not write a go-verify bundle at ${GO_INPUT:-<unset>}" >&2
        go_auth_rc=2
    else
        set +e
        bash "$REPO_ROOT/tools/cert-authenticate/run-in-docker.sh" \
            --input "$GO_INPUT" \
            --out "$GO_REPORT" \
            --require-rust-votes "$MIN_RUST_VOTE_ROUNDS"
        go_auth_rc=$?
        set -e
        echo "    cert-authenticate exit: $go_auth_rc (report: $GO_REPORT)"
    fi
elif [ -n "$RUST_ACCOUNT" ] && [ "$RUN_GO_AUTH" = "0" ]; then
    echo "==> go-algorand cert authentication: SKIPPED (--no-go-authenticate)"
fi

# -- Summary ----------------------------------------------------------------
echo ""
if [ "$fork_rc" -eq 0 ] && [ "$cert_rc" -eq 0 ] && [ "$go_auth_rc" -eq 0 ]; then
    if [ "$RUN_CERT" = "1" ] && [ -n "$RUST_ACCOUNT" ] && [ "$RUN_GO_AUTH" = "1" ]; then
        echo "verify-soak: CLEAN — fork detector + Go→Rust cert cross-verify +"
        echo "             Rust→Go cert authentication all passed."
    elif [ "$RUN_CERT" = "1" ]; then
        echo "verify-soak: CLEAN — fork detector + Go→Rust cert cross-verify both passed."
    else
        echo "verify-soak: fork-clean (cert cross-verify skipped via --no-cert-crossverify)."
    fi
    exit 0
fi

worst=0
if [ "$fork_rc" -gt "$worst" ]; then
    worst=$fork_rc
fi
if [ "$cert_rc" -gt "$worst" ]; then
    worst=$cert_rc
fi
if [ "$go_auth_rc" -gt "$worst" ]; then
    worst=$go_auth_rc
fi
echo "verify-soak: FAILED — fork_rc=$fork_rc cert_rc=$cert_rc go_auth_rc=$go_auth_rc (exit=$worst)" >&2
exit "$worst"
