#!/usr/bin/env bash
# PLAN-32 / TASK-88 — mixed-cluster soak verifier.
#
# Wraps the two TASK-88 tools:
#
#   1. algo-fork-detector — pulls /v2/blocks/{r} from every Go REST node
#      in the mixed cluster and asserts identical block digests per round.
#   2. algo-cert-crossverify — cross-verifies certs the Go nodes produced
#      by authenticating them against an algod-rust ledger (the Rust
#      relay's ledger.sqlite, copied out of the container into a temp
#      directory for the duration of the run).
#
# Usage:
#   verify-soak.sh [--from-round N] [--to-round M] [--stride S]
#                  [--tools-dir PATH] [--skip-preflight]
#
# Exit codes:
#   0 — both tools reported clean
#   2 — at least one tool reported a failure (fork or cert
#       authentication error); the tool's own non-zero exit propagates
#   3 — preflight failed (cluster not healthy)
#   4 — extracting the Rust ledger failed
#
# Notes:
# - Rust → Go cert verification (the inverse direction) is out of scope
#   until the Rust node runs online participation keys (PLAN-35). This
#   script only exercises Go-produced cert verification under the Rust
#   verifier.
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
# Cert cross-verify is OPT-IN today because the mixed-cluster Rust node
# runs in `relay` mode and doesn't populate a full ledger (empty proto,
# empty hdrdata, no participation tracker). The cert-crossverify binary
# detects this and bails fast, but there's no point running it by
# default until TASK-95 lands a full-sync Rust node in the harness.
# Pass `--with-cert-crossverify <full-sync-ledger.sqlite>` to opt in.
CERT_LEDGER=""

usage() {
    cat <<EOF
usage: $(basename "$0") [--from-round N] [--to-round M] [--stride S]
                        [--tools-dir PATH] [--out-dir PATH]
                        [--with-cert-crossverify PATH] [--skip-preflight]

Options:
  --from-round N         First round to verify (default: 1).
  --to-round M           Last round to verify (default: cluster's current
                         max round at preflight time).
  --stride S             Sample every S'th round for cert cross-verify
                         (fork detection always runs every round).
                         Default: 20 (so a 200-round soak samples 10).
  --tools-dir PATH       Directory containing algo-fork-detector and
                         algo-cert-crossverify binaries. Default:
                         \$REPO_ROOT/target/debug — rebuild first with
                         'cargo build -p algo-fork-detector -p algo-cert-crossverify'.
  --out-dir PATH         Where to write verifier JSONL output (default:
                         the mixed-cluster root).
  --with-cert-crossverify PATH
                         Run cert cross-verify against the SQLite ledger
                         at PATH. Must be a full-sync algod-rust ledger
                         (not the mixed-cluster relay's, which lacks
                         proto/hdrdata/participation state — see TASK-95).
                         If omitted, cert cross-verify is skipped with a
                         note.
  --skip-preflight       Skip the status.sh health check.
  -h, --help             Show this help.

Artifacts written:
  \$OUT_DIR/verify-fork-<ts>.jsonl
  \$OUT_DIR/verify-cert-<ts>.jsonl (only with --with-cert-crossverify)
EOF
}

# need_arg <flag> "\$@" — error out if the next argv token is missing
# or looks like another flag. Avoids \`\$2: unbound variable\` under set -u.
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
        --with-cert-crossverify)  need_arg "$@"; CERT_LEDGER="$2"; shift 2 ;;
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
for bin in "$FORK_BIN" "$CERT_BIN"; do
    if [ ! -x "$bin" ]; then
        echo "error: $bin not found or not executable" >&2
        echo "       rebuild with:" >&2
        echo "         cargo build -p algo-fork-detector -p algo-cert-crossverify" >&2
        exit 2
    fi
done

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
if [ -z "$TO_ROUND" ]; then
    max_round_line="$("$HERE/status.sh" | awk '/^cluster healthy/ {print; exit}')"
    TO_ROUND="$(printf '%s\n' "$max_round_line" | sed -n 's/.*max round \([0-9][0-9]*\).*/\1/p')"
    if [ -z "$TO_ROUND" ]; then
        echo "error: could not derive --to-round from status.sh output" >&2
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
    --nodes "go-node-1=http://127.0.0.1:4001,go-node-2=http://127.0.0.1:4002,go-node-3=http://127.0.0.1:4003" \
    --from-round "$FROM_ROUND" \
    --to-round "$TO_ROUND" \
    --token-file "$TOKEN_FILE" \
    --jsonl-out "$FORK_OUT"
fork_rc=$?
set -e
echo "    fork-detector exit: $fork_rc (output: $FORK_OUT)"

# -- 2. Cert cross-verify (Go → Rust) — OPT-IN -----------------------------
cert_rc=0
if [ -n "$CERT_LEDGER" ]; then
    if [ ! -f "$CERT_LEDGER" ]; then
        echo "error: --with-cert-crossverify path $CERT_LEDGER does not exist" >&2
        exit 4
    fi
    CERT_OUT="$OUT_DIR/verify-cert-$(date +%s).jsonl"
    echo "==> cert cross-verify (Go-produced → Rust verifier), stride $STRIDE"
    echo "    ledger: $CERT_LEDGER"
    set +e
    "$CERT_BIN" \
        --node http://127.0.0.1:4001 \
        --token-file "$TOKEN_FILE" \
        --ledger-sqlite "$CERT_LEDGER" \
        --from-round "$FROM_ROUND" \
        --to-round "$TO_ROUND" \
        --stride "$STRIDE" \
        --jsonl-out "$CERT_OUT"
    cert_rc=$?
    set -e
    echo "    cert-crossverify exit: $cert_rc (output: $CERT_OUT)"
else
    echo "==> cert cross-verify: SKIPPED (pass --with-cert-crossverify <path> to enable)"
    echo "    The mixed-cluster Rust relay today does NOT maintain a full"
    echo "    ledger — imported blocks land with empty proto/hdrdata and"
    echo "    the participation tracker is never populated, so cert"
    echo "    verification would fail at the first round. Tracked as TASK-95"
    echo "    (follow-up: enable full-sync mode for cert cross-verify)."
fi

# -- Summary ----------------------------------------------------------------
echo ""
if [ "$fork_rc" -eq 0 ] && [ "$cert_rc" -eq 0 ]; then
    if [ -n "$CERT_LEDGER" ]; then
        echo "verify-soak: CLEAN — fork detector + Go→Rust cert cross-verify both passed."
    else
        echo "verify-soak: fork-clean (cert cross-verify skipped — see --help)."
    fi
    exit 0
fi
echo "verify-soak: FAILED — fork_rc=$fork_rc cert_rc=$cert_rc" >&2
exit 2
