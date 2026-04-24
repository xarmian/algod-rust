#!/usr/bin/env bash
# PLAN-32 / TASK-88 + TASK-95 — mixed-cluster soak verifier.
#
# Wraps the two verifier tools:
#
#   1. algo-fork-detector — pulls /v2/blocks/{r} from every Go REST node
#      in the mixed cluster and asserts identical block digests per round.
#   2. algo-cert-crossverify — cross-verifies certs the Go nodes produced
#      by authenticating them against an algod-rust ledger. As of
#      TASK-95 the mixed-cluster Rust relay seeds accountbase +
#      accounttotals from genesis and applies each imported block, so
#      its `/app/ledger.sqlite` is a valid verifier input. This script
#      `docker cp`s it out into a temp dir for the run and cleans up
#      on exit.
#
# Usage:
#   verify-soak.sh [--from-round N] [--to-round M] [--stride S]
#                  [--tools-dir PATH] [--no-cert-crossverify]
#                  [--cert-ledger PATH] [--skip-preflight]
#
# Exit codes:
#   0 — every tool that ran reported clean
#   1 — the fork detector exited with its degraded-coverage code
#       (insufficient or fetch errors without `--allow-degraded`)
#   2 — the fork detector detected a real fork (bubbled up verbatim)
#       OR the cert cross-verify tool failed authentication
#   3 — preflight failed (cluster not healthy, no token file, etc.)
#   4 — extracting the Rust ledger failed
#
# When both tools run and both fail, the larger exit code (most severe)
# wins.
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
# Cert cross-verify runs by default as of TASK-95 (the Rust relay now
# maintains a full-sync ledger). Pass --no-cert-crossverify to skip it
# (e.g. for a quick fork-only check), or --cert-ledger PATH to point at
# an externally-prepared SQLite instead of the relay container's.
RUN_CERT=1
CERT_LEDGER_OVERRIDE=""

usage() {
    cat <<EOF
usage: $(basename "$0") [--from-round N] [--to-round M] [--stride S]
                        [--tools-dir PATH] [--out-dir PATH]
                        [--no-cert-crossverify] [--cert-ledger PATH]
                        [--skip-preflight]

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
  --no-cert-crossverify  Skip the cert cross-verify step entirely.
                         Fork detection still runs. Useful for a fast
                         sanity check when you don't care about cert
                         authentication.
  --cert-ledger PATH     Use an externally-prepared SQLite ledger at
                         PATH instead of docker cp'ing from
                         phase6-rust-node-4:/app/ledger.sqlite. The
                         ledger must be caught up past --to-round.
  --skip-preflight       Skip the status.sh health check.
  -h, --help             Show this help.

Artifacts written:
  \$OUT_DIR/verify-fork-<ts>.jsonl
  \$OUT_DIR/verify-cert-<ts>.jsonl (unless --no-cert-crossverify)
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
        --cert-ledger)            need_arg "$@"; CERT_LEDGER_OVERRIDE="$2"; shift 2 ;;
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

# Fork detector is always required; cert tool is only required when
# the caller opted into --with-cert-crossverify. That way a user
# running fork-only doesn't have to build the cert crate too.
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

# -- 2. Cert cross-verify (Go → Rust) — DEFAULT ON (TASK-95) ---------------
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
        if [ ! -f "$CERT_LEDGER_OVERRIDE" ]; then
            echo "error: --cert-ledger path $CERT_LEDGER_OVERRIDE does not exist" >&2
            exit 4
        fi
        CERT_LEDGER_PATH="$CERT_LEDGER_OVERRIDE"
        echo "==> cert cross-verify (Go-produced → Rust verifier), stride $STRIDE"
        echo "    ledger: $CERT_LEDGER_PATH (--cert-ledger override)"
    else
        WORKDIR="$(mktemp -d -t verify-soak.XXXXXX)"
        CERT_LEDGER_PATH="$WORKDIR/ledger.sqlite"
        echo "==> cert cross-verify (Go-produced → Rust verifier), stride $STRIDE"
        echo "    copying Rust ledger from phase6-rust-node-4:/app/ledger.sqlite"
        if ! docker cp phase6-rust-node-4:/app/ledger.sqlite "$CERT_LEDGER_PATH" 2>/dev/null; then
            echo "error: failed to docker cp the Rust ledger." >&2
            echo "       is phase6-rust-node-4 running?" >&2
            exit 4
        fi
        if [ ! -s "$CERT_LEDGER_PATH" ]; then
            echo "error: extracted ledger $CERT_LEDGER_PATH is empty" >&2
            exit 4
        fi
        # Capture the WAL + SHM so the SQLite snapshot is self-consistent.
        # These may not exist on a quiescent node; ignore failures.
        for sidecar in ledger.sqlite-wal ledger.sqlite-shm; do
            docker cp "phase6-rust-node-4:/app/$sidecar" "$WORKDIR/$sidecar" 2>/dev/null || true
        done
        echo "    ledger size: $(du -h "$CERT_LEDGER_PATH" | awk '{print $1}')"
    fi
    set +e
    "$CERT_BIN" \
        --node http://127.0.0.1:4001 \
        --token-file "$TOKEN_FILE" \
        --ledger-sqlite "$CERT_LEDGER_PATH" \
        --from-round "$FROM_ROUND" \
        --to-round "$TO_ROUND" \
        --stride "$STRIDE" \
        --jsonl-out "$CERT_OUT"
    cert_rc=$?
    set -e
    echo "    cert-crossverify exit: $cert_rc (output: $CERT_OUT)"
else
    echo "==> cert cross-verify: SKIPPED (--no-cert-crossverify)"
fi

# -- Summary ----------------------------------------------------------------
echo ""
if [ "$fork_rc" -eq 0 ] && [ "$cert_rc" -eq 0 ]; then
    if [ "$RUN_CERT" = "1" ]; then
        echo "verify-soak: CLEAN — fork detector + Go→Rust cert cross-verify both passed."
    else
        echo "verify-soak: fork-clean (cert cross-verify skipped via --no-cert-crossverify)."
    fi
    exit 0
fi

# Propagate the most severe child exit code so callers can distinguish
# (fork=2 catastrophic vs degraded=1 coverage vs cert=2 authn fail vs
# successful 0). If both tools failed, the larger code wins.
worst=0
if [ "$fork_rc" -gt "$worst" ]; then
    worst=$fork_rc
fi
if [ "$cert_rc" -gt "$worst" ]; then
    worst=$cert_rc
fi
echo "verify-soak: FAILED — fork_rc=$fork_rc cert_rc=$cert_rc (exit=$worst)" >&2
exit "$worst"
