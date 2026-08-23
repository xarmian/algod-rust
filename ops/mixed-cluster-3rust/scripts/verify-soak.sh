#!/usr/bin/env bash
# Issue #496 (Phase 7) — 3 Go + 3 Rust mixed-cluster soak verifier.
#
# Copy of ../../mixed-cluster/scripts/verify-soak.sh pointed at this
# directory's six-node topology (phase7-* containers, ports 4101-4106).
# Unlike the 4-node harness, --rust-account/--min-rust-vote-rounds is
# meant to actually GATE here: at 50/50 stake the Rust vote is
# quorum-necessary, so a real soak run should always pass --rust-account
# and a --min-rust-vote-rounds well above the default of 1.
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
#   3. (issue #470 §2) `tools/cert-authenticate` — the inverse
#      direction. `algo-cert-crossverify --export-go-input` dumps the
#      raw (block, cert) bytes plus the ledger facts Go's verifier
#      needs, and the Go helper re-authenticates each certificate with
#      go-algorand v4.6.0-stable's own
#      `agreement.Certificate.Authenticate`. Combined with step 2, every
#      sampled certificate is proven to authenticate under BOTH
#      implementations. Enabled by passing `--rust-account`.
#
# Usage:
#   verify-soak.sh [--from-round N] [--to-round M] [--stride S]
#                  [--tools-dir PATH] [--no-cert-crossverify]
#                  [--cert-ledger PATH] [--skip-preflight]
#                  [--rust-account ADDR] [--min-rust-vote-rounds N]
#                  [--no-go-authenticate]
#
# Exit codes:
#   0 — every tool that ran reported clean
#   1 — the fork detector exited with its degraded-coverage code
#       (insufficient or fetch errors without `--allow-degraded`)
#   2 — the fork detector detected a real fork (bubbled up verbatim)
#       OR the cert cross-verify tool failed authentication
#       OR the Go-side authenticator rejected a certificate
#   3 — preflight failed (cluster not healthy, no token file, etc.)
#   4 — extracting the Rust ledger failed
#
# When several tools run and more than one fails, the larger exit code
# (most severe) wins.
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
# Cert cross-verify runs by default as of TASK-95 (the Rust relay now
# maintains a full-sync ledger). Pass --no-cert-crossverify to skip it
# (e.g. for a quick fork-only check), or --cert-ledger PATH to point at
# an externally-prepared SQLite instead of the relay container's.
RUN_CERT=1
CERT_LEDGER_OVERRIDE=""
# issue #470 §2 — Rust → Go direction.
RUST_ACCOUNT="${RUST_ACCOUNT:-}"
MIN_RUST_VOTE_ROUNDS="${MIN_RUST_VOTE_ROUNDS:-1}"
RUN_GO_AUTH=1

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
                         phase7-rust-node-4:/app/ledger.sqlite. The
                         ledger must be caught up past --to-round.
  --skip-preflight       Skip the status.sh health check.
  --rust-account ADDR    (#470 §2) Address of the Rust participant.
                         Enables the vote-in-certificate assertion and
                         the Go-side re-authentication step.
  --min-rust-vote-rounds N
                         Fail unless at least N sampled certificates
                         contain a vote from --rust-account (default 1).
  --no-go-authenticate   Skip the go-algorand-side authentication even
                         when --rust-account is given (e.g. no Docker,
                         or you only want the Rust-side assertions).
  -h, --help             Show this help.

Artifacts written:
  \$OUT_DIR/verify-fork-<ts>.jsonl
  \$OUT_DIR/verify-cert-<ts>.jsonl (unless --no-cert-crossverify)
  \$OUT_DIR/verify-go-input-<ts>.json  (with --rust-account)
  \$OUT_DIR/verify-go-report-<ts>.json (with --rust-account)
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
    --nodes "go-node-1=http://127.0.0.1:4101,go-node-2=http://127.0.0.1:4102,go-node-3=http://127.0.0.1:4103" \
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
        # `--cert-ledger` accepts the split-ledger layout introduced by
        # TASK-100: either a bare prefix (`/path/to/ledger`) or any
        # member of the pair (`/path/to/ledger.sqlite`,
        # `/path/to/ledger.tracker.sqlite`, `/path/to/ledger.block.sqlite`).
        # Derive the prefix the same way `algo_ledger::derive_ledger_prefix`
        # does and require the tracker file to exist — `algo-cert-crossverify`
        # opens the pair via `SqliteLedger::open(prefix)`, which gates on
        # `<prefix>.tracker.sqlite`. Pre-TASK-100 single-file ledgers are
        # not supported.
        CERT_PREFIX_CANDIDATE="${CERT_LEDGER_OVERRIDE%.tracker.sqlite}"
        CERT_PREFIX_CANDIDATE="${CERT_PREFIX_CANDIDATE%.block.sqlite}"
        CERT_PREFIX_CANDIDATE="${CERT_PREFIX_CANDIDATE%.sqlite}"
        if [ ! -s "${CERT_PREFIX_CANDIDATE}.tracker.sqlite" ]; then
            echo "error: --cert-ledger path $CERT_LEDGER_OVERRIDE is not a split-layout" >&2
            echo "       ledger (no non-empty ${CERT_PREFIX_CANDIDATE}.tracker.sqlite)." >&2
            echo "       Pre-TASK-100 single-file ledgers are no longer supported by" >&2
            echo "       algo-cert-crossverify; re-sync to produce a tracker+block pair." >&2
            exit 4
        fi
        if [ ! -s "${CERT_PREFIX_CANDIDATE}.block.sqlite" ]; then
            # cert-crossverify reads `blockdb.blocks`, so a missing or
            # empty block file would let `SqliteLedger::open` ATTACH an
            # empty stub and then fail later with a less actionable
            # error. Refuse up front.
            echo "error: --cert-ledger split prefix $CERT_PREFIX_CANDIDATE is missing the" >&2
            echo "       block database (no non-empty ${CERT_PREFIX_CANDIDATE}.block.sqlite)." >&2
            echo "       Provide both .tracker.sqlite + .block.sqlite, or re-sync." >&2
            exit 4
        fi
        CERT_LEDGER_PATH="$CERT_PREFIX_CANDIDATE"
        echo "==> cert cross-verify (Go-produced → Rust verifier), stride $STRIDE"
        echo "    ledger: $CERT_LEDGER_PATH (--cert-ledger override)"
    else
        WORKDIR="$(mktemp -d -t verify-soak.XXXXXX)"
        # Since TASK-100 the Rust node writes a pair of files
        # (`<prefix>.tracker.sqlite` + `<prefix>.block.sqlite`) instead of
        # a single `ledger.sqlite`. cert-crossverify only needs the
        # tracker file (it reads accountbase / onlineaccounts /
        # onlineroundparamstail / blocks via SqliteLedger::open, which
        # also opens the block file from the derived prefix). We snapshot
        # both files into $WORKDIR and pass the bare prefix to the
        # verifier.
        CERT_LEDGER_PREFIX="$WORKDIR/ledger"
        CERT_LEDGER_PATH="$CERT_LEDGER_PREFIX"
        TRACKER_PATH="${CERT_LEDGER_PREFIX}.tracker.sqlite"
        BLOCK_PATH="${CERT_LEDGER_PREFIX}.block.sqlite"
        echo "==> cert cross-verify (Go-produced → Rust verifier), stride $STRIDE"
        # Use SQLite's online backup API from INSIDE the container to
        # snapshot atomically. Plain `docker cp` of the WAL-mode main
        # file + sidecar WAL/SHM from a running writer can race with
        # appends or checkpoints and produce an inconsistent snapshot
        # that either fails to open or reports impossible state. The
        # `.backup` command runs the SQLite backup API which holds a
        # read lock for the duration and writes a fully consistent
        # file, which we then docker cp out in a single transfer.
        #
        # Requires sqlite3 inside the algod-rust container image; our
        # Dockerfile includes it. Fall back to plain docker cp with a
        # warning if `.backup` isn't available (e.g. slim images built
        # in CI without sqlite3).
        echo "    snapshotting Rust tracker + block databases via SQLite backup API"
        if docker exec phase7-rust-node-4 sqlite3 /app/ledger.tracker.sqlite \
                    ".backup '/app/verify-soak-tracker.sqlite'" >/dev/null 2>&1 \
                && docker exec phase7-rust-node-4 sqlite3 /app/ledger.block.sqlite \
                    ".backup '/app/verify-soak-block.sqlite'" >/dev/null 2>&1; then
            if ! docker cp phase7-rust-node-4:/app/verify-soak-tracker.sqlite \
                    "$TRACKER_PATH" 2>/dev/null; then
                echo "error: failed to docker cp the tracker snapshot." >&2
                exit 4
            fi
            if ! docker cp phase7-rust-node-4:/app/verify-soak-block.sqlite \
                    "$BLOCK_PATH" 2>/dev/null; then
                echo "error: failed to docker cp the block snapshot." >&2
                exit 4
            fi
            # Clean up the in-container snapshots; don't leak volume
            # space across runs. `rm -f` is safe even if a file vanished.
            docker exec phase7-rust-node-4 rm -f \
                    /app/verify-soak-tracker.sqlite \
                    /app/verify-soak-block.sqlite \
                >/dev/null 2>&1 || true
        else
            echo "    warning: sqlite3 .backup unavailable in container;" >&2
            echo "    falling back to raw docker cp (may be racy under heavy writes)" >&2
            if ! docker cp phase7-rust-node-4:/app/ledger.tracker.sqlite \
                    "$TRACKER_PATH" 2>/dev/null; then
                echo "error: failed to docker cp the tracker DB." >&2
                echo "       is phase7-rust-node-4 running?" >&2
                exit 4
            fi
            if ! docker cp phase7-rust-node-4:/app/ledger.block.sqlite \
                    "$BLOCK_PATH" 2>/dev/null; then
                echo "error: failed to docker cp the block DB." >&2
                echo "       is phase7-rust-node-4 running?" >&2
                exit 4
            fi
            for sidecar in \
                    ledger.tracker.sqlite-wal ledger.tracker.sqlite-shm \
                    ledger.block.sqlite-wal ledger.block.sqlite-shm; do
                docker cp "phase7-rust-node-4:/app/$sidecar" "$WORKDIR/$sidecar" \
                    2>/dev/null || true
            done
        fi
        if [ ! -s "$TRACKER_PATH" ] || [ ! -s "$BLOCK_PATH" ]; then
            echo "error: extracted ledger pair under $WORKDIR is empty" >&2
            exit 4
        fi
        echo "    ledger size: tracker=$(du -h "$TRACKER_PATH" | awk '{print $1}') block=$(du -h "$BLOCK_PATH" | awk '{print $1}')"
    fi
    # (#470 §2) When a Rust participant address is supplied, additionally
    # assert its votes are present in the sampled certs and dump the
    # bundle the go-algorand-side authenticator consumes.
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
        --node http://127.0.0.1:4101 \
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

# -- 3. Go-side certificate authentication (Rust → Go, issue #470 §2) ------
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
if [ "$go_auth_rc" -gt "$worst" ]; then
    worst=$go_auth_rc
fi
echo "verify-soak: FAILED — fork_rc=$fork_rc cert_rc=$cert_rc go_auth_rc=$go_auth_rc (exit=$worst)" >&2
exit "$worst"
