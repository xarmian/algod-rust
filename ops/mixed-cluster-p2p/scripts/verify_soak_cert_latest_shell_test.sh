#!/usr/bin/env bash
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Shell test for verify-soak.sh's --cert-latest N (issue #1913, the P2P
# analogue of ops/mixed-cluster's #1821). No Docker, no real verifiers: the
# fork detector and cert cross-verify binaries are stubs that record their
# arguments, and the Rust ledger is a tiny sqlite block DB passed through
# --cert-ledger. The script under test is copied into a throwaway tree that
# mirrors the repo layout (it resolves ../mixed-cluster/scripts/cert_window.sh
# relative to itself) so no netroot/ is created inside the checkout.
#
#   bash ops/mixed-cluster-p2p/scripts/verify_soak_cert_latest_shell_test.sh

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_P2P="$(cd "$HERE/.." && pwd)"
SRC_MIXED="$(cd "$SRC_P2P/../mixed-cluster" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILS=0

ok() { echo "ok   - $1"; }
bad() { echo "FAIL - $1"; FAILS=$((FAILS + 1)); }
check() {  # check <name> <expected> <actual>
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}

command -v python3 >/dev/null 2>&1 || { echo "python3 required"; exit 1; }

# Mirror of the repo layout.
R="$TMP/repo"
P2P="$R/ops/mixed-cluster-p2p"
mkdir -p "$P2P/scripts" "$R/ops/mixed-cluster/scripts" "$P2P/netroot/Node1" "$TMP/bin" "$TMP/out"
cp "$SRC_P2P/scripts/verify-soak.sh" "$P2P/scripts/"
cp "$SRC_MIXED/scripts/cert_window.sh" "$SRC_MIXED/scripts/cert_window.py" "$R/ops/mixed-cluster/scripts/"
echo aaaa > "$P2P/netroot/Node1/algod.token"

# Stub verifiers: record argv; exit codes controllable.
cat > "$TMP/bin/algo-fork-detector" <<'EOF'
#!/usr/bin/env bash
echo "$@" > "$STUB_DIR/fork.args"
exit 0
EOF
cat > "$TMP/bin/algo-cert-crossverify" <<'EOF'
#!/usr/bin/env bash
echo "$@" > "$STUB_DIR/cert.args"
exit 0
EOF
chmod +x "$TMP/bin/algo-fork-detector" "$TMP/bin/algo-cert-crossverify"
export STUB_DIR="$TMP"

# Snapshot ledger: split layout, block DB holds rounds 1..500.
python3 - "$TMP/snap" <<'EOF'
import sqlite3, sys
p = sys.argv[1]
sqlite3.connect(p + ".tracker.sqlite").execute("CREATE TABLE t(x)").connection.commit()
c = sqlite3.connect(p + ".block.sqlite")
c.execute("CREATE TABLE blocks(rnd INTEGER)")
c.executemany("INSERT INTO blocks VALUES (?)", [(i,) for i in range(1, 501)])
c.commit()
EOF

run() {  # run <args...>; sets RC, OUT
    rm -f "$TMP/cert.args" "$TMP/fork.args"
    OUT="$(bash "$P2P/scripts/verify-soak.sh" --skip-preflight --tools-dir "$TMP/bin" \
        --out-dir "$TMP/out" --cert-ledger "$TMP/snap" --from-round 1 --to-round 900 \
        --stride 20 "$@" 2>&1)"
    RC=$?
}
arg_of() {  # arg_of <flag>: value following <flag> in the recorded cert args
    [ -f "$TMP/cert.args" ] || { echo "<no cert run>"; return; }
    awk -v f="$1" '{for (i = 1; i < NF; i++) if ($i == f) { print $(i + 1); exit }}' "$TMP/cert.args"
}

# 1. Without the flag the cert pass keeps the requested --to-round.
run
check "no flag: exit 0" 0 "$RC"
check "no flag: cert to-round is the requested one" 900 "$(arg_of --to-round)"

# 2. --cert-latest 1: only the snapshot's own newest round.
run --cert-latest 1
check "latest 1: exit 0" 0 "$RC"
check "latest 1: from-round = snapshot tip" 500 "$(arg_of --from-round)"
check "latest 1: to-round = snapshot tip" 500 "$(arg_of --to-round)"
check "latest 1: fork detector still covers the whole range" "1 900" \
    "$(awk '{for (i = 1; i < NF; i++) { if ($i == "--from-round") a=$(i+1); if ($i == "--to-round") b=$(i+1) } print a, b}' "$TMP/fork.args")"
case "$OUT" in *"CERT_LATEST=1 cert cross-verify covers 500..500"*) ok "latest 1: announces the clamp" ;; *) bad "latest 1: announces the clamp" ;; esac

# 3. --cert-latest 3.
run --cert-latest 3
check "latest 3: from-round" 498 "$(arg_of --from-round)"
check "latest 3: to-round" 500 "$(arg_of --to-round)"

# 4. CERT_LATEST env is equivalent to the flag.
CERT_LATEST=2 run
check "env CERT_LATEST=2: from-round" 499 "$(arg_of --from-round)"
check "env CERT_LATEST=2: to-round" 500 "$(arg_of --to-round)"

# 5. N larger than the available range is clamped at --from-round.
run --from-round 499 --cert-latest 50
check "latest 50 clamps at --from-round" 499 "$(arg_of --from-round)"

# 6. Non-numeric N is rejected (exit 2) before any cert run.
run --cert-latest x
check "non-numeric N: exit 2" 2 "$RC"
check "non-numeric N: no cert run" "<no cert run>" "$(arg_of --from-round)"

# 7. --help documents the flag.
case "$(bash "$P2P/scripts/verify-soak.sh" --help 2>&1)" in *--cert-latest*) ok "--help mentions --cert-latest" ;; *) bad "--help mentions --cert-latest" ;; esac

if [ "$FAILS" -ne 0 ]; then
    echo "$FAILS failure(s)"
    exit 1
fi
echo "all verify-soak --cert-latest shell tests passed"
