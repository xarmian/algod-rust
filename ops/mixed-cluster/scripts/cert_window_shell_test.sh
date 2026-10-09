#!/usr/bin/env bash
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Shell-plumbing test for cert_window.sh (issue #1777). No Docker: `docker` and
# `sqlite3` are stubs on PATH, so every fallback branch of verify-soak.sh's
# cert-window path runs.
#
#   bash ops/mixed-cluster/scripts/cert_window_shell_test.sh

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
FAILS=0

ok() { echo "ok   - $1"; }
bad() { echo "FAIL - $1"; FAILS=$((FAILS + 1)); }
check() {  # check <name> <expected> <actual>
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected '$2', got '$3')"; fi
}

mkdir -p "$TMP/bin"
# Fake docker: `docker exec <ctr> sqlite3 <path> <sql>` prints $FAKE_DOCKER_OUT
# and exits $FAKE_DOCKER_RC.
cat > "$TMP/bin/docker" <<'EOF'
#!/usr/bin/env bash
[ -n "${FAKE_DOCKER_OUT:-}" ] && echo "$FAKE_DOCKER_OUT"
exit "${FAKE_DOCKER_RC:-0}"
EOF
# Fake host sqlite3: absent-equivalent (fails) unless FAKE_SQLITE_OUT is set.
cat > "$TMP/bin/sqlite3" <<'EOF'
#!/usr/bin/env bash
[ -n "${FAKE_SQLITE_OUT:-}" ] || exit 1
echo "$FAKE_SQLITE_OUT"
EOF
chmod +x "$TMP/bin/docker" "$TMP/bin/sqlite3"
export PATH="$TMP/bin:$PATH"

# shellcheck source=cert_window.sh
source "$HERE/cert_window.sh"

# A real sqlite file for the python-module fallback.
DB="$TMP/block.sqlite"
python3 -c 'import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("CREATE TABLE blocks (rnd INTEGER PRIMARY KEY)")
c.executemany("INSERT INTO blocks VALUES (?)", [(1702,), (1703,), (2702,)])
c.commit()' "$DB"

# 1. container sqlite3 works
export FAKE_DOCKER_OUT=1702 FAKE_DOCKER_RC=0
check "container probe" 1702 "$(probe_earliest_container ctr /x)"

# 2. container sqlite3 missing -> empty
export FAKE_DOCKER_OUT="" FAKE_DOCKER_RC=127
check "container probe failure is empty" "" "$(probe_earliest_container ctr /x)"
export FAKE_DOCKER_OUT="Error: no such table" FAKE_DOCKER_RC=0
check "container probe non-numeric is empty" "" "$(probe_earliest_container ctr /x)"

# 3. host sqlite3 stub, then python module fallback (stub fails)
export FAKE_SQLITE_OUT=1500
check "host sqlite3 probe" 1500 "$(probe_earliest_file "$DB")"
export FAKE_SQLITE_OUT=""
check "python sqlite3 module fallback" 1702 "$(probe_earliest_file "$DB")"
check "missing file is empty" "" "$(probe_earliest_file "$TMP/nope.sqlite")"

# 4. window resolution
unset CERT_WINDOW CERT_RETAIN_MARGIN
resolve_cert_window 1 2702 1702 >/dev/null
check "known earliest: from" 2124 "$CERT_FROM"   # 1702 + 422
check "known earliest: clamped" 1 "$CERT_CLAMPED"

out="$(resolve_cert_window 1 2702 "")"
resolve_cert_window 1 2702 "" >/dev/null
check "unknown earliest: last 900" 1802 "$CERT_FROM"
check "unknown earliest: clamped" 1 "$CERT_CLAMPED"
case "$out" in *"CERT_WINDOW_CLAMPED=1"*"earliest unknown"*) ok "unknown earliest is announced" ;; *) bad "unknown earliest is announced: $out" ;; esac

CERT_WINDOW=300 resolve_cert_window 1 2702 "" >/dev/null
check "unknown earliest honours CERT_WINDOW" 2402 "$CERT_FROM"

resolve_cert_window 1 300 1 >/dev/null
check "archival short run unclamped" 0 "$CERT_CLAMPED"

# 5. bad inputs fail loudly (return 2)
CERT_WINDOW=abc resolve_cert_window 1 100 1 >/dev/null 2>&1
check "non-numeric CERT_WINDOW rejected" 2 "$?"
CERT_RETAIN_MARGIN=x resolve_cert_window 1 100 1 >/dev/null 2>&1
check "non-numeric margin rejected" 2 "$?"
mkdir -p "$TMP/bad"
printf 'import sys\nsys.stderr.write("boom")\nsys.exit(1)\n' > "$TMP/bad/cert_window.py"
err="$(CERT_WINDOW_DIR="$TMP/bad" resolve_cert_window 1 100 1 2>&1 >/dev/null)"
rc=$?
check "python failure returns 2" 2 "$rc"
case "$err" in *"cert_window.py failed: boom"*) ok "python failure is reported" ;; *) bad "python failure is reported: $err" ;; esac

if [ "$FAILS" -ne 0 ]; then
    echo "$FAILS failure(s)"
    exit 1
fi
echo "all cert_window shell tests passed"
