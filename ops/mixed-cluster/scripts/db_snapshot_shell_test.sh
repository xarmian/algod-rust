#!/usr/bin/env bash
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Shell test for db_snapshot.sh (issue #1963). No Docker: `docker` is a stub
# on PATH whose `exec ... sqlite3 ... .backup` fails with SQLITE_BUSY for the
# first $FAKE_BUSY_ATTEMPTS calls.
#
#   bash ops/mixed-cluster/scripts/db_snapshot_shell_test.sh

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
# Fake docker: every `docker exec` records its argv; one that runs `sqlite3`
# fails with a locked-database message while attempts <= FAKE_BUSY_ATTEMPTS.
cat > "$TMP/bin/docker" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$FAKE_DOCKER_LOG"
n=$(grep -c sqlite3 "$FAKE_DOCKER_LOG")
if [ "$n" -le "${FAKE_BUSY_ATTEMPTS:-0}" ]; then
    echo "Error: database is locked" >&2
    exit 1
fi
exit 0
STUB
chmod +x "$TMP/bin/docker"
export PATH="$TMP/bin:$PATH"
export FAKE_DOCKER_LOG="$TMP/docker.log"
export PHASE6_BACKUP_SLEEP=0

# shellcheck source=db_snapshot.sh
source "$HERE/db_snapshot.sh"

# 1. immediate success: one attempt, with a busy timeout in the sqlite3 call
: > "$FAKE_DOCKER_LOG"; export FAKE_BUSY_ATTEMPTS=0
phase6_backup_db ctr /app/x.sqlite /app/x.snap 2>"$TMP/err"; rc=$?
check "immediate success" 0 "$rc"
check "one attempt" 1 "$(grep -c sqlite3 "$FAKE_DOCKER_LOG")"
case "$(cat "$FAKE_DOCKER_LOG")" in *".timeout"*) ok "busy timeout is set" ;; *) bad "busy timeout is set: $(cat "$FAKE_DOCKER_LOG")" ;; esac
case "$(cat "$FAKE_DOCKER_LOG")" in *".backup '/app/x.snap'"*) ok "backup target passed" ;; *) bad "backup target: $(cat "$FAKE_DOCKER_LOG")" ;; esac

# 2. busy twice then success -> consistent snapshot, three attempts
: > "$FAKE_DOCKER_LOG"; export FAKE_BUSY_ATTEMPTS=2
phase6_backup_db ctr /app/x.sqlite /app/x.snap 2>"$TMP/err"; rc=$?
check "busy twice then success" 0 "$rc"
check "three attempts" 3 "$(grep -c sqlite3 "$FAKE_DOCKER_LOG")"
case "$(cat "$TMP/err")" in *"database is locked"*) ok "failed attempts' stderr is logged" ;; *) bad "stderr logged: $(cat "$TMP/err")" ;; esac

# 3. busy on every attempt -> failure after the bounded number of attempts
: > "$FAKE_DOCKER_LOG"; export FAKE_BUSY_ATTEMPTS=999 PHASE6_BACKUP_ATTEMPTS=4
phase6_backup_db ctr /app/x.sqlite /app/x.snap 2>"$TMP/err"; rc=$?
check "always busy fails" 1 "$rc"
check "bounded attempts" 4 "$(grep -c sqlite3 "$FAKE_DOCKER_LOG")"
unset PHASE6_BACKUP_ATTEMPTS

# 4. the inconsistent-snapshot announcement is grep-able like CERT_WINDOW_CLAMPED
out="$(phase6_announce_inconsistent_snapshot "tracker backup failed" 2>&1)"
case "$out" in *"SNAPSHOT_INCONSISTENT=1"*"tracker backup failed"*) ok "inconsistent snapshot is announced" ;; *) bad "announcement: $out" ;; esac

echo
if [ "$FAILS" -eq 0 ]; then
    echo "all db_snapshot checks passed"
else
    echo "$FAILS db_snapshot check(s) FAILED"
    exit 1
fi
