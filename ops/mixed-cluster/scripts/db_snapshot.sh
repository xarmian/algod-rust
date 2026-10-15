#!/usr/bin/env bash
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Sourced by verify-soak.sh (issue #1963): a consistent snapshot of the live
# Rust node's SQLite ledger files.
#
#   phase6_docker_exec <args...>                     docker exec without MSYS
#       path conversion of container paths.
#   phase6_backup_db <container> <src-db> <dst-db>   sqlite3 .backup inside the
#       container, with a busy timeout and a bounded retry; sqlite3's stderr of
#       every failed attempt goes to stderr. 0 on success, 1 when all attempts
#       failed.
#   phase6_announce_inconsistent_snapshot <reason>   prints the grep-able
#       `SNAPSHOT_INCONSISTENT=1` line that consensus-conformance.sh turns
#       into a summary WARN, and that marks a cert failure as inconclusive.
#
# Env: PHASE6_BACKUP_ATTEMPTS (default 6), PHASE6_BACKUP_SLEEP seconds between
# attempts (default 3), PHASE6_BACKUP_TIMEOUT_MS sqlite busy timeout (default
# 30000). `.backup` holds a read lock while the node keeps writing; without a
# busy timeout it fails at once with SQLITE_BUSY and the script used to fall
# back to a raw copy of a WAL-mode database, which is not consistent.

# `docker exec` with container paths. Git Bash (MSYS) rewrites an argument
# like /app/x.sqlite into C:/Program Files/Git/app/x.sqlite, so on Windows
# the container never saw the right path (#1963). Harmless elsewhere.
phase6_docker_exec() {
    MSYS_NO_PATHCONV=1 docker exec "$@"
}

phase6_backup_db() {
    local ctr="$1" src="$2" dst="$3"
    local attempts="${PHASE6_BACKUP_ATTEMPTS:-6}" sleep_s="${PHASE6_BACKUP_SLEEP:-3}"
    local timeout_ms="${PHASE6_BACKUP_TIMEOUT_MS:-30000}" i out rc
    for ((i = 1; i <= attempts; i++)); do
        out="$(phase6_docker_exec "$ctr" sqlite3 "$src" ".timeout $timeout_ms" ".backup '$dst'" 2>&1)"
        rc=$?
        if [ "$rc" = 0 ]; then
            return 0
        fi
        # 126/127: the exec could not run sqlite3 at all (missing or not
        # executable); no number of retries changes that.
        if [ "$rc" = 126 ] || [ "$rc" = 127 ]; then
            echo "    sqlite3 is not runnable in $ctr (exit $rc): $(printf '%s' "$out" | tr '
' '  ')" >&2
            return 1
        fi
        echo "    sqlite3 .backup of $src failed (attempt $i/$attempts): $(printf '%s' "$out" | tr '\r\n' '  ')" >&2
        [ "$i" -lt "$attempts" ] && sleep "$sleep_s"
    done
    return 1
}

phase6_announce_inconsistent_snapshot() {
    echo "    SNAPSHOT_INCONSISTENT=1 the Rust ledger could not be snapshotted consistently ($1);" \
         "a cert failure below may be a snapshot artefact, not a node bug"
}
