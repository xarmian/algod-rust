#!/usr/bin/env bash
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Sourced by verify-soak.sh (issue #1777): the shell plumbing around
# cert_window.py, kept in its own file so cert_window_shell_test.sh can drive
# every fallback branch with stubbed `docker` / `sqlite3`.
#
#   probe_earliest_file <block.sqlite>          lowest block round or nothing
#   probe_earliest_container <ctr> <path>       same, via `docker exec sqlite3`
#   resolve_cert_window <from> <to> [earliest]  sets CERT_FROM / CERT_CLAMPED /
#                                               CERT_REASON; returns 2 on error
#
# Never silently unclamped: an unknown earliest round makes cert_window.py fall
# back to CERT_WINDOW (else the last 900 rounds) and report "earliest unknown".

CERT_WINDOW_DIR="${CERT_WINDOW_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"

_is_round() { [[ "${1:-}" =~ ^[0-9]+$ ]]; }

probe_earliest_file() {
    local f="$1" out=""
    [ -s "$f" ] || return 0
    if command -v sqlite3 >/dev/null 2>&1; then
        out="$(sqlite3 "$f" 'SELECT MIN(rnd) FROM blocks' 2>/dev/null | tr -d '\r' || true)"
    fi
    if ! _is_round "$out" && command -v python3 >/dev/null 2>&1; then
        out="$(python3 -c 'import sqlite3, sys; print(sqlite3.connect(sys.argv[1]).execute("SELECT MIN(rnd) FROM blocks").fetchone()[0])' "$f" 2>/dev/null | tr -d '\r' || true)"
    fi
    if _is_round "$out"; then
        echo "$out"
    fi
    return 0
}

probe_earliest_container() {
    local ctr="$1" path="$2" out=""
    out="$(docker exec "$ctr" sqlite3 "$path" 'SELECT MIN(rnd) FROM blocks' 2>/dev/null | tr -d '\r' || true)"
    if _is_round "$out"; then
        echo "$out"
    fi
    return 0
}

resolve_cert_window() {
    local frm="$1" to="$2" earliest="${3:-}" out
    CERT_WINDOW="${CERT_WINDOW:-0}"
    if ! _is_round "$CERT_WINDOW"; then
        echo "error: CERT_WINDOW must be a non-negative integer (got '$CERT_WINDOW')" >&2
        return 2
    fi
    CERT_RETAIN_MARGIN="${CERT_RETAIN_MARGIN:-auto}"
    if [ "$CERT_RETAIN_MARGIN" != "auto" ] && ! _is_round "$CERT_RETAIN_MARGIN"; then
        echo "error: CERT_RETAIN_MARGIN must be 'auto' or a non-negative integer (got '$CERT_RETAIN_MARGIN')" >&2
        return 2
    fi
    if ! out="$(python3 "$CERT_WINDOW_DIR/cert_window.py" "$frm" "$to" "${earliest:-none}" \
            "$CERT_RETAIN_MARGIN" "$CERT_WINDOW" "${SEED_LOOKBACK:-2}" "${SEED_REFRESH_INTERVAL:-80}" 2>&1)"; then
        echo "error: cert_window.py failed: $out" >&2
        return 2
    fi
    out="$(printf '%s' "$out" | tr -d '\r')"
    read -r CERT_FROM CERT_CLAMPED CERT_REASON <<< "$out"
    if ! _is_round "${CERT_FROM:-}" || [ -z "${CERT_CLAMPED:-}" ]; then
        echo "error: cert_window.py produced unparsable output: '$out'" >&2
        return 2
    fi
    if [ "$CERT_CLAMPED" = "1" ]; then
        echo "    CERT_WINDOW_CLAMPED=1 cert cross-verify covers $CERT_FROM..$to only (requested $frm..$to): $CERT_REASON"
    fi
    return 0
}
