#!/usr/bin/env bash
# Tear down the P2P interop + consensus harness (issues #543, #589). By
# default this stops all four containers (`docker compose down -v`, which
# also removes rust-node-4's named data volume) but preserves the
# generated netroot/ tree so a subsequent start.sh can reuse keys +
# genesis. Pass --purge to wipe netroot/ as well (forces a clean bootstrap
# on next start.sh).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

host_path() {
    if [ -n "${MSYSTEM:-}" ]; then
        (cd "$1" 2>/dev/null && pwd -W) || echo "$1"
    else
        echo "$1"
    fi
}

PURGE=0
for arg in "$@"; do
    case "$arg" in
        --purge) PURGE=1 ;;
        -h|--help)
            cat <<EOF
usage: $(basename "$0") [--purge]

  --purge   also delete netroot/ so the next start.sh re-generates keys +
            genesis from scratch. Default is to keep netroot/ for reuse.
EOF
            exit 0
            ;;
        *)
            echo "unknown arg: $arg" >&2
            exit 2
            ;;
    esac
done

cd "$ROOT"
echo "==> docker compose down -v"
docker compose down -v --remove-orphans

if [ "$PURGE" = "1" ]; then
    echo "==> purging netroot/"
    if [ -d "$ROOT/netroot" ]; then
        if ! MSYS_NO_PATHCONV=1 docker run --rm \
                -v "$(host_path "$ROOT/netroot"):/netroot" \
                --entrypoint sh \
                algorand/algod:4.7.0-stable \
                -c 'rm -rf /netroot/* /netroot/.[!.]* 2>/dev/null || true'; then
            echo "warning: container-based purge failed (image unavailable?); \
falling back to host-side rm (may leave root-owned files behind)" >&2
        fi
        rm -rf "$ROOT/netroot" 2>/dev/null || true
        if [ -d "$ROOT/netroot" ]; then
            echo "warning: $ROOT/netroot still exists after purge — \
likely contains uid-1001 files. Re-run with docker available." >&2
        fi
    fi
fi

echo "P2P interop harness stopped."
