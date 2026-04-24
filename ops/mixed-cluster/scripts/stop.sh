#!/usr/bin/env bash
# Tear down the PLAN-32 / TASK-86 mixed-cluster harness. By default this
# stops containers and removes their volumes but preserves the generated
# netroot/ tree so a subsequent start.sh can reuse keys + genesis. Pass
# --purge to wipe netroot/ as well (forces a clean bootstrap on next
# start.sh).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

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
    # goal network create writes files as the `algorand` user inside the
    # container (uid 1001). On host filesystems those files end up owned
    # by uid 1001 too, which the current host user typically can't delete
    # with a plain `rm -rf`. Do the deletion from inside a container so
    # root-in-namespace can unlink them, then clean up the now-empty
    # directory from the host side.
    if [ -d "$ROOT/netroot" ]; then
        # Prefer the in-container rm so root-owned files can be unlinked.
        # If the algod image isn't cached and the host is offline, the
        # pull will fail — fall back to a best-effort host-side rm so we
        # don't leave a half-cleaned netroot/ behind. A partial purge is
        # still preferable to `set -e` aborting mid-cleanup.
        if ! docker run --rm \
                -v "$ROOT/netroot:/netroot" \
                --entrypoint sh \
                algorand/algod:4.5.1-stable \
                -c 'rm -rf /netroot/* /netroot/.[!.]* 2>/dev/null || true'; then
            echo "warning: container-based purge failed (image unavailable?); \
falling back to host-side rm (may leave root-owned files behind)" >&2
        fi
        # Host-side fallback — works for host-owned leftovers and no-ops
        # on already-clean trees. `|| true` guards against leftover
        # root-owned files we couldn't unlink above.
        rm -rf "$ROOT/netroot" 2>/dev/null || true
        if [ -d "$ROOT/netroot" ]; then
            echo "warning: $ROOT/netroot still exists after purge — \
likely contains uid-1001 files. Re-run with docker available." >&2
        fi
    fi
fi

echo "cluster stopped."
