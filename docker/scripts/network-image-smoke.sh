#!/usr/bin/env bash
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Smoke test of a network image (`voimain`, `aramidmain`; issue #2074,
# epic #2068): run the container, wait for /health, check that /versions
# reports the network's genesis id and that the round advances, then that
# the node stops promptly and cleanly (no panic in its log).
#
#   docker/scripts/network-image-smoke.sh <image> <genesis_id> [host_port]
#
# Environment: HEALTH_TIMEOUT (s, default 300), ROUND_TIMEOUT (s, default 1500:
# the first round can take a fast catchup), ADVANCE_TIMEOUT (s, default 900: after the import the node
# still downloads the lookback blocks before it follows).
#
# The relays these networks sync from are external, so every failure is
# classified (issue #2121): `FAILURE CLASS: external network` when the node
# is healthy but the relays did not serve it, `FAILURE CLASS: node` when the
# node itself misbehaved (exited, panicked, did not stop in time, ...).

set -euo pipefail

IMAGE="${1:?usage: network-image-smoke.sh <image> <genesis_id> [host_port]}"
GENESIS_ID="${2:?usage: network-image-smoke.sh <image> <genesis_id> [host_port]}"
PORT="${3:-18090}"
NAME="network-smoke-$$"
TOKEN="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
BASE="http://127.0.0.1:${PORT}"
LOG=/tmp/network-smoke.log

# always show what the node said and remove the container
trap 'docker logs "$NAME" > "$LOG" 2>&1 || true; echo "--- entrypoint + first log lines"; head -40 "$LOG"; echo "--- catchup/sync lines"; grep -aiE "catchup|catchpoint|FAST_CATCHUP|lookback|ERROR" "$LOG" | grep -av "WS block fetch failed" | tail -40; echo "--- tail"; grep -av "WARN" "$LOG" | tail -40; docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT

get() { curl -sf -m 10 -H "X-Algo-API-Token: $TOKEN" "$BASE$1"; }
last_round() { get /v2/status | grep -o '"last-round":[0-9]*' | cut -d: -f2; }

# A panic anywhere in the node's log is a node failure, whatever else
# happened.
panics() {
  docker logs "$NAME" > "$LOG" 2>&1 || true
  grep -a -A1 "panicked at" "$LOG" || true
}

# fail <class> <message>: <class> is `node` (the node misbehaved) or `peers`
# (the node may be fine; check whether the relays are what failed it).
fail() {
  local class="$1" msg="$2" p
  p="$(panics)"
  if [ -n "$p" ]; then
    echo "FAILURE CLASS: node: $msg, and a thread panicked:" >&2
    printf '%s\n' "$p" | head -20 >&2 || true
  elif [ "$class" = peers ] && grep -aqE \
    "No relay answered|every candidate peer failed|block fetch failed|error sending request|lookback block download failed" "$LOG"; then
    echo "FAILURE CLASS: external network: $msg; the node is up but the relays did not serve" \
      "the catchpoint or the blocks (see the catchup/sync lines below). Not a node failure." >&2
  else
    echo "FAILURE CLASS: node: $msg" >&2
  fi
  exit 1
}

docker run -d --name "$NAME" -e TOKEN="$TOKEN" -p "${PORT}:8080" "$IMAGE" >/dev/null

echo "==> waiting for /health"
deadline=$(( $(date +%s) + ${HEALTH_TIMEOUT:-300} ))
until curl -sf "$BASE/health" >/dev/null; do
  [ "$(date +%s)" -lt "$deadline" ] || fail node "/health did not answer"
  docker inspect -f '{{.State.Running}}' "$NAME" | grep -q true \
    || fail node "the container exited"
  sleep 3
done

echo "==> checking /versions"
versions="$(get /versions)"
echo "$versions"
case "${versions//[[:space:]]/}" in
*"\"genesis_id\":\"${GENESIS_ID}\""*) ;;
*) fail node "/versions does not report genesis_id=${GENESIS_ID}" ;;
esac

echo "==> waiting for the first round (block sync or fast catchup)"
deadline=$(( $(date +%s) + ${ROUND_TIMEOUT:-1500} ))
r1=0
while :; do
  r1="$(last_round 2>/dev/null || echo 0)"
  [ "${r1:-0}" -gt 0 ] && break
  [ "$(date +%s)" -lt "$deadline" ] || fail peers "the round never left 0"
  docker inspect -f '{{.State.Running}}' "$NAME" | grep -q true \
    || fail node "the container exited"
  sleep 5
done
echo "round $r1"

echo "==> waiting for the round to advance"
deadline=$(( $(date +%s) + ${ADVANCE_TIMEOUT:-900} ))
while :; do
  r2="$(last_round 2>/dev/null || echo 0)"
  [ "${r2:-0}" -gt "$r1" ] && break
  [ "$(date +%s)" -lt "$deadline" ] || fail peers "the round did not advance past $r1"
  docker inspect -f '{{.State.Running}}' "$NAME" | grep -q true \
    || fail node "the container exited"
  sleep 5
done
echo "round advanced $r1 -> $r2"

# The node must stop on SIGTERM well inside docker's grace period, whatever
# its catchup is doing (a live catchup still fetching lookback blocks from
# slow relays included, issue #2121).
start=$(date +%s)
docker stop -t 30 "$NAME" >/dev/null
took=$(( $(date +%s) - start ))
echo "docker stop took ${took}s"
[ "$took" -lt 20 ] || fail node "docker stop took ${took}s (the node did not shut down on SIGTERM)"
[ -z "$(panics)" ] || fail node "the node stopped, but a thread panicked"
echo "ok"
