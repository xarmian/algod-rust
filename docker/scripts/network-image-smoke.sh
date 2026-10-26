#!/usr/bin/env bash
# Copyright (c) 2026 Algod DAO
# SPDX-License-Identifier: MIT
# See the LICENSE-MIT file in the repository root for the full license text.

# Smoke test of a network image (`voimain`, later `aramidmain`; issue #2074,
# epic #2068): run the container, wait for /health, check that /versions
# reports the network's genesis id and that the round advances.
#
#   docker/scripts/network-image-smoke.sh <image> <genesis_id> [host_port]
#
# Environment: HEALTH_TIMEOUT (s, default 300), ROUND_TIMEOUT (s, default 1200:
# the first round can take a fast catchup), ADVANCE_TIMEOUT (s, default 180).

set -euo pipefail

IMAGE="${1:?usage: network-image-smoke.sh <image> <genesis_id> [host_port]}"
GENESIS_ID="${2:?usage: network-image-smoke.sh <image> <genesis_id> [host_port]}"
PORT="${3:-18090}"
NAME="network-smoke-$$"
TOKEN="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
BASE="http://127.0.0.1:${PORT}"

# always show what the node said and remove the container
trap 'docker logs "$NAME" 2>&1 | tail -80 || true; docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT

get() { curl -sf -m 10 -H "X-Algo-API-Token: $TOKEN" "$BASE$1"; }
last_round() { get /v2/status | grep -o '"last-round":[0-9]*' | cut -d: -f2; }

docker run -d --name "$NAME" -e TOKEN="$TOKEN" -p "${PORT}:8080" "$IMAGE" >/dev/null

echo "==> waiting for /health"
deadline=$(( $(date +%s) + ${HEALTH_TIMEOUT:-300} ))
until curl -sf "$BASE/health" >/dev/null; do
  [ "$(date +%s)" -lt "$deadline" ] || { echo "fatal: /health did not answer" >&2; exit 1; }
  docker inspect -f '{{.State.Running}}' "$NAME" | grep -q true \
    || { echo "fatal: the container exited" >&2; exit 1; }
  sleep 3
done

echo "==> checking /versions"
versions="$(get /versions)"
echo "$versions"
case "${versions//[[:space:]]/}" in
*"\"genesis_id\":\"${GENESIS_ID}\""*) ;;
*)
  echo "fatal: /versions does not report genesis_id=${GENESIS_ID}" >&2
  exit 1
  ;;
esac

echo "==> waiting for the first round (block sync or fast catchup)"
deadline=$(( $(date +%s) + ${ROUND_TIMEOUT:-1200} ))
r1=0
while :; do
  r1="$(last_round 2>/dev/null || echo 0)"
  [ "${r1:-0}" -gt 0 ] && break
  [ "$(date +%s)" -lt "$deadline" ] || { echo "fatal: the round never left 0" >&2; exit 1; }
  sleep 5
done
echo "round $r1"

echo "==> waiting for the round to advance"
deadline=$(( $(date +%s) + ${ADVANCE_TIMEOUT:-180} ))
while :; do
  r2="$(last_round 2>/dev/null || echo 0)"
  [ "${r2:-0}" -gt "$r1" ] && break
  [ "$(date +%s)" -lt "$deadline" ] || { echo "fatal: the round did not advance past $r1" >&2; exit 1; }
  sleep 5
done
echo "round advanced $r1 -> $r2"

start=$(date +%s)
docker stop -t 30 "$NAME" >/dev/null
took=$(( $(date +%s) - start ))
echo "docker stop took ${took}s"
[ "$took" -lt 20 ] || { echo "fatal: docker stop took ${took}s" >&2; exit 1; }
echo "ok"
