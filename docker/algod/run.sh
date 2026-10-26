#!/usr/bin/env bash
# Copyright (C) 2019-2026 Algorand Foundation Ltd.
# Modifications Copyright (C) 2026 Algod DAO
# This file is part of algod-rust, a modified work based on go-algorand
# (https://github.com/algorand/go-algorand).
#
# algod-rust is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# algod-rust is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with algod-rust.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

# Container entrypoint of the algod-rust `algod` image (issue #1991): the
# counterpart of go-algorand's docker/files/run/run.sh, honouring the same
# environment variables, /etc/algorand files and data-directory layout so that
# `algorand/algod` users can switch by changing only the image name.
#
# Differences from go's script (see docs/DOCKER_MIGRATION.md):
#   * `algocfg` flags come after the sub-command (`algocfg set -p K -v V -d .`);
#   * NODE_EXPORTER is not configured (algod-rust has none);
#   * telemetry options are accepted and ignored (diagcfg is a no-op);
#   * START_KMD=1 runs `kmd serve` directly (`goal kmd start` is not ported);
#   * private networks (no NETWORK) are created and started with
#     `goal network create/start` like go's script, and the container stops
#     the network on SIGTERM instead of `tail -f`-ing forever;
#   * algod is `exec`ed so that `docker stop`'s SIGTERM reaches it.
#
# The script is also `source`d by its shell test (docker/algod/run_sh_test.sh),
# which replaces `exec_algod` / `start_kmd`; `main` only runs when executed.

set -e

: "${ALGORAND_DATA:=/algod/data}"
: "${ALGOD_PORT:=8080}"
: "${KMD_PORT:=7833}"
GENESIS_DIR="${GENESIS_DIR:-/node/run/genesis}"
ETC_DIR="${ETC_DIR:-/etc/algorand}"
CATCHUP_DELAY="${CATCHUP_DELAY:-5}"
RUN_DIR="${RUN_DIR:-/node/run}"

if [ "$ALGORAND_DATA" != "/algod/data" ] && [ -z "${ALGOD_ENTRYPOINT_TEST:-}" ]; then
  echo "Do not override 'ALGORAND_DATA' environment variable."
  exit 1
fi

if [ "$DEBUG" = "1" ]; then
  set -x
fi

set_or_not() {
  if [ -n "$1" ]; then echo "Set"; else echo "Not Set"; fi
}

die() {
  echo "$*" >&2
  exit 1
}

# To allow mounting the data directory we need to change permissions to our
# algorand user. The script is initially run as root in order to change them,
# afterwards it is re-launched as the algorand user (gosu replaces the process,
# so signals keep reaching the final algod).
drop_privileges() {
  if [ "$(id -u)" = '0' ] && [ -z "${ALGOD_ENTRYPOINT_TEST:-}" ]; then
    chown -R algorand:algorand "$ALGORAND_DATA"
    exec gosu algorand "$(readlink -f "$0")" "$@"
  fi
}

####################
# Helper functions #
####################

# The network's REST gateway that advertises `last-catchpoint` in /v2/status,
# for networks without a static `latest.catchpoint` index (issue #2074; go's
# `goal node catchup` only knows the Algorand S3 index). Add a network here to
# give its image the same FAST_CATCHUP behaviour (see docs/NETWORK_PRESETS.md).
default_catchpoint_status_url() {
  case "$1" in
  voimain) echo "https://mainnet-api.voi.nodely.dev/v2/status" ;;
  aramidmain) echo "https://algod.aramidmain.a-wallet.net/v2/status" ;;
  *) echo "" ;;
  esac
}

# Prints the catchpoint label FAST_CATCHUP should use, or nothing to let
# `goal node catchup` look the label up itself (Algorand networks). Order:
# $CATCHPOINT, then the `last-catchpoint` of $CATCHPOINT_STATUS_URL (default:
# the network's gateway above). With a status URL configured, a gateway that
# does not answer or advertises no catchpoint yields no label and returns 1.
resolve_catchpoint_label() {
  if [ -n "${CATCHPOINT:-}" ]; then
    echo "$CATCHPOINT"
    return 0
  fi
  local url="${CATCHPOINT_STATUS_URL-$(default_catchpoint_status_url "$NETWORK")}"
  [ -n "$url" ] || return 0
  local i body label
  for i in $(seq 1 "${CATCHPOINT_LABEL_TRIES:-5}"); do
    body="$(curl -fsS -m 20 "$url" 2>/dev/null || true)"
    label="$(printf '%s' "$body" | sed -n 's/.*"last-catchpoint"[[:space:]]*:[[:space:]]*"//p' | sed 's/".*$//')"
    if [ -n "$label" ]; then
      echo "$label"
      return 0
    fi
    sleep "$CATCHUP_DELAY"
  done
  return 1
}

# SRV name of the network's relays, for networks where only some relays can
# serve a fast catchup (see pin_serving_relays).
default_srv_name() {
  case "$1" in
  voimain) echo "_algobootstrap._tcp.voimain.mainnet-voi.network" ;;
  aramidmain) echo "_algobootstrap._tcp.aramidmain.a-wallet.net" ;;
  *) echo "" ;;
  esac
}

# Prints a round in base 36, as go names the catchpoint file in
# /v1/<genesis>/ledger/<round>.
base36() {
  local n="$1" digits=0123456789abcdefghijklmnopqrstuvwxyz out=""
  if [ "$n" -le 0 ]; then
    echo 0
    return 0
  fi
  while [ "$n" -gt 0 ]; do
    out="${digits:$((n % 36)):1}$out"
    n=$((n / 36))
  done
  echo "$out"
}

# On Voi only a few of the SRV relays serve the catchpoint file and the blocks
# above it; the others answer 404 or time out, and a node that discovers them
# all stalls after the import while it downloads the lookback blocks (issue
# #2072 found this on the soak, #2074 in the image smoke test). Like the soak,
# probe the relays for the catchpoint file and use the ones that have it as
# the node's peers. Only with FAST_CATCHUP=1, no PEER_ADDRESS and a network
# with an SRV name; if no relay answers, DNS discovery stays in charge.
#
# Issue #2095: the node no longer NEEDS this. Its catchpoint download fails
# over across the ranked candidate relays, and the lookback-block download
# rotates past stalled/pruned relays with a bounded per-request timeout, so a
# bare `participate --network voimain` + POST /v2/catchup completed twice
# against live Voi with every SRV relay (docs/NETWORK_PRESETS.md). The pin is
# kept as a cheap optimisation (it skips the failed attempts) and because the
# image-level smoke and aramidmain paths were not re-verified without it.
pin_serving_relays() {
  [ -z "${PEER_ADDRESS:-}" ] && [ "${FAST_CATCHUP:-}" = "1" ] || return 0
  local srv label round path peers="" prio weight port target code
  srv="$(default_srv_name "$NETWORK")"
  [ -n "$srv" ] || return 0
  label="$(resolve_catchpoint_label)" || label=""
  round="${label%%#*}"
  case "$round" in '' | *[!0-9]*) return 0 ;; esac
  # (every preset's genesis id is <network>-v1.0)
  path="/v1/${NETWORK}-v1.0/ledger/$(base36 "$round")"
  while read -r prio weight port target; do
    [ -n "$target" ] || continue
    target="${target%.}"
    code="$(curl -s -m 8 -o /dev/null -w '%{http_code}' "http://$target:$port$path" 2>/dev/null || true)"
    echo "relay $target:$port: catchpoint file HTTP $code"
    if [ "$code" = "200" ]; then
      peers="${peers:+$peers;}$target:$port"
    fi
  done < <(dig +short SRV "$srv" 2>/dev/null)
  if [ -n "$peers" ]; then
    echo "Using the relays that serve the catchpoint: $peers"
    PEER_ADDRESS="$peers"
    # (the same label for the catchup that follows)
    CATCHPOINT="$label"
  else
    echo "No relay answered with the catchpoint file; leaving the peers to DNS discovery." >&2
  fi
}

catchup() {
  sleep "$CATCHUP_DELAY"
  # go's REST API answers within a second; algod-rust resolves its peers
  # first, so wait until the node answers before asking it to catch up, and
  # retry (a request refused while it is still starting is not a failure)
  local i ready=0
  for i in $(seq 1 "${CATCHUP_WAIT_TRIES:-150}"); do
    if goal node status >/dev/null 2>&1; then ready=1; break; fi
    sleep "${CATCHUP_WAIT_SLEEP:-2}"
  done
  if [ "$ready" = 0 ]; then
    echo "FAST_CATCHUP: the node did not answer in time; trying to start the catchup anyway" >&2
  fi
  local label=""
  if ! label="$(resolve_catchpoint_label)"; then
    echo "FAST_CATCHUP: no catchpoint label could be fetched for '$NETWORK'; skipping the fast catchup (the node syncs from its peers; set CATCHPOINT=<label> to choose one)" >&2
    return 1
  fi
  for i in 1 2 3 4 5; do
    if goal node catchup --force --min "${CATCHUP_MIN:-1000000}" ${label:+"$label"}; then
      supervise_catchup "$label"
      return $?
    fi
    sleep "$CATCHUP_DELAY"
  done
  return 1
}

# The node accepts a catchup and runs it in the background; one that ends
# without a ledger (the catchpoint relay it picked was unreachable, a download
# was cut off) leaves the node at round 0, where it can never sync block by
# block on a network whose relays have no early blocks (Voi). The relay for
# each catchup is drawn from the ranked candidates, so asking again usually
# succeeds (issue #2074: seen on GitHub runners). `goal node status` prints a
# `Catchpoint:` line while a catchup runs; a node still at round 0 without one,
# on two consecutive polls, has none running, so request it again, at most
# CATCHUP_RETRIES times.
supervise_catchup() {
  local label="$1" retries="${CATCHUP_RETRIES:-20}" idle=0 n=0 unknown=0 out
  while [ "$n" -lt "$retries" ]; do
    sleep "${CATCHUP_POLL:-20}"
    out="$(goal node status 2>/dev/null)" || out=""
    # (an unreachable node or unrecognised output: stop after 30 polls in a row)
    case "$out" in
    *"Last committed block: "*) unknown=0 ;;
    *)
      unknown=$((unknown + 1))
      if [ "$unknown" -ge 30 ]; then return 1; fi
      continue
      ;;
    esac
    if printf '%s
' "$out" | grep -q '^Catchpoint: '; then
      idle=0
    elif printf '%s
' "$out" | grep -q '^Last committed block: [1-9]'; then
      return 0
    elif printf '%s
' "$out" | grep -q '^Last committed block: 0$'; then
      idle=$((idle + 1))
      if [ "$idle" -ge 2 ]; then
        idle=0
        n=$((n + 1))
        echo "FAST_CATCHUP: the catchup ended without a ledger; asking again ($n/$retries)" >&2
        goal node catchup --force --min "${CATCHUP_MIN:-1000000}" ${label:+"$label"} || true
      fi
    fi
  done
  echo "FAST_CATCHUP: giving up after $retries retries" >&2
  return 1
}

exec_algod() {
  exec algod "$@"
}

start_kmd() {
  if [ "$START_KMD" = "1" ]; then
    kmd serve -d "$ALGORAND_DATA/kmd-v0.5" -a "0.0.0.0:${KMD_PORT}" --allow-origin '*'
  fi
}

configure_data_dir() {
  cd "$ALGORAND_DATA"

  # check for config file overrides.
  if [ -f "$ETC_DIR/config.json" ]; then
    cp "$ETC_DIR/config.json" config.json
  fi
  if [ -f "$ETC_DIR/algod.token" ]; then
    cp "$ETC_DIR/algod.token" algod.token
  fi
  if [ -f "$ETC_DIR/algod.admin.token" ]; then
    cp "$ETC_DIR/algod.admin.token" algod.admin.token
  fi
  if [ -f "$ETC_DIR/logging.config" ]; then
    cp "$ETC_DIR/logging.config" logging.config
  fi

  # initialize config with profile.
  if [ "$PROFILE" != "" ]; then
    algocfg profile set "$PROFILE" --yes -d "$ALGORAND_DATA"
  fi

  # set profile overrides
  if [ "$GOSSIP_PORT" != "" ]; then
    algocfg set -p NetAddress -v "0.0.0.0:${GOSSIP_PORT}" -d .
    algocfg set -p DisableNetworking -v "false" -d .
    algocfg set -p IncomingConnectionsLimit -v "1000" -d .
  fi

  algocfg set -p EndpointAddress -v "0.0.0.0:${ALGOD_PORT}" -d .

  # set token overrides
  for dir in "${ALGORAND_DATA}"/../*/; do
    if [ "$TOKEN" != "" ]; then
      printf '%s\n' "$TOKEN" >"$dir/algod.token"
    fi
    if [ "$ADMIN_TOKEN" != "" ]; then
      printf '%s\n' "$ADMIN_TOKEN" >"$dir/algod.admin.token"
    fi
  done

  # configure telemetry (accepted for compatibility; algod-rust has none)
  if [ "$TELEMETRY_NAME" != "" ]; then
    echo "TELEMETRY_NAME is accepted but ignored: algod-rust has no telemetry." >&2
    diagcfg telemetry name -n "$TELEMETRY_NAME" -d "$ALGORAND_DATA"
    if [ "$TELEMETRY_URL" != "" ]; then
      diagcfg telemetry endpoint -e "$TELEMETRY_URL" -d "$ALGORAND_DATA"
    fi
    diagcfg telemetry enable -d "$ALGORAND_DATA"
  elif ! [ -f "$ETC_DIR/logging.config" ]; then
    diagcfg telemetry disable
  fi

  # prepare kmd
  if [ "$START_KMD" = "1" ]; then
    local KMD_DIR="kmd-v0.5"
    # on initial bootstrap, this directory won't exist.
    mkdir -p "$KMD_DIR"
    chmod 0700 "$KMD_DIR"
    cd "$KMD_DIR"
    if [ -f "$ETC_DIR/kmd_config.json" ]; then
      cp "$ETC_DIR/kmd_config.json" kmd_config.json
    else
      echo "{ \"address\":\"0.0.0.0:${KMD_PORT}\", \"allowed_origins\":[\"*\"] }" >kmd_config.json
    fi

    if [ "$KMD_TOKEN" != "" ]; then
      printf '%s\n' "$KMD_TOKEN" >kmd.token
    fi
    cd "$ALGORAND_DATA"
  fi
}

start_public_network() {
  cd "$ALGORAND_DATA"

  configure_data_dir
  start_kmd &

  pin_serving_relays

  if [ "$FAST_CATCHUP" = "1" ]; then
    catchup &
  fi

  if [ "$PEER_ADDRESS" != "" ]; then
    echo "Using peer(s): $PEER_ADDRESS"
    exec_algod -o -p "$PEER_ADDRESS"
  else
    # redirect output to stdout
    exec_algod -o
  fi
}

start_new_public_network() {
  mkdir -p "$ALGORAND_DATA"
  cd "$ALGORAND_DATA"

  # initialize genesis.json
  if [ "$GENESIS_ADDRESS" != "" ]; then
    # download genesis file from peer
    echo "Attempting to download genesis file from $GENESIS_ADDRESS"
    # -f: an HTTP error must not leave an error page behind as genesis.json
    # (every later start would take the "existing data dir" branch with it)
    if ! curl -fsS "$GENESIS_ADDRESS/genesis" -o genesis.json; then
      rm -f genesis.json
      echo "Unable to download the genesis file from $GENESIS_ADDRESS" >&2
      exit 1
    fi
  elif [ -n "$NETWORK" ] && [ -d "$GENESIS_DIR/${NETWORK}" ]; then
    echo "Installing genesis file for ${NETWORK}"
    cp "$GENESIS_DIR/${NETWORK}/genesis.json" genesis.json
  else
    echo "No genesis file for '$NETWORK' is available."
    exit 1
  fi

  configure_data_dir

  # if the peer address is set, it will be used instead of the DNS bootstrap ID
  if [ "$PEER_ADDRESS" != "" ]; then
    local ID
    case $NETWORK in
    mainnet) ID="<network>.algorand.network" ;;
    testnet) ID="<network>.algorand.network" ;;
    betanet) ID="<network>.algodev.network" ;;
    alphanet) ID="<network>.algodev.network" ;;
    devnet) ID="<network>.algodev.network" ;;
    fnet) ID="<network>.algorand.tech" ;;
    # algod-rust network presets carry their own DNS bootstrap template
    # (docs/NETWORK_PRESETS.md); leave DNSBootstrapID at its default
    voimain | aramidmain) ID="" ;;
    *)
      echo "Unknown network."
      exit 1
      ;;
    esac
    if [ -n "$ID" ]; then
      echo Setting DNS Bootstrap ID to "$ID"
      algocfg set -p DNSBootstrapID -v "$ID" -d "$ALGORAND_DATA"
    fi
  elif [ "$NETWORK" = "fnet" ]; then
    echo Setting FNet DNS Bootstrap ID
    algocfg set -p DNSBootstrapID -v "<network>.algorand.tech" -d "$ALGORAND_DATA"
  fi

  start_public_network
}

# Follow the node's output until the container is told to stop, then stop the
# network cleanly (go just `tail -f`s node.log and leaves it to docker to kill
# the node).
# Stop the network and exit when the container is told to stop. Installed before
# the first long-running step (create / start): the entrypoint is PID 1 in the
# container, where a signal without a handler is dropped, so a `docker stop`
# landing during startup would otherwise be ignored until the grace period
# ends and Docker SIGKILLs it (issue #2018).
stop_network_on_signal() {
  PRIVATE_NETWORK_ROOT="$ALGORAND_DATA/.."
  trap 'goal network stop -r "$PRIVATE_NETWORK_ROOT" || true; kill ${TAIL_PID:-} ${KMD_PID:-} 2>/dev/null || true; exit 0' TERM INT
}

follow_private_network() {
  cd "$ALGORAND_DATA"
  # -F: the logs may not exist yet, and are recreated on restart
  tail -F node.log algod-out.log algod-err.log 2>/dev/null &
  TAIL_PID=$!
  stop_network_on_signal
  wait "$TAIL_PID"
  # (only reached when tail died: the network is still up, so this is an error)
  exit 1
}

start_private_network() {
  stop_network_on_signal
  configure_data_dir
  start_kmd &
  KMD_PID=$!

  goal network start -r "${ALGORAND_DATA}/.."
  follow_private_network
}

start_new_private_network() {
  stop_network_on_signal
  local TEMPLATE="template.json"
  if [ -f "$ETC_DIR/template.json" ]; then
    cp "$ETC_DIR/template.json" "$RUN_DIR/$TEMPLATE"
  elif [ "$DEV_MODE" = "1" ]; then
    TEMPLATE="devmode_template.json"
  fi
  sed -i "s/NUM_ROUNDS/${NUM_ROUNDS:-30000}/" "$RUN_DIR/$TEMPLATE"

  # Check if keys are mounted, and if so, use them as the pregenerated keys
  if [ -d "$ETC_DIR/keys" ]; then
    # (a restart after a failed first start must not nest keys/keys)
    rm -rf "$RUN_DIR/keys"
    cp -r "$ETC_DIR/keys" "$RUN_DIR/keys"
    goal network create --noclean -n dockernet -r "${ALGORAND_DATA}/.." -t "$RUN_DIR/$TEMPLATE" -p "$RUN_DIR/keys"
  else
    goal network create --noclean -n dockernet -r "${ALGORAND_DATA}/.." -t "$RUN_DIR/$TEMPLATE"
  fi

  start_private_network
}

##############
# Entrypoint #
##############

main() {
  drop_privileges "$@"

  echo "Starting Algod Docker Container"
  echo "   ALGORAND_DATA:   $ALGORAND_DATA"
  echo "   NETWORK:         $NETWORK"
  echo "   PROFILE:         $PROFILE"
  echo "   DEV_MODE:        $DEV_MODE"
  echo "   START_KMD:       ${START_KMD:-"Not Set"}"
  echo "   FAST_CATCHUP:    $FAST_CATCHUP"
  echo "   CATCHPOINT:      ${CATCHPOINT:-}"
  # (go prints the token values; the admin token is full control of the node
  # and `docker logs` is routinely shipped, so only whether they are set)
  echo "   TOKEN:           $(set_or_not "$TOKEN")"
  echo "   ADMIN_TOKEN:     $(set_or_not "$ADMIN_TOKEN")"
  echo "   KMD_TOKEN:       $(set_or_not "$KMD_TOKEN")"

  echo "   TELEMETRY_NAME:  $TELEMETRY_NAME"
  echo "   TELEMETRY_URL:   $TELEMETRY_URL"
  echo "   NUM_ROUNDS:      $NUM_ROUNDS"
  echo "   GENESIS_ADDRESS: $GENESIS_ADDRESS"
  echo "   PEER_ADDRESS:    $PEER_ADDRESS"
  echo "   GOSSIP_PORT:     $GOSSIP_PORT"
  echo "   ALGOD_PORT:      $ALGOD_PORT"

  # If the data directory is initialized, start the existing environment.
  if [ -f "$ALGORAND_DATA/../network.json" ]; then
    start_private_network
    exit 1
  elif [ -f "$ALGORAND_DATA/genesis.json" ]; then
    start_public_network
    exit 1
  fi

  # Initialize and start the network.
  if [ "$NETWORK" == "" ] && [ "$PEER_ADDRESS" == "" ]; then
    start_new_private_network
  else
    start_new_public_network
  fi
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
